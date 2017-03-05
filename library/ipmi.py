#!/usr/bin/env python
# -*- coding:utf8 -*-

import subprocess
import collections
from helpers.logger import log_error

# Named tuple representing CPU statistics.
#
# cpu1MinLoad: 1 minute load
# cpu5MinLoad: 5 minute load
# cpu15MinLoad: 15 minute load
#
CPUStats = collections.namedtuple('CPUStats',
                                  ['cpu_1_min', 'cpu_5_min', 'cpu_15_min'])

# Named tuple representing RAM statistics.
#
# total: Total Memory (bytes)
# used: Used Memory (bytes)
#
MemoryStats = collections.namedtuple('MemoryStats', ['total', 'used'])

# Named tuple representing disks.
#
# device: the device name for the disk
# path: the path from the disk
#
Disk = collections.namedtuple('Disk', ['device', 'path'])

# Named tuple representing disk statistics.
#
# size: storage size (bytes)
# used: storage used (bytes)
#
DiskStats = collections.namedtuple('DiskStats', ['size', 'used'])

# Named tuple representing an interface.
#
# name: the name of the interface
# mac: the MAC of the interface
# ip: the IP of the interface
#
Interface = collections.namedtuple('Interface', ['name', 'mac', 'ip'])

# Named tuple representing network interface statistics.
#
# bandwidth: current bandwidth (bytes/s)
# rx_bytes: total number of octets received (bytes)
# tx_bytes: total number of octets transmitted (bytes)
# error: number of outbound packets not transmitted because of errors
#
InterfaceStats = collections.namedtuple(
    'InterfaceStats', ['bandwidth', 'rx_bytes', 'tx_bytes', 'error'])

# Named tuple representing an Fan.
#
# name: the name of the fan
#
RPM = collections.namedtuple('RPM', ['name'])

# Named tuple representing Fan statistics.
#
# speed: current speed(RPM)
# status: state of fan (ok)
#
RPMStats = collections.namedtuple('RPMStats', ['speed', 'status'])

# Named tuple representing an voltage.
#
# name: the name of the system element
#
Volt = collections.namedtuple('Volt', ['name'])

# Named tuple representing voltage statistics.
#
# voltage: current voltage(Volt)
# status: state of element (ok)
#
VoltStats = collections.namedtuple('VoltStats', ['voltage', 'status'])

# Named tuple representing an temperature.
#
# name: the name of the system element
#
Degree = collections.namedtuple('Degree', ['name'])

# Named tuple representing network temperature statistics.
#
# temperature: current temperature(Degree C)
# status: state of element (ok)
#
DegreeStats = collections.namedtuple('DegreeStats', ['temperature', 'status'])


class IPMIException(Exception):
    pass


class IPMIInspector(object):
    def __init__(self):
        super(IPMIInspector, self).__init__()

    def execute_ipmi_command(self, host, command):
        hostname = host.hostname
        password = host.netloc.split(":")[1].split("@")[0]
        user = host.netloc.split(":")[0]
        all_command = "ipmitool "
        all_command += command
        all_command += " -H " + hostname
        all_command += " -U " + user
        all_command += " -P " + password
        child = subprocess.Popen(
            all_command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        output, error = child.communicate()
        if child.returncode == 0:
            return output
        else:

            log_error(error)
        raise IPMIException

    def execute_sensor_ipmi_command(self, host):
        return self.execute_ipmi_command(host, "sensor")

    def execute_syslog_ipmi_command(self, host):
        return self.execute_ipmi_command(host, "sel list")

    def get_sensor_list(self, host, sensor=None):
        sensor_list = []
        output = self.execute_sensor_ipmi_command(host)
        for line in output.split('\n'):
            if line:
                if sensor is None:
                    sensor_list.append({
                        "name": line.split('|')[0].strip(),
                        "value": float(line.split('|')[1].strip()),
                        "status": line.split('|')[3].strip()
                    })
                elif line.split('|')[2].strip() == sensor:
                    sensor_list.append({
                        "name": line.split('|')[0].strip(),
                        "value": float(line.split('|')[1].strip()),
                        "status": line.split('|')[3].strip()
                    })
        if not sensor_list:
            log_error("No %s sensor", sensor)
        else:
            return sensor_list

    def inspect_speed(self, host):

        sensor_list = self.get_sensor_list(host, "RPM")
        for sensor in sensor_list:
            rpm = RPM(name=sensor["name"])
            stats = RPMStats(speed=sensor["value"], status=sensor["status"])
            yield (rpm, stats)

    def inspect_voltage(self, host):
        sensor_list = self.get_sensor_list(host, "Volts")
        for sensor in sensor_list:
            volt = Volt(name=sensor["name"])
            stats = VoltStats(voltage=sensor["value"], status=sensor["status"])
            yield (volt, stats)

    def inspect_temperature(self, host):
        sensor_list = self.get_sensor_list(host, "degrees C")
        for sensor in sensor_list:
            degree = Degree(name=sensor["name"])
            stats = DegreeStats(
                temperature=sensor["value"], status=sensor["status"])
            yield (degree, stats)
