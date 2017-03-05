#!/usr/bin/env python
# -*- coding:utf8 -*-

import netsnmp


class SNMPInspector():
    #CPU OIDs
    _cpu_1_min_load_oid = "1.3.6.1.4.1.2021.10.1.3.1"
    _cpu_5_min_load_oid = "1.3.6.1.4.1.2021.10.1.3.2"
    _cpu_15_min_load_oid = "1.3.6.1.4.1.2021.10.1.3.3"
    #Memory OIDs
    _memory_total_oid = "1.3.6.1.4.1.2021.4.5.0"
    _memory_used_oid = "1.3.6.1.4.1.2021.4.6.0"
    #Disk OIDs
    _disk_index_oid = "1.3.6.1.4.1.2021.9.1.1"
    _disk_path_oid = "1.3.6.1.4.1.2021.9.1.2"
    _disk_device_oid = "1.3.6.1.4.1.2021.9.1.3"
    _disk_size_oid = "1.3.6.1.4.1.2021.9.1.6"
    _disk_used_oid = "1.3.6.1.4.1.2021.9.1.8"
    #Network Interface OIDs
    _interface_index_oid = "1.3.6.1.2.1.2.2.1.1"
    _interface_name_oid = "1.3.6.1.2.1.2.2.1.2"
    _interface_bandwidth_oid = "1.3.6.1.2.1.2.2.1.5"
    _interface_mac_oid = "1.3.6.1.2.1.2.2.1.6"
    _interface_ip_oid = "1.3.6.1.2.1.4.20.1.2"
    _interface_received_oid = "1.3.6.1.2.1.2.2.1.10"
    _interface_transmitted_oid = "1.3.6.1.2.1.2.2.1.16"
    _interface_error_oid = "1.3.6.1.2.1.2.2.1.20"
    #Default port and security name
    _port = 161
    _security_name = 'public'


class OID:

    sysName = "1.3.6.1.2.1.1.5.0"
    sysDescr = "1.3.6.1.2.1.1.1.0"
    sysUpTimeInstance = "1.3.6.1.2.1.1.3.0"
    sysContact = "1.3.6.1.2.1.1.4.0"
    sysLocation = "1.3.6.1.2.1.1.6.0"

    dot1dBaseNumPorts = "1.3.6.1.2.1.17.1.2.0"
    dot1dBasePortIfIndex = "1.3.6.1.2.1.17.1.4.1.2"

    dot1dTpFdbAddress = "1.3.6.1.2.1.17.4.3.1.1"
    dot1dTpFdbPort = "1.3.6.1.2.1.17.4.3.1.2"
    dot1dTpFdbStatus = "1.3.6.1.2.1.17.4.3.1.3"

    ifAdminStatus = "1.3.6.1.2.1.2.2.1.7"
    ifOperStatus = "1.3.6.1.2.1.2.2.1.8"
    ifDescr = "1.3.6.1.2.1.2.2.1.2"
    ifIndex = "1.3.6.1.2.1.2.2.1.1"
    ifType = "1.3.6.1.2.1.2.2.1.3"
    ifAlias = "1.3.6.1.2.1.31.1.1.1.18"

    ifName = "1.3.6.1.2.1.31.1.1.1.1"
    ifStackStatus = "1.3.6.1.2.1.31.1.2.1.3"
    ifInOctects = "1.3.6.1.2.1.2.2.1.10"
    ifInUcastPkts = "1.3.6.1.2.1.2.2.1.11"
    ifOutUcastPkts = "1.3.6.1.2.1.2.2.1.17"
    ifSpeed = "1.3.6.1.2.1.2.2.1.5"

    dot1qTpFdbEntry = "1.3.6.1.2.1.17.7.1.2.2.1"
    dot1qTpFdbPort = "1.3.6.1.2.1.17.7.1.2.2.1.2"
    dot1qTpFdbStatus = "1.3.6.1.2.1.17.7.1.2.2.1.3"

    dot1qVlanStaticEntry = "1.3.6.1.2.1.17.7.1.4.3.1"  # Dot1qVlanStaticEntry
    dot1qVlanStaticName = "1.3.6.1.2.1.17.7.1.4.3.1.1"
    dot1qVlanFdbId = "1.3.6.1.2.1.17.7.1.4.2.1.3"
    dot1qVlanStaticEgressPorts = "1.3.6.1.2.1.17.7.1.4.3.1.2"  # portlist
    dot1qVlanForbiddenEgressPorts = "1.3.6.1.2.1.17.7.1.4.3.1.3"  # portlist
    dot1qVlanStaticUntaggedPorts = "1.3.6.1.2.1.17.7.1.4.3.1.4"  # portlist
    dot1qVlanStaticRowStatus = "1.3.6.1.2.1.17.7.1.4.3.1.5"  #    RowStatus 1:active, 2:notInService, 3:notReady, 4:createAndGo, 5:createAndWait, 6:destroy
    dot1qPvid = "1.3.6.1.2.1.17.7.1.4.5.1.1"

    linksysGeneralPortAccess = "1.3.6.1.4.1.89.48.22.1.1"

    force10chSysCardUpperTemp = "1.3.6.1.4.1.6027.3.1.1.2.3.1.8"
    force10chSerialNumber = "1.3.6.1.4.1.6027.3.1.1.1.2.0"

    # 4526.1.2.13.1.1.1.<vlan id> = i <vlan id>
    # 4526.1.2.13.1.1.2.<vlan id> = s <vlan name>
    # 4526.1.2.13.1.1.3.<vlan id> = i <active 1 ? >
    netgearVlanStaticId = "1.3.6.1.4.1.4516.1.2.13.1.1.1"
    netgearVlanStaticName = "1.3.6.1.4.1.4526.1.2.13.1.1.2"
    netgearVlanStaticRowStatus = "1.3.6.1.4.1.4526.1.2.13.1.1.3"  # i 6 destroy, i 1 active , 5 create (and wait ? ) 4 works too
    # pvid 1.3.6.1.4.1.4526.1.2.11.6.1.12.<pid> i <vlan id>
    netgearGeneralPortAccess = "1.3.6.1.4.1.4526.1.2.11.6.1.12"
    # port member
    #4526.1.2.13.2.1.1.<pid>.<vlan id> = i <pid>
    #4526.1.2.13.2.1.2.<pid>.<vlan id> = i <vlan id>
    #4526.1.2.13.2.1.3.<pid>.<vlan id> = i 1
    #4526.1.2.13.2.1.4.<pid>.<vlan id> = i <tagged = 2, untagged = 1>
    netgearVlanTaggedTable = "1.3.6.1.4.1.4526.1.2.13.2.1"
    netgearVlanTaggedPortId = "1.3.6.1.4.1.4526.1.2.13.2.1.1"
    netgearVlanTaggedVlanId = "1.3.6.1.4.1.4526.1.2.13.2.1.2"
    # guess work about this row
    netgearVlanTaggedRowStatus = "1.3.6.1.4.1.4526.1.2.13.2.1.3"
    netgearVlanTaggedType = "1.3.6.1.4.1.4526.1.2.13.2.1.4"

    ciscoVtpVlanState = "1.3.6.1.4.1.9.9.46.1.3.1.1.2"
    ciscoVtpVlanEditTable = "1.3.6.1.4.1.9.9.46.1.4.2"
    ciscoVtpVlanEditOperation = "1.3.6.1.4.1.9.9.46.1.4.1.1.1"  #.1
    ciscoVtpVlanEditBufferOwner = "1.3.6.1.4.1.9.9.46.1.4.1.1.3"  # .1
    ciscoVtpVlanEditRowStatus = "1.3.6.1.4.1.9.9.46.1.4.2.1.11"  #.1.<vlan id>
    ciscoVtpVlanEditType = "1.3.6.1.4.1.9.9.46.1.4.2.1.3"  #.1.<vlan id>
    ciscoVtpVlanEditName = "1.3.6.1.4.1.9.9.46.1.4.2.1.4"  #.1.<vlan id>
    ciscoVtpVlanEditDot10Said = " 1.3.6.1.4.1.9.9.46.1.4.2.1.6"  #.1.<vlan id>
    ciscoVtpVlanType = "1.3.6.1.4.1.9.9.46.1.3.1.1.3"
    ciscoVtpVlanName = "1.3.6.1.4.1.9.9.46.1.3.1.1.4"
    ciscoVtpVlanifIndex = "1.3.6.1.4.1.9.9.46.1.3.1.1.18"
    ciscoVmVlan = "1.3.6.1.4.1.9.9.68.1.2.2.1.2"
    ciscoVmMembershipSummaryMemberPorts = "1.3.6.1.4.1.9.9.68.1.2.1.1.2"

    ciscoVlanTrunkPortEncapsulationType = "1.3.6.1.4.1.9.9.46.1.6.1.1.3"
    ciscoVlanTrunkPortVlansEnabled = "1.3.6.1.4.1.9.9.46.1.6.1.1.4"
    ciscoVlanTrunkPortVlansPruningEligible = "1.3.6.1.4.1.9.9.46.1.6.1.1.10"

    extremeVlanStaticName = "1.3.6.1.4.1.1916.1.2.1.2.1.2"
    extremeVlanStaticType = "1.3.6.1.4.1.1916.1.2.1.2.1.3"
    extremeVlanStaticExternalID = "1.3.6.1.4.1.1916.1.2.1.2.1.4"
    extremeVlanStaticRowStatus = "1.3.6.1.4.1.1916.1.2.1.2.1.6"
    extremeVlanNextAvailableIndex = "1.3.6.1.4.1.1916.1.2.2.1.0"
    extremeVlanTaggedType = "1.3.6.1.4.1.1916.1.2.3.1.1.2"
    extremeVlanTaggedTag = "1.3.6.1.4.1.1916.1.2.3.1.1.3"
    extremeVlanTaggedRowStatus = "1.3.6.1.4.1.1916.1.2.3.1.1.4"
    extremeOverTemperatureAlarm = "1.3.6.1.4.1.1916.1.1.1.7.0"
    extremeCurrentTemperature = "1.3.6.1.4.1.1916.1.1.1.8.0"
    extremeFanStatusTable = "1.3.6.1.4.1.1916.1.1.1.9.1.2"
    extremeSystemID = "1.3.6.1.4.1.1916.1.1.1.18.0"

    threecomVlanStaticName = "1.3.6.1.4.1.43.10.1.14.1.2.1.2"
    threecomVlanStaticType = "1.3.6.1.4.1.43.10.1.14.1.2.1.3"
    threecomVlanStaticExternalID = "1.3.6.1.4.1.43.10.1.14.1.2.1.4"
    threecomVlanStaticRowStatus = "1.3.6.1.4.1.43.10.1.14.1.2.1.6"
    threecomVlanNextAvailableIndex = "1.3.6.1.4.1.43.10.1.14.3.1.0"
    threecomVlanTaggedType = "1.3.6.1.4.1.43.10.1.14.4.1.1.2"
    threecomVlanTaggedTag = "1.3.6.1.4.1.43.10.1.14.4.1.1.3"
    threecomVlanTaggedRowStatus = "1.3.6.1.4.1.43.10.1.14.4.1.1.4"
    threecomStackUnitSerialNumber = "1.3.6.1.4.1.43.10.27.1.1.1.13.1"

    hpPoeTable = "1.3.6.1.2.1.105.1.1.1.3.1"
    hpPoeDeliveringStatusTable = "1.3.6.1.2.1.105.1.1.1.6.1"
    hpPoePowerPriorityTable = "1.3.6.1.2.1.105.1.1.1.7.1"
    hpPoeOverloadCounterTable = "1.3.6.1.2.1.105.1.1.1.13.1"
    hpPoeNominalPower = "1.3.6.1.2.1.105.1.3.1.1.2.1"
    hpPoeOperationalStatus = "1.3.6.1.2.1.105.1.3.1.1.3.1"
    hpPoePowerConsumption = "1.3.6.1.2.1.105.1.3.1.1.4.1"

    apcSerialNumber = "1.3.6.1.4.1.318.1.1.12.1.6.0"
    apcCurrent = "1.3.6.1.4.1.318.1.1.12.2.3.1.1.2.1"
    apcControl = "1.3.6.1.4.1.318.1.1.12.3.3.1.1.4"
    apcStatus = "1.3.6.1.4.1.318.1.1.12.3.5.1.1.4"

    sensatronicsProbe = "1.3.6.1.4.1.16174.1.1.1.3"

    ###########################################################################################
    #   SNMP CISCO OIDs
    ###########################################################################################
    # CISCO-VTP-MIB.my OIDs for Catalyst switch
    VLAN_STATUS_TABLE = "1.3.6.1.4.1.9.9.46.1.3.1.1.2.1"
    VLAN_TYPES_TABLE = "1.3.6.1.4.1.9.9.46.1.3.1.1.3.1"
    VLAN_NAMES_TABLE = "1.3.6.1.4.1.9.9.46.1.3.1.1.4.1"
    # CISCO-VLAN-MEMBERSHIP.my OIDs for Catalyst switch
    VLAN_TO_PORTS_TABLE = "1.3.6.1.4.1.9.9.68.1.2.2.1.2"

    SWITCH_DB_ADDRESSES_TABLE = "1.3.6.1.2.1.17.4.3.1.1"
    SWITCH_DB_PORTS_TABLE = "1.3.6.1.2.1.17.4.3.1.2"
    SWITCH_DB_STATUS_TABLE = "1.3.6.1.2.1.17.4.3.1.3"
    PORT_IDS_TABLE = "1.3.6.1.2.1.17.1.4.1.2"
    IFNAME_TABLE = "1.3.6.1.2.1.31.1.1.1.1"

    VLAN_PORTS_TABLE = "1.3.6.1.4.1.9.9.68.1.2.1.1.2"

    # Adding VLANs
    VLAN_EDIT_TABLE = "1.3.6.1.4.1.9.9.46.1.4.2"
    VLAN_EDIT_OPERATION = "1.3.6.1.4.1.9.9.46.1.4.1.1.1.1"
    VLAN_EDIT_BUFFER_OWNER = "1.3.6.1.4.1.9.9.46.1.4.1.1.3.1"
    VLAN_EDIT_ROW_STATUS = "1.3.6.1.4.1.9.9.46.1.4.2.1.11.1"
    VLAN_EDIT_TYPE = "1.3.6.1.4.1.9.9.46.1.4.2.1.3.1"
    VLAN_EDIT_NAME = "1.3.6.1.4.1.9.9.46.1.4.2.1.4.1"
    VLAN_EDIT_DOT_10_SAID = "1.3.6.1.4.1.9.9.46.1.4.2.1.6.1"

    # Adding Ports
    VLAN_VM_VLAN = "1.3.6.1.4.1.9.9.68.1.2.2.1.2"


class Snmp:
    version = 2
    community = "public"
    useNumeric = True
    destination = None

    _session = None

    def __init__(self):
        self._session = netsnmp.Session(
            Version=self.version,
            Community=self.community,
            UseNumeric=self.useNumeric)

    def dest(self, destination):
        self.destination = destination

    def get(self, oid):
        var = netsnmp.Varbind(oid)
        ret = netsnmp.snmpget(
            var,
            Version=self.version,
            Community=self.community,
            UseNumeric=self.useNumeric,
            DestHost=self.destination)
        return ret[0]

    def walk(self, oid, format=None):
        var = netsnmp.VarList(netsnmp.Varbind(oid))
        ret = netsnmp.snmpwalk(
            var,
            Version=self.version,
            Community=self.community,
            UseNumeric=self.useNumeric,
            DestHost=self.destination)

        if format == "values":
            return [var[i].val for i in range(len(var))]
        elif format == "keys":
            return [var[i].iid for i in range(len(var))]
        elif format == "tuples":
            return [(var[i].iid, var[i].val) for i in range(len(var))]
        elif format == "dict":
            return dict([(var[i].iid, var[i].val) for i in range(len(var))])
        else:
            return [(var[i].tag, var[i].iid, var[i].type, var[i].val)
                    for i in range(len(var))]


import binascii


class Switch:
    _snmp = None
    "Internal variable holding SNMP instance"

    OID = {
        'vendor_sign': '.1.3.6.1.2.1.1.1.0',
        'interface': {
            'name': '.1.3.6.1.2.1.2.2.1.2',
            'type': '.1.3.6.1.2.1.2.2.1.3',
            'mac': '.1.3.6.1.2.1.2.2.1.6',
        },
        'cam': {
            'cisco': {
                'vlan_state': '.1.3.6.1.4.1.9.9.46.1.3.1.1.2',
                'mac_address': '.1.3.6.1.2.1.17.4.3.1.1',
                'mac_bridge_port': '.1.3.6.1.2.1.17.4.3.1.2',
                'bridge_interface': '.1.3.6.1.2.1.17.1.4.1.2',
            },
            'juniper': {
                'vlan_tags': '.1.3.6.1.4.1.2636.3.40.1.5.1.5.1.5',
                'mac_port': '.1.3.6.1.2.1.17.7.1.2.2.1.2',
                'mac_status': '.1.3.6.1.2.1.17.7.1.2.2.1.3',
                'bridge_interface': '.1.3.6.1.2.1.17.1.4.1.2'
            },
            # 'h3c': {
            #     'mac_address' : '.1.3.6.1.4.1.2011.2.23.1.3.1.1.1',
            #     'mac_vlan' : '.1.3.6.1.4.1.2011.2.23.1.3.1.1.2',
            #     'mac_port' : '.1.3.6.1.4.1.2011.2.23.1.3.1.1.3',
            #     },
            'h3c': {
                'mac_port': '.1.3.6.1.2.1.17.7.1.2.2.1.2',
                'bridge_interface': '.1.3.6.1.2.1.17.1.4.1.2'
            }
        },
    }
    "List of used SNMP OIDs"

    def __init__(self, dest=None):
        self._snmp = Snmp()

        if dest != None:
            self._snmp.dest(dest)

    def setDest(self, dest):
        self._snmp.dest(dest)

    def getVendor(self, dest=None):
        if dest != None:
            self._snmp.dest(dest)
        ven = self._snmp.get(self.OID['vendor_sign'])
        if ven == None:  # host unreachable
            return 'unknown'
        if ven.find('Cisco IOS Software') >= 0 or ven.find(
                'Cisco Internetwork') >= 0:
            return 'cisco'
        if ven.find('Juniper Networks') >= 0:
            return 'juniper'
        if ven.find('H3C') >= 0 or ven.find('Hangzhou H3C') >= 0:
            return 'h3c'
        if ven.find('Huawei Versatile') >= 0 or ven.find(
                'HUAWEI-3COM CORP') >= 0:
            return 'huawei'
        if ven.find('HP V1910') >= 0 or ven.find('HP Comware') >= 0:
            return 'hp'
        if ven.find('3Com Switch') >= 0 or ven.find(
                'Huawei-3Com Versatile') >= 0:
            return '3com'
        return 'unknown'

    def binToMac(self, bin):
        mac = binascii.hexlify(bin)
        return ":".join(
            [mac[0:12:2][i] + mac[1:12:2][i] for i in range(len(mac) / 2)])

    def tagToMac(self, tag):
        return ":".join(
            [hex(int(x))[2:].rjust(2, "0") for x in tag.split(".")])

    def getInterfaces(self, dest=None):
        if dest != None:
            self._snmp.dest(dest)

        int_name = self._snmp.walk(self.OID['interface']['name'])
        int_mac = self._snmp.walk(self.OID['interface']['mac'])

        return [(int_name[i][1], int_name[i][3], self.binToMac(int_mac[i][3]))
                for i in range(len(int_name))]

    def getCamTable(self, dest=None, vendor=None, translateInterface=False):
        if dest != None:
            self._snmp.dest(dest)

        if vendor == None:
            vendor = self.getVendor()
        if vendor == "cisco":
            # get all known vlans
            vlans = self._snmp.walk(
                self.OID['cam']['cisco']['vlan_state'], format="keys")

            if translateInterface:
                # get all known interfaces
                interfaces = self._snmp.walk(
                    self.OID['interface']['name'], format="dict")

            # for each vlan: get known mac addresses and bridge ports
            macs = []
            community = self._snmp.community
            for vlan in vlans:
                self._snmp.community = community + "@" + vlan

                mac = [(x[0][24:] + "." + x[1], self.binToMac(x[3]))
                       for x in self._snmp.walk(self.OID['cam']['cisco'][
                           'mac_address'])]
                bridgeport = dict([(x[0][24:] + "." + x[1], x[3])
                                   for x in self._snmp.walk(self.OID['cam'][
                                       'cisco']['mac_bridge_port'])])

                # get bridgeport-to-interface translation table for current vlan
                bridges = self._snmp.walk(
                    self.OID['cam']['cisco']['bridge_interface'],
                    format="dict")

                for i in range(len(mac)):
                    try:
                        if bridgeport.has_key(mac[i][0]):
                            cur_mac = mac[i][1]
                            cur_bridgeport = bridgeport[mac[i][0]]
                            cur_interface = bridges[cur_bridgeport]

                            if translateInterface:
                                cur_interface = interfaces[cur_interface]

                        macs.append((vlan, cur_mac, cur_interface))
                    except KeyError:
                        pass

            self._snmp.community = community

            return macs

        elif vendor == "juniper":
            bridge = self._snmp.walk(
                self.OID['cam']['juniper']['bridge_interface'], format='dict')
            vlan = self._snmp.walk(
                self.OID['cam']['juniper']['vlan_tags'], format='dict')

            if translateInterface:
                # get all known interfaces
                interfaces = self._snmp.walk(
                    self.OID['interface']['name'], format="dict")

            port = [(
                x[0][28:] + "." + x[1], bridge[x[3]]
            ) for x in self._snmp.walk(self.OID['cam']['juniper']['mac_port'])
                    if x[3] != '0']

            macs = []
            for i in port:
                cur_vlan, cur_mac = i[0].split(".", 1)
                cur_interface = i[1]

                if translateInterface:
                    cur_interface = interfaces[cur_interface]

                macs.append(
                    (vlan[cur_vlan], self.tagToMac(cur_mac), cur_interface))

            return macs

        # elif vendor == "h3c":
        #     mac = [(x[0][33:]+"."+x[1], self.binToMac(x[3])) for x in self._snmp.walk(self.OID['cam']['h3c']['mac_address'])]
        #     vlan = dict([(x[0][33:]+"."+x[1], x[3]) for x in self._snmp.walk(self.OID['cam']['h3c']['mac_vlan'])])
        #     port = dict([(x[0][33:]+"."+x[1], x[3]) for x in self._snmp.walk(self.OID['cam']['h3c']['mac_port'])])
        #
        #     if translateInterface:
        #         # get all known interfaces
        #         interfaces = self._snmp.walk(self.OID['interface']['name'], format="dict")
        #
        #     macs = []
        #     for i in range(len(mac)):
        #         if vlan.has_key(mac[i][0]) and port.has_key(mac[i][0]):
        #             cur_mac = mac[i][1]
        #             cur_vlan = vlan[mac[i][0]]
        #             cur_interface = port[mac[i][0]]
        #
        #             if translateInterface:
        #                 cur_interface = interfaces[cur_interface]
        #
        #             macs.append((cur_vlan, cur_mac, cur_interface))
        #
        #     return macs

        elif vendor == "h3c" or vendor == "huawei" or vendor == "hp" or vendor == "3com":
            mac = [(x[0][28:] + "." + x[1], x[3])
                   for x in self._snmp.walk(self.OID['cam']['h3c']['mac_port'])
                   ]
            bridge = self._snmp.walk(
                self.OID['cam']['h3c']['bridge_interface'], format='dict')

            if translateInterface:
                # get all known interfaces
                interfaces = self._snmp.walk(
                    self.OID['interface']['name'], format="dict")

            macs = []
            for i in mac:
                cur_vlan, cur_mac = i[0].split(".", 1)
                cur_interface = bridge[i[1]]

                if translateInterface:
                    cur_interface = interfaces[cur_interface]

                macs.append((cur_vlan, self.tagToMac(cur_mac), cur_interface))

            return macs

        else:  #TODO
            return []

        return []
