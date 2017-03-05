#!/usr/bin/env python
# -*- coding:utf8 -*-
from library.idrac import Idrac


class idrac:
    def help(self, req, resp):
        h = '''
                    Dell IDRAC管理

            ops idrac pxeboot -h 10.2.3.4               pxe启动
            ops idrac powerup -h 10.2.3.4               开电源
            ops idrac powerdown -h 10.2.3.4             关电源
            ops idrac reboot -h 10.2.3.4                重启
            ops idrac get_power_status -h 10.2.3.4      获取电源状态

            ops idrac get_network_config -h 10.2.3.4    获取网络配置
            ops idrac get_nic_info -h 10.2.3.4          获取网卡信息
            ops idrac get_sn -h 10.2.3.4                获取sn号
            ops idrac get_sys_info -h 10.2.3.4          获取系统配置
            ops idrac enable_syslog -h 10.2.3.4 -s 10.4.4.4   打开syslog

            ops idrac get_disk -h 10.2.3.4              获取磁盘信息
            ops idrac get_vdisk -h 10.2.3.4             获取虚拟磁盘信息

        '''
        return h

    def pxeboot(self, req, resp):
        host = req.get_param(name='h')
        if host is None:
            return '-h(host_manage_ip) need'
        idrac = Idrac(host=host)
        return idrac.setup_pxeboot_once()

    def powerup(self, req, resp):
        host = req.get_param(name='h')
        if host is None:
            return '-h(host_manage_ip) need'
        idrac = Idrac(host=host)
        return idrac.powerup()

    def powerdown(self, req, resp):
        host = req.get_param(name='h')
        if host is None:
            return '-h(host_manage_ip) need'
        idrac = Idrac(host=host)
        return idrac.powerdown()

    def reboot(self, req, resp):
        host = req.get_param(name='h')
        if host is None:
            return '-h(host_manage_ip) need'
        idrac = Idrac(host=host)
        return idrac.reboot()

    def get_network_config(self, req, resp):
        host = req.get_param(name='h')
        if host is None:
            return '-h(host_manage_ip) need'
        idrac = Idrac(host=host)
        return idrac.get_network_config()

    def get_sn(self, req, resp):
        host = req.get_param(name='h')
        if host is None:
            return '-h(host_manage_ip) need'
        idrac = Idrac(host=host)
        return idrac.get_sn()

    def get_sys_info(self, req, resp):
        host = req.get_param(name='h')
        if host is None:
            return '-h(host_manage_ip) need'
        idrac = Idrac(host=host)
        return idrac.get_sys_info()

    def get_power_status(self, req, resp):
        host = req.get_param(name='h')
        if host is None:
            return '-h(host_manage_ip) need'
        idrac = Idrac(host=host)
        return idrac.get_power_status()

    def enable_syslog(self, req, resp):
        host = req.get_param(name='h')
        if host is None:
            return '-h(host_manage_ip) need'

        syslog_ip = req.get_param(name='s')
        if host is None:
            return '-s(syslog_ip) need'
        idrac = Idrac(host=host)
        return idrac.enable_syslog(syslog_ip)

    def get_disk(self, req, resp):
        host = req.get_param(name='h')
        if host is None:
            return '-h(host_manage_ip) need'
        idrac = Idrac(host=host)
        return idrac.get_disk()

    def get_vdisk(self, req, resp):
        host = req.get_param(name='h')
        if host is None:
            return '-h(host_manage_ip) need'
        idrac = Idrac(host=host)
        return idrac.get_vdisk()

    def get_nic_info(self, req, resp):
        host = req.get_param(name='h')
        if host is None:
            return '-h(host_manage_ip) need'
        idrac = Idrac(host=host)
        return idrac.get_nic_info()
