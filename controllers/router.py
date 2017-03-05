#!/usr/bin/env python
# -*- coding:utf8 -*-

from netmiko import ConnectHandler, SCPConn
from configs import router_config
from helpers.logger import log_error, log_debug


class router:
    def help(self, req, resp):
        h = '''
                            路由器管理
                ops router show -i 10.3.128.1 -c "show run"  执行查看命令
                ops router config -i 10.3.128.1 -c "logging buffered 20000,logging buffered 20010,no logging console" 执行配置命令 多条用,分开

        '''
        return h

    def _connect(self, ip):
        if not ip:
            return None
        router_config.update({'ip': ip})
        self.connect = ConnectHandler(**router_config)

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.connect.disconnect()

    def show(self, req, resp):
        '''查看状态或配置'''
        ip = req.get_param(name='i')
        cmd = req.get_param(name='c')
        if ip is None:
            return '-i(ip) need'
        if cmd is None:
            return '-c(cmd) need'
        self._connect(ip)
        return self.connect.send_command(cmd)

    def config(self, req, resp):
        '''修改配置'''
        ip = req.get_param(name='i')
        cmd = req.get_param(name='c')
        if ip is None:
            return '-i(ip) need'
        if cmd is None:
            return '-c(cmd) need'
        self._connect(ip)
        cmds = cmd.split(',')
        return self.connect.send_config_set(cmds)
