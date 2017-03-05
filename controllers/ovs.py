#!/usr/bin/env python
# -*- coding:utf8 -*-


class ovs:
    def help(self, req, resp):
        h = '''
                        ovsdb-server 开启tcp监听 可以远程集中控制

            ops ovs addbr
            ops ovs delbr
            ops ovs listbr

            ops ovs addport
            ops ovs delport
            ops ovs listport

            ops ovs addflow
            ops ovs delflow
            ops ovs listflow

        '''
        return h

    def addbr(self, req, resp):
        pass

    def delbr(self, req, resp):
        pass

    def listbr(self, req, resp):
        pass

    def addport(self, req, resp):
        pass

    def delport(self, req, resp):
        pass

    def listport(self, req, resp):
        pass

    def addflow(self, req, resp):
        pass

    def delfllow(self, req, resp):
        pass

    def listflow(self, req, resp):
        pass
