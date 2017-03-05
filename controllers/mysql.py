#!/usr/bin/env python
# -*- coding:utf8 -*-
from library.mysqlops import *


class mysql:
    def help(self, req, resp):
        h = '''
                                    mysql管理
                        使用percona(server,toolkit,xtrabackup), mha, oneproxy

            ops mysql create_instance 创建实例
            ops mysql del_instance 删除实例
            ops mysql list_instance 获取实例列表

            ops mysql online 上线
            ops mysql offline 下线

            ops mysql create_group 添加一组
            ops mysql list_group 查看


            ops mysql deploy 发布ddl,dml sql

            ops mysql slowlog 获取慢查询

            ops mysql list_backup 查看备份

	        ops mysql query 查询
        '''
        return h

    def create_instance(self, req, resp):
        pass

    def del_instance(self, req, resp):
        pass

    def list_instance(self, req, resp):
        pass

    def online(self, req, resp):
        pass

    def offline(self, req, resp):
        pass

    def create_group(self, req, resp):
        pass

    def list_group(self, req, resp):
        pass

    def deploy(self, req, resp):
        pass

    def slowlog(self, req, resp):
        pass

    def list_backup(self, req, resp):
        pass
