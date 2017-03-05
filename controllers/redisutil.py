#!/usr/bin/env python
# -*- coding:utf8 -*-


class redisutil:
    def help(self, req, resp):
        h = '''
                        redis管理(使用codis,redis-cluster)

            ops redisutil create_instance 创建实例
            ops redisutil del_instance 删除实例
            ops redisutil list_instance 获取实例列表

            ops redisutil scale     扩容
            ops redisutil migrate   迁移
	    ops redisutil query 查询
        '''
        return h

    def create_instance(self, req, resp):
        pass

    def del_instance(self, req, resp):
        pass

    def list_instance(self, req, resp):
        pass

    def scale(self, req, resp):
        pass

    def migrate(self, req, resp):
        pass

    def query(self, req, resp):
        pass
