#!/usr/bin/env python
# -*- coding:utf8 -*-
import hashlib
from helpers.logger import log_error
from models.operator_log import OperatorLog, AnsibleLog


class log:
    def help(self, req, resp):
        h = '''
            ops log list -l 100 查看最新的100条操作记录
            ops log ansible_error -l 100 查看最新的100条错误记录
        '''
        return h

    def list(self, req, resp):
        if len(req._params) > 0:
            limit = int(req.get_param(name='l'))
        else:
            limit = 10
        history = OperatorLog.select().order_by(OperatorLog.id.desc()).limit(
            limit)
        result = []
        for item in history:
            result.append({
                'uid': item.login_uid,
                'user': item.login_user,
                'server_ip': item.server_ip,
                'action_data': item.post_data,
                'action': item.func,
                'controller': item.controller
            })
        return result

    def ansible_error(self, req, resp):
        if len(req._params) > 0:
            limit = int(req.get_param(name='l'))
        else:
            limit = 10
        history = AnsibleLog.select().where(
            AnsibleLog.result_status ==
            'fail').order_by(AnsibleLog.id.desc()).limit(limit)
        result = []
        for item in history:
            result.append({
                'result': item.result,
                'category': item.category,
                'server_ip': item.server_ip,
                'create_timestamp': item.create_timestamp
            })
        return result

    def callback(self, req, resp):
        accept_key = '<M(^BJB<*&RGKJKLSO'
        m1 = hashlib.md5()
        m1.update(accept_key + req.get_param(name='host', default=''))
        if req.get_param(name='access_token') != m1.hexdigest():
            msg = 'invalid access_token,ansible calback fail'
            log_error(msg)
            raise Exception(msg)
        else:
            ansible_log = AnsibleLog()
            ansible_log.category = req.get_param(name='classify')
            ansible_log.result = req.get_param(name='result')
            ansible_log.result_status = req.get_param(name='result_status')
            ansible_log.server_ip = req.get_param(name='host')
            return ansible_log.save()
