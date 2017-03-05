#!/usr/bin/env python
# -*- coding:utf8 -*-
from library.cloudflare import CloudFlare
from library.dnspod import Dnspod
from helpers.logger import log_error

support = ['dnspod', 'cloudflare']
allowed_types = ['A', 'CNAME', 'AAAA', 'NS']


class dns:
    def help(self, req, resp):
        h = '''
                                    dns管理


                            公网dns 支持dnspod,cloudflare

                                注释:
                                    -t : 类型 支持dnspod cloudflare
                                    -d : 域名
                                    -rt : dns类型 支持 A,CNAME,AAAA,NS
                                    -n : 名
                                    -c : 内容
                                    -h : 操作的机器

            ops dns list_domains -t dnspod 获取公网dns域名列表
            ops dns add_record -d domain --rt record_type -n name -c content -t dnspod 添加公网dns
            ops dns edit_record -d domain --ri record_id --rt record_type -n name -c content -t dnspod 修改公网dns
            ops dns del_record -d domain --ri record_id -t dnspod 删除公网dns


        '''
        return h

    def list_domains(self, req, resp):
        t = req.get_param(name='t')
        if t is None or t not in support:
            return '%s type is not support' % t
        if t == 'cloudflare':
            try:
                cloudflare = CloudFlare()
                return cloudflare.get_domains_list()
            except Exception as e:
                log_error(e)
                raise Exception(e)
        elif t == 'dnspod':
            try:
                dp = Dnspod()
                return dp.get_domains_list()
            except Exception as e:
                log_error(e)
                raise Exception(e)

    def add_record(self, req, resp):
        record_type = req.get_param(name='rt')
        name = req.get_param(name='n')
        content = req.get_param(name='c')
        domain = req.get_param(name='d')
        t = req.get_param(name='t')
        if t is None or t not in support:
            return '%s type is not support' % t
        if record_type is None or record_type not in allowed_types:
            return '%s type is not support' % t
        if name is None or name == '':
            return '-n is empty'
        if content is None or content == '':
            return '-c is empty'
        if domain is None or domain == '':
            return '-d is empty'

        if t == 'cloudflare':
            try:
                cloudflare = CloudFlare()
                return cloudflare.add_record(
                    domain=domain,
                    record_type=record_type,
                    name=name,
                    content=content)
            except Exception as e:
                log_error(e)
                raise Exception(e)
        elif t == 'dnspod':
            try:
                dp = Dnspod()
                return dp.add_record(
                    domain=domain,
                    record_type=record_type,
                    name=name,
                    content=content)
            except Exception as e:
                log_error(e)
                raise Exception(e)

    def del_record(self, req, resp):
        record_id = req.get_param(name='ri')
        domain = req.get_param(name='d')
        t = req.get_param(name='t')
        if t is None or t not in support:
            return '%s type is not support' % t
        if record_id is None or record_id == '':
            return '-rt is empty'
        if domain is None or domain == '':
            return '-d is empty'

        if t == 'cloudflare':
            try:
                cloudflare = CloudFlare()
                return cloudflare.delete_record(
                    domain=domain, record_id=record_id)
            except Exception as e:
                log_error(e)
                raise Exception(e)
        elif t == 'dnspod':
            try:
                dp = Dnspod()
                return dp.delete_record(domain=domain, record_id=record_id)
            except Exception as e:
                log_error(e)
                raise Exception(e)

    def edit_record(self, req, resp):
        record_type = req.get_param(name='rt')
        record_id = req.get_param(name='ri')
        name = req.get_param(name='n')
        content = req.get_param(name='c')
        domain = req.get_param(name='d')
        t = req.get_param(name='t')
        if t is None or t not in support:
            return '%s type is not support' % t
        if record_type is None or record_type not in allowed_types:
            return '%s type is not support' % t
        if record_id is None or record_id == '':
            return '-rt is empty'
        if name is None or name == '':
            return '-n is empty'
        if content is None or content == '':
            return '-c is empty'
        if domain is None or domain == '':
            return '-d is empty'

        if t == 'cloudflare':
            try:
                cloudflare = CloudFlare()
                return cloudflare.add_record(
                    domain=domain,
                    record_type=record_type,
                    name=name,
                    content=content)
            except Exception as e:
                log_error(e)
                raise Exception(e)

        elif t == 'dnspod':
            try:
                dp = Dnspod()
                return dp.add_record(
                    domain=domain,
                    record_type=record_type,
                    name=name,
                    content=content)
            except Exception as e:
                log_error(e)
                raise Exception(e)
