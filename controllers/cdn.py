#!/usr/bin/env python
# -*- coding:utf8 -*-

from library.aliyun import Connection
from library.qcloud import Cdn
import upyun
import os
import requests
from configs import upyun_config, chinacache_config
from helpers.logger import log_error, log_debug
import simplejson as json

support = ['alicdn', 'upyun', 'chinacache', 'qcloud']


class cdn:
    def help(self, req, resp):
        h = '''
                                    cdn刷新工具

                        请确认配置好configs/__init__.py中的对应的配置

            ops cdn refresh --file /tmp/test.txt,/tmp/fafew.txt --domain test.example.com -t alicdn 刷新cdn文件
                            -t 支持 alicdn , qcloud ,  upyun , chinacache ,默认全部

        '''
        return h

    def refresh(self, req, resp):
        file = req.get_param(name='file')
        domain = req.get_param(name='domain')
        t = req._params['t']
        if t is None or t not in support:
            return '%s type is not support' % t
        if file is None or file == '':
            return '--file is empty'
        if domain is None or domain == '':
            return '--domain is empty'
        files = file.split(',')
        if t == 'alicdn':
            try:
                return self._refresh_alicdn(domain=domain, files=files)
            except Exception as e:
                log_error(e)
                raise Exception(e)
        elif t == 'qcloud':
            try:
                return self._refresh_qcloud(domain=domain, files=files)
            except Exception as e:
                log_error(e)
                raise Exception(e)
        elif t == 'upyun':
            try:
                up = self._get_upyun()
                up.up.purge(files=files, domain=domain)
            except Exception as e:
                log_error(e)
                raise Exception(e)
        elif t == 'chinacache':
            try:
                self._refresh_chinacache(domain=domain, files=files)
            except Exception as e:
                log_error(e)
                raise Exception(e)
        else:
            try:
                self._refresh_alicdn(domain=domain, files=files)
                self._refresh_qcloud(domain=domain, files=files)

                up = self._get_upyun()
                up.up.purge(files=files, domain=domain)

                self._refresh_chinacache(domain=domain, files=files)
                return 'ok'
            except Exception as e:
                log_error(e)
                raise Exception(e)

    def _refresh_qcloud(self, domain, files):
        service = Cdn()
        for f in files:
            try:
                params = {
                    'entityFileName': os.path.basename(f),
                    'entityFile': domain + '/' + f
                }
                service.UploadCdnEntity(params)
            except Exception as e:
                log_error(e)
                raise Exception(e)
        return True

    def _refresh_alicdn(self, domain, files):
        args = {}
        args['Action'] = 'RefreshObjectCaches'
        args['ObjectType'] = 'File'
        for f in files:
            args['ObjectPath'] = domain + '/' + f
            log_debug('flush http://%s' % args['ObjectPath'])
            try:
                log_debug(json.dumps(args))
                aliyun = Connection(region_id='cn-hangzhou', service='cdn')
                aliyun.get(args)
            except Exception as e:
                log_error(e)
                raise Exception(e)
        return True

    def _get_upyun(self):
        up = None
        try:
            up = upyun.UpYun(
                upyun_config.get('bucket'),
                username=upyun_config.get('username'),
                password=upyun_config.get('password'))
        except Exception as e:
            log_error(e)
            try:
                up = upyun.UpYun(
                    upyun_config.get('bucket'),
                    secret=upyun_config.get('secret'))
            except Exception as e:
                log_error(e)
                raise Exception(e)
        return up

    def _refresh_chinacache(self, domain, files):
        urls = ['http//' + domain + '/' + filename for filename in files]
        task = '{"urls":%s}' % urls
        data = {
            'username': chinacache_config.get('username'),
            'password': chinacache_config.get('password'),
            'task': task
        }
        r = requests.post(
            'https://r.chinacache.com/content/refresh', data=data)
        return r.text
