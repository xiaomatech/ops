#!/usr/bin/env python
# -*- coding:utf8 -*-

import urllib
import requests
import binascii
import hashlib
import hmac
import sys
import os
import copy
import warnings
import random
import time
warnings.filterwarnings("ignore")
sys.path.append(os.path.split(os.path.realpath(__file__))[0] + os.sep + '..')
from configs import qcloud_config


class Sign:
    def __init__(self, secretId, secretKey):
        self.secretId = secretId
        self.secretKey = secretKey

    def make(self, requestHost, requestUri, params, method='GET'):
        list = {}
        for param_key in params:
            if method == 'post' and str(params[param_key])[0:1] == "@":
                continue
            list[param_key] = params[param_key]
        srcStr = method.upper() + requestHost + requestUri + '?' + "&".join(
            k.replace("_", ".") + "=" + str(list[k])
            for k in sorted(list.keys()))
        hashed = hmac.new(self.secretKey, srcStr, hashlib.sha1)
        return binascii.b2a_base64(hashed.digest())[:-1]


class Request:
    timeout = 10
    version = 'SDK_PYTHON_1.1'

    def __init__(self):
        self.secretId = qcloud_config.get('secret_id')
        self.secretKey = qcloud_config.get('secret_key')

    def generateUrl(self, requestHost, requestUri, params, method='post'):
        params['RequestClient'] = Request.version
        sign = Sign(self.secretId, self.secretKey)
        params['Signature'] = sign.make(requestHost, requestUri, params,
                                        method)
        params = urllib.urlencode(params)

        url = 'https://%s%s' % (requestHost, requestUri)
        if (method.upper() == 'GET'):
            url += '?' + params

        return url

    def send(self,
             requestHost,
             requestUri,
             params,
             files={},
             method='GET',
             debug=0):
        params['RequestClient'] = Request.version
        sign = Sign(self.secretId, self.secretKey)
        params['Signature'] = sign.make(requestHost, requestUri, params,
                                        method)

        url = 'https://%s%s' % (requestHost, requestUri)

        if (method.upper() == 'GET'):
            req = requests.get(url,
                               params=params,
                               timeout=Request.timeout,
                               verify=False)
            if (debug):
                print 'url:', req.url, '\n'
        else:
            req = requests.post(
                url,
                data=params,
                files=files,
                timeout=Request.timeout,
                verify=False)
            if (debug):
                print 'url:', req.url, '\n'

        if req.status_code != requests.codes.ok:
            req.raise_for_status()

        return req.text


class Base:
    debug = 0
    requestHost = ''
    requestUri = '/v2/index.php'
    _params = {}

    def __init__(self, region=None, method='GET'):
        self.secretId = qcloud_config.get('secret_id')
        self.secretKey = qcloud_config.get('secret_key')
        self.defaultRegion = region or qcloud_config.get('region')
        self.method = method or 'post'

    def _checkParams(self, action, params):
        self._params = copy.deepcopy(params)
        self._params['Action'] = action[0].upper() + action[1:]

        if (self._params.has_key('Region') != True):
            self._params['Region'] = self.defaultRegion

        if (self._params.has_key('SecretId') != True):
            self._params['SecretId'] = self.secretId

        if (self._params.has_key('Nonce') != True):
            self._params['Nonce'] = random.randint(1, sys.maxint)

        if (self._params.has_key('Timestamp') != True):
            self._params['Timestamp'] = int(time.time())

        return self._params

    def generateUrl(self, action, params):
        self._checkParams(action, params)
        request = Request(self.secretId, self.secretKey)
        return request.generateUrl(self.requestHost, self.requestUri,
                                   self._params, self.method)

    def call(self, action, params, files={}):
        self._checkParams(action, params)
        request = Request(self.secretId, self.secretKey)
        return request.send(self.requestHost, self.requestUri, self._params,
                            files, self.method, self.debug)


class Account(Base):
    requestHost = 'account.api.qcloud.com'


class Bill(Base):
    requestHost = 'bill.api.qcloud.com'


class Bm(Base):
    requestHost = 'bm.api.qcloud.com'


class Cbs(Base):
    requestHost = 'cbs.api.qcloud.com'


class Cdb(Base):
    requestHost = 'cdb.api.qcloud.com'


class Cmem(Base):
    requestHost = 'cmem.api.qcloud.com'


class Cvm(Base):
    requestHost = 'cvm.api.qcloud.com'


class Eip(Base):
    requestHost = 'eip.api.qcloud.com'


class Image(Base):
    requestHost = 'image.api.qcloud.com'


class Lb(Base):
    requestHost = 'lb.api.qcloud.com'


class Live(Base):
    requestHost = 'live.api.qcloud.com'


class Market(Base):
    requestHost = 'market.api.qcloud.com'


class Monitor(Base):
    requestHost = 'monitor.api.qcloud.com'


class Scaling(Base):
    requestHost = 'scaling.api.qcloud.com'


class Sec(Base):
    requestHost = 'csec.api.qcloud.com'


class Snapshot(Base):
    requestHost = 'snapshot.api.qcloud.com'


class Tdsql(Base):
    requestHost = 'tdsql.api.qcloud.com'


class Trade(Base):
    requestHost = 'trade.api.qcloud.com'


class Vod(Base):
    requestHost = 'vod.api.qcloud.com'


class Vpc(Base):
    requestHost = 'vpc.api.qcloud.com'


class Wenzhi(Base):
    requestHost = 'wenzhi.api.qcloud.com'


class Yunsou(Base):
    requestHost = 'yunsou.api.qcloud.com'


class Cdn(Base):
    requestHost = 'cdn.api.qcloud.com'

    def UploadCdnEntity(self, params):
        action = 'UploadCdnEntity'
        if (params.get('entityFile') == None):
            raise ValueError, 'entityFile can not be empty.'
        if (os.path.isfile(params['entityFile']) == False):
            raise ValueError, 'entityFile is not exist.'

        file = params.pop('entityFile')
        if ('entityFileMd5' not in params):
            params['entityFileMd5'] = hashlib.md5(open(file, 'rb').read(
            )).hexdigest()

        files = {'entityFile': open(file, 'rb')}

        return self.call(action, params, files)
