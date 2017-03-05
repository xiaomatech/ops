#!/usr/bin/env python
# -*- coding:utf8 -*-

import requests
import simplejson as json
from requests.auth import HTTPBasicAuth
from configs import etcd_config


class Etcd(object):
    def __init__(self, room):
        user = etcd_config.get(room).get('username')
        password = etcd_config.get(room).get('username')
        endpoint = etcd_config.get(room).get('endpoint')

        if user and password:
            auth = HTTPBasicAuth(user, password)
        else:
            auth = None
        self.endpoint = endpoint
        self.auth = auth

    def set(self, key, value, ttl=None):
        uri = '%s/v2/keys/%s' % (self.endpoint, key)
        data = {'value': value}
        if ttl is not None:
            data['ttl'] = ttl

        res = requests.put(uri, data=data, auth=self.auth)
        res.raise_for_status()
        return json.loads(res.text)

    def append(self, key, value, ttl=None):
        uri = '%s/v2/keys/%s' % (self.endpoint, key)
        data = {'value': value}
        if ttl is not None:
            data['ttl'] = ttl

        res = requests.post(uri, data=data, auth=self.auth)
        res.raise_for_status()
        return json.loads(res.text)

    def mkdir(self, key, ttl=None):
        uri = '%s/v2/keys/%s' % (self.endpoint, key)
        data = {'dir': True}
        if ttl is not None:
            data['ttl'] = ttl

        res = requests.put(uri, data=data, auth=self.auth)
        res.raise_for_status()
        return json.loads(res.text)

    def rmdir(self, key, recursive=False):
        uri = '%s/v2/keys/%s?dir=true&recursive=%s' % (
            self.endpoint,
            key,
            'true' if recursive else 'false', )
        res = requests.delete(uri, auth=self.auth)

        res.raise_for_status()
        return json.loads(res.text)

    def get(self, key, recursive=False):
        uri = '%s/v2/keys/%s?recursive=%s' % (
            self.endpoint,
            key,
            'true' if recursive else 'false', )
        res = requests.get(uri, auth=self.auth)
        res.raise_for_status()
        return json.loads(res.text)

    def wait(self, key, recursive=False):
        uri = '%s/v2/keys/%s?wait=true&recursive=%s' % (
            self.endpoint,
            key,
            'true' if recursive else 'false', )
        res = requests.get(uri, auth=self.auth)
        res.raise_for_status()
        return json.loads(res.text)

    def get_all(self, key):
        uri = '%s/v2/keys/%s' % (self.endpoint, key)
        res = requests.get(uri, auth=self.auth)
        res.raise_for_status()
        data = json.loads(res.text)

        return data['node'].get('nodes', [])

    def delete(self, key):
        uri = '%s/v2/keys/%s' % (self.endpoint, key)
        res = requests.delete(uri, auth=self.auth)
        res.raise_for_status()
        return json.loads(res.text)
