#!/usr/bin/env python
# -*- coding:utf8 -*-

from library.etcd import Etcd


class config:
    def help(self, req, resp):
        h = '''
                            配置中心(使用etcd)
            支持多机房(-r 是configs/__init__.py中德etcd_config的机房名)


            ops config set -k key -v value -t 123 -r gz
            ops config append -k key -v value -t 123 -r gz
            ops config mkdir -k key -t 123 -r gz
            ops config rmdir -k key --recursive t -r gz
            ops config wait -k key --recursive t -r gz
            ops config get_all -k key -r gz
            ops config get -k key --recursive t -r gz
            ops config delete -k key -r gz

        '''
        return h

    def set(self, req, resp):
        key = req.get_param(name='k')
        value = req.get_param(name='v')
        ttl = req.get_param(name='t')
        room = req.get_param(name='r')
        if room is None:
            return '-r(room) need'
        if ttl is None:
            return '-t(ttl) need'
        if value is None:
            return '-v(value) need'
        if key is None:
            return '-k(key) need'
        etcd = Etcd(room=room)
        return etcd.set(key, value, ttl)

    def append(self, req, resp):
        key = req.get_param(name='k')
        value = req.get_param(name='v')
        ttl = req.get_param(name='t')
        room = req.get_param(name='r')
        if room is None:
            return '-r(room) need'
        if ttl is None:
            return '-t(ttl) need'
        if value is None:
            return '-v(value) need'
        if key is None:
            return '-k(key) need'
        etcd = Etcd(room=room)
        return etcd.append(key, value, ttl)

    def mkdir(self, req, resp):
        key = req.get_param(name='k')
        ttl = req.get_param(name='t')
        room = req.get_param(name='r')
        if room is None:
            return '-r(room) need'
        if ttl is None:
            return '-t(ttl) need'
        if key is None:
            return '-k(key) need'
        etcd = Etcd(room=room)
        return etcd.mkdir(key, ttl)

    def rmdir(self, req, resp):
        key = req.get_param(name='k')
        recursive = req._params['recursive']
        room = req.get_param(name='r')
        if room is None:
            return '-r(room) need'
        if recursive is None:
            return '--recursive(recursive) need'
        if key is None:
            return '-k(key) need'
        etcd = Etcd(room=room)
        return etcd.rmdir(key, recursive)

    def get(self, req, resp):
        key = req.get_param(name='k')
        recursive = req.get_param(name='recursive')
        room = req.get_param(name='r')
        if room is None:
            return '-r(room) need'
        if recursive is None:
            return '--recursive(recursive) need'
        if key is None:
            return '-k(key) need'
        etcd = Etcd(room=room)
        return etcd.get(key, recursive)

    def wait(self, req, resp):
        key = req.get_param(name='k')
        recursive = req.get_param(name='recursive')
        room = req.get_param(name='r')
        if room is None:
            return '-r(room) need'
        if recursive is None:
            return '--recursive(recursive) need'
        if key is None:
            return '-k(key) need'
        etcd = Etcd(room=room)
        return etcd.wait(key, recursive)

    def get_all(self, req, resp):
        key = req.get_param(name='k')
        room = req.get_param(name='r')
        if room is None:
            return '-r(room) need'
        if key is None:
            return '-k(key) need'
        etcd = Etcd(room=room)
        return etcd.get_all(key)

    def delete(self, req, resp):
        key = req.get_param(name='k')
        room = req.get_param(name='r')
        if room is None:
            return '-r(room) need'
        if key is None:
            return '-k(key) need'
        etcd = Etcd(room=room)
        return etcd.delete(key)
