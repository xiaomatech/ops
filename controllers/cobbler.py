#!/usr/bin/env python
# -*- coding:utf8 -*-

from library.cobbler import System, Profile
from configs import cobbler_config


class cobbler:
    def help(self, req, resp):
        h = '''
                                    自动装机

                            把任务提交到cobbler 然后通过idrac或 ipmi重启机器执行任务
                            idrac 参考 ops idrac help
                            ipmi  参考 ops ipmi help

            ops cobbler create -r gz-ns 添加安装系统的任务
            ops cobbler modify -r gz-ns 修改安装系统的任务
            ops cobbler rebuild -r gz-ns 添加重装系统的任务
            ops cobbler delete  -r gz-ns 删除一个任务

            ops cobbler list_profiles -r gz-ns 获取系统模板
            ops cobbler profile -n test -r gz-ns 获取模板详情

            ops cobbler list_systems  -r gz-ns 获取系统列表
            ops cobbler system -n test -r gz-ns 获取系统详情
        '''
        return h

    def create(self, req, resp):
        room = req.get_param(name='r')
        if room is None:
            return '-r(room) need'
        system = System(cobbler_config.get(room))
        params = req._params
        del (params['r'])
        return system.create(params)

    def modify(self, req, resp):
        room = req.get_param(name='r')
        if room is None:
            return '-r(room) need'
        system = System(cobbler_config.get(room))
        params = req._params
        system_name = params['s']
        if system_name is None:
            return '-s(system_name) need'
        del (params['r'])
        del (params['s'])
        return system.modify(system_name=system_name, params=params)

    def rebuild(self, req, resp):
        room = req.get_param(name='r')
        if room is None:
            return '-r(room) need'
        system = System(cobbler_config.get(room))
        params = req._params
        del (params['r'])
        return system.rebuild(params=params)

    def delete(self, req, resp):
        room = req.get_param(name='r')
        if room is None:
            return '-r(room) need'
        system = System(cobbler_config.get(room))
        system_name = req.get_param(name='s')
        if system_name is None:
            return '-s(system_name) need'
        return system.delete(system_names=system_name)

    def list_profiles(self, req, resp):
        room = req.get_param(name='r')
        if room is None:
            return '-r(room) need'
        profile = Profile(cobbler_config.get(room))
        return profile.get_items()

    def profile(self, req, resp):
        room = req.get_param(name='r')
        if room is None:
            return '-r(room) need'
        name = req.get_param(name='n')
        if room is None:
            return '-n(name) need'
        profile = Profile(cobbler_config.get(room))
        return profile.get_item(name)

    def system(self, req, resp):
        room = req.get_param(name='r')
        if room is None:
            return '-r(room) need'
        name = req.get_param(name='n')
        if room is None:
            return '-n(name) need'
        system = System(cobbler_config.get(room))
        return system.get_item(name)

    def list_systems(self, req, resp):
        room = req.get_param(name='r')
        if room is None:
            return '-r(room) need'
        system = System(cobbler_config.get(room))
        return system.get_items()

    def list_cobbler(self, req, resp):
        result = []
        for _, item in enumerate(cobbler_config):
            result.append(cobbler_config[item]['ip'])
        return result
