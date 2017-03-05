#!/usr/bin/env python
# -*- coding:utf8 -*-
import xmlrpclib
import traceback
import logging
import os
import subprocess
import re

from helpers.logger import log_debug, log_error, log_info


class Cobbler(object):

    TYPE = None

    def __init__(self, **kwargs):
        self.username = kwargs.get('username')
        self.password = kwargs.get('password')
        self.api_url = 'http://' + kwargs.get('ip') + '/cobbler_web'

    def get_remote(self):
        remote = xmlrpclib.Server(self.api_url)
        return remote

    def get_token(self):
        remote = self.get_remote()
        try:
            token = remote.login(self.username, self.password)
        except:
            logging.error(traceback.format_exc())
            raise RuntimeError('get cobbler token error')
        return token

    def get_fileds(self):
        pass

    def execute_cmd(self, params):
        """
            @params: list or tuple
            return (bool, stdout, error_msg)
        """
        if not isinstance(params, (list, tuple)):
            log_error('params must be list or tuple')
            return (False, '', 'params must be list or tuple')
        pop = subprocess.Popen(
            params,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)

        code = pop.wait()
        if code == 0:
            return (True, pop.stdout.read(), '')
        else:
            return (False, pop.stdout.read(), pop.stderr.read())


class System(Cobbler):

    TYPE = 'system'

    def get_fileds(self):

        interface = {
            'mac_address': [True, False, [], '', u'mac'],
            'connected_mode': [False, False, [], '', ''],
            'mtu': [False, False, [], '', ''],
            'ip_address': [True, False, [], '', u'ip'],
            'interface_type': [False, False, [], '', ''],
            'interface_master': [False, False, [], '', ''],
            'bonding_opts': [False, False, [], '', ''],
            'bridge_opts': [False, False, [], '', ''],
            'management': [False, False, [], '', ''],
            'static': [False, False, [], '', ''],
            'netmask': [False, False, [], '', ''],
            'if_gateway': [False, False, [], '', ''],
            'dhcp_tag': [False, False, [], '', ''],
            'dns_name': [False, False, [], '', u'dns'],
            'static_routes': [False, False, [], '', ''],
            'virt_bridge': [False, False, [], '', ''],
            'ipv6_address': [False, False, [], '', ''],
            'ipv6_prefix': [False, False, [], '', ''],
            'ipv6_secondaries': [False, False, [], '', ''],
            'ipv6_mtu': [False, False, [], '', ''],
            'ipv6_static_routes': [False, False, [], '', ''],
            'ipv6_default_gateway': [False, False, [], '', ''],
            'cnames': [False, False, [], '', ''],
        }
        fileds = {
            'name': [True, False, [], '', ''],
            'owners': [False, False, [], '', ''],
            'profile': [True, False, [], '', 'profile'],
            'image': [False, False, [], '', ''],
            'status': [False, False, [], '', ''],
            'kernel_options': [False, False, [], '', ''],
            'kernel_options_post': [False, False, [], '', ''],
            'ks_meta': [False, False, [], '', ''],
            'enable_gpxe': [False, False, [], '', ''],
            'proxy': [False, False, [], '', ''],
            'netboot_enabled': [False, False, [], '', ''],
            'kickstart': [False, False, [], '', ''],
            'comment': [False, False, [], '', ''],
            'depth': [False, False, [], '', ''],
            'server': [False, False, [], '', ''],
            'virt_path': [False, False, [], '', ''],
            'virt_type': [False, False, [], '', ''],
            'virt_cpus': [False, False, [], '', ''],
            'virt_file_size': [False, False, [], '', ''],
            'virt_disk_driver': [False, False, [], '', ''],
            'virt_ram': [False, False, [], '', ''],
            'virt_auto_boot': [False, False, [], '', ''],
            'virt_pxe_boot': [False, False, [], '', ''],
            'ctime': [False, False, [], '', ''],
            'mtime': [False, False, [], '', ''],
            'power_type': [True, False, [], '', ''],
            'power_address': [True, False, [], '', ''],
            'power_user': [True, False, [], '', ''],
            'power_pass': [True, False, [], '', ''],
            'power_id': [False, False, [], '', ''],
            'hostname': [False, False, [], '', ''],
            'gateway': [False, False, [], '', ''],
            'name_servers': [False, False, [], '', ''],
            'name_servers_search': [False, False, [], '', ''],
            'ipv6_default_device': [False, False, [], '', ''],
            'ipv6_autoconfiguration': [False, False, [], '', ''],
            'network_widget_a': [False, False, [], '', ''],
            'network_widget_b': [False, False, [], '', ''],
            'network_widget_c': [False, False, [], '', ''],
            'mgmt_classes': [False, False, [], '', ''],
            'mgmt_parameters': [False, False, [], '', ''],
            'boot_files': [False, False, [], '', ''],
            'fetchable_files': [False, False, [], '', ''],
            'template_files': [False, False, [], '', ''],
            'redhat_management_key': [False, False, [], '', ''],
            'redhat_management_server': [False, False, [], '', ''],
            'template_remote_kickstarts': [False, False, [], '', ''],
            'repos_enabled': [False, False, [], '', ''],
            'ldap_enabled': [False, False, [], '', ''],
            'ldap_type': [False, False, [], '', ''],
            'monit_enabled': [False, False, [], '', ''],
            'interface': interface
        }
        return fileds

    def _check_fileds(self, fileds, params):
        mandatory_fileds = filter(lambda x: fileds[x][0], fileds.keys())
        for k in mandatory_fileds:
            if not params.get(k, None):
                log_error('Variable "{0}" is mandatory, check your params.'.
                          format(k))

        scode_fileds = filter(lambda x: fileds[x][1], fileds.keys())
        for k in scode_fileds:
            val = params.get(k)
            if val:
                if val not in fileds[k][2]:
                    log_error('Variable {0} value is Error, must in {1}'.
                              format(k, fileds[k][2]))

    def check_fileds(self, params):

        fileds = self.get_fileds()
        interface_fileds = fileds.pop('interface')
        interfaces = params.get('interfaces')
        if interfaces:
            for interface_name, interface in interfaces.items():
                self._check_fileds(interface_fileds, interface)
        self._check_fileds(fileds, params)

    def power(self, params):
        remote = self.get_remote()
        token = self.get_token()
        log_debug('systems[{0}] power{1}'.format(
            params.get('systems'), params.get('power')))
        result = remote.background_power_system(params, token)
        return result

    def rebuild(self, params):
        log_info("rebuild set param")
        systems = params.pop('systems')
        for system_name in systems:
            self.modify(system_name, params)
        # build power params
        power_data = {'power': 'reboot', 'systems': systems}
        log_info('rebuild power reboot')
        result = self.power(power_data)
        return result

    def create(self, params):
        remote = self.get_remote()
        token = self.get_token()
        log_info('create system params:{0}'.format(params))
        self.check_fileds(params)
        system_id = remote.new_system(token)
        log_info("new system id {0}".format(system_id))
        interfaces = {}
        if params.has_key('interfaces'):
            interfaces = params.pop('interfaces')
        for key, val in params.items():
            remote.modify_system(system_id, key, val, token)
            log_info("set params {0} = {1}".format(key, val))

        for interface_name, params in interfaces.items():
            temp_dict = {}
            log_info("struct interface params {0}".format(interface_name))
            for key, val in params.items():
                temp_dict['%s-%s' % (key, interface_name)] = val
            log_info("update interface {0}".format(temp_dict))
            remote.modify_system(system_id, 'modify_interface', temp_dict,
                                 token)
            del temp_dict
        log_info("save system {0}".format(system_id))
        remote.save_system(system_id, token)
        log_info("sync system info")
        remote.sync(token)
        return system_id

    def modify(self, system_name, params):
        remote = self.get_remote()
        token = self.get_token()
        log_debug('modify system params:{0}'.format(params))
        interfaces = {}
        if params.has_key('interfaces'):
            interfaces = params.pop('interfaces')

        if not remote.has_item(self.TYPE, system_name):
            log_error('System {0} not found'.format(system_name))

        system_id = remote.get_system_handle(system_name, token)

        for key, val in params.items():
            log_info("set params {0} = {1}".format(key, val))
            remote.modify_system(system_id, key, val, token)

        for interface_name, params in interfaces.items():
            temp_dict = {}
            log_info("struct interface params {0}".format(interface_name))
            for key, val in params.items():
                temp_dict['%s-%s' % (key, interface_name)] = val
            log_info("update interface {0}".format(temp_dict))
            remote.modify_system(system_id, 'modify_interface', temp_dict,
                                 token)
            del temp_dict
        log_info("save system {0}".format(system_id))
        remote.save_system(system_id, token)
        log_info("sync system info")
        sync_task = remote.sync(token)
        return sync_task

    def delete(self, system_names):
        if not isinstance(system_names, (list, tuple)):
            log_error('params must be list or tuple')
        remote = self.get_remote()
        token = self.get_token()
        error_list = []
        for obj_name in system_names:
            try:
                remote.xapi_object_edit('system', obj_name, "remove", {
                    'name': obj_name,
                    'recursive': False
                }, token)
            except xmlrpclib.Fault, msg:
                error_list.append('{0} delete failed，error info {1}'.format(
                    obj_name, msg.faultString))
        return error_list

    def get_item(self, system_name):
        remote = self.get_remote()
        token = self.get_token()
        result = remote.get_system(system_name, token)
        if not isinstance(result, dict):
            log_error('system not found')
        return result


class Distros(Cobbler):
    def _check_iso(self, path):

        if not os.path.exists(path):
            log_error('{0} does not exist'.format(path))

    def get_fileds(self):

        return {
            'path': [True, False, [], '', u'distro address'],
            'name': [True, False, [], '', u'distros name'],
            'arch': [
                False, True, [
                    'i386', 'x86_64', 'ia64', 'ppc', 'ppc64', 's390', 's390x',
                    'arm'
                ], 'i386', u'distro type'
            ],
            'breed': [
                False, True, ['redhat', 'debian', 'ubuntu', 'suse'], 'redhat',
                u'distro type'
            ]
        }

    def upload(self, params):
        path = params.get('path')
        osname = params.pop('filename')
        name = params.get('name')
        dvd = '/'.join([path, osname])
        log_info("check iso {0}".format(dvd))
        self._check_iso(dvd)
        mnt_sub = "/data/cobbler/{0}".format(name)
        params['path'] = mnt_sub
        mnt_sub_cmd = ['mkdir', '-p', mnt_sub]
        mount_cmd = ['mount', '-o', 'loop', dvd, mnt_sub]
        log_info('create temp dir %s' % str(mnt_sub))
        ret, out_info, error_msg = self.execute_cmd(mnt_sub_cmd)
        if not ret:
            log_error('execute {0} error{1}'.format(mnt_sub_cmd, error_msg))
            raise RuntimeError('execute {0} error{1}'.format(mnt_sub_cmd,
                                                             error_msg))
        log_info("mount iso {0}".format(dvd))
        ret, out_info, error_msg = self.execute_cmd(mount_cmd)
        if not ret:
            log_error('execute {0} error{1}'.format(mount_cmd, error_msg))
            raise RuntimeError('execute {0} error{1}'.format(mount_cmd,
                                                             error_msg))
        remote = self.get_remote()
        token = self.get_token()
        log_info("async import iso")
        task_name = remote.background_import(params, token)
        return task_name, mnt_sub

    def after_upload(self, task_name, mnt_sub):
        remote = self.get_remote()
        token = self.get_token()
        umount_cmd = ["umount", mnt_sub]
        del_mnt_sub_cmd = ['rm', '-rf', mnt_sub]
        log_info("check task {0} result".format(task_name))
        status = remote.get_task_status(task_name)
        while status[2] not in ('complete', 'failed'):
            status = remote.get_task_status(task_name)
        log_info("task execute complete - result[{0}]".format(status[2]))
        log_info("sync info")
        remote.sync(token)
        log_info("umount iso {0}".format(mnt_sub))
        ret, out_info, error_msg = self.execute_cmd(umount_cmd)
        if not ret:
            log_error('execute {0} error{1}'.format(umount_cmd, error_msg))
        log_info("delete temp dir{0}".format(mnt_sub))
        ret, out_info, error_msg = self.execute_cmd(del_mnt_sub_cmd)
        if not ret:
            log_error('execute {0} error{1}'.format(del_mnt_sub_cmd,
                                                    error_msg))

    def get_item(self, distros_name):
        remote = self.get_remote()
        token = self.get_token()
        result = remote.get_distro(distros_name, token)
        if not isinstance(result, dict):
            log_error('distro not found')
        return result


class Profile(Cobbler):

    TYPE = 'profile'

    def get_items(self):
        remote = self.get_remote()
        return remote.get_profiles()

    def get_item(self, name):
        remote = self.get_remote()
        return remote.get_profile(name)

    def get_item_names(self):
        remote = self.get_remote()
        return remote.get_item_names(self.TYPE)


class Event(Cobbler):
    def get_event(self, event_id):
        result = {}
        try:
            remote = self.get_remote()
            status = remote.get_task_status(event_id)
            loginfo = remote.get_event_log(event_id)
            result['status'] = status[2]
            result['event_log'] = loginfo
        except xmlrpclib.Fault, msg:
            re_no_event = re.compile('.*?no event with that id.*?', re.S)
            if re.findall(re_no_event, msg.faultString):
                log_error('no event with that id')
        return result

    def get_events(self):
        remote = self.get_remote()
        events = remote.get_events()
        result = {}
        for event_id in events.keys():
            single_info = self.get_event(event_id)
            result[event_id] = single_info
        return result
