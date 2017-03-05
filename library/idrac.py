#!/usr/bin/env python
# -*- coding:utf8 -*-

import urllib2
from configs import idrac_config


class Idrac(object):
    def __init__(self, host):
        self.sid = None
        self.host = host
        self.username = idrac_config.get('username')
        self.password = idrac_config.get('password')

    def __enter__(self):
        return self

    def __exit__(self):
        self._logout()

    def _inject_header(self, data):
        if data is not None:
            return "<?xml version='1.0'?>" + data

    def _extract_value(self, data, value):
        if data is None:
            return
        try:
            return data.split('<%s>' % value)[1].split('</%s>' % value)[0]
        except KeyError:
            raise Exception('unable to extract %s' % value)

    def _extract_sid(self, data):
        return self._extract_value(data, 'SID')

    def _extract_cmd_output(self, data):
        return self._extract_value(data, 'CMDOUTPUT')

    def _make_request(self, uri, data=None):
        opener = urllib2.build_opener()
        if self.sid:
            opener.addheaders.append(('Cookie', 'sid=%s' % self.sid))
        return opener.open('https://%s/cgi-bin/%s' % (self.host, uri),
                           self._inject_header(data)).read()

    def _login(self):
        data = '<LOGIN><REQ><USERNAME>%s</USERNAME><PASSWORD>%s</PASSWORD></REQ></LOGIN>' % (
            self.username, self.password)
        resp = self._make_request('/login', data)
        self.sid = self._extract_sid(resp)

    def _logout(self):
        self._make_request('/logout')
        self.sid = None

    def run_command(self, cmd):
        if self.sid is None:
            self._login()
        try:
            data = '<EXEC><REQ><CMDINPUT>racadm %s</CMDINPUT><MAXOUTPUTLEN>0x0fff</MAXOUTPUTLEN></REQ></EXEC>' % cmd
            return self._extract_cmd_output(
                self._make_request('/exec', data)).strip()
        finally:
            self._logout()

    def get_group_config(self, group):
        return self.run_command('getconfig -g %s' % group)

    def pxeboot(self):
        self.run_command(
            'config -g cfgServerInfo -o cfgServerFirstBootDevice pxe')
        self.run_command('config -g cfgServerInfo -o cfgServerBootOnce 1')
        return self.powercycle()

    def powercycle(self):
        return self.run_command('serveraction powercycle')

    def powerdown(self):
        return self.run_command('serveraction powerdown')

    def powerup(self):
        return self.run_command('serveraction powerup')

    def setup_pxeboot_once(self):
        return self.run_command(
            'config -g cfgServerInfo -o cfgServerBootOnce 1')

    def get_boot_order(self):
        return self.run_command('get BIOS.BiosBootSettings.BootSeq')

    def get_network_config(self):
        return self.run_command('getniccfg')

    def set_network(self, ip, netmask, gateway):
        return self.run_command('setniccfg -s {0} {1} {2}'.format(ip, netmask,
                                                                  gateway))

    def get_sn(self):
        return self.run_command('getsvctag')

    def get_mac(self):
        return self.run_command('getsysinfo -s')

    def reboot(self):
        return self.run_command('serveraction powercycle')

    def get_sys_info(self):
        return self.run_command('getsysinfo')

    def get_power_status(self):
        return self.run_command('serveraction powercatatus')

    def get_led_status(self):
        return self.run_command('getled -m chassis')

    def set_led_off(self):
        return self.run_command('setled -m chassis OFF')

    def set_led_on(self):
        return self.run_command('setled -m chassis ON')

    def enable_syslog(self, syslog_ip):
        if self.run_command(
                'config -g cfgRemoteHosts -o cfgRhostsSyslogEnable 1'):
            self.run_command(
                'config -g cfgRemoteHosts -o cfgRhostsSyslogServer1 {0}'.
                format(syslog_ip))

    def export_xml(self, xml_file):
        return self.run_command('hwinventory export -f %s ' % xml_file)

    def update_bios(self, bios_file1, bios_file2, bios_file3, li):
        self.run_command('update -f %s -l %s' % (bios_file1, li))
        self.run_command('update -f %s -l %s' % (bios_file2, li))
        self.run_command('update -f %s -l %s' % (bios_file3, li))
        return self.run_command('serveraction hardreset')

    def enable_email_alerts(self):
        return self.run_command(
            'config -g cfgEmailAlert -o cfgEmailAlertEnable -i 1 1')

    def disable_email_alerts(self):
        return self.run_command(
            'config -g cfgEmailAlert -o cfgEmailAlertEnable -i 1 0')

    def list_users(self):
        users = {}
        _username = ''

        for idx in range(1, 17):
            cmd = self.run_command(
                'racadm getconfig -g cfgUserAdmin -i {0}'.format(idx))
            for user in cmd.splitlines():
                if not user.startswith('cfg'):
                    continue

                (k, v) = user.split('=')
                if k.startswith('cfgUserAdminUserName'):
                    _username = v.strip()
                    if v:
                        users[_username] = {'index': idx}
                    else:
                        break
                else:
                    users[_username].update({k: v})
        return users

    def delete_user(self, username, uid=None):
        if uid is None:
            user = self.list_users()
        uid = user[username]['index']
        if uid:
            self.run_command(
                'config -g cfgUserAdmin -o cfgUserAdminUserName -i {0} ""'.
                format(uid))
        else:
            return False

        return True

    def change_password(self, username, password, uid=None):
        if uid is None:
            user = self.list_users()
        uid = user[username]['index']
        if uid:
            self.run_command(
                'config -g cfgUserAdmin -o cfgUserAdminPassword -i {0} {1}'.
                format(uid, password))
        else:
            return False

        return True

    def create_user(self, username, password, permissions, users=None):
        '''
        DRAC Privileges
          * login                   : Login to iDRAC
          * drac                    : Configure iDRAC
          * user_management         : Configure Users
          * clear_logs              : Clear Logs
          * server_control_commands : Execute Server Control Commands
          * console_redirection     : Access Console Redirection
          * virtual_media           : Access Virtual Media
          * test_alerts             : Test Alerts
          * debug_commands          : Execute Debug Commands
        '''
        _uids = set()

        if users is None:
            users = self.list_users()

        if username in users:
            return False

        for i in users.keys():
            _uids.add(users[i]['index'])

        uid = sorted(list(set(range(2, 12)) - _uids), reverse=True).pop()
        if not self.run_command(
                'config -g cfgUserAdmin -o cfgUserAdminUserName -i {0} {1}'.
                format(uid, username)):
            self.delete_user(self, username, uid)
            return False
        if not self.set_permissions(username, permissions, uid):
            self.delete_user(username, uid)
            return False

        if not self.change_password(username, password, uid):
            self.delete_user(username, uid)
            return False

        if not self.run_command(
                'config -g cfgUserAdmin -o cfgUserAdminEnable -i {0} 1'.format(
                    uid)):
            self.delete_user(username, uid)
            return False
        return True

    def set_permissions(self, username, permissions, uid=None):
        '''
       DRAC Privileges
         * login                   : Login to iDRAC
         * drac                    : Configure iDRAC
         * user_management         : Configure Users
         * clear_logs              : Clear Logs
         * server_control_commands : Execute Server Control Commands
         * console_redirection     : Access Console Redirection
         * virtual_media           : Access Virtual Media
         * test_alerts             : Test Alerts
         * debug_commands          : Execute Debug Commands
       '''
        privileges = {
            'login': '0x0000001',
            'drac': '0x0000002',
            'user_management': '0x0000004',
            'clear_logs': '0x0000008',
            'server_control_commands': '0x0000010',
            'console_redirection': '0x0000020',
            'virtual_media': '0x0000040',
            'test_alerts': '0x0000080',
            'debug_commands': '0x0000100'
        }

        permission = 0
        if uid is None:
            user = self.list_users()
            uid = user[username]['index']

        for i in permissions.split(','):
            perm = i.strip()

            if perm in privileges:
                permission += int(privileges[perm], 16)

        return self.run_command(
            'config -g cfgUserAdmin -o cfgUserAdminPrivilege -i {0} 0x{1:08X}'.
            format(uid, permission))

    def get_disk(self):
        return self.run_command('raid get pdisks -o')

    def get_vdisk(self):
        return self.run_command('raid get vdisks')

    def get_nic_info(self):
        return self.run_command('get iDRAC.NIC')
