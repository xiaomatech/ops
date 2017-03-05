#!/usr/bin/env python
# -*- coding:utf8 -*-

from pyzabbix import ZabbixAPI, ZabbixAPIException
import socket
from datetime import datetime
import time
import glob
import re
import hashlib
import simplejson as json
from configs import zabbix_config
from helpers.logger import log_info, log_error
from models.zabbix import *
from helpers.cache import r, cache


class monitor:
    def __init__(self):
        try:
            self.zapi = ZabbixAPI(
                server=zabbix_config.get('server'), timeout=360)
            self.zapi.session.verify = False
            self.zapi.timeout = 360
            self.zapi.login(
                user=zabbix_config.get('user'),
                password=zabbix_config.get('password'))
        except Exception as e:
            log_error(e)

    def help(self, req, resp):
        h = '''
                前提条件:
                    1,修改configs/__init__.py中的zabbix_config,zabbix_db_config 和 ssh_config(可选)
                    2,系统的模板在vendors/zabbix/templates 自动导入请使用 ops monitor import_templates

            ops monitor import_templates 导入模板
            ops monitor list_all          列出所有机器
            ops monitor list_red          列出状态出错机器
            ops monitor list_group        列出组
            ops monitor list_template     列出模板
            ops monitor disable -s hostname    禁用监控
            ops monitor enable  -s hostname    开启监控
            ops monitor list_able     开启监控列表
            ops monitor list_disable     关闭监控列表
            ops monitor del_host -s hostname  删除监控机器
            ops monitor add_hostgroup -g groupname -s hostname 添加主机到主机组
            ops monitor del_hostgroup -g groupname -s hostname 从主机组中删除主机
            exmaple:
                   ops monitor list_all |grep -i pre  |awk '{print $4}' |xargs -n 1 ops monitor add_hostgroup -g 'ns-test' -s

            ops monitor del_hosttemplate -s hostname -t templatename  删除监控机器模板
            ops monitor get_item -s hostname 查看主机的items项

            注意:本工具是以hostname为标准去处理问题的,如果出现hostname与主机真实hostname
            不一致的情况,需要修改Zabbix上的hostname为主机上的hostname
        '''
        return h

    def get_alert_all(self, req, resp):
        hostname = req.get_param(name='s') or req.get_header(name='HOSTNAME')
        if hostname is None:
            return '-s(hostname) need'
        hostid = self.zapi.host.get({
            "host": hostname,
            "output": "hostid"
        })[0]["hostid"]
        host_info = {'hostid': hostid, 'output': 'extend'}
        host_alert = self.zapi.alert.get(filter=host_info)
        alert_info = []
        for alert in host_alert:
            t_time = alert.get('clock')
            t_message = alert.get('message')

            time_now = time.time()
            time_interval = int(time_now) - int(t_time)
            if time_interval < 86400:
                x = time.localtime(int(t_time))
                t_time = time.strftime('%Y-%m-%d %H:%M:%S', x)
                alert_info.append((t_time, t_message))
        alert_info.reverse()

        return alert_info

    def get_alert_day(self, req, resp):
        hostname = req.get_param(name='s') or req.get_header(name='HOSTNAME')
        if hostname is None:
            return '-s(hostname) need'
        hostid = self.zapi.host.get({
            "host": hostname,
            "output": "hostid"
        })[0]["hostid"]
        trigger_id, event_id, alert_info = [], [], []
        time_till = int(time.time())
        time_from = time_till - 86400
        host_info = {'hostid': hostid, 'output': 'extend'}
        host_trigger = self.zapi.trigger.get(filter=host_info)
        for trigger in host_trigger:
            trigger_id.append(trigger.get('triggerid'))
        for id in trigger_id:
            trigger_info = {
                'output': 'extend',
                "select_acknowledges": "extend",
                "objectid": id,
                "sortorder": "DESC"
            }
            host_event = self.zapi.event.get(filter=trigger_info)
            for event in host_event:
                event_id.append(event.get('eventid'))

        for id in event_id:
            alerts_info = {"output": "extend", "eventid": id}
            host_alert = self.zapi.alert.get(filter=alerts_info)
            for alert in host_alert:
                message = alert.get('message')
                sendto = alert.get('sendto')
                clock = alert.get('clock')
                if int(clock) > time_from:
                    x = time.localtime(int(clock))
                    clock = time.strftime('%Y-%m-%d %H:%M:%S', x)
                    alert_info.append((clock, sendto, message))
        alert_info.reverse()
        return alert_info

    def _get_list(self, lists, key):
        l = []
        for i in lists:
            l.append(i[key])
        return l

    def del_hosttemplate(self, req, resp):
        hostname = req.get_param(name='s') or req.get_header(name='HOSTNAME')
        template = req.get_param(name='t')
        if hostname is None:
            return '-s(hostname) need'
        if template is None:
            return '-t(template) need'
        hostid = self.zapi.host.get({
            "host": hostname,
            "output": "hostid"
        })[0]["hostid"]
        templateid = self.zapi.template.get({
            "output": "templateid",
            "filter": {
                "host": template
            }
        })[0]["templateid"]

        if not str(hostid).isdigit():
            return hostid
        if not str(templateid).isdigit():
            return templateid
        return self.zapi.host.massremove(
            hostids=[hostid], templateids_clear=templateid)

    def create_host_group(self, req, resp):
        groupnames = req.get_param(name='g')
        if groupnames is None:
            return '-g(groupnames) need'
        group_names = groupnames.split(',')
        group_add_list = []
        for group_name in group_names:
            result = self.zapi.hostgroup.get({'filter': {'name': group_name}})
            if not result:
                try:
                    self.zapi.hostgroup.create({'name': group_name})
                    group_add_list.append(group_name)
                except Exception as e:
                    return group_add_list
        return group_add_list

    def delete_host_group(self, req, resp):
        group_ids = req.get_param(name='g')
        if group_ids is None:
            return '-g(group_ids) need'
        return self.zapi.hostgroup.delete(group_ids)

    def get_group_ids(self, req, resp):
        host_groups = req.get_param('host_groups')

        group_ids = []
        if host_groups is None:
            group_list = self.zapi.hostgroup.get({
                'output': 'extend',
                'filter': {
                    'name': host_groups
                }
            })
        else:
            group_list = self.zapi.hostgroup.get({'output': 'extend'})
        for group in group_list:
            group_id = group['groupid']
            group_ids.append(group_id)
        return group_ids, group_list

    def del_hostgroup(self, req, resp):
        groupname = req.get_param(name='g')
        hostname = req.get_param(name='s') or req.get_header(name='HOSTNAME')
        if groupname is None:
            return '-g(groupname) need'
        if hostname is None:
            return '-s(hostname) need'
        hostid = self.zapi.host.get({
            "host": hostname,
            "output": "hostid"
        })[0]["hostid"]
        groupid = self.zapi.hostgroup.get({
            "output": "groupid",
            "filter": {
                "name": groupname
            }
        })[0]["groupid"]
        if hostid != '' and groupid != '':
            return self.zapi.hostgroup.massremove(
                groupids=[groupid], hostids=[hostid])
        else:
            return 'invalid group or hostname'

    def add_hostgroup(self, req, resp):
        groupname = req.get_param(name='g')
        hostname = req.get_param(name='s') or req.get_header(name='HOSTNAME')
        if groupname is None:
            return '-g(groupname) need'
        if hostname is None:
            return '-s(hostname) need'
        hostid = self.zapi.host.get({
            "host": hostname,
            "output": "hostid"
        })[0]["hostid"]
        groupid = self.zapi.hostgroup.get({
            "output": "groupid",
            "filter": {
                "name": groupname
            }
        })[0]["groupid"]
        if hostid != '' and groupid != '':
            return self.zapi.hostgroup.massadd(
                groups=[groupid], hosts=[hostid])
        else:
            return 'invalid group or hostname'

    def create_hostgroup(self, req, resp):
        groupname = req.get_param(name='g')
        if groupname is None:
            return '-g(groupname) need'
        if not self.zapi.hostgroup.exists(name=groupname):
            return self.zapi.hostgroup.create(name=groupname)
        else:
            return 'already exists'

    def del_host(self, req, resp):
        hostname = req.get_param(name='s') or req.get_header(name='HOSTNAME')
        if not hostname:
            return "param error: hostname empty"
        hostid = self.zapi.host.get({
            "host": hostname,
            "output": "hostid"
        })[0]["hostid"]
        if str(hostid).isdigit():
            return self.zapi.host.delete(hostid)
        return hostid

    def list_disable(self, req, resp):
        rows = Hosts.select().join(
            Interface,
            on=(Hosts.hostid == Interface.hostid)).where(Hosts.status == 1)
        ret = []
        for row in rows:
            ret.append({'hostid': row.hostid, 'host': row.host, 'ip': row.ip})
        return ret

    @cache()
    def list_red(self, req, resp):
        rows = Hosts.select().join(Interface,on=(Hosts.hostid==Interface.hostid))\
            .where(Hosts.available==2 | Hosts.ipmi_available == 2).where(Hosts.hostid == Hosts.proxy_hostid)
        ret = []
        for row in rows:
            ret.append({'hostid': row.hostid, 'host': row.host, 'ip': row.ip})
        return ret

    def list_able(self, req, resp):
        return self._listable(0)

    def list_disable(self, req, resp):
        return self._listable(1)

    @cache()
    def _listable(self, status=1):
        status = int(status)
        rows = Hosts.select().join(Interface,on=(Hosts.hostid==Interface.hostid))\
            .where(Hosts.status==status & Hosts.hostid == Hosts.proxy_hostid)
        ret = []
        for row in rows:
            ret.append({'hostid': row.hostid, 'host': row.host, 'ip': row.ip})
        return ret

    @cache()
    def list_all(self, req, resp):
        rows = Hosts.select().join(Interface,on=(Hosts.hostid==Interface.hostid)) \
            .where(Hosts.hostid == Hosts.proxy_hostid).order_by(Interface.ip.desc())
        ret = []
        for row in rows:
            ret.append({'hostid': row.hostid, 'host': row.host, 'ip': row.ip})
        return ret

    def api(self, req, resp):
        param = req.get_param(name='param')
        method = req.get_param(name='method')
        if param is None:
            return '--param need'
        if method is None:
            return '--method need'
        log_info('%s, %s' % (type(param), str(param)))
        return self.zapi.do_request(method, json.loads(param))['result']

    def _md5_string(self, raw_string):
        m = hashlib.md5()
        m.update(raw_string)
        return m.hexdigest()

    def list_group(self, req, resp):
        ret = ''
        groups = Groups.select().order_by(Groups.name)
        for group in groups:
            ret = ret + str('"%s"' % group.name.encode("utf-8")) + "\n"
        return ret

    def list_groupip(self, req, resp):
        ret = ''
        groupname = req.get_param(name='g')
        if groupname is None:
            return '-g(groupname) need'
        groups = Groups.select().join(HostsGroups,on=(Groups.groupid==HostsGroups.groupid))\
            .join(Hosts,on=(Hosts.hostid==HostsGroups.hostid))\
            .join(Interface,on=(Hosts.hostid==Interface.hostid))\
            .where(Groups.name==groupname).order_by(Hosts.host)
        for group in groups:
            ret = ret + str('"%s","%s"' %
                            (group.ip.encode("utf-8"), group.host)) + "\n"

        return ret

    def list_template(self, req, resp):
        ret = ''
        groups = Hosts.select().where(Hosts.status == 3).order_by(Hosts.host)
        for group in groups:
            ret = ret + str('"%s"' % group.host.encode("utf-8")) + "\n"
        return ret

    def get_templateid(self, req, resp):
        hostname = req.get_param(name='s') or req.get_header(name='HOSTNAME')
        if hostname is None:
            return '-s(hostname) need'

        hostid = self.zapi.host.get({
            "host": hostname,
            "output": "hostid"
        })[0]["hostid"]
        ret = ''
        return self.zapi.host.get(
            output=['hostid'],
            selectParentTemplates=['templateid', 'name'],
            hostids=hostid)

    def enable_trigger(self, req, resp):
        hostname = req.get_param(name='s') or req.get_header(name='HOSTNAME')
        if not hostname:
            return '-s(hostname) need'
        description = req.get_param(name='d')
        if not description:
            return '-d(description) need'
        return self._abletrigger(hostname, description, 0)

    def disable_trigger(self, req, resp):
        hostname = req.get_param(name='s') or req.get_header(name='HOSTNAME')
        if not hostname:
            return '-s(hostname) need'
        description = req.get_param(name='d')
        if not description:
            return '-d(description) need'
        return self._abletrigger(hostname, description, 1)

    def _abletrigger(self, hostname=None, description=None, status=0):
        try:
            if hostname is None:
                return '-s(hostname) need'
            hostid = self.zapi.host.get({
                "filter": {
                    "host": hostname
                }
            })[0]["hostid"]
            triggerid = self.zapi.trigger.get(
                hostids=hostid,
                search={"description": description})[0]['triggerid']
            para = '''
                    {
                        "triggerid": "%s",
                        "status": %s
                    }
                    ''' % (triggerid, status)
            ret = self.zapi.trigger.update(json.loads(para))
            return ret

        except Exception as er:
            return 'error:' + str(er)

    def enable_item(self, req, resp):
        hostname = req.get_param(name='s') or req.get_header(name='HOSTNAME')
        if not hostname:
            return '-s(hostname) need'
        item = req.get_param(name='i')
        if not item:
            return '-i(item) need'
        return self._ableitem(hostname, item, 0)

    def disable_item(self, req, resp):
        hostname = req.get_param(name='s') or req.get_header(name='HOSTNAME')
        if not hostname:
            return '-s(hostname) need'
        item = req.get_param(name='i')
        if not item:
            return '-i(item) need'
        return self._ableitem(hostname, item, 1)

    def _ableitem(self, hostname=None, item=None, status=0):
        try:
            if hostname is None:
                return '-s(hostname) need'
            hostid = self.zapi.host.get({
                "filter": {
                    "host": hostname
                }
            })[0]["hostid"]
            itemid = self.zapi.item.get({
                "output": "extend",
                "hostids": hostid,
                "search": {
                    "key_": item
                }
            })[0]["itemid"]
            para = '''
                   {
                        "itemid": "%s",
                        "status": %s
                   }
                   ''' % (itemid, status)
            ret = self.zapi.item.update(json.loads(para))
            return ret

        except Exception as er:
            return 'error:' + str(er)

    def enable(self, req, resp):
        hostname = req.get_param(name='s') or req.get_header(name='HOSTNAME')
        if not hostname:
            return '-s(hostname) need'
        return self._able(hostname, 0)

    def disable(self, req, resp):
        hostname = req.get_param(name='s') or req.get_header(name='HOSTNAME')
        if not hostname:
            return '-s(hostname) need'
        return self._able(hostname, 1)

    def _able(self, hostname=None, status=0):
        try:
            if hostname is None:
                return '-s(hostname) need'
            hostid = self.zapi.host.get({
                "host": hostname,
                "output": "hostid"
            })[0]["hostid"]

            para = '''
            {
                "hostid": "%s",
                "status": %s
            }
            ''' % (hostid, status)
            ret = self.zapi.host.update(json.loads(para))
            return ret
        except Exception as er:
            return 'error:' + str(er)

    def get_current_issues(self, req, resp):
        # Get a list of all issues (AKA tripped triggers)
        triggers = self.zapi.trigger.get(only_true=1,
                                         skipDependent=1,
                                         monitored=1,
                                         active=1,
                                         output='extend',
                                         expandDescription=1,
                                         expandData='host')

        # Do another query to find out which issues are Unacknowledged
        unack_triggers = self.zapi.trigger.get(only_true=1,
                                               skipDependent=1,
                                               monitored=1,
                                               active=1,
                                               output='extend',
                                               expandDescription=1,
                                               expandData='host',
                                               withLastEventUnacknowledged=1)
        unack_trigger_ids = [t['triggerid'] for t in unack_triggers]
        for t in triggers:
            t['unacknowledged'] = True if t['triggerid'] in unack_trigger_ids \
                else False

        result = []
        for t in triggers:
            if int(t['value']) == 1:
                result.append("{0} {1} {2} - {3} {4}".format(
                    t['priority'], t['templateid'], t['triggerid'], t[
                        'description'], '(Unack)'
                    if t['unacknowledged'] else ''))
        return result

    def fix_host_ips(self, req, resp):
        result = []
        for h in self.zapi.hostinterface.get(output=["dns", "ip", "useip"],
                                             selectHosts=["host"],
                                             filter={"main": 1,
                                                     "type": 1}):
            if h['dns'] != h['hosts'][0]['host']:
                result.append('Warning: %s has dns "%s"' %
                              (h['hosts'][0]['host'], h['dns']))

            if h['useip'] == '1':
                result.append('%s is using IP instead of hostname. Skipping.' %
                              h['hosts'][0]['host'])
                continue

            try:
                lookup = socket.gethostbyaddr(h['dns'])
            except socket.gaierror as e:
                log_error(h['dns'], e)
                continue
            actual_ip = lookup[2][0]

            if actual_ip != h['ip']:
                result.append("%s has the wrong IP: %s. Changing it to: %s" %
                              (h['hosts'][0]['host'], h['ip'], actual_ip))

                try:
                    self.zapi.hostinterface.update(
                        interfaceid=h['interfaceid'], ip=actual_ip)
                except ZabbixAPIException as e:
                    log_error(e)
        return result

    def import_templates(self, req, resp):
        rules = {
            'applications': {
                'createMissing': 'true',
                'updateExisting': 'true'
            },
            'discoveryRules': {
                'createMissing': 'true',
                'updateExisting': 'true'
            },
            'graphs': {
                'createMissing': 'true',
                'updateExisting': 'true'
            },
            'groups': {
                'createMissing': 'true'
            },
            'hosts': {
                'createMissing': 'true',
                'updateExisting': 'true'
            },
            'images': {
                'createMissing': 'true',
                'updateExisting': 'true'
            },
            'items': {
                'createMissing': 'true',
                'updateExisting': 'true'
            },
            'maps': {
                'createMissing': 'true',
                'updateExisting': 'true'
            },
            'screens': {
                'createMissing': 'true',
                'updateExisting': 'true'
            },
            'templateLinkage': {
                'createMissing': 'true',
                'updateExisting': 'true'
            },
            'templates': {
                'createMissing': 'true',
                'updateExisting': 'true'
            },
            'templateScreens': {
                'createMissing': 'true',
                'updateExisting': 'true'
            },
            'triggers': {
                'createMissing': 'true',
                'updateExisting': 'true'
            },
            'valueMaps': {
                'createMissing': 'true',
                'updateExisting': 'true'
            }
        }

        files = glob.glob('vendors/zabbix/templates/*.xml')
        for filename in files:
            with open(filename, 'r') as f:
                template = f.read()
                try:
                    self.zapi.confimport('xml', template, rules)
                except ZabbixAPIException as e:
                    log_error(filename + '\r\n' + str(e))
        return 'ok'

    def add_trigger(self, req, resp):
        description = req.get_param(name='d')
        expression = req.get_param(name='e')
        priority = req.get_param(name='p')
        if not description:
            return '-d(description) need'
        if not expression:
            return '-e(expression) need'
        if not priority:
            return '-p(priority) need'

        result = []
        try:
            self.zapi.trigger.create({
                "description": description,
                "expression": expression,
                "priority": priority
            })
        except Exception as e:
            log_error(e)
            raise Exception(e)

        return result

    def massremove_template(self, req, resp):
        result = []
        templates = req.get_param(name='t')
        hostname = req.get_param(name='s') or req.get_header(name='HOSTNAME')
        if not templates:
            return '-t(templates) need'
        if not hostname:
            return '-s(hostname) need'
        templates_id = self.zapi.template.get({
            "output": "templateid",
            "filter": {
                "host": templates.split(",")
            }
        })
        templateids = self._get_list(templates_id, "templateid")
        hostid = self.zapi.host.get({
            "filter": {
                "host": hostname
            }
        })[0]["hostid"]
        try:
            result.append(
                self.zapi.template.massremove({
                    "templateids": templateids,
                    "templateids_clear": templateids,
                    "hostids": hostid
                }))
        except Exception as e:
            log_error(e)
            raise Exception(e)

        return result

    def massadd_template(self, req, resp):
        result = []
        templates = req.get_param(name='t')
        hostname = req.get_param(name='s') or req.get_header(name='HOSTNAME')
        if not templates:
            return '-t(templates) need'
        if not hostname:
            return '-s(hostname) need'
        templates_id = self.zapi.template.get({
            "output": "templateid",
            "filter": {
                "host": templates.split(",")
            }
        })
        hostid = self.zapi.host.get({
            "filter": {
                "host": hostname
            }
        })[0]["hostid"]
        try:
            result.append(
                self.zapi.template.massadd({
                    "templates": templates_id,
                    "hosts": hostid
                }))
        except Exception as e:
            log_error(e)
            raise Exception(e)

        return result

    def get_trigger(self, req, resp):
        hostname = req.get_param(name='s') or req.get_header(name='HOSTNAME')
        hostid = self.zapi.host.get({
            "filter": {
                "host": hostname
            }
        })[0]["hostid"]
        if not hostid:
            return False
        host_info = {'hostid': hostid, 'output': 'extend'}
        host_trigger = self.zapi.trigger.get(filter=host_info)
        trigger_info = {}
        for trigger in host_trigger:
            t_value = int(trigger.get('value'))
            if t_value == 1:
                t_time = int(trigger.get('lastchange'))
                t_des = trigger.get('description')
                t_time = datetime.fromtimestamp(t_time)
                trigger_info[t_time] = t_des
        return trigger_info

    def get_item(self, req, resp):
        hostname = req.get_param(name='s') or req.get_header(name='HOSTNAME')
        pattern1 = re.compile(r'.*\[(.*)\].*')
        pattern2 = re.compile(r'.*\[(/.*),.*\]')
        pattern3 = re.compile(r'.*\[,(.*)\].*')
        hostid = self.zapi.host.get({
            "filter": {
                "host": hostname
            }
        })[0]["hostid"]
        if not hostid:
            return False
        host_info = {'hostid': hostid, 'output': 'extend'}
        item_info = []
        zabbix_item = self.zapi.item.get(filter=host_info)
        for item in zabbix_item:
            item_name = item.get('name')
            item_key = item.get('key_')
            if 'network traffic on' in item_name:
                match = pattern1.match(item_key)
                if match:
                    interface = match.groups()[0]
                    item_name = item_name.replace('$1', interface)
            if 'Free' in item_name:
                match = pattern2.match(item_key)
                if match:
                    disk = match.groups()[0]
                    item_name = item_name.replace('$1', disk)
            if 'CPU $2 time' in item_name:
                match = pattern3.match(item_key)
                if match:
                    cpu_type = match.groups()[0]
                    item_name = item_name.replace('$2', cpu_type)
            item_info.append(item_name)

        return item_info

    def delete_item(self, req, resp):
        hostname = req.get_param(name='s') or req.get_header(name='HOSTNAME')
        key = req.get_param(name='k')
        if not hostname:
            return '-s(hostname) need'
        if not key:
            return '-k(key) need'
        result = []
        hostid = self.zapi.host.get({
            "filter": {
                "host": hostname
            }
        })[0]["hostid"]
        itemid = self.zapi.item.get({
            "output": "extend",
            "hostids": hostid,
            "search": {
                "key_": key
            }
        })[0]["itemid"]
        result.append(hostid, '\t', itemid)
        self.zapi.item.delete({"params": itemid})

        return result

    def add_item(self, req, resp):
        result = []
        hostname = req.get_param(name='s') or req.get_header(name='HOSTNAME')
        template = req.get_param(name='t')
        key = req.get_param(name='k')
        name = req.get_param(name='n')
        type = req.get_param(name='type')
        value_type = req.get_param(name='v')
        delay = req.get_param(name='delay')
        interfaceid = req.get_param(name='i')
        history = req.get_param(name='h')
        units = req.get_param(name='u')
        delta = req.get_param(name='d')
        params = req.get_param(name='p')
        if not hostname:
            return '-s(hostname) need'
        if not key:
            return '-k(key) need'
        if not name:
            return '-n(name) need'
        if not type:
            return '--type(type) need'
        if not value_type:
            return '-v(value_type) need'
        if not delay:
            return '-d(delay) need'
        if not interfaceid:
            return '-i(interfaceid) need'
        if not history:
            return '-h(history) need'
        if not units:
            return '-u(units) need'
        if not delta:
            return '-d(delta) need'
        if not params:
            return '-p(params) need'

        result = []
        application = req.get_param['application']
        if hostname and not template:
            host = self.zapi.host.get({"filter": {"host": hostname}})[0]
            hostid = host['hostid']
        elif template and not hostname:
            template = self.zapi.template.get({
                "filter": {
                    "host": template
                }
            })[0]
            templateid = template["templateid"]
            hostid = templateid
            _application = self.zapi.application.get({
                "output": "extend",
                "templateids": hostid,
                "filter": {
                    "name": application
                }
            })[0]
            applicationid = json.loads(json.dumps(_application))[
                "applicationid"]
        try:
            if 'applicationid' in dir():
                result.append(
                    self.zapi.item.create({
                        "name": name,
                        "key_": key,
                        "hostid": hostid,
                        "type": (type),
                        "interfaceid": interfaceid,
                        "value_type": value_type,
                        "delay": delay,
                        "history": history,
                        "delta": delta,
                        "units": units,
                        "params": params,
                        "applications": [applicationid]
                    }))
            else:
                result.append(
                    self.zapi.item.create({
                        "name": name,
                        "key_": key,
                        "hostid": hostid,
                        "type": (type),
                        "interfaceid": interfaceid,
                        "value_type": value_type,
                        "delay": delay,
                        "history": history,
                        "delta": delta,
                        "units": units,
                        "params": params
                    }))
        except Exception as e:
            log_error(e)
            raise Exception(e)

        return result

    def update_host(self, req, resp):
        result = []
        status = req.get_param(name='t')
        hostname = req.get_param(name='s') or req.get_header(name='HOSTNAME')
        name = req.get_param(name='n')
        if not status:
            return '-t(status) need'
        if not hostname:
            return '-s(hostname) need'
        if not name:
            return '-n(name) need'
        hostid = self.zapi.host.get({
            "filter": {
                "host": hostname
            }
        })[0]["hostid"]
        result.append(hostname, '\t', hostid, '\t', status)
        try:
            msg = self.zapi.host.update({
                "hostid": hostid,
                "status": status,
                "name": name
            })
            result.append(msg)
        except Exception as e:
            log_error(e)
            raise Exception(e)

        return result

    def massadd_host(self, req, resp):
        templates = req.get_param(name='t')
        hostname = req.get_param(name='s') or req.get_header(name='HOSTNAME')
        groups = req.get_param(name='g')
        if not groups:
            return '-g(groups) need'
        if not hostname:
            return '-s(hostname) need'
        if not templates:
            return '-t(templates) need'

        hostid = self.zapi.host.get({
            "filter": {
                "host": hostname
            }
        })[0]["hostid"]
        if templates:
            templates_id = self.zapi.template.get({
                "output": "templateid",
                "filter": {
                    "host": templates.split(",")
                }
            })
        else:
            templates_id = ""
        if groups:
            groups_id = self.zapi.hostgroup.get({
                "output": "groupid",
                "filter": {
                    "name": groups.split(",")
                }
            })
        else:
            groups_id = ""
        if templates_id and groups_id:
            self.zapi.host.massremove(
                templates=templates_id, groups=groups_id, hosts=hostid)
        elif templates_id and not groups_id:
            self.zapi.host.massremove(templates=templates_id, hostids=hostid)
        elif not templates_id and groups_id:
            self.zapi.host.massremove(groups=groups_id, hosts=hostid)
        return 'ok'

    def massremove_host(self, req, resp):
        templates = req.get_param(name='t')
        hostname = req.get_param(name='s') or req.get_header(name='HOSTNAME')
        groups = req.get_param(name='g')
        if not groups:
            return '-g(groups) need'
        if not hostname:
            return '-s(hostname) need'
        if not templates:
            return '-t(templates) need'

        hostid = self.zapi.host.get({
            "filter": {
                "host": hostname
            }
        })[0]["hostid"]
        if templates:
            templates_id = self.zapi.template.get({
                "output": "templateid",
                "filter": {
                    "host": templates.split(",")
                }
            })
            templateids = self._get_list(templates_id, "templateid")
        else:
            templateids = ""
        if groups:
            groups_id = self.zapi.hostgroup.get({
                "output": "groupid",
                "filter": {
                    "name": groups.split(",")
                }
            })
            groupids = self._get_list(groups_id, "groupid")
        else:
            groupids = ""
        if templateids and groupids:
            self.zapi.host.massremove(
                templateids_clear=templateids,
                groupids=groupids,
                hostids=hostid)
        elif templateids and not groupids:
            self.zapi.host.massremove(
                templateids_clear=templateids, hostids=hostid)
        elif not templateids and groupids:
            self.zapi.host.massremove(groupids=groupids, hostids=hostid)

        return 'ok'

    def create_screen(self, req, resp):
        screen_name = req.get_param(name='screen_name')
        h_size = req.get_param(name='h_size')
        v_size = req.get_param(name='v_size')
        screen = self.zapi.screen.create({
            'name': screen_name,
            'hsize': h_size,
            'vsize': v_size
        })
        return screen['screenids'][0]

    def update_screen(self, req, resp):
        screen_name = req.get_param(name='screen_name')
        h_size = req.get_param(name='h_size')
        v_size = req.get_param(name='v_size')
        screen_id = self._get_screen_id(screen_name=screen_name)
        return self.zapi.screen.update({
            'screenid': screen_id,
            'hsize': h_size,
            'vsize': v_size
        })

    def delete_screen(self, req, resp):
        screen_name = req.get_param(name='screen_name')
        screen_id = self._get_screen_id(screen_name=screen_name)
        return self.zapi.screen.delete([screen_id])

    def get_graphs_by_host_id(self, req, resp):
        hostname = req.get_param(name='s') or req.get_header(name='HOSTNAME')
        if hostname is None:
            return '-s(hostname) need'
        graph_name = req.get_param['g']
        if graph_name is None:
            return '-g(graph_name) need'
        host_id = self.zapi.host.get({
            "host": hostname,
            "output": "hostid"
        })[0]["hostid"]
        graph_name_list = graph_name.split(',')
        graph_ids = []
        for graph_name in graph_name_list:
            graphs_list = self.zapi.graph.get({
                'output': 'extend',
                'search': {
                    'name': graph_name
                },
                'hostids': host_id
            })
            graph_id_list = []
            if len(graphs_list) > 0:
                for graph in graphs_list:
                    graph_id = graph['graphid']
                    graph_id_list.append(graph_id)
            if len(graph_id_list) > 0:
                graph_ids.extend(graph_id_list)
        return graph_ids

    def get_screen_items(self, req, resp):
        screen_name = req.get_param(name='screen_name')
        if screen_name is None:
            return '--screen_name need'
        screen_id = self._get_screen_id(screen_name=screen_name)
        screen_item_list = self.zapi.screenitem.get({
            'output': 'extend',
            'screenids': screen_id
        })
        return screen_item_list

    def delete_screen_items(self, req, resp):
        screen_name = req.get_param(name='screen_name')
        if screen_name is None:
            return '--screen_name need'
        screen_id = self._get_screen_id(screen_name=screen_name)
        screen_item_id = req.get_param['g']
        if screen_item_id is None:
            return '-g(screen_item_id) need'
        screen_item_id_list = screen_item_id.split(',')
        if len(screen_item_id_list) == 0:
            return True
        screen_item_list = self.get_screen_items(screen_id)
        if len(screen_item_list) > 0:
            self.zapi.screenitem.delete(screen_item_id_list)
            return True
        return False

    def create_screen_items(self, req, resp):
        screen_name = req.get_param(name='screen_name')
        if screen_name is None:
            return '--screen_name need'
        hosts = req.get_param(name='hosts')
        if hosts is None:
            return '--hosts need'
        screen_id = self._get_screen_id(screen_name=screen_name)
        width = req.get_param(name='width')
        height = req.get_param(name='height')
        if len(hosts) < 4:
            if width is None or width < 0:
                width = 500
        else:
            if width is None or width < 0:
                width = 200
        if height is None or height < 0:
            height = 100

        for i, host in enumerate(hosts):
            graph_id_list = self.get_graphs_by_host_id(req=req, resp=resp)
            for j, graph_id in enumerate(graph_id_list):
                if graph_id is not None:
                    self.zapi.screenitem.create({
                        'screenid': screen_id,
                        'resourcetype': 0,
                        'resourceid': graph_id,
                        'width': width,
                        'height': height,
                        'x': i,
                        'y': j,
                        'colspan': 1,
                        'rowspan': 1,
                        'elements': 0,
                        'valign': 0,
                        'halign': 0,
                        'style': 0,
                        'dynamic': 0,
                        'sort_triggers': 0
                    })
        return 'ok'

    def delete_maintenance(self, req, resp):
        maintenance_id = req.get_param(name="m")
        if maintenance_id is None:
            return '-m(maintenance_id) need'
        return self.zapi.maintenance.delete(maintenance_id)

    def get_maintenance_id(self, req, resp):
        name = req.get_param(name="n")
        if name is None:
            return '-n(name) need'
        result = self.zapi.maintenance.get({"filter": {"name": name}})
        maintenance_ids = []
        for res in result:
            maintenance_ids.append(res["maintenanceid"])
        return maintenance_ids

    def _get_screen_id(self, screen_name):
        if screen_name == "":
            return None
        screen_id_list = self.zapi.screen.get({
            'output': 'extend',
            'search': {
                "name": screen_name
            }
        })
        if len(screen_id_list) >= 1:
            screen_id = screen_id_list[0]['screenid']
            return screen_id
        return None

    def _get_host_by_host_name(self, host_name):
        host_list = self.zapi.host.get({
            'output': 'extend',
            'filter': {
                'host': [host_name]
            }
        })
        return host_list[0]

    def _get_proxyid_by_proxy_name(self, proxy_name):
        proxy_list = self.zapi.proxy.get({
            'output': 'extend',
            'filter': {
                'host': [proxy_name]
            }
        })
        return proxy_list[0]['proxyid']

    def _get_group_ids_by_group_names(self, group_names):
        group_ids = []
        group_list = self.zapi.hostgroup.get({
            'output': 'extend',
            'filter': {
                'name': group_names
            }
        })
        for group in group_list:
            group_id = group['groupid']
            group_ids.append({'groupid': group_id})
        return group_ids

    def _get_host_templates_by_host_id(self, host_id):
        template_ids = []
        template_list = self.zapi.template.get({
            'output': 'extend',
            'hostids': host_id
        })
        for template in template_list:
            template_ids.append(template['templateid'])
        return template_ids

    def get_host_groups_by_host_id(self, host_id):
        exist_host_groups = []
        host_groups_list = self.zapi.hostgroup.get({
            'output': 'extend',
            'hostids': host_id
        })

        if len(host_groups_list) >= 1:
            for host_groups_name in host_groups_list:
                exist_host_groups.append(host_groups_name['name'])
        return exist_host_groups

    def link_or_clear_template(self, req, resp):
        hostname = req.get_param(name='s') or req.get_header(name='HOSTNAME')
        if hostname is None:
            return '-s(hostname) need'
        templates = req.get_param['t']
        if templates is None:
            return '-t(templates) need'
        host_id = self.zapi.host.get({
            "host": hostname,
            "output": "hostid"
        })[0]["hostid"]

        template_id_list = self.zapi.template.get({
            "output": "templateid",
            "filter": {
                "host": templates.split(",")
            }
        })
        exist_template_id_list = self._get_host_templates_by_host_id(host_id)

        exist_template_ids = set(exist_template_id_list)
        template_ids = set(template_id_list)
        template_id_list = list(template_ids)

        templates_clear = exist_template_ids.difference(template_ids)
        templates_clear_list = list(templates_clear)
        request_str = {
            'hostid': host_id,
            'templates': template_id_list,
            'templates_clear': templates_clear_list
        }
        return self.zapi.host.update(request_str)

    def update_inventory_mode(self, req, resp):
        hostname = req.get_param(name='s') or req.get_header(name='HOSTNAME')
        if hostname is None:
            return '-s(hostname) need'
        inventory_mode = req.get_param(name='i')
        if not inventory_mode:
            return '-i(inventory_mode) need'
        host_id = self.zapi.host.get({
            "host": hostname,
            "output": "hostid"
        })[0]["hostid"]
        if inventory_mode == "automatic":
            inventory_mode = int(1)
        elif inventory_mode == "manual":
            inventory_mode = int(0)
        elif inventory_mode == "disabled":
            inventory_mode = int(-1)

        request_str = {'hostid': host_id, 'inventory_mode': inventory_mode}
        return self.zapi.host.update(request_str)

    def get_host_macro(self, req, resp):
        hostname = req.get_param(name='s') or req.get_header(name='HOSTNAME')
        if hostname is None:
            return '-s(hostname) need'
        host_id = self.zapi.host.get({
            "host": hostname,
            "output": "hostid"
        })[0]["hostid"]
        return self.zapi.usermacro.get({
            "output": "extend",
            "selectSteps": "extend",
            'hostids': [host_id]
        })

    def create_host_macro(self, req, resp):
        hostname = req.get_param(name='s') or req.get_header(name='HOSTNAME')
        if hostname is None:
            return '-s(hostname) need'
        macro_name = req.get_param(name='n')
        if macro_name is None:
            return '--n(macro_name) need'
        macro_value = req.get_param(name='v')
        if macro_value is None:
            return '-v(macro_value) need'
        host_id = self.zapi.host.get({
            "host": hostname,
            "output": "hostid"
        })[0]["hostid"]
        return self.zapi.usermacro.create({
            'hostid': host_id,
            'macro': '{$' + macro_name + '}',
            'value': macro_value
        })

    def get_host(self, req, resp):
        result = []
        hostname = req.get_param(name='s') or req.get_header(name='HOSTNAME')
        if not hostname:
            return '-s(hostname) need'
        try:
            hostinfo = self.zapi.host.get({
                "filter": {
                    "host": hostname
                },
                "output": "hostid",
                "selectGroups": "extend",
                "selectParentTemplates": ["templateid", "name"]
            })[0]
            hostid = hostinfo["hostid"]
            host_group_list = []
            host_template_list = []
            for l in hostinfo["groups"]:
                host_group_list.append(l["name"])
            for t in hostinfo["parentTemplates"]:
                host_template_list.append(t["name"])
            result.append(
                "host %s exist, hostid : %s, group: %s, template: %s " %
                (hostname, hostid, host_group_list, host_template_list))
        except:
            log_error("host not exist: %s" % hostname)
            raise Exception("host not exist: %s" % hostname)
        return result

    def delete_host(self, req, resp):
        result = []
        hostname = req.get_param(name='s') or req.get_header(name='HOSTNAME')
        if not hostname:
            return '-s(hostname) need'

        hostid = self.zapi.host.get({
            "filter": {
                "host": hostname
            },
            "output": "hostid"
        })[0]["hostid"]
        result.append(hostname, '\t', hostid)
        try:
            result = self.zapi.host.delete([hostid])
            result.append(result)
        except Exception as e:
            log_error(e)
            raise Exception(e)

        return result

    def add_host(self, req, resp):
        result = []
        status = req.get_param(name='t') or 0
        ip = req.get_param(name='i') or req.get_header(name='SERVER-IP')
        proxy = req.get_param(name='p')
        hostname = req.get_param(name='s') or req.get_header(name='HOSTNAME')
        if not hostname:
            return '-s(hostname) need'
        if not ip:
            return '-i(ip) need'
        if not status:
            return '-t(status) need'
        if proxy:
            proxy_id = self.zapi.proxy.get({
                "output": "proxyid",
                "selectInterface": "extend",
                "filter": {
                    "host": proxy
                }
            })[0]['proxyid']
        else:
            proxy_id = ""

        groups = req.get_param['groups']
        templates = req.get_param['templates']
        groups_id = self.zapi.hostgroup.get({
            "output": "groupid",
            "filter": {
                "name": groups.split(",")
            }
        })
        templates_id = self.zapi.template.get({
            "output": "templateid",
            "filter": {
                "host": templates.split(",")
            }
        })
        try:
            if proxy_id:
                result.append(
                    self.zapi.host.create({
                        "host": hostname,
                        "groups": groups_id,
                        "templates": templates_id,
                        "interfaces": [{
                            "type": 1,
                            "main": 1,
                            "useip": 1,
                            "ip": ip,
                            "dns": "",
                            "port": "10050"
                        }],
                        "proxy_hostid": proxy_id,
                        "status": status
                    }))
            else:
                result.append(
                    self.zapi.host.create({
                        "host": hostname,
                        "groups": groups_id,
                        "templates": templates_id,
                        "interfaces": [{
                            "type": 1,
                            "main": 1,
                            "useip": 1,
                            "ip": ip,
                            "dns": "",
                            "port": "10050",
                            "status": status
                        }]
                    }))
        except Exception as e:
            log_error(e)
            raise Exception(e)
        return result

    def update_hostInterface(self, req, resp):
        result = []
        main = req.get_param(name='m')
        ip = req.get_param(name='i')
        port = req.get_param(name='p')
        useip = req.get_param(name='u')
        dns = req.get_param(name='d')
        hostname = req.get_param(name='s') or req.get_header(name='HOSTNAME')
        if not hostname:
            return '-s(hostname) need'
        if not dns:
            return '-d(dns) need'
        if not useip:
            return '-u(useip) need'
        if not port:
            return '-p(port) need'
        if not ip:
            return '-i(ip) need'
        if not main:
            return '-m(main) need'

        hostid = self.zapi.host.get({
            "host": hostname,
            "output": "hostid"
        })[0]["hostid"]
        interfaceid = self.zapi.hostinterface.get({
            "hostids": hostid,
            "output": "interfaceid"
        })[0]["interfaceid"]
        result.append(hostname, '\t', hostid, '\t', interfaceid)
        try:
            msg = self.zapi.hostinterface.update({
                "interfaceid": interfaceid,
                "ip": ip,
                "main": main,
                "port": port,
                "useip": useip,
                "dns": dns
            })
            result.append(msg)
        except Exception as e:
            log_error(e)
            raise Exception(e)
        return result

    def get_history(self, req, resp):
        groupname = req.get_param(name='g')
        graphid = req.get_param['i']
        time_from = req.get_param(name='time_from')
        time_till = req.get_param(name='time_till')
        hostname = req.get_param(name='s') or req.get_header(name='HOSTNAME')
        if not hostname:
            return '-s(hostname) need'
        if not groupname:
            return '-g(groupname) need'
        if not graphid:
            return '-i(graphid) need'
        if not time_from:
            return '--time_from(time_from) need'
        if not hostname:
            return '--time_till(time_till) need'
        result = []

        time_from = int(
            time.mktime(time.strptime(time_from, '%Y-%m-%d %H:%M:%S')))
        time_till = int(
            time.mktime(time.strptime(time_till, '%Y-%m-%d %H:%M:%S')))

        hostid = self.zapi.host.get({
            "host": hostname,
            "output": "hostid"
        })[0]["hostid"]
        groupid = self.zapi.hostgroup.get({
            "output": "groupid",
            "filter": {
                "name": groupname
            }
        })[0]["groupid"]

        item = self.zapi.item.get({
            "output": ["itemid", "name"],
            "hostids": hostid,
            "graphids": graphid,
            "groupids": groupid
        })
        for key in item:
            result.append(key['name'])
            result.append(
                self.zapi.history.get({
                    "output": ["value", "clock"],
                    "history": 0,
                    "itemids": key['itemid'],
                    "sortfield": "clock",
                    "sortorder": "DESC",
                    "time_from": time_from,
                    "time_till": time_till
                }))
        return result

    def get_graph(self, req, resp):
        hostname = req.get_param['hostname'] or req.get_header(name='HOSTNAME')
        hostid = self.zapi.host.get({
            "filter": {
                "host": hostname
            }
        })[0]["hostid"]
        zabbix_graph = self.zapi.graph.get({
            "output": "extend",
            "hostid": hostid
        })
        graph_ids = {}
        for graph in zabbix_graph:
            graph_id = int(graph['graphid'])
            graph_name = graph['name']
            graph_ids[graph_name] = graph_id
        return graph_ids

    def add_graph_mapi(self, req, resp):
        name = req.get_param(name='n')
        interface = req.get_param(name='i')
        hostname = req.get_param(name='s') or req.get_header(name='HOSTNAME')
        if not hostname:
            return '-s(hostname) need'
        if not interface:
            return '-i(interface) need'
        if not name:
            return '-n(name) need'
        key_responseTime = interface + "-responseTime"
        key_0_200 = interface + "-0-200"
        key_200_500 = interface + "-200-500"
        key_500_1000 = interface + "-500-1000"
        key_1000_2000 = interface + "-1000-2000"
        key_2000_999999 = interface + "-2000-999999"
        key_Total_Requests = interface + "-Total-Requests"
        key_httpCode_200 = interface + "-HttpCode-200"
        key_httpCode_4xx = interface + "-HttpCode-400"
        key_httpCode_5xx = interface + "-HttpCode-500"

        hostid = self.zapi.template.get({
            "filter": {
                "host": hostname
            }
        })[0]["templateid"]
        i_responseTime = self.zapi.item.get({
            "output": "extend",
            "hostids": hostid,
            "search": {
                "key_": key_responseTime
            }
        })[0]["itemid"]
        i_0_200 = self.zapi.item.get({
            "output": "extend",
            "hostids": hostid,
            "search": {
                "key_": key_0_200
            }
        })[0]["itemid"]
        i_200_500 = self.zapi.item.get({
            "output": "extend",
            "hostids": hostid,
            "search": {
                "key_": key_200_500
            }
        })[0]["itemid"]
        i_500_1000 = self.zapi.item.get({
            "output": "extend",
            "hostids": hostid,
            "search": {
                "key_": key_500_1000
            }
        })[0]["itemid"]
        i_1000_2000 = self.zapi.item.get({
            "output": "extend",
            "hostids": hostid,
            "search": {
                "key_": key_1000_2000
            }
        })[0]["itemid"]
        i_2000_999999 = self.zapi.item.get({
            "output": "extend",
            "hostids": hostid,
            "search": {
                "key_": key_2000_999999
            }
        })[0]["itemid"]
        i_Total_Requests = self.zapi.item.get({
            "output": "extend",
            "hostids": hostid,
            "search": {
                "key_": key_Total_Requests
            }
        })[0]["itemid"]

        i_httpCode_200 = self.zapi.item.get({
            "output": "extend",
            "hostids": hostid,
            "search": {
                "key_": key_httpCode_200
            }
        })[0]["itemid"]
        i_httpCode_4xx = self.zapi.item.get({
            "output": "extend",
            "hostids": hostid,
            "search": {
                "key_": key_httpCode_4xx
            }
        })[0]["itemid"]
        i_httpCode_5xx = self.zapi.item.get({
            "output": "extend",
            "hostids": hostid,
            "search": {
                "key_": key_httpCode_5xx
            }
        })[0]["itemid"]

        api = "MAPI - " + name
        api_response_time = "MAPI - " + name + " response time"

        self.zapi.graph.create({
            "name": api,
            "width": 900,
            "height": 200,
            "gitems": [{
                "itemid": i_httpCode_200,
                "color": "00DD00",
                "drawtype": 1,
                "yaxisside": 0,
                "sortorder": 0
            }, {
                "itemid": i_httpCode_4xx,
                "color": "DD00DD",
                "drawtype": 1,
                "yaxisside": 0,
                "sortorder": 1
            }, {
                "itemid": i_httpCode_5xx,
                "color": "DD0000",
                "drawtype": 1,
                "yaxisside": 0,
                "sortorder": 2
            }, {
                "itemid": i_responseTime,
                "color": "0000DD",
                "drawtype": 0,
                "yaxisside": 1,
                "sortorder": 3
            }]
        })
        self.zapi.graph.create({
            "name": api_response_time,
            "width": 900,
            "height": 200,
            "gitems": [{
                "itemid": i_0_200,
                "color": "33FF33",
                "drawtype": 1,
                "yaxisside": 0
            }, {
                "itemid": i_200_500,
                "color": "008800",
                "drawtype": 1,
                "yaxisside": 0
            }, {
                "itemid": i_500_1000,
                "color": "CCCC00",
                "drawtype": 1,
                "yaxisside": 0
            }, {
                "itemid": i_1000_2000,
                "color": "FF3333",
                "drawtype": 1,
                "yaxisside": 0
            }, {
                "itemid": i_2000_999999,
                "color": "880000",
                "drawtype": 1,
                "yaxisside": 0
            }, {
                "itemid": i_Total_Requests,
                "color": "CC00CC",
                "drawtype": 0,
                "yaxisside": 0
            }, {
                "itemid": i_responseTime,
                "color": "0000BB",
                "drawtype": 0,
                "yaxisside": 1
            }]
        })
        return 'ok'

    def add_graph(self, req, resp):
        pool = req.get_param(name='p')
        name = req.get_param(name='n')
        interface = req.get_param(name='i')
        hostname = req.get_param(name='s') or req.get_header(name='HOSTNAME')
        if not hostname:
            return '-s(hostname) need'
        if not interface:
            return '-i(interface) need'
        if not name:
            return '-n(name) need'
        if not pool:
            return '-p(pool) need'

        key_responseTime = interface + "-responseTime"
        key_0_200 = interface + "-0-200"
        key_200_500 = interface + "-200-500"
        key_500_1000 = interface + "-500-1000"
        key_1000_2000 = interface + "-1000-2000"
        key_2000_999999 = interface + "-2000-999999"
        key_Total_Requests = interface + "-Total-Requests"
        key_retMsg_FAIL = interface + "-retMsg-FAIL"
        key_retMsg_SUCC = interface + "-retMsg-SUCC"

        hostid = self.zapi.host.get({
            "filter": {
                "host": hostname
            }
        })[0]["hostid"]
        i_responseTime = self.zapi.item.get({
            "output": "extend",
            "hostids": hostid,
            "search": {
                "key_": key_responseTime
            }
        })[0]["itemid"]
        i_0_200 = self.zapi.item.get({
            "output": "extend",
            "hostids": hostid,
            "search": {
                "key_": key_0_200
            }
        })[0]["itemid"]
        i_200_500 = self.zapi.item.get({
            "output": "extend",
            "hostids": hostid,
            "search": {
                "key_": key_200_500
            }
        })[0]["itemid"]
        i_500_1000 = self.zapi.item.get({
            "output": "extend",
            "hostids": hostid,
            "search": {
                "key_": key_500_1000
            }
        })[0]["itemid"]
        i_1000_2000 = self.zapi.item.get({
            "output": "extend",
            "hostids": hostid,
            "search": {
                "key_": key_1000_2000
            }
        })[0]["itemid"]
        i_2000_999999 = self.zapi.item.get({
            "output": "extend",
            "hostids": hostid,
            "search": {
                "key_": key_2000_999999
            }
        })[0]["itemid"]
        i_Total_Requests = self.zapi.item.get({
            "output": "extend",
            "hostids": hostid,
            "search": {
                "key_": key_Total_Requests
            }
        })[0]["itemid"]
        i_retMsg_FAIL = self.zapi.item.get({
            "output": "extend",
            "hostids": hostid,
            "search": {
                "key_": key_retMsg_FAIL
            }
        })[0]["itemid"]
        i_retMsg_SUCC = self.zapi.item.get({
            "output": "extend",
            "hostids": hostid,
            "search": {
                "key_": key_retMsg_SUCC
            }
        })[0]["itemid"]

        api = "API (" + pool + ") -- " + name
        api_response_time = "API (" + pool + ") -- " + name + " response time"
        api_response_time_pie = "API (" + pool + ") -- " + name + " response time (pie)"

        self.zapi.graph.create({
            "name": api,
            "width": 900,
            "height": 200,
            "gitems": [{
                "itemid": i_retMsg_FAIL,
                "color": "CC0000",
                "drawtype": 1,
                "yaxisside": 0
            }, {
                "itemid": i_retMsg_SUCC,
                "color": "00EE00",
                "drawtype": 1,
                "yaxisside": 0
            }, {
                "itemid": i_Total_Requests,
                "color": "C800C8",
                "drawtype": 0,
                "yaxisside": 0
            }, {
                "itemid": i_responseTime,
                "color": "0000BB",
                "drawtype": 0,
                "yaxisside": 1
            }]
        })
        self.zapi.graph.create({
            "name": api_response_time,
            "width": 900,
            "height": 200,
            "gitems": [{
                "itemid": i_0_200,
                "color": "33FF33",
                "drawtype": 1,
                "yaxisside": 0
            }, {
                "itemid": i_200_500,
                "color": "008800",
                "drawtype": 1,
                "yaxisside": 0
            }, {
                "itemid": i_500_1000,
                "color": "CCCC00",
                "drawtype": 1,
                "yaxisside": 0
            }, {
                "itemid": i_1000_2000,
                "color": "FF3333",
                "drawtype": 1,
                "yaxisside": 0
            }, {
                "itemid": i_2000_999999,
                "color": "880000",
                "drawtype": 1,
                "yaxisside": 0
            }, {
                "itemid": i_Total_Requests,
                "color": "CC00CC",
                "drawtype": 0,
                "yaxisside": 0
            }, {
                "itemid": i_responseTime,
                "color": "0000BB",
                "drawtype": 0,
                "yaxisside": 1
            }]
        })
        self.zapi.graph.create({
            "name": api_response_time_pie,
            "width": 900,
            "height": 300,
            "graphtype": 2,
            "gitems": [{
                "itemid": i_0_200,
                "color": "33FF33"
            }, {
                "itemid": i_200_500,
                "color": "008800"
            }, {
                "itemid": i_500_1000,
                "color": "CCCC00"
            }, {
                "itemid": i_1000_2000,
                "color": "FF3333"
            }, {
                "itemid": i_2000_999999,
                "color": "880000"
            }]
        })

        return 'ok'
