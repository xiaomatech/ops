#!/usr/bin/env python
# -*- coding:utf8 -*-

autoloader_dir = ['controllers']  #['library','helpers','models','controllers']

common_db_config = {
    'host': '127.0.0.1',
    'port': 3306,
    'user': 'root',
    'password': '',
    #'max_connections': 100,
    #'charset':'utf8mb4',
    #'threadlocals':True
}

zabbix_db_config = {
    'host': '172.16.119.180',
    'port': 3306,
    'user': 'root',
    'password': '',
    #'max_connections': 100,
    #'charset':'utf8mb4',
    #'threadlocals':True
}

redis_conf = {
    'host': '127.0.0.1',
    'port': 6379,
    'db': 0,
    'max_connections': 600,
}

log_common = {
    'mode': 'a+',
    'maxBytes': 1073741824,  #1G
    'backupCount': 5
}

log_error_config = {'log_file': './logs/error.log'}

log_debug_config = {'log_file': './logs/debug.log'}

log_loader = {'log_file': './logs/loader.log'}

zabbix_config = {
    'server': 'http://172.16.119.180',
    'user': 'admin',
    'password': 'zabbix',
}

ssh_config = {
    'private_key_file': '',
    'port': 22,
    'user': 'ops',
    'password': 'feafoanohfd',
    'timeout': 15
}

cobbler_config = {
    'gz-ns': {  #gz-ns idc cobbler-web config
        'username': '',
        'password': '',
        'ip': '',
    },
    'wx-gj': {  #wx-gj idc cobbler-web config
        'username': '',
        'password': '',
        'ip': '',
    },
    'hk-mjq': {  #bj-mjq idc cobbler-web config
        'username': '',
        'password': '',
        'ip': '',
    }
}

cmdb_config = {
    'key_can_use_list': [
        'cop', 'owt', 'loc', 'idc', 'pdl', 'sbs', 'srv', 'mod', 'grp', 'ptn',
        'cln', 'fls', 'status', 'virt'
    ]
}
deploy_config = {
    'deploy_to_dir': '/data/www',
    'version_dir': 'releases',
    'current_dir': 'current',
    'rsync_extra_params': '',
    'git_branch': 'master',
    'get_url_base': 'http://repository.example.com/repository/releases',
}

kvm_config = {
    'user': 'ops',
    'password': '325f6be6bf7e3e68d5b803068129673b',
    'root_images_template':
    '/var/lib/libvirt/images/centos6.qcow2',  #'/var/lib/libvirt/images/centos7.qcow2'
    'kvm_data_rootdir': '/data/kvm',
    'cache_mode': 'writeback',
    'bridge': 'br0',
    'volume_group': 'storage_pool',
    'disksize': 100,
    'host_model': False,
    'virtio': True,
    'netdev': 'eth0',
    'bond_mode': 'balance-rr',
    'migrate_undefine': True,
    'migrate_unsafe': False,
    'migrate_live': True,
}

docker_config = {
    'tlscert': '../uploads/docker-client-cert.pem',
    'tlskey': '../uploads/docker-client-key.pem',
    'tlscacert': '../uploads/docker-ca.pem',
    'base_image': 'alpine'
}
etcd_config_cmd = {'server': '10.3.120.98', 'prefix': '/ops'}
etcd_config = {
    'gz': {
        'endpoint': '',
        'username': '',
        'password': ''
    },
    'wx': {
        'endpoint': '',
        'username': '',
        'password': ''
    }
}

jenkins_config = {'url': '', 'user': '', 'password': ''}

idrac_config = {'username': '', 'password': ''}

ovs_config = {'port': 6632, }

advance_path = [
    # path => user list
    {
        r'/dns/*': ['admin', 'manager', 'ops']
    },
    {
        r'/idrac/*': ['admin', 'manager', 'ops']
    },
    {
        r'/kvm/add_flavor': ['admin', 'manager', 'ops']
    }
]

aliyun_config = {
    'access_key_id': '',
    'secret_access_key': '',
}

aws_config = {}

qcloud_config = {'secret_id': '', 'secret_key': '', 'region': 'gz'}
upyun_config = {'bucket': '', 'username': '', 'password': '', 'secret': ''}

chinacache_config = {'username': '', 'password': ''}
dnspod_config = {
    'login_email': '',
    'login_password': '',
}

cloudflare_config = {'token': '', 'email': ''}

ldap_config = {'url': '', 'user': '', 'password': ''}

netconf_config = {
    'nexus': {
        'user': 'test',
        'password': '',
        'port': 830
    },
    'h3c': {
        'user': 'test',
        'password': '',
        'port': 830
    }
}
elasticsearch_config = {'hosts': ''}

router_config = {
    'device_type':
    'hp_comware',  #hp_comware : h3c , cisco_ios : cisco #具体参考https://github.com/ktbyers/netmiko
    'port': 22,
    'username': 'router',
    'password': '',
}

switch_config = {
    'device_type':
    'hp_comware',  #hp_comware : h3c , cisco_ios : cisco #具体参考https://github.com/ktbyers/netmiko
    'port': 22,
    'username': 'switch',
    'password': '',
}
