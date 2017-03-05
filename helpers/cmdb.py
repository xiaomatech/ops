#!/usr/bin/env python
# -*- coding:utf8 -*-
from configs import cmdb_config
from models.cmdb import *


def server_tag_ip(tag):
    if tag is None:
        return None
    taglist = tag.split('_')
    result = []
    if len(taglist) < 1:
        return result
    sql = '''select * from ip left join server_tag on server_tag.assets_id = ip.assets_id
                             where '''
    sql_list = []
    for item in taglist:
        tmp = item.split('.')
        key, value = tmp[0], tmp[1]
        key_can_use_list = cmdb_config.get('key_can_use_list')
        if key not in key_can_use_list:
            continue
        sql_list.append(''' server_tag.assets_id in (
                                select server_tag.assets_id from server_tag
                                where server_tag.server_tag_value ='%s' and server_tag.server_tag_key = '%s'
                ) ''' % (value, key))
    if len(sql_list) < 1:
        return result
    res = Ip.raw(sql + ' and '.join(sql_list))

    for server in res:
        if server.ip not in result:
            result.append(server.ip)
    return result


def server_tag_group(tag):
    if tag is None:
        return None
    taglist = tag.split('_')
    result = []
    if len(taglist) < 1:
        return result
