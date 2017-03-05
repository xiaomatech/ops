#!/usr/bin/env python
# -*- coding:utf8 -*-

import re
import falcon
from configs import advance_path
from models.operator_log import *
from datetime import datetime
import simplejson as json


#记录访问日志
def do_log_history(req, resp):
    for item in advance_path:
        path = item.keys()[0]
        if not re.search(path, req.path):
            continue
        else:
            user_group = req.get_header('LOGIN-USER')
            groups = item.values()[0]
            if user_group not in groups:
                raise falcon.HTTPForbidden(
                    title='You not allow access it',
                    description='Please connect the manager')

    request_id = req.get_header(name='REQUEST-ID')
    if request_id is None:
        return
    request_id = request_id[-20:]
    paths = filter(lambda x: x != '', req.path.split('/'))
    if len(paths) >= 2:
        ctrl_name = paths[0]
        func_name = paths[1]
    elif len(paths) == 1:
        func_name = paths[0]
    create_timestamp = datetime.now()
    OperatorLog.insert(
        request=request_id,
        controller=ctrl_name,
        exec_path=req.get_header(name='EXEC-PATH'),
        func=func_name,
        login_gid=req.get_header(name='LOGIN-GID'),
        login_uid=req.get_header(name='LOGIN-UID'),
        login_user=req.get_header(name='LOGIN-USER'),
        post_data=json.dumps(req._params),
        server_ip=req.get_header(name='SERVER-IP'),
        create_timestamp=create_timestamp).execute()


#记录结果
def do_log_result(req, resp):
    request_id = req.get_header(name='REQUEST-ID')
    if request_id is None:
        return
    request_id = request_id[-20:]
    respone_timestamp = datetime.now()
    OperatorLog.update(
        result=json.dumps(resp.body),
        respone_timestamp=respone_timestamp).where(
            OperatorLog.request == request_id).execute()
