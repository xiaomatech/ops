#!/usr/bin/env python
# -*- coding:utf8 -*-

import falcon
from hooks import *
from loader import Loader
from middleware import MultipartMiddleware
import simplejson as json
from helpers.logger import log_error

loader = Loader(application_path='./')


def sink(req, resp):
    do_log_history(req, resp)

    paths = filter(lambda x: x != '', req.path.split('/'))
    ctrl_name = func_name = 'index'
    if len(paths) >= 2:
        ctrl_name = paths[0]
        func_name = paths[1]
    elif len(paths) == 1:
        func_name = paths[0]
    ctrl = loader.ctrl(ctrl_name)

    if ctrl == None or not hasattr(ctrl, func_name):
        resp.status = falcon.HTTP_404
        resp.body = "Not Found"
    else:
        try:
            content = getattr(ctrl, func_name)(req, resp)
            if resp.body == None:
                if isinstance(content, unicode):
                    resp.body = unicode.encode(content, 'utf-8', 'ignore')
                elif isinstance(content, str):
                    resp.body = content
                else:
                    resp.body = json.dumps(content)
        except Exception as ex:
            log_error(ex)
            resp.status = falcon.HTTP_500
            resp.body = str(ex)
            #resp.body = 'A server error occurred. Please contact the administrator'
    do_log_result(req, resp)


app = falcon.API(middleware=[MultipartMiddleware()])

app.add_sink(sink, r'/*')

if __name__ == '__main__':
    from wsgiref import simple_server
    httpd = simple_server.make_server('0.0.0.0', 8000, app)
    httpd.serve_forever()
