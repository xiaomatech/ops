#!/usr/bin/python
# -*- coding:utf8 -*-

import cgi


class MultipartMiddleware(object):
    def __init__(self, parser=None):
        self.parser = cgi.FieldStorage

    def parse(self, stream, environ, keep_blank_values=1):
        return self.parser(
            fp=stream, environ=environ, keep_blank_values=keep_blank_values)

    def process_request(self, req, resp, **kwargs):

        if 'multipart/form-data' not in (req.content_type or ''):
            return

        form = self.parse(stream=req.env['wsgi.input'], environ=req.env)
        for key in form:
            field = form[key]
            if not getattr(field, 'filename', False):
                field = form.getvalue(key, None)
            req._params[key] = field
