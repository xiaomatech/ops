#!/usr/bin/env python
# -*- coding:utf8 -*-
import os
from urllib import unquote


class file:
    def upload(self, req, resp):
        image = req.get_param('file')
        raw = image.file.read()
        filename = 'uploads/' + unquote(image.filename)
        if not os.path.exists(filename):
            open(filename, 'wb').write(raw)
            return 'success'
        else:
            return 'file exists'

    def download(self, req, resp):
        filename = 'uploads' + os.path.sep + unquote(req.params.get('file'))
        if os.path.exists(filename):
            return open(filename, 'rb').read()
        else:
            return ''

    def listfile(self, req, resp):
        result = []
        for i in os.listdir('uploads'):
            if os.path.isdir('uploads/' + i):
                for j in os.listdir('uploads/' + i):
                    result.append(i + '/' + j)
            else:
                result.append(i)

        return "\n".join(result)

    def help(self, req, resp):
        h = '''
            ops file download 下载文件
            ops file upload   下载文件
            ops file listfile  查看文件列表
        '''
        return h
