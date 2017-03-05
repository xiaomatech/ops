#!/usr/bin/env python
# -*- coding:utf8 -*-
import os
import imp


class help:
    def list(self, req, resp):
        self.controllers_dir = './controllers/'
        self.help = []
        self.help.append('ops listfile 查看可下载的文件\n')
        self.help.append('ops upload test.txt 上传文件\n')
        self.help.append('ops download test.txt 下载文件\n')
        self.help.append('ops shell test.sh 下载并执行\n')
        self.help.append('ops rpmupload -f ./test/nginx.rpm 上传rpm到私有仓库\n')
        self.help.append('ops daemon -s restart 启动守护进程以便能实时watch命令执行\n')
        for module in os.listdir(self.controllers_dir):
            if module.startswith('__') or module.endswith('.pyc') or module.startswith('help') \
                    or module.startswith('file') or module.startswith('complete') :
                continue
            module = module.replace('.pyc', '').replace('.py', '')
            self.help.append('ops ' + module + '\n')
        return "\n\t  查看各模块帮助  \n\t\n\t" + "\n\t".join(self.help) + '\n\n'
