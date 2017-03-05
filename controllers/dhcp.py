#!/usr/bin/env python
# -*- coding:utf8 -*-


class dhcp:
    def help(self, req, resp):
        h = '''
                    DNSmasq的DNS解析、以及DHCP地址分配系统

            内网dhcp

            ops dhcp


            内网dns 支持多机房 (私网通信尽量跟公网用不同域名 比如公网meizu.com 私网可用meizu.internal)

            ops dhcp list_domains 获取私网域名列表
            ops dhcp add_record -d test.domain.internal --rt A -c 10.3.134.111 -h 10.4.1.3 添加私网dns
            ops dhcp edit_record -d test.domain.internal --rt A -c 10.3.134.111 -h 10.4.1.3 添加私网dns
            ops dhcp del_record -d test.domain.internal --rt A -c 10.3.134.111 -h 10.4.1.3 添加私网dns

        '''
        return h
