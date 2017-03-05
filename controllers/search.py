#!/usr/bin/env python
# -*- coding:utf8 -*-
from configs import elasticsearch_config
from elasticsearch import Elasticsearch
from datetime import datetime


class Search:
    def help(self, req, resp):
        h = '''
        '''
        return h

    def _client(self):
        return
