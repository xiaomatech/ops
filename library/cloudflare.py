#!/usr/bin/env python
# -*- coding:utf8 -*-

import requests
import simplejson as json
from configs import cloudflare_config
allowedTypes = ['A', 'CNAME', 'AAAA', 'NS']


class CloudFlareApiError(Exception):
    pass


class CloudFlare:
    def __init__(self):
        self.__token = cloudflare_config.get('token')
        self.__email = cloudflare_config.get('email')

    def __request(self, action, params=None):
        req_params = {'tkn': self.__token, 'email': self.__email, 'a': action}
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json',
            'User-Agent':
            'Mozilla/5.0 (compatible; CFSubdomains/1.0; https://github.com/slurin/CFSubdomains)'
        }
        if params:
            req_params.update(params)
        request = requests.post(
            'https://www.cloudflare.com/api_json.html',
            data=req_params,
            headers=headers,
            timeout=10)
        results = json.loads(request.text.decode('utf-8'))
        if results['result'] != 'success':
            raise CloudFlareApiError(results['msg'])
        return results

    def get_domains_list(self):
        cf_response = self.__request('zone_load_multi')
        available_domains = []
        for zone in cf_response['response']['zones']['objs']:
            available_domains.append([zone['zone_name'], zone['zone_name']])
        return available_domains

    def add_record(self, domain, record_type, name, content):
        if record_type not in allowedTypes:
            raise CloudFlareApiError('Type ' + record_type +
                                     ' is not allowed!')
        post_fields = {
            'z': domain,
            'type': record_type,
            'name': name,
            'content': content,
            'ttl': 1
        }
        cfResponse = self.__request('rec_new', post_fields)
        return cfResponse['response']['rec']['obj']['rec_id']

    def edit_record(self, domain, record_id, record_type, name, content):
        if record_type not in allowedTypes:
            raise CloudFlareApiError('Type ' + record_type +
                                     ' is not allowed!')
        post_fields = {
            'id': record_id,
            'z': domain,
            'type': record_type,
            'name': name,
            'content': content,
            'ttl': 1
        }
        cf_response = self.__request('rec_edit', post_fields)
        return cf_response['response']['rec']['obj']['rec_id']

    def delete_record(self, domain, record_id):
        self.__request('rec_delete', {'z': domain, 'id': record_id})
        return True
