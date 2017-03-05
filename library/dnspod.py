#!/usr/bin/env python
# -*- coding:utf8 -*-

import requests
import simplejson as json
from configs import dnspod_config

allowedTypes = ['A', 'CNAME', 'AAAA', 'NS']


class DnspodApiError(Exception):
    pass


class Dnspod:
    def __init__(self):
        dp_response = self.__request('Auth', {
            'login_email': dnspod_config.get('login_email'),
            'login_password': dnspod_config.get('login_password')
        })
        self.__token = dp_response['user_token']

    def __request(self, action_addr, params=None):
        req_params = {'format': 'json', 'user_token': self.__token}
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json',
            'User-Agent': 'CFSubdomains/1.0.0 (self00@xavi.top)'
        }
        if params:
            req_params.update(params)
        request = requests.post(
            'https://api.dnspod.com/' + action_addr,
            data=req_params,
            headers=headers,
            timeout=10)
        results = json.loads(request.text.decode('utf-8', 'ignore'))

        if results['status']['code'] != '1':
            raise DnspodApiError(results['status']['message'])
        return results

    def get_domains_list(self):
        dp_response = self.__request('Domain.List')
        available_domains = []
        for zone in dp_response['domains']:
            available_domains.append([zone['name'], str(zone['id'])])
        return available_domains

    def add_record(self, domain_uid, record_type, name, content):
        if record_type not in allowedTypes:
            raise DnspodApiError('Type: ' + record_type + ' is not allowed!')
        post_fields = {
            'domain_id': domain_uid,
            'sub_domain': name,
            'record_type': record_type,
            'record_line': 'default',
            'value': content
        }
        dp_response = self.__request('Record.Create', post_fields)
        return dp_response['record']['id']

    def editRecord(self, domain_uid, record_id, record_type, name, content):
        if record_type not in allowedTypes:
            raise DnspodApiError('Type: ' + record_type + ' is not allowed!')
        post_fields = {
            'domain_id': domain_uid,
            'record_id': record_id,
            'sub_domain': name,
            'record_type': record_type,
            'record_line': 'default',
            'value': content
        }
        dp_response = self.__request('Record.Modify', post_fields)
        return dp_response['record']['id']

    def deleteRecord(self, domainUid, recordId):
        self.__request('Record.Remove',
                       {'domain_id': domainUid,
                        'record_id': recordId})
        return True
