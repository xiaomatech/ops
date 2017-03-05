#!/usr/bin/env python
# -*- coding:utf8 -*-
from ldap3 import Server, Connection, ServerPool, ALL, SASL, AUTO_BIND_NO_TLS, AUTH_SIMPLE
from configs import ldap_config


class Ldap:
    def help(self, req, resp):
        h = '''
                            ldap operation
                    ops ldap search --base fea --filter fea
                    ops ldap rebind --user user --password password
                    ops ldap modify --dn dn --changes changes
                    ops ldap modify_dn --dn dn --relative_dn relative_dn
                    ops ldap delete --dn dn
                    ops ldap compare --dn dn --attribute attribute --value value
                    ops ldap add --dn dn --attribute attribute
        '''
        return h

    def _client(self):
        server = Server(ldap_config.get('url'), get_info=ALL)
        conn = Connection(
            server,
            user=ldap_config.get('user'),
            password=ldap_config.get('password'),
            authentication=SASL,
            sasl_mechanism='GSSAPI',
            auto_bind=AUTO_BIND_NO_TLS)
        return conn

    def search(self, req, resp):
        conn = self._client()
        search_base = req.get_params(name='base')
        search_filter = req.get_params(name='filter')
        if search_base is None:
            return '--base(search_base) need'
        if search_filter is None:
            return '--filter(search_filter) need'
        conn.search(
            search_base=search_base,
            search_filter=search_filter,
            attributes=[
                'cn', 'userPrincipalName', 'userAccountControl', 'givenName',
                'sn'
            ])
        return conn.response

    def rebind(self, req, resp):
        conn = self._client()
        user = req.get_params(name='user')
        password = req.get_params(name='password')
        if user is None:
            return '--user(user) need'
        if password is None:
            return '--password(password) need'
        conn.rebind(user=user, password=password)
        return conn.result

    def modify(self, req, resp):
        conn = self._client()
        dn = req.get_params(name='dn')
        changes = req.get_params(name='changes')
        if dn is None:
            return '--dn(dn) need'
        if changes is None:
            return '--changes(changes) need'
        conn.modify(dn=dn, changes=changes)
        return conn.result

    def modify_dn(self, req, resp):
        conn = self._client()
        relative_dn = req.get_params(name='relative_dn')
        dn = req.get_params(name='dn')
        if relative_dn is None:
            return '--relative_dn(relative_dn) need'
        if dn is None:
            return '--dn(dn) need'
        conn.modify_dn(dn=dn, relative_dn=relative_dn)
        return conn.result

    def delete(self, req, resp):
        conn = self._client()
        dn = req.get_params(name='dn')
        if dn is None:
            return '--dn(dn) need'
        conn.delete(dn=dn)
        return conn.result

    def compare(self, req, resp):
        conn = self._client()
        dn = req.get_params(name='dn')
        attribute = req.get_params(name='attribute')
        value = req.get_params(name='value')
        if dn is None:
            return '--dn(dn) need'
        if attribute is None:
            return '--attribute(attribute) need'
        if value is None:
            return '--value(value) need'
        conn.compare(dn=dn, attribute=attribute, value=value)
        return conn.result

    def add(self, req, resp):
        conn = self._client()
        dn = req.get_params(name='dn')
        attribute = req.get_params(name='attribute')
        if dn is None:
            return '--dn(dn) need'
        if attribute is None:
            return '--attribute(attribute) need'
        conn.add(dn=dn, attributes=attribute)
        return conn.result
