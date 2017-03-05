#!/usr/bin/env python
# -*- coding:utf8 -*-

import simplejson as json
import random

from redis import Connection
from redis import BlockingConnectionPool
from redis._compat import LifoQueue, Full
from redis.exceptions import ConnectionError

from kazoo.client import KazooClient
from kazoo.protocol.states import KeeperState
from helpers.logger import log_debug, log_warning

_CODIS_PROXY_STATE_ONLINE = 'online'
_ZK_MAX_RETRY_INTERVAL = 10
_ZK_MAX_RETRY_TIMES = -1


class CodisConnectionPool(BlockingConnectionPool):
    """
    Codis Proxy Connection Pool::
        >>> from redis import StrictRedis
        >>> connection_pool = CodisConnectionPool.create().zk_client("127.0.0.1:2181").zk_proxy_dir("/zk/codis/db_test/proxy").build()
        >>> r = StrictRedis(connection_pool=connection_pool)
        >>> r.set('foo', 'bar')
        >>> r.get('foo')
    It performs the same funxtion as the default
    ``:py:class: ~redis.connection.BlockingConnectionPool`` implementation.
    The difference is that, this connection pool implement
    auto-balance and auto-discovery for connection to Codis Proxy.
    """

    def __init__(self,
                 zk_client,
                 zk_proxy_dir,
                 auto_close_zk_client=True,
                 max_connections=100,
                 timeout=20,
                 connection_class=Connection,
                 queue_class=LifoQueue,
                 **connection_kwargs):

        if not isinstance(max_connections, int) or max_connections < 0:
            raise ValueError('"max_connections" must be a positive integer')

        self.zk_client = zk_client
        self.zk_proxy_dir = zk_proxy_dir
        self.auto_close_zk_client = auto_close_zk_client
        self.connection_kwargs = connection_kwargs
        self.connection_class = connection_class
        self.queue_class = queue_class
        self.max_connections = max_connections
        self.timeout = timeout
        self.proxy_list = []

        if self.zk_client.client_state == KeeperState.CLOSED:
            self.zk_client.start()
        # self.zk_client.ensure_path(self.zk_proxy_dir)
        self.reset()
        self._init_proxy_watcher()

    def _init_proxy_watcher(self):
        @self.zk_client.ChildrenWatch(
            self.zk_proxy_dir, allow_session_lost=True, send_event=True)
        def proxyChanged(children, event):
            log_warning("proxy changed: %s, %s" % (children, event))
            # if event:
            self._reset_zk()

    def reset(self):
        super(CodisConnectionPool, self).reset()
        # reset codis proxy list
        self._reset_zk()

    def _reset_zk(self):
        tmp_list = []
        log_warning("reset zk proxy list...")
        for child in self.zk_client.get_children(self.zk_proxy_dir):
            try:
                child_path = '/'.join((self.zk_proxy_dir, child))
                data, stat = self.zk_client.get(child_path)
                proxy_info = json.loads(data)
                state, addr = proxy_info["state"], proxy_info["addr"]
                # if state != _CODIS_PROXY_STATE_ONLINE:
                # continue
                # a smart way here we should listen the new proxy state
                # util be changed to online
                #     pass
                addr = addr.split(':')
                tmp_list.append((addr[0], int(addr[1])))
            except Exception, e:
                raise ConnectionError("Error while parse zk proxy(%s): %s" %
                                      (child, e.args))
        self.proxy_list = tmp_list
        log_warning("got zk proxy list:%s" % self.proxy_list)

    def make_connection(self):
        "Make a fresh random connection from proxy list."
        host, port = random.choice(self.proxy_list)
        self.connection_kwargs.update({'host': host, 'port': port})
        connection = self.connection_class(**self.connection_kwargs)
        log_debug("choose HostAndPort %s:%s from zk proxy path" % (host, port))
        self._connections.append(connection)
        return connection

    def get_connection(self, command_name, *keys, **options):
        return super(CodisConnectionPool, self).get_connection(
            command_name, *keys, **options)

    def release(self, connection):
        "Release the connection back to the pool, meanwhile check validation"
        discard = False
        if (connection.host, connection.port) not in self.proxy_list:
            discard = True

        # Make sure we haven't changed process.
        self._checkpid()
        if connection.pid != self.pid:
            return

        # Put the connection back into the pool.
        try:
            if not discard:
                self.pool.put_nowait(connection)
                log_debug("put connection %s:%s back to pool" %
                          (connection.host, connection.port))
            else:
                connection.disconnect()
                self._connections.remove(connection)
                self.pool.put_nowait(None)
                log_warning("discard connection %s:%s" %
                            (connection.host, connection.port))
        except Full:
            # perhaps the pool has been reset() after a fork? regardless,
            # we don't want this connection
            pass

    def disconnect(self):
        super(CodisConnectionPool, self).disconnect()
        if self.auto_close_zk_client:
            #self.zk_client.stop()
            pass

    @staticmethod
    def create():
        return CodisConnectionPool.Builder()

    class Builder:
        """
        Builder class used to build CodisConnectionPool step by step
        """

        def __init__(self):
            pass

        def zk_client(self,
                      zk_hosts,
                      max_delay=_ZK_MAX_RETRY_INTERVAL,
                      max_tries=_ZK_MAX_RETRY_TIMES):
            self.zk_hosts = zk_hosts
            self.zk_max_delay = max_delay
            self.zk_max_tries = max_tries
            return self

        def zk_proxy_dir(self, zk_proxy_dir):
            self.zk_proxy_dir = zk_proxy_dir
            return self

        def build(self, **connection_kwargs):
            assert self.zk_hosts
            assert self.zk_proxy_dir

            retry = {
                "max_delay": self.zk_max_delay,
                "max_tries": self.zk_max_tries
            }
            zk_client = KazooClient(
                hosts=self.zk_hosts, connection_retry=retry)
            zk_client.start()
            zk_client.ensure_path(self.zk_proxy_dir)
            return CodisConnectionPool(zk_client, self.zk_proxy_dir, True,
                                       **connection_kwargs)
