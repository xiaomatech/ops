#!/usr/bin/env python
# -*- coding:utf8 -*-

CONN_SOCKET = 4
CONN_TLS = 3
CONN_SSH = 2
CONN_TCP = 1
TLS_PORT = 16514
SSH_PORT = 22
TCP_PORT = 16509
# list of console types
QEMU_CONSOLE_TYPES = ['vnc', 'spice']

# default console type
QEMU_CONSOLE_DEFAULT_TYPE = 'vnc'

import threading
import string

import libvirt
from libvirt import libvirtError
import socket
import random
import libxml2
import inspect
import os.path

try:
    from libvirt import libvirtError, VIR_DOMAIN_XML_SECURE, VIR_MIGRATE_LIVE, \
        VIR_MIGRATE_UNSAFE, VIR_DOMAIN_UNDEFINE_SNAPSHOTS_METADATA
except:
    from libvirt import libvirtError, VIR_DOMAIN_XML_SECURE, VIR_MIGRATE_LIVE

from libvirt import VIR_INTERFACE_XML_INACTIVE

from xml.etree import ElementTree
from datetime import datetime
from IPy import IP
import base64
from configs import kvm_config
from helpers.logger import log_error
from threading import Condition, Lock, currentThread
import time


class util():
    @staticmethod
    def get_rbd_storage_data(stg):
        xml = stg.XMLDesc(0)
        ceph_user = util.get_xml_path(xml, "/pool/source/auth/@username")

        def get_ceph_hosts(ctx):
            hosts = []
            for host in ctx.xpathEval("/pool/source/host"):
                name = host.prop("name")
                if name:
                    hosts.append({'name': name, 'port': host.prop("port")})
            return hosts

        ceph_hosts = util.get_xml_path(xml, func=get_ceph_hosts)
        secret_uuid = util.get_xml_path(xml, "/pool/source/auth/secret/@uuid")
        return ceph_user, secret_uuid, ceph_hosts

    @staticmethod
    def is_kvm_available(xml):
        kvm_domains = util.get_xml_path(xml, "//domain/@type='kvm'")
        if kvm_domains > 0:
            return True
        else:
            return False

    @staticmethod
    def randomMAC():
        """Generate a random MAC address."""
        # qemu MAC
        oui = [0x52, 0x54, 0x00]

        mac = oui + [
            random.randint(0x00, 0xff), random.randint(0x00, 0xff),
            random.randint(0x00, 0xff)
        ]
        return ':'.join(map(lambda x: "%02x" % x, mac))

    @staticmethod
    def randomUUID():
        """Generate a random UUID."""

        u = [random.randint(0, 255) for dummy in range(0, 16)]
        return "-".join(
            ["%02x" * 4, "%02x" * 2, "%02x" * 2, "%02x" * 2,
             "%02x" * 6]) % tuple(u)

    @staticmethod
    def get_max_vcpus(conn, type=None):
        """@param conn: libvirt connection to poll for max possible vcpus
           @type type: optional guest type (kvm, etc.)"""
        if type is None:
            type = conn.getType()
        try:
            m = conn.getMaxVcpus(type.lower())
        except libvirt.libvirtError as e:
            log_error(str(e))
            m = 32
        return m

    @staticmethod
    def xml_escape(str):
        """Replaces chars ' " < > & with xml safe counterparts"""
        if str is None:
            return None

        str = str.replace("&", "&amp;")
        str = str.replace("'", "&apos;")
        str = str.replace("\"", "&quot;")
        str = str.replace("<", "&lt;")
        str = str.replace(">", "&gt;")
        return str

    @staticmethod
    def compareMAC(p, q):
        """Compare two MAC addresses"""
        pa = p.split(":")
        qa = q.split(":")

        if len(pa) != len(qa):
            if p > q:
                return 1
            else:
                return -1

        for i in xrange(len(pa)):
            n = int(pa[i], 0x10) - int(qa[i], 0x10)
            if n > 0:
                return 1
            elif n < 0:
                return -1
        return 0

    @staticmethod
    def get_xml_path(xml, path=None, func=None):
        """
        Return the content from the passed xml xpath, or return the result
        of a passed function (receives xpathContext as its only arg)
        """
        doc = None
        ctx = None
        result = None

        try:
            doc = libxml2.parseDoc(xml)
            ctx = doc.xpathNewContext()

            if path:
                ret = ctx.xpathEval(path)
                if ret is not None:
                    if type(ret) == list:
                        if len(ret) >= 1:
                            result = ret[0].content
                    else:
                        result = ret

            elif func:
                result = func(ctx)

            else:
                raise ValueError("'path' or 'func' is required.")
        finally:
            if doc:
                doc.freeDoc()
            if ctx:
                ctx.xpathFreeContext()
        return result

    @staticmethod
    def pretty_mem(val):
        val = int(val)
        if val > (10 * 1024 * 1024):
            return "%2.2f GB" % (val / (1024.0 * 1024.0))
        else:
            return "%2.0f MB" % (val / 1024.0)

    @staticmethod
    def pretty_bytes(val):
        val = int(val)
        if val > (1024 * 1024 * 1024):
            return "%2.2f GB" % (val / (1024.0 * 1024.0 * 1024.0))
        else:
            return "%2.2f MB" % (val / (1024.0 * 1024.0))

    @staticmethod
    def cpu_version(ctx):
        for info in ctx.xpathEval('/sysinfo/processor/entry'):
            elem = info.xpathEval('@name')[0].content
            if elem == 'version':
                return info.content
        return 'Unknown'

    @staticmethod
    def network_size(net, dhcp=None):
        """
        Func return gateway, mask and dhcp pool.
        """
        mask = IP(net).strNetmask()
        addr = IP(net)
        gateway = addr[1].strNormal()
        dhcp_pool = [addr[2].strNormal(), addr[addr.len() - 2].strNormal()]
        if dhcp:
            return gateway, mask, dhcp_pool
        else:
            return gateway, mask, None


# Read write lock
# ---------------


class ReadWriteLock(object):
    """Read-Write lock class. A read-write lock differs from a standard
    threading.RLock() by allowing multiple threads to simultaneously hold a
    read lock, while allowing only a single thread to hold a write lock at the
    same point of time.
    When a read lock is requested while a write lock is held, the reader
    is blocked; when a write lock is requested while another write lock is
    held or there are read locks, the writer is blocked.
    Writers are always preferred by this implementation: if there are blocked
    threads waiting for a write lock, current readers may request more read
    locks (which they eventually should free, as they starve the waiting
    writers otherwise), but a new thread requesting a read lock will not
    be granted one, and block. This might mean starvation for readers if
    two writer threads interweave their calls to acquireWrite() without
    leaving a window only for readers.
    In case a current reader requests a write lock, this can and will be
    satisfied without giving up the read locks first, but, only one thread
    may perform this kind of lock upgrade, as a deadlock would otherwise
    occur. After the write lock has been granted, the thread will hold a
    full write lock, and not be downgraded after the upgrading call to
    acquireWrite() has been match by a corresponding release().
    """

    def __init__(self):
        """Initialize this read-write lock."""

        # Condition variable, used to signal waiters of a change in object
        # state.
        self.__condition = Condition(Lock())

        # Initialize with no writers.
        self.__writer = None
        self.__upgradewritercount = 0
        self.__pendingwriters = []

        # Initialize with no readers.
        self.__readers = {}

    def acquireRead(self, timeout=None):
        """Acquire a read lock for the current thread, waiting at most
        timeout seconds or doing a non-blocking check in case timeout is <= 0.
        In case timeout is None, the call to acquireRead blocks until the
        lock request can be serviced.
        In case the timeout expires before the lock could be serviced, a
        RuntimeError is thrown."""

        if timeout is not None:
            endtime = time() + timeout
        me = currentThread()
        self.__condition.acquire()
        try:
            if self.__writer is me:
                # If we are the writer, grant a new read lock, always.
                self.__writercount += 1
                return
            while True:
                if self.__writer is None:
                    # Only test anything if there is no current writer.
                    if self.__upgradewritercount or self.__pendingwriters:
                        if me in self.__readers:
                            # Only grant a read lock if we already have one
                            # in case writers are waiting for their turn.
                            # This means that writers can't easily get starved
                            # (but see below, readers can).
                            self.__readers[me] += 1
                            return
                            # No, we aren't a reader (yet), wait for our turn.
                    else:
                        # Grant a new read lock, always, in case there are
                        # no pending writers (and no writer).
                        self.__readers[me] = self.__readers.get(me, 0) + 1
                        return
                if timeout is not None:
                    remaining = endtime - time()
                    if remaining <= 0:
                        # Timeout has expired, signal caller of this.
                        raise RuntimeError("Acquiring read lock timed out")
                    self.__condition.wait(remaining)
                else:
                    self.__condition.wait()
        finally:
            self.__condition.release()

    def acquireWrite(self, timeout=None):
        """Acquire a write lock for the current thread, waiting at most
        timeout seconds or doing a non-blocking check in case timeout is <= 0.
        In case the write lock cannot be serviced due to the deadlock
        condition mentioned above, a ValueError is raised.
        In case timeout is None, the call to acquireWrite blocks until the
        lock request can be serviced.
        In case the timeout expires before the lock could be serviced, a
        RuntimeError is thrown."""

        if timeout is not None:
            endtime = time() + timeout
        me, upgradewriter = currentThread(), False
        self.__condition.acquire()
        try:
            if self.__writer is me:
                # If we are the writer, grant a new write lock, always.
                self.__writercount += 1
                return
            elif me in self.__readers:
                # If we are a reader, no need to add us to pendingwriters,
                # we get the upgradewriter slot.
                if self.__upgradewritercount:
                    # If we are a reader and want to upgrade, and someone
                    # else also wants to upgrade, there is no way we can do
                    # this except if one of us releases all his read locks.
                    # Signal this to user.
                    log_error("Inevitable dead lock, denying write lock")
                    raise ValueError(
                        "Inevitable dead lock, denying write lock")
                upgradewriter = True
                self.__upgradewritercount = self.__readers.pop(me)
            else:
                # We aren't a reader, so add us to the pending writers queue
                # for synchronization with the readers.
                self.__pendingwriters.append(me)
            while True:
                if not self.__readers and self.__writer is None:
                    # Only test anything if there are no readers and writers.
                    if self.__upgradewritercount:
                        if upgradewriter:
                            # There is a writer to upgrade, and it's us. Take
                            # the write lock.
                            self.__writer = me
                            self.__writercount = self.__upgradewritercount + 1
                            self.__upgradewritercount = 0
                            return
                            # There is a writer to upgrade, but it's not us.
                            # Always leave the upgrade writer the advance slot,
                            # because he presumes he'll get a write lock directly
                            # from a previously held read lock.
                    elif self.__pendingwriters[0] is me:
                        # If there are no readers and writers, it's always
                        # fine for us to take the writer slot, removing us
                        # from the pending writers queue.
                        # This might mean starvation for readers, though.
                        self.__writer = me
                        self.__writercount = 1
                        self.__pendingwriters = self.__pendingwriters[1:]
                        return
                if timeout is not None:
                    remaining = endtime - time()
                    if remaining <= 0:
                        # Timeout has expired, signal caller of this.
                        if upgradewriter:
                            # Put us back on the reader queue. No need to
                            # signal anyone of this change, because no other
                            # writer could've taken our spot before we got
                            # here (because of remaining readers), as the test
                            # for proper conditions is at the start of the
                            # loop, not at the end.
                            self.__readers[me] = self.__upgradewritercount
                            self.__upgradewritercount = 0
                        else:
                            # We were a simple pending writer, just remove us
                            # from the FIFO list.
                            self.__pendingwriters.remove(me)
                        raise RuntimeError("Acquiring write lock timed out")
                    self.__condition.wait(remaining)
                else:
                    self.__condition.wait()
        finally:
            self.__condition.release()

    def release(self):
        """Release the currently held lock.
        In case the current thread holds no lock, a ValueError is thrown."""

        me = currentThread()
        self.__condition.acquire()
        try:
            if self.__writer is me:
                # We are the writer, take one nesting depth away.
                self.__writercount -= 1
                if not self.__writercount:
                    # No more write locks; take our writer position away and
                    # notify waiters of the new circumstances.
                    self.__writer = None
                    self.__condition.notifyAll()
            elif me in self.__readers:
                # We are a reader currently, take one nesting depth away.
                self.__readers[me] -= 1
                if not self.__readers[me]:
                    # No more read locks, take our reader position away.
                    del self.__readers[me]
                    if not self.__readers:
                        # No more readers, notify waiters of the new
                        # circumstances.
                        self.__condition.notifyAll()
            else:
                raise ValueError("Trying to release unheld lock")
        finally:
            self.__condition.release()


class wvmConnection(object):
    """
    class representing a single connection stored in the Connection Manager
    # to-do: may also need some locking to ensure to not connect simultaniously in 2 threads
    """

    def __init__(self, host, conn):
        """
        Sets all class attributes and tries to open the connection
        """
        # connection lock is used to lock all changes to the connection state attributes
        # (connection and last_error)
        self.connection_state_lock = threading.Lock()
        self.connection = None
        self.last_error = None

        # credentials
        self.host = host
        self.login = kvm_config.get('user')
        self.passwd = kvm_config.get('password')
        self.type = conn

        # connect
        self.connect()

    def connect(self):
        self.connection_state_lock.acquire()
        try:
            # recheck if we have a connection (it may have been
            if not self.connected:
                if self.type == CONN_TCP:
                    self.__connect_tcp()
                elif self.type == CONN_SSH:
                    self.__connect_ssh()
                elif self.type == CONN_TLS:
                    self.__connect_tls()
                elif self.type == CONN_SOCKET:
                    self.__connect_socket()
                else:
                    raise ValueError('"{type}" is not a valid connection type'.
                                     format(type=self.type))

                if self.connected:
                    # do some preprocessing of the connection:
                    #     * set keep alive interval
                    #     * set connection close/fail handler
                    try:
                        self.connection.setKeepAlive(5, 5)
                        try:
                            self.connection.registerCloseCallback(
                                self.__connection_close_callback, None)
                        except Exception as e:
                            # Temporary fix for libvirt > libvirt-0.10.2-41
                            log_error(str(e))
                    except libvirtError as e:
                        # hypervisor driver does not seem to support persistent connections
                        self.last_error = str(e)
                        log_error(str(e))
        finally:
            self.connection_state_lock.release()

    @property
    def connected(self):
        try:
            return self.connection is not None and self.connection.isAlive()
        except libvirtError as e:
            log_error(str(e))
            # isAlive failed for some reason
            return False

    def __libvirt_auth_credentials_callback(self, credentials, user_data):
        for credential in credentials:
            if credential[0] == libvirt.VIR_CRED_AUTHNAME:
                credential[4] = self.login
                if len(credential[4]) == 0:
                    credential[4] = credential[3]
            elif credential[0] == libvirt.VIR_CRED_PASSPHRASE:
                credential[4] = self.passwd
            else:
                return -1
        return 0

    def __connection_close_callback(self, connection, reason, opaque=None):
        self.connection_state_lock.acquire()
        try:
            # on server shutdown libvirt module gets freed before the close callbacks are called
            # so we just check here if it is still present
            if libvirt is not None:
                if (reason == libvirt.VIR_CONNECT_CLOSE_REASON_ERROR):
                    self.last_error = 'connection closed: Misc I/O error'
                elif (reason == libvirt.VIR_CONNECT_CLOSE_REASON_EOF):
                    self.last_error = 'connection closed: End-of-file from server'
                elif (reason == libvirt.VIR_CONNECT_CLOSE_REASON_KEEPALIVE):
                    self.last_error = 'connection closed: Keepalive timer triggered'
                elif (reason == libvirt.VIR_CONNECT_CLOSE_REASON_CLIENT):
                    self.last_error = 'connection closed: Client requested it'
                else:
                    self.last_error = 'connection closed: Unknown error'

            # prevent other threads from using the connection (in the future)
            self.connection = None
        finally:
            self.connection_state_lock.release()

    def __connect_tcp(self):
        flags = [libvirt.VIR_CRED_AUTHNAME, libvirt.VIR_CRED_PASSPHRASE]
        auth = [flags, self.__libvirt_auth_credentials_callback, None]
        uri = 'qemu+tcp://%s/system' % self.host

        try:
            self.connection = libvirt.openAuth(uri, auth, 0)
            self.last_error = None

        except libvirtError as e:
            self.last_error = 'Connection Failed: ' + str(e)
            log_error(self.last_error)
            self.connection = None

    def __connect_ssh(self):
        uri = 'qemu+ssh://%s@%s/system' % (self.login, self.host)

        try:
            self.connection = libvirt.open(uri)
            self.last_error = None

        except libvirtError as e:
            self.last_error = 'Connection Failed: ' + str(e) + ' --- ' + repr(
                libvirt.virGetLastError())
            log_error(self.last_error)
            self.connection = None

    def __connect_tls(self):
        flags = [libvirt.VIR_CRED_AUTHNAME, libvirt.VIR_CRED_PASSPHRASE]
        auth = [flags, self.__libvirt_auth_credentials_callback, None]
        uri = 'qemu+tls://%s@%s/system' % (self.login, self.host)

        try:
            self.connection = libvirt.openAuth(uri, auth, 0)
            self.last_error = None

        except libvirtError as e:
            self.last_error = 'Connection Failed: ' + str(e)
            log_error(self.last_error)
            self.connection = None

    def __connect_socket(self):
        uri = 'qemu:///system'

        try:
            self.connection = libvirt.open(uri)
            self.last_error = None

        except libvirtError as e:
            self.last_error = 'Connection Failed: ' + str(e)
            log_error(self.last_error)
            self.connection = None

    def close(self):
        """
        closes the connection (if it is active)
        """
        self.connection_state_lock.acquire()
        try:
            if self.connected:
                try:
                    # to-do: handle errors?
                    self.connection.close()
                except libvirtError as e:
                    log_error(str(e))

            self.connection = None
            self.last_error = None
        finally:
            self.connection_state_lock.release()

    def __del__(self):
        if self.connection is not None:
            # unregister callback (as it is no longer valid if this instance gets deleted)
            try:
                self.connection.unregisterCloseCallback()
            except libvirtError as e:
                log_error(str(e))

    def __unicode__(self):
        if self.type == CONN_TCP:
            type_str = u'tcp'
        elif self.type == CONN_SSH:
            type_str = u'ssh'
        elif self.type == CONN_TLS:
            type_str = u'tls'
        else:
            type_str = u'invalid_type'

        return u'qemu+{type}://{user}@{host}/system'.format(
            type=type_str, user=self.login, host=self.host)

    def __repr__(self):
        return '<wvmConnection {connection_str}>'.format(
            connection_str=unicode(self))

    ignore_codes = set([
        libvirt.VIR_ERR_NO_DOMAIN,  # Domain not found
        libvirt.VIR_ERR_NO_NETWORK,  # Network not found
    ])

    def __exit__(self, exc_type, exc_value, traceback):
        if (self.connection and exc_type and inspect.isclass(exc_type) and
                issubclass(exc_type, libvirt.libvirtError) and
                exc_value.get_error_level() == libvirt.VIR_ERR_ERROR and
                exc_value.get_error_code() not in self.ignore_codes):
            try:
                self.close()
            except libvirtError as e:
                log_error(str(e))

            self.connection = None


class wvmConnect(object):
    def __init__(self, host, conn):
        self.host = host
        self.login = kvm_config.get('user')
        self.passwd = kvm_config.get('password')
        self.conn = conn
        self._connections = dict()
        self._connections_lock = ReadWriteLock()

        # get connection from connection manager
        self.wvm = self.get_connection(host, conn)

    def get_connection(self, host, conn):
        host = unicode(host)

        connection = self._search_connection(host, conn)

        if (connection is None):
            self._connections_lock.acquireWrite()
            try:
                # we have to search for the connection again after aquireing the write lock
                # as the thread previously holding the write lock may have already added our connection
                connection = self._search_connection(host, conn)
                if (connection is None):
                    # create a new connection if a matching connection does not already exist
                    connection = wvmConnection(host, conn)

                    # add new connection to connection dict
                    if host in self._connections:
                        self._connections[host].append(connection)
                    else:
                        self._connections[host] = [connection]
            finally:
                self._connections_lock.release()

        elif not connection.connected:
            # try to (re-)connect if connection is closed
            connection.connect()

        if connection.connected:
            # return libvirt connection object
            return connection.connection
        else:
            # raise libvirt error
            raise libvirtError(connection.last_error)

    def _search_connection(self, host, conn):
        """
        search the connection dict for a connection with the given credentials
        if it does not exist return None
        """
        self._connections_lock.acquireRead()
        try:
            if (host in self._connections):
                connections = self._connections[host]
                for connection in connections:
                    if (connection.login == kvm_config.get('user') and
                            connection.passwd == kvm_config.get('password') and
                            connection.type == conn):
                        return connection
        finally:
            self._connections_lock.release()

        return None

    def host_is_up(self, conn_type, hostname):
        """
        returns True if the given host is up and we are able to establish
        a connection using the given credentials.
        """
        try:
            socket_host = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket_host.settimeout(1)
            if conn_type == CONN_SSH:
                if ':' in hostname:
                    LIBVIRT_HOST, PORT = (hostname).split(":")
                    PORT = int(PORT)
                else:
                    PORT = SSH_PORT
                    LIBVIRT_HOST = hostname
                socket_host.connect((LIBVIRT_HOST, PORT))
            if conn_type == CONN_TCP:
                socket_host.connect((hostname, TCP_PORT))
            if conn_type == CONN_TLS:
                socket_host.connect((hostname, TLS_PORT))
            socket_host.close()
            return True
        except libvirtError as err:
            log_error(str(err))
            return err

    def get_cap_xml(self):
        """Return xml capabilities"""
        return self.wvm.getCapabilities()

    def is_kvm_supported(self):
        """Return KVM capabilities."""
        return util.is_kvm_available(self.get_cap_xml())

    def get_storages(self):
        storages = []
        for pool in self.wvm.listStoragePools():
            storages.append(pool)
        for pool in self.wvm.listDefinedStoragePools():
            storages.append(pool)
        return storages

    def get_networks(self):
        virtnet = []
        for net in self.wvm.listNetworks():
            virtnet.append(net)
        for net in self.wvm.listDefinedNetworks():
            virtnet.append(net)
        return virtnet

    def get_ifaces(self):
        interface = []
        for inface in self.wvm.listInterfaces():
            interface.append(inface)
        for inface in self.wvm.listDefinedInterfaces():
            interface.append(inface)
        return interface

    def get_iface(self, name):
        return self.wvm.interfaceLookupByName(name)

    def get_secrets(self):
        return self.wvm.listSecrets()

    def get_secret(self, uuid):
        return self.wvm.secretLookupByUUIDString(uuid)

    def get_storage(self, name):
        return self.wvm.storagePoolLookupByName(name)

    def get_volume_by_path(self, path):
        return self.wvm.storageVolLookupByPath(path)

    def get_network(self, net):
        return self.wvm.networkLookupByName(net)

    def get_instance(self, name):
        return self.wvm.lookupByName(name)

    def get_instances(self):
        instances = []
        for inst_id in self.wvm.listDomainsID():
            dom = self.wvm.lookupByID(int(inst_id))
            instances.append(dom.name())
        for name in self.wvm.listDefinedDomains():
            instances.append(name)
        return instances

    def get_snapshots(self):
        instance = []
        for snap_id in self.wvm.listDomainsID():
            dom = self.wvm.lookupByID(int(snap_id))
            if dom.snapshotNum(0) != 0:
                instance.append(dom.name())
        for name in self.wvm.listDefinedDomains():
            dom = self.wvm.lookupByName(name)
            if dom.snapshotNum(0) != 0:
                instance.append(dom.name())
        return instance

    def get_net_device(self):
        netdevice = []
        for dev in self.wvm.listAllDevices(0):
            xml = dev.XMLDesc(0)
            dev_type = util.get_xml_path(xml, '/device/capability/@type')
            if dev_type == 'net':
                netdevice.append(
                    util.get_xml_path(xml, '/device/capability/interface'))
        return netdevice

    def get_host_instances(self):
        vname = {}
        memory = self.wvm.getInfo()[1] * 1048576
        for name in self.get_instances():
            dom = self.get_instance(name)
            mem = util.get_xml_path(dom.XMLDesc(0), "/domain/currentMemory")
            mem = int(mem) * 1024
            mem_usage = (mem * 100) / memory
            cur_vcpu = util.get_xml_path(
                dom.XMLDesc(0), "/domain/vcpu/@current")
            if cur_vcpu:
                vcpu = cur_vcpu
            else:
                vcpu = util.get_xml_path(dom.XMLDesc(0), "/domain/vcpu")
            vname[dom.name()] = (dom.info()[0], vcpu, mem, mem_usage)
        return vname

    def close(self):
        self.wvm.close()


class wvmHostDetails(wvmConnect):
    def get_memory_usage(self):
        """
        Function return memory usage on node.
        """
        get_all_mem = self.wvm.getInfo()[1] * 1048576
        get_freemem = self.wvm.getMemoryStats(-1, 0)
        if type(get_freemem) == dict:
            free = (get_freemem.values()[0] + get_freemem.values()[2] +
                    get_freemem.values()[3]) * 1024
            percent = (100 - ((free * 100) / get_all_mem))
            usage = (get_all_mem - free)
            mem_usage = {'usage': usage, 'percent': percent}
        else:
            mem_usage = {'usage': None, 'percent': None}
        return mem_usage

    def get_cpu_usage(self):
        """
        Function return cpu usage on node.
        """
        prev_idle = 0
        prev_total = 0
        cpu = self.wvm.getCPUStats(-1, 0)
        if type(cpu) == dict:
            for num in range(2):
                idle = self.wvm.getCPUStats(-1, 0).values()[1]
                total = sum(self.wvm.getCPUStats(-1, 0).values())
                diff_idle = idle - prev_idle
                diff_total = total - prev_total
                diff_usage = (1000 *
                              (diff_total - diff_idle) / diff_total + 5) / 10
                prev_total = total
                prev_idle = idle
                if num == 0:
                    time.sleep(1)
                else:
                    if diff_usage < 0:
                        diff_usage = 0
        else:
            return {'usage': None}
        return {'usage': diff_usage}

    def get_node_info(self):
        """
        Function return host server information: hostname, cpu, memory, ...
        """
        info = []
        info.append(self.wvm.getHostname())
        info.append(self.wvm.getInfo()[0])
        info.append(self.wvm.getInfo()[1] * 1048576)
        info.append(self.wvm.getInfo()[2])
        info.append(
            util.get_xml_path(
                self.wvm.getSysinfo(0), func=util.cpu_version))
        info.append(self.wvm.getURI())
        return info

    def hypervisor_type(self):
        """Return hypervisor type"""
        return util.get_xml_path(self.get_cap_xml(),
                                 "/capabilities/guest/arch/domain/@type")


class wvmInstances(wvmConnect):
    def get_instance_status(self, name):
        inst = self.get_instance(name)
        return inst.info()[0]

    def get_instance_memory(self, name):
        inst = self.get_instance(name)
        mem = util.get_xml_path(inst.XMLDesc(0), "/domain/currentMemory")
        return int(mem) / 1024

    def get_instance_vcpu(self, name):
        inst = self.get_instance(name)
        cur_vcpu = util.get_xml_path(inst.XMLDesc(0), "/domain/vcpu/@current")
        if cur_vcpu:
            vcpu = cur_vcpu
        else:
            vcpu = util.get_xml_path(inst.XMLDesc(0), "/domain/vcpu")
        return vcpu

    def get_instance_managed_save_image(self, name):
        inst = self.get_instance(name)
        return inst.hasManagedSaveImage(0)

    def get_uuid(self, name):
        inst = self.get_instance(name)
        return inst.UUIDString()

    def start(self, name):
        dom = self.get_instance(name)
        dom.create()

    def shutdown(self, name):
        dom = self.get_instance(name)
        dom.shutdown()

    def force_shutdown(self, name):
        dom = self.get_instance(name)
        dom.destroy()

    def managedsave(self, name):
        dom = self.get_instance(name)
        dom.managedSave(0)

    def managed_save_remove(self, name):
        dom = self.get_instance(name)
        dom.managedSaveRemove(0)

    def suspend(self, name):
        dom = self.get_instance(name)
        dom.suspend()

    def resume(self, name):
        dom = self.get_instance(name)
        dom.resume()

    def moveto(self, conn, name, live, unsafe, undefine):
        flags = 0
        if live and conn.get_status() == 1:
            flags |= VIR_MIGRATE_LIVE
        if unsafe and conn.get_status() == 1:
            flags |= VIR_MIGRATE_UNSAFE
        dom = conn.get_instance(name)
        dom.migrate(self.wvm, flags, name, None, 0)
        if undefine:
            dom.undefine()

    def define_move(self, name):
        dom = self.get_instance(name)
        xml = dom.XMLDesc(VIR_DOMAIN_XML_SECURE)
        self.wvm.defineXML(xml)


class wvmInstance(wvmConnect):
    def __init__(self, host, conn, vname):
        wvmConnect.__init__(self, host, conn)
        self.instance = self.get_instance(vname)

    def start(self):
        self.instance.create()

    def shutdown(self):
        self.instance.shutdown()

    def force_shutdown(self):
        self.instance.destroy()

    def managedsave(self):
        self.instance.managedSave(0)

    def managed_save_remove(self):
        self.instance.managedSaveRemove(0)

    def suspend(self):
        self.instance.suspend()

    def resume(self):
        self.instance.resume()

    def delete(self):
        try:
            self.instance.undefineFlags(VIR_DOMAIN_UNDEFINE_SNAPSHOTS_METADATA)
        except libvirtError as e:
            log_error(str(e))
            self.instance.undefine()

    def _XMLDesc(self, flag):
        return self.instance.XMLDesc(flag)

    def _defineXML(self, xml):
        return self.wvm.defineXML(xml)

    def get_status(self):
        return self.instance.info()[0]

    def get_autostart(self):
        return self.instance.autostart()

    def set_autostart(self, flag):
        return self.instance.setAutostart(flag)

    def get_uuid(self):
        return self.instance.UUIDString()

    def get_vcpu(self):
        vcpu = util.get_xml_path(self._XMLDesc(0), "/domain/vcpu")
        return int(vcpu)

    def get_cur_vcpu(self):
        cur_vcpu = util.get_xml_path(self._XMLDesc(0), "/domain/vcpu/@current")
        if cur_vcpu:
            return int(cur_vcpu)

    def get_memory(self):
        mem = util.get_xml_path(self._XMLDesc(0), "/domain/memory")
        return int(mem) / 1024

    def get_cur_memory(self):
        mem = util.get_xml_path(self._XMLDesc(0), "/domain/currentMemory")
        return int(mem) / 1024

    def get_description(self):
        return util.get_xml_path(self._XMLDesc(0), "/domain/description")

    def get_max_memory(self):
        return self.wvm.getInfo()[1] * 1048576

    def get_max_cpus(self):
        """Get number of physical CPUs."""
        hostinfo = self.wvm.getInfo()
        pcpus = hostinfo[4] * hostinfo[5] * hostinfo[6] * hostinfo[7]
        range_pcpus = xrange(1, int(pcpus + 1))
        return range_pcpus

    def get_net_device(self):
        def get_mac_ipaddr(net, mac_host):
            def fixed(ctx):
                for net in ctx.xpathEval('/network/ip/dhcp/host'):
                    mac = net.xpathEval('@mac')[0].content
                    host = net.xpathEval('@ip')[0].content
                    if mac == mac_host:
                        return host
                return None

            return util.get_xml_path(net.XMLDesc(0), func=fixed)

        def networks(ctx):
            result = []
            for net in ctx.xpathEval('/domain/devices/interface'):
                mac_host = net.xpathEval('mac/@address')[0].content
                nic_host = net.xpathEval(
                    'source/@network|source/@bridge|source/@dev')[0].content
                try:
                    net = self.get_network(nic_host)
                    ip = get_mac_ipaddr(net, mac_host)
                except libvirtError as e:
                    log_error(str(e))
                    ip = None
                result.append({'mac': mac_host, 'nic': nic_host, 'ip': ip})
            return result

        return util.get_xml_path(self._XMLDesc(0), func=networks)

    def get_disk_device(self):
        def disks(ctx):
            result = []
            dev = None
            volume = None
            storage = None
            src_fl = None
            disk_format = None
            for disk in ctx.xpathEval('/domain/devices/disk'):
                device = disk.xpathEval('@device')[0].content
                if device == 'disk':
                    try:
                        dev = disk.xpathEval('target/@dev')[0].content
                        src_fl = disk.xpathEval(
                            'source/@file|source/@dev|source/@name|source/@volume'
                        )[0].content
                        disk_format = disk.xpathEval('driver/@type')[0].content
                        try:
                            vol = self.get_volume_by_path(src_fl)
                            volume = vol.name()
                            stg = vol.storagePoolLookupByVolume()
                            storage = stg.name()
                        except libvirtError as e:
                            log_error(str(e))
                            volume = src_fl
                    except libvirtError as e:
                        log_error(str(e))
                    finally:
                        result.append({
                            'dev': dev,
                            'image': volume,
                            'storage': storage,
                            'path': src_fl,
                            'format': disk_format
                        })
            return result

        return util.get_xml_path(self._XMLDesc(0), func=disks)

    def get_media_device(self):
        def disks(ctx):
            result = []
            dev = None
            volume = None
            storage = None
            src_fl = None
            for media in ctx.xpathEval('/domain/devices/disk'):
                device = media.xpathEval('@device')[0].content
                if device == 'cdrom':
                    try:
                        dev = media.xpathEval('target/@dev')[0].content
                        try:
                            src_fl = media.xpathEval('source/@file')[0].content
                            vol = self.get_volume_by_path(src_fl)
                            volume = vol.name()
                            stg = vol.storagePoolLookupByVolume()
                            storage = stg.name()
                        except libvirtError as e:
                            log_error(str(e))
                            src_fl = None
                            volume = src_fl
                    except libvirtError as e:
                        log_error(str(e))
                    finally:
                        result.append({
                            'dev': dev,
                            'image': volume,
                            'storage': storage,
                            'path': src_fl
                        })
            return result

        return util.get_xml_path(self._XMLDesc(0), func=disks)

    def mount_iso(self, dev, image):
        def attach_iso(dev, disk, vol):
            if disk.get('device') == 'cdrom':
                for elm in disk:
                    if elm.tag == 'target':
                        if elm.get('dev') == dev:
                            src_media = ElementTree.Element('source')
                            src_media.set('file', vol.path())
                            disk.insert(2, src_media)
                            return True

        storages = self.get_storages()
        for storage in storages:
            stg = self.get_storage(storage)
            if stg.info()[0] != 0:
                for img in stg.listVolumes():
                    if image == img:
                        vol = stg.storageVolLookupByName(image)
        tree = ElementTree.fromstring(self._XMLDesc(0))
        for disk in tree.findall('devices/disk'):
            if attach_iso(dev, disk, vol):
                break
        if self.get_status() == 1:
            xml = ElementTree.tostring(disk)
            self.instance.attachDevice(xml)
            xmldom = self._XMLDesc(VIR_DOMAIN_XML_SECURE)
        if self.get_status() == 5:
            xmldom = ElementTree.tostring(tree)
        self._defineXML(xmldom)

    def umount_iso(self, dev, image):
        tree = ElementTree.fromstring(self._XMLDesc(0))
        for disk in tree.findall('devices/disk'):
            if disk.get('device') == 'cdrom':
                for elm in disk:
                    if elm.tag == 'source':
                        if elm.get('file') == image:
                            src_media = elm
                    if elm.tag == 'target':
                        if elm.get('dev') == dev:
                            disk.remove(src_media)
        if self.get_status() == 1:
            xml_disk = ElementTree.tostring(disk)
            self.instance.attachDevice(xml_disk)
            xmldom = self._XMLDesc(VIR_DOMAIN_XML_SECURE)
        if self.get_status() == 5:
            xmldom = ElementTree.tostring(tree)
        self._defineXML(xmldom)

    def cpu_usage(self):
        cpu_usage = {}
        if self.get_status() == 1:
            nbcore = self.wvm.getInfo()[2]
            cpu_use_ago = self.instance.info()[4]
            time.sleep(1)
            cpu_use_now = self.instance.info()[4]
            diff_usage = cpu_use_now - cpu_use_ago
            cpu_usage['cpu'] = 100 * diff_usage / (1 * nbcore * 10**9L)
        else:
            cpu_usage['cpu'] = 0
        return cpu_usage

    def disk_usage(self):
        devices = []
        dev_usage = []
        tree = ElementTree.fromstring(self._XMLDesc(0))
        for disk in tree.findall('devices/disk'):
            if disk.get('device') == 'disk':
                dev_file = None
                dev_bus = None
                network_disk = True
                for elm in disk:
                    if elm.tag == 'source':
                        if elm.get('protocol'):
                            dev_file = elm.get('protocol')
                            network_disk = True
                        if elm.get('file'):
                            dev_file = elm.get('file')
                        if elm.get('dev'):
                            dev_file = elm.get('dev')
                    if elm.tag == 'target':
                        dev_bus = elm.get('dev')
                if (dev_file and dev_bus) is not None:
                    if network_disk:
                        dev_file = dev_bus
                    devices.append([dev_file, dev_bus])
        for dev in devices:
            if self.get_status() == 1:
                rd_use_ago = self.instance.blockStats(dev[0])[1]
                wr_use_ago = self.instance.blockStats(dev[0])[3]
                time.sleep(1)
                rd_use_now = self.instance.blockStats(dev[0])[1]
                wr_use_now = self.instance.blockStats(dev[0])[3]
                rd_diff_usage = rd_use_now - rd_use_ago
                wr_diff_usage = wr_use_now - wr_use_ago
            else:
                rd_diff_usage = 0
                wr_diff_usage = 0
            dev_usage.append({
                'dev': dev[1],
                'rd': rd_diff_usage,
                'wr': wr_diff_usage
            })
        return dev_usage

    def net_usage(self):
        devices = []
        dev_usage = []
        tree = ElementTree.fromstring(self._XMLDesc(0))
        if self.get_status() == 1:
            tree = ElementTree.fromstring(self._XMLDesc(0))
            for target in tree.findall("devices/interface/target"):
                devices.append(target.get("dev"))
            for i, dev in enumerate(devices):
                rx_use_ago = self.instance.interfaceStats(dev)[0]
                tx_use_ago = self.instance.interfaceStats(dev)[4]
                time.sleep(1)
                rx_use_now = self.instance.interfaceStats(dev)[0]
                tx_use_now = self.instance.interfaceStats(dev)[4]
                rx_diff_usage = (rx_use_now - rx_use_ago) * 8
                tx_diff_usage = (tx_use_now - tx_use_ago) * 8
                dev_usage.append({
                    'dev': i,
                    'rx': rx_diff_usage,
                    'tx': tx_diff_usage
                })
        else:
            for i, dev in enumerate(self.get_net_device()):
                dev_usage.append({'dev': i, 'rx': 0, 'tx': 0})
        return dev_usage

    def get_telnet_port(self):
        telnet_port = None
        service_port = None
        tree = ElementTree.fromstring(self._XMLDesc(0))
        for console in tree.findall('devices/console'):
            if console.get('type') == 'tcp':
                for elm in console:
                    if elm.tag == 'source':
                        if elm.get('service'):
                            service_port = elm.get('service')
                    if elm.tag == 'protocol':
                        if elm.get('type') == 'telnet':
                            if service_port is not None:
                                telnet_port = service_port
        return telnet_port

    def get_console_listen_addr(self):
        listen_addr = util.get_xml_path(
            self._XMLDesc(0), "/domain/devices/graphics/@listen")
        if listen_addr is None:
            listen_addr = util.get_xml_path(
                self._XMLDesc(0), "/domain/devices/graphics/listen/@address")
            if listen_addr is None:
                return "127.0.0.1"
        return listen_addr

    def get_console_socket(self):
        socket = util.get_xml_path(
            self._XMLDesc(0), "/domain/devices/graphics/@socket")
        return socket

    def get_console_type(self):
        console_type = util.get_xml_path(
            self._XMLDesc(0), "/domain/devices/graphics/@type")
        return console_type

    def set_console_type(self, console_type):
        current_type = self.get_console_type()
        if current_type == console_type:
            return True
        if console_type == '' or console_type not in QEMU_CONSOLE_TYPES:
            return False
        xml = self._XMLDesc(VIR_DOMAIN_XML_SECURE)
        root = ElementTree.fromstring(xml)
        try:
            graphic = root.find("devices/graphics[@type='%s']" % current_type)
        except SyntaxError as e:
            log_error(str(e))
            # Little fix for old version ElementTree
            graphic = root.find("devices/graphics")
        graphic.set('type', console_type)
        newxml = ElementTree.tostring(root)
        self._defineXML(newxml)

    def get_console_port(self, console_type=None):
        if console_type is None:
            console_type = self.get_console_type()
        port = util.get_xml_path(
            self._XMLDesc(0),
            "/domain/devices/graphics[@type='%s']/@port" % console_type)
        return port

    def get_console_websocket_port(self):
        console_type = self.get_console_type()
        websocket_port = util.get_xml_path(
            self._XMLDesc(0),
            "/domain/devices/graphics[@type='%s']/@websocket" % console_type)
        return websocket_port

    def get_console_passwd(self):
        return util.get_xml_path(
            self._XMLDesc(VIR_DOMAIN_XML_SECURE),
            "/domain/devices/graphics/@passwd")

    def set_console_passwd(self, passwd):
        xml = self._XMLDesc(VIR_DOMAIN_XML_SECURE)
        root = ElementTree.fromstring(xml)
        console_type = self.get_console_type()
        try:
            graphic = root.find("devices/graphics[@type='%s']" % console_type)
        except SyntaxError as e:
            log_error(str(e))
            # Little fix for old version ElementTree
            graphic = root.find("devices/graphics")
        if graphic is None:
            return False
        if passwd:
            graphic.set('passwd', passwd)
        else:
            try:
                graphic.attrib.pop('passwd')
            except Exception as e:
                log_error(str(e))
        newxml = ElementTree.tostring(root)
        return self._defineXML(newxml)

    def set_console_keymap(self, keymap):
        xml = self._XMLDesc(VIR_DOMAIN_XML_SECURE)
        root = ElementTree.fromstring(xml)
        console_type = self.get_console_type()
        try:
            graphic = root.find("devices/graphics[@type='%s']" % console_type)
        except SyntaxError as e:
            log_error(str(e))
            # Little fix for old version ElementTree
            graphic = root.find("devices/graphics")
        if keymap:
            graphic.set('keymap', keymap)
        else:
            try:
                graphic.attrib.pop('keymap')
            except libvirtError as e:
                log_error(str(e))
        newxml = ElementTree.tostring(root)
        self._defineXML(newxml)

    def get_console_keymap(self):
        return util.get_xml_path(
            self._XMLDesc(VIR_DOMAIN_XML_SECURE),
            "/domain/devices/graphics/@keymap") or ''

    def change_settings(self, description, cur_memory, memory, cur_vcpu, vcpu):
        """
        Function change ram and cpu on vds.
        """
        memory = int(memory) * 1024
        cur_memory = int(cur_memory) * 1024

        xml = self._XMLDesc(VIR_DOMAIN_XML_SECURE)
        tree = ElementTree.fromstring(xml)

        set_mem = tree.find('memory')
        set_mem.text = str(memory)
        set_cur_mem = tree.find('currentMemory')
        set_cur_mem.text = str(cur_memory)
        set_desc = tree.find('description')
        set_vcpu = tree.find('vcpu')
        set_vcpu.text = vcpu
        set_vcpu.set('current', cur_vcpu)

        if not set_desc:
            tree_desc = ElementTree.Element('description')
            tree_desc.text = description
            tree.insert(2, tree_desc)
        else:
            set_desc.text = description

        new_xml = ElementTree.tostring(tree)
        self._defineXML(new_xml)

    def get_iso_media(self):
        iso = []
        storages = self.get_storages()
        for storage in storages:
            stg = self.get_storage(storage)
            if stg.info()[0] != 0:
                try:
                    stg.refresh(0)
                except libvirtError as e:
                    log_error(str(e))
                for img in stg.listVolumes():
                    if img.lower().endswith('.iso'):
                        iso.append(img)
        return iso

    def delete_disk(self):
        disks = self.get_disk_device()
        for disk in disks:
            vol = self.get_volume_by_path(disk.get('path'))
            vol.delete(0)

    def _snapshotCreateXML(self, xml, flag):
        self.instance.snapshotCreateXML(xml, flag)

    def create_snapshot(self, name):
        xml = """<domainsnapshot>
                     <name>%s</name>
                     <state>shutoff</state>
                     <creationTime>%d</creationTime>""" % (name, time.time())
        xml += self._XMLDesc(VIR_DOMAIN_XML_SECURE)
        xml += """<active>0</active>
                  </domainsnapshot>"""
        self._snapshotCreateXML(xml, 0)

    def get_snapshot(self):
        snapshots = []
        snapshot_list = self.instance.snapshotListNames(0)
        for snapshot in snapshot_list:
            snap = self.instance.snapshotLookupByName(snapshot, 0)
            snap_time_create = util.get_xml_path(
                snap.getXMLDesc(0), "/domainsnapshot/creationTime")
            snapshots.append({
                'date': str(datetime.fromtimestamp(int(snap_time_create))),
                'name': snapshot
            })
        return snapshots

    def snapshot_delete(self, snapshot):
        snap = self.instance.snapshotLookupByName(snapshot, 0)
        snap.delete(0)

    def snapshot_revert(self, snapshot):
        snap = self.instance.snapshotLookupByName(snapshot, 0)
        self.instance.revertToSnapshot(snap, 0)

    def get_managed_save_image(self):
        return self.instance.hasManagedSaveImage(0)

    def clone_instance(self, clone_data):
        clone_dev_path = []

        xml = self._XMLDesc(VIR_DOMAIN_XML_SECURE)
        tree = ElementTree.fromstring(xml)
        name = tree.find('name')
        name.text = clone_data['name']
        uuid = tree.find('uuid')
        tree.remove(uuid)

        for num, net in enumerate(tree.findall('devices/interface')):
            elm = net.find('mac')
            elm.set('address', clone_data['net-' + str(num)])

        for disk in tree.findall('devices/disk'):
            if disk.get('device') == 'disk':
                elm = disk.find('target')
                device_name = elm.get('dev')
                if device_name:
                    target_file = clone_data['disk-' + device_name]
                    try:
                        meta_prealloc = clone_data['meta-' + device_name]
                    except libvirtError as e:
                        log_error(str(e))
                        meta_prealloc = False
                    elm.set('dev', device_name)

                elm = disk.find('source')
                source_file = elm.get('file')
                if source_file:
                    clone_dev_path.append(source_file)
                    clone_path = os.path.join(
                        os.path.dirname(source_file), target_file)
                    elm.set('file', clone_path)

                    vol = self.get_volume_by_path(source_file)
                    vol_format = util.get_xml_path(
                        vol.XMLDesc(0), "/volume/target/format/@type")

                    if vol_format == 'qcow2' and meta_prealloc:
                        meta_prealloc = True
                    vol_clone_xml = """
                                    <volume>
                                        <name>%s</name>
                                        <capacity>0</capacity>
                                        <allocation>0</allocation>
                                        <target>
                                            <format type='%s'/>
                                        </target>
                                    </volume>""" % (target_file, vol_format)
                    stg = vol.storagePoolLookupByVolume()
                    stg.createXMLFrom(vol_clone_xml, vol, meta_prealloc)

        self._defineXML(ElementTree.tostring(tree))


class wvmCreate(wvmConnect):
    def get_storages_images(self):
        """
        Function return all images on all storages
        """
        images = []
        storages = self.get_storages()
        for storage in storages:
            stg = self.get_storage(storage)
            try:
                stg.refresh(0)
            except libvirtError as e:
                log_error(str(e))
            for img in stg.listVolumes():
                if img.endswith('.iso'):
                    pass
                else:
                    images.append(img)
        return images

    def get_os_type(self):
        """Get guest capabilities"""
        return util.get_xml_path(self.get_cap_xml(),
                                 "/capabilities/guest/os_type")

    def get_host_arch(self):
        """Get guest capabilities"""
        return util.get_xml_path(self.get_cap_xml(),
                                 "/capabilities/host/cpu/arch")

    def get_cache_modes(self):
        """Get cache available modes"""
        return {
            'default': 'Default',
            'none': 'Disabled',
            'writethrough': 'Write through',
            'writeback': 'Write back',
            'directsync': 'Direct sync',  # since libvirt 0.9.5
            'unsafe': 'Unsafe',  # since libvirt 0.9.7
        }

    '''
        <volume type='block'>
          <name>sda1</name>
          <key>/dev/sda1</key>
          <source>
          </source>
          <capacity unit='bytes'>106896384</capacity>
          <allocation unit='bytes'>106896384</allocation>
          <target>
            <path>/dev/sda1</path>
            <format type='none'/>
            <permissions>
              <mode>0660</mode>
              <owner>0</owner>
              <group>6</group>
              <label>system_u:object_r:fixed_disk_device_t:s0</label>
            </permissions>
          </target>
        </volume>
    '''

    def create_volume(self,
                      storage,
                      name,
                      size,
                      format='qcow2',
                      metadata=False):
        size = int(size) * 1073741824
        stg = self.get_storage(storage)
        storage_type = util.get_xml_path(stg.XMLDesc(0), "/pool/@type")
        if storage_type == 'dir':
            name += '.img'
            alloc = 0
        else:
            alloc = size
            metadata = False
        xml = """
            <volume>
                <name>%s</name>
                <capacity>%s</capacity>
                <allocation>%s</allocation>
                <target>
                    <format type='%s'/>
                </target>
            </volume>""" % (name, size, alloc, format)
        stg.createXML(xml, metadata)
        try:
            stg.refresh(0)
        except libvirtError as e:
            log_error(str(e))
        vol = stg.storageVolLookupByName(name)
        return vol.path()

    def get_volume_type(self, path):
        vol = self.get_volume_by_path(path)
        vol_type = util.get_xml_path(
            vol.XMLDesc(0), "/volume/target/format/@type")
        if vol_type == 'unknown':
            return 'raw'
        if vol_type:
            return vol_type
        else:
            return 'raw'

    def get_volume_path(self, volume):
        storages = self.get_storages()
        for storage in storages:
            stg = self.get_storage(storage)
            if stg.info()[0] != 0:
                stg.refresh(0)
                for img in stg.listVolumes():
                    if img == volume:
                        vol = stg.storageVolLookupByName(img)
                        return vol.path()

    def get_storage_by_vol_path(self, vol_path):
        vol = self.get_volume_by_path(vol_path)
        return vol.storagePoolLookupByVolume()

    def clone_from_template(self, clone, template, metadata=False):
        vol = self.get_volume_by_path(template)
        stg = vol.storagePoolLookupByVolume()
        storage_type = util.get_xml_path(stg.XMLDesc(0), "/pool/@type")
        format = util.get_xml_path(
            vol.XMLDesc(0), "/volume/target/format/@type")
        if storage_type == 'dir':
            clone += '.img'
        else:
            metadata = False
        xml = """
            <volume>
                <name>%s</name>
                <capacity>0</capacity>
                <allocation>0</allocation>
                <target>
                    <format type='%s'/>
                </target>
            </volume>""" % (clone, format)
        stg.createXMLFrom(xml, vol, metadata)
        clone_vol = stg.storageVolLookupByName(clone)
        return clone_vol.path()

    def _defineXML(self, xml):
        self.wvm.defineXML(xml)

    def delete_volume(self, path):
        vol = self.get_volume_by_path(path)
        vol.delete()

    def create_instance(self,
                        name,
                        memory,
                        vcpu,
                        uuid,
                        root_image,
                        images=None,
                        bridge=None,
                        networks=None,
                        vg_name=None,
                        mac=None):
        """
        Create VM function
        """
        memory = int(memory) * 1024
        host_model = kvm_config.get('host_model')
        cache_mode = kvm_config.get('cache_mode')
        virtio = kvm_config.get('virtio')

        if bridge is None:
            bridge = kvm_config.get('bridge')

        if vg_name is None:
            vg_name = kvm_config.get('volume_group')

        if self.is_kvm_supported():
            hypervisor_type = 'kvm'
            host_model_str = 'host-passthrough'
        else:
            hypervisor_type = 'qemu'
            host_model_str = 'host-model'

        xml = """
                <domain type='%s'>
                  <name>%s</name>
                  <description>%s</description>
                  <uuid>%s</uuid>
                  <memory unit='KiB'>%s</memory>
                  <vcpu placement='static'>%s</vcpu>""" % (
            hypervisor_type, name, name, uuid, memory, vcpu)
        if host_model:
            xml += """<cpu mode='%s'/>""" % host_model_str
        xml += """<os>
                    <type arch='%s'>%s</type>
                    <boot dev='hd'/>
                  </os>""" % (self.get_host_arch(), self.get_os_type())
        xml += """<features>
                    <acpi/><apic/><pae/>
                  </features>
                  <clock offset="localtime"/>
                  <on_poweroff>destroy</on_poweroff>
                  <on_reboot>restart</on_reboot>
                  <on_crash>restart</on_crash>
                  <devices>"""

        disk_letters = list(string.lowercase)
        if images:
            for image, img_type in images.items():
                stg = self.get_storage_by_vol_path(image)
                stg_type = util.get_xml_path(stg.XMLDesc(0), "/pool/@type")

                if stg_type == 'rbd':
                    ceph_user, secret_uuid, ceph_hosts = util.get_rbd_storage_data(
                        stg)
                    xml += """<disk type='network' device='disk'>
                                <driver name='qemu' type='%s' cache='%s'/>
                                <auth username='%s'>
                                    <secret type='ceph' uuid='%s'/>
                                </auth>
                                <source protocol='rbd' name='%s'>""" % (
                        img_type, cache_mode, ceph_user, secret_uuid, image)
                    if isinstance(ceph_hosts, list):
                        for host in ceph_hosts:
                            if host.get('port'):
                                xml += """
                                       <host name='%s' port='%s'/>""" % (
                                    host.get('name'), host.get('port'))
                            else:
                                xml += """
                                       <host name='%s'/>""" % host.get('name')
                    xml += """
                                </source>"""
                else:
                    xml += """<disk type='file' device='disk'>
                                <driver name='qemu' type='%s' cache='%s' io="threads"/>
                                <source file='%s'/>""" % (img_type, cache_mode,
                                                          image)

                if virtio:
                    xml += """<target dev='vd%s' bus='virtio'/>""" % (
                        disk_letters.pop(0), )
                else:
                    xml += """<target dev='sd%s' bus='ide'/>""" % (
                        disk_letters.pop(0), )
                xml += """</disk>"""
        else:
            xml += """ <disk type='file' device='disk'>
                          <driver name='qemu' type='qcow2' cache='none'/>
                          <source file='%s'/>
                          <target dev='vda' bus='virtio'/>
                        </disk>
                        <disk type='block' device='disk'>
                            <driver name='qemu' type='raw' cache="%s" io="threads"/>
                            <source dev='/dev/%s/%s'/>
                            <target dev='sdb' bus='virtio'/>
                        </disk>""" % (root_image, cache_mode, vg_name, name)

        if mac is None:
            mac = util.randomMAC()

        if networks:
            for net in networks.split(','):
                xml += """<interface type='network'>"""
                if mac:
                    xml += """<mac address='%s'/>""" % mac
                xml += """<source network='%s'/>""" % net
                if virtio:
                    xml += """<model type='virtio'/>"""
                xml += """</interface>"""
        else:
            xml += """
                        <interface type='bridge'>
                          <mac address='%s'/>
                          <source bridge='%s'/>
                          <target dev='vnet%s'/>
                          <model type='virtio'/>
                          <driver>
                            <host csum='off' gso='off' tso4='off' tso6='off' ecn='off' ufo='off' mrg_rxbuf='off'/>
                            <guest csum='off' tso4='off' tso6='off' ecn='off' ufo='off'/>
                          </driver>
                        </interface>
                    """ % (mac, bridge, uuid.split('-')[-1])

        xml += """  <input type='tablet' bus='usb'/>
                    <input type='mouse' bus='ps2'/>
                    <serial type='pty'>
                      <target port='0'/>
                    </serial>
                    <console type='pty'>
                      <target type='serial' port='0'/>
                    </console>
                    <memballoon model='virtio'>
                    </memballoon>
                  </devices>
                </domain>"""
        self._defineXML(xml)


class wvmInterfaces(wvmConnect):
    def get_iface_info(self, name):
        iface = self.get_iface(name)
        xml = iface.XMLDesc(0)
        mac = iface.MACString()
        itype = util.get_xml_path(xml, "/interface/@type")
        state = iface.isActive()
        return {'name': name, 'type': itype, 'state': state, 'mac': mac}

    def define_iface(self, xml, flag=0):
        self.wvm.interfaceDefineXML(xml, flag)

    def create_iface(self,
                     name,
                     itype,
                     netdev,
                     vlan_id=None,
                     ipv4_type=None,
                     ipv4_addr=None,
                     ipv4_gw=None,
                     bond_mode=None,
                     ipv6_type=None,
                     ipv6_addr=None,
                     ipv6_gw=None,
                     stp='off',
                     delay=1,
                     mode='onboot',
                     mtu=1500):
        xml = """<interface type='%s' name='%s'>
                    <mtu size='%s'/>
                    <start mode='%s'/>""" % (itype, name, mtu, mode)
        if ipv4_type == 'dhcp':
            xml += """<protocol family='ipv4'>
                        <dhcp/>
                      </protocol>"""
        if ipv4_type == 'static':
            address, prefix = ipv4_addr.split('/')
            xml += """<protocol family='ipv4'>
                        <ip address='%s' prefix='%s'/>
                      </protocol>""" % (address, prefix)
        if ipv6_type == 'dhcp':
            xml += """<protocol family='ipv6'>
                        <dhcp/>
                      </protocol>"""
        if ipv6_type == 'static':
            address, prefix = ipv6_addr.split('/')
            xml += """<protocol family='ipv6'>
                        <ip address='%s' prefix='%s'/>
                      </protocol>""" % (address, prefix)

        if itype == 'bridge':
            xml += """<bridge stp='%s' delay='%s'>""" % (stp, delay)
            if vlan_id is not None:
                xml += """
                    <interface type='vlan' name='%s'>
                      <vlan tag='%s'>
                        <interface name='%s'/>
                      </vlan>
                """ % (name + '.' + str(vlan_id), vlan_id, netdev)
            else:
                xml += """
                        <interface name='%s' type='ethernet' >
                        """ % netdev

            xml += """</interface>
            </bridge>"""
        if itype == 'bond':
            xml += """
                  <bond mode='%s'>
                    <miimon freq='100' updelay='10' carrier='ioctl'/>
                    """ % bond_mode
            for item in netdev:
                xml += """
                        <interface type='ethernet' name='%s'>
                        </interface>
                        """ % item
            xml += """
                  </bond>
            """
        xml += """</interface>"""
        self.define_iface(xml)
        iface = self.get_iface(name)
        iface.create(0)


class wvmInterface(wvmConnect):
    def __init__(self, host, conn, iface):
        wvmConnect.__init__(self, host, conn)
        self.iface = self.get_iface(iface)

    def _XMLDesc(self, flags=0):
        return self.iface.XMLDesc(flags)

    def get_start_mode(self):
        try:
            xml = self._XMLDesc(VIR_INTERFACE_XML_INACTIVE)
            return util.get_xml_path(xml, "/interface/start/@mode")
        except libvirtError as e:
            log_error(str(e))
            return None

    def is_active(self):
        return self.iface.isActive()

    def get_mac(self):
        mac = self.iface.MACString()
        if mac:
            return mac
        else:
            return None

    def get_type(self):
        xml = self._XMLDesc()
        return util.get_xml_path(xml, "/interface/@type")

    def get_ipv4_type(self):
        try:
            xml = self._XMLDesc(VIR_INTERFACE_XML_INACTIVE)
            ipaddr = util.get_xml_path(xml, "/interface/protocol/ip/@address")
            if ipaddr:
                return 'static'
            else:
                return 'dhcp'
        except libvirtError as e:
            log_error(str(e))
            return None

    def get_ipv4(self):
        xml = self._XMLDesc()
        int_ipv4_ip = util.get_xml_path(xml, "/interface/protocol/ip/@address")
        int_ipv4_mask = util.get_xml_path(xml,
                                          "/interface/protocol/ip/@prefix")
        if not int_ipv4_ip or not int_ipv4_mask:
            return None
        else:
            return int_ipv4_ip + '/' + int_ipv4_mask

    def get_ipv6_type(self):
        try:
            xml = self._XMLDesc(VIR_INTERFACE_XML_INACTIVE)
            ipaddr = util.get_xml_path(xml,
                                       "/interface/protocol[2]/ip/@address")
            if ipaddr:
                return 'static'
            else:
                return 'dhcp'
        except libvirtError as e:
            log_error(str(e))
            return None

    def get_ipv6(self):
        xml = self._XMLDesc()
        int_ipv6_ip = util.get_xml_path(xml,
                                        "/interface/protocol[2]/ip/@address")
        int_ipv6_mask = util.get_xml_path(xml,
                                          "/interface/protocol[2]/ip/@prefix")
        if not int_ipv6_ip or not int_ipv6_mask:
            return None
        else:
            return int_ipv6_ip + '/' + int_ipv6_mask

    def get_bridge(self):
        if self.get_type() == 'bridge':
            xml = self._XMLDesc()
            return util.get_xml_path(xml, "/interface/bridge/interface/@name")
        else:
            return None

    def stop_iface(self):
        self.iface.destroy(flags=0)

    def start_iface(self):
        self.iface.create(flags=0)

    def delete_iface(self):
        self.iface.undefine()


class wvmNetworks(wvmConnect):
    def get_networks_info(self):
        get_networks = self.get_networks()
        networks = []
        for network in get_networks:
            net = self.get_network(network)
            net_status = net.isActive()
            net_bridge = net.bridgeName()
            net_forwd = util.get_xml_path(
                net.XMLDesc(0), "/network/forward/@mode")
            networks.append({
                'name': network,
                'status': net_status,
                'device': net_bridge,
                'forward': net_forwd
            })
        return networks

    def define_network(self, xml):
        self.wvm.networkDefineXML(xml)

    def create_network(self,
                       name,
                       forward,
                       gateway,
                       mask,
                       dhcp,
                       bridge,
                       openvswitch,
                       fixed=False):
        xml = """
            <network>
                <name>%s</name>""" % name
        if forward in ['nat', 'route', 'bridge']:
            xml += """<forward mode='%s'/>""" % forward
        xml += """<bridge """
        if forward in ['nat', 'route', 'none']:
            xml += """stp='on' delay='0'"""
        if forward == 'bridge':
            xml += """name='%s' macTableManager="libvirt" """ % bridge
        xml += """/>"""
        if openvswitch is True:
            xml += """<virtualport type='openvswitch'/>"""
        if forward != 'bridge':
            xml += """
                        <ip address='%s' netmask='%s'>""" % (gateway, mask)
            if dhcp:
                xml += """<dhcp>
                            <range start='%s' end='%s' />""" % (dhcp[0],
                                                                dhcp[1])
                if fixed:
                    fist_oct = int(dhcp[0].strip().split('.')[3])
                    last_oct = int(dhcp[1].strip().split('.')[3])
                    for ip in range(fist_oct, last_oct + 1):
                        xml += """<host mac='%s' ip='%s.%s' />""" % (
                            util.randomMAC(), gateway[:-2], ip)
                xml += """</dhcp>"""

            xml += """</ip>"""
        xml += """</network>"""
        self.define_network(xml)
        net = self.get_network(name)
        net.create()
        net.setAutostart(1)


class wvmNetwork(wvmConnect):
    def __init__(self, host, conn, net):
        wvmConnect.__init__(self, host, conn)
        self.net = self.get_network(net)

    def get_name(self):
        return self.net.name()

    def _XMLDesc(self, flags):
        return self.net.XMLDesc(flags)

    def get_autostart(self):
        return self.net.autostart()

    def set_autostart(self, value):
        self.net.setAutostart(value)

    def is_active(self):
        return self.net.isActive()

    def get_uuid(self):
        return self.net.UUIDString()

    def get_bridge_device(self):
        try:
            return self.net.bridgeName()
        except libvirtError as e:
            log_error(str(e))
            return None

    def start(self):
        self.net.create()

    def stop(self):
        self.net.destroy()

    def delete(self):
        self.net.undefine()

    def get_ipv4_network(self):
        xml = self._XMLDesc(0)
        if util.get_xml_path(xml, "/network/ip") is None:
            return None
        addrStr = util.get_xml_path(xml, "/network/ip/@address")
        netmaskStr = util.get_xml_path(xml, "/network/ip/@netmask")
        prefix = util.get_xml_path(xml, "/network/ip/@prefix")

        if prefix:
            prefix = int(prefix)
            binstr = ((prefix * "1") + ((32 - prefix) * "0"))
            netmaskStr = str(IP(int(binstr, base=2)))

        if netmaskStr:
            netmask = IP(netmaskStr)
            gateway = IP(addrStr)
            network = IP(gateway.int() & netmask.int())
            ret = IP(str(network) + "/" + netmaskStr)
        else:
            ret = IP(str(addrStr))

        return ret

    def get_ipv4_forward(self):
        xml = self._XMLDesc(0)
        fw = util.get_xml_path(xml, "/network/forward/@mode")
        forwardDev = util.get_xml_path(xml, "/network/forward/@dev")
        return [fw, forwardDev]

    def get_ipv4_dhcp_range(self):
        xml = self._XMLDesc(0)
        dhcpstart = util.get_xml_path(xml, "/network/ip/dhcp/range[1]/@start")
        dhcpend = util.get_xml_path(xml, "/network/ip/dhcp/range[1]/@end")
        if not dhcpstart or not dhcpend:
            return None

        return [IP(dhcpstart), IP(dhcpend)]

    def get_ipv4_dhcp_range_start(self):
        dhcp = self.get_ipv4_dhcp_range()
        if not dhcp:
            return None

        return dhcp[0]

    def get_ipv4_dhcp_range_end(self):
        dhcp = self.get_ipv4_dhcp_range()
        if not dhcp:
            return None

        return dhcp[1]

    def can_pxe(self):
        xml = self.get_xml()
        forward = self.get_ipv4_forward()[0]
        if forward and forward != "nat":
            return True
        return bool(util.get_xml_path(xml, "/network/ip/dhcp/bootp/@file"))

    def get_mac_ipaddr(self):
        def network(ctx):
            result = []
            for net in ctx.xpathEval('/network/ip/dhcp/host'):
                host = net.xpathEval('@ip')[0].content
                mac = net.xpathEval('@mac')[0].content
                result.append({'host': host, 'mac': mac})
            return result

        return util.get_xml_path(self._XMLDesc(0), func=network)


class wvmSecrets(wvmConnect):
    def create_secret(self, ephemeral, private, secret_type, data):
        xml = """<secret ephemeral='%s' private='%s'>
                    <usage type='%s'>""" % (ephemeral, private, secret_type)
        if secret_type == 'ceph':
            xml += """<name>%s</name>""" % (data)
        if secret_type == 'volume':
            xml += """<volume>%s</volume>""" % (data)
        if secret_type == 'iscsi':
            xml += """<target>%s</target>""" % (data)
        xml += """</usage>
                 </secret>"""
        self.wvm.secretDefineXML(xml)

    def get_secret_value(self, uuid):
        secrt = self.get_secret(uuid)
        value = secrt.value()
        return base64.b64encode(value)

    def set_secret_value(self, uuid, value):
        secrt = self.get_secret(uuid)
        value = base64.b64decode(value)
        secrt.setValue(value)

    def delete_secret(self, uuid):
        secrt = self.get_secret(uuid)
        secrt.undefine()


class wvmStorages(wvmConnect):
    def get_storages_info(self):
        get_storages = self.get_storages()
        storages = []
        for pool in get_storages:
            stg = self.get_storage(pool)
            stg_status = stg.isActive()
            stg_type = util.get_xml_path(stg.XMLDesc(0), "/pool/@type")
            if stg_status:
                stg_vol = len(stg.listVolumes())
            else:
                stg_vol = None
            stg_size = stg.info()[1]
            storages.append({
                'name': pool,
                'status': stg_status,
                'type': stg_type,
                'volumes': stg_vol,
                'size': stg_size
            })
        return storages

    def define_storage(self, xml, flag):
        self.wvm.storagePoolDefineXML(xml, flag)

    def create_storage(self, stg_type, name, source, target):
        xml = """
                <pool type='%s'>
                <name>%s</name>""" % (stg_type, name)
        if stg_type == 'logical':
            xml += """
                  <source>
                  """
            for device in source.split(','):
                xml += """
                            <device path='%s'/>
                        """ % device
            xml += """
                    <name>%s</name>
                    <format type='lvm2'/>
                  </source>""" % name
        if stg_type == 'logical':
            target = '/dev/' + name
        xml += """
                  <target>
                       <path>%s</path>
                  </target>
                </pool>""" % target
        self.define_storage(xml, 0)
        stg = self.get_storage(name)
        if stg_type == 'logical':
            stg.build(0)
        stg.create(0)
        stg.setAutostart(1)

    def create_storage_ceph(self, stg_type, name, ceph_pool, ceph_host,
                            ceph_user, secret):
        xml = """
                <pool type='%s'>
                <name>%s</name>
                <source>
                    <name>%s</name>
                    <host name='%s' port='6789'/>
                    <auth username='%s' type='ceph'>
                        <secret uuid='%s'/>
                    </auth>
                </source>
                </pool>""" % (stg_type, name, ceph_pool, ceph_host, ceph_user,
                              secret)
        self.define_storage(xml, 0)
        stg = self.get_storage(name)
        stg.create(0)
        stg.setAutostart(1)

    def create_storage_netfs(self, stg_type, name, netfs_host, source,
                             source_format, target):
        xml = """
                <pool type='%s'>
                <name>%s</name>
                <source>
                    <host name='%s'/>
                    <dir path='%s'/>
                    <format type='%s'/>
                </source>
                <target>
                    <path>%s</path>
                </target>
                </pool>""" % (stg_type, name, netfs_host, source,
                              source_format, target)
        self.define_storage(xml, 0)
        stg = self.get_storage(name)
        stg.create(0)
        stg.setAutostart(1)


class wvmStorage(wvmConnect):
    def __init__(self, host, conn, pool):
        wvmConnect.__init__(self, host, conn)
        self.pool = self.get_storage(pool)

    def get_name(self):
        return self.pool.name()

    def info(self):
        return self.pool.info()

    def get_status(self):
        status = [
            'Not running', 'Initializing pool, not available',
            'Running normally', 'Running degraded'
        ]
        try:
            return status[self.pool.info()[0]]
        except ValueError as e:
            log_error(str(e))
            return 'Unknown'

    def get_size(self):
        return [self.pool.info()[1], self.pool.info()[3]]

    def _XMLDesc(self, flags):
        return self.pool.XMLDesc(flags)

    def _createXML(self, xml, flags):
        self.pool.createXML(xml, flags)

    def _createXMLFrom(self, xml, vol, flags):
        self.pool.createXMLFrom(xml, vol, flags)

    def _define(self, xml):
        return self.wvm.storagePoolDefineXML(xml, 0)

    def is_active(self):
        return self.pool.isActive()

    def get_uuid(self):
        return self.pool.UUIDString()

    def start(self):
        self.pool.create(flags=0)

    def stop(self):
        self.pool.destroy()

    def delete(self):
        self.pool.undefine()

    def destroy(self):
        self.pool.delete(flags=0)

    def get_autostart(self):
        return self.pool.autostart()

    def set_autostart(self, value):
        self.pool.setAutostart(value)

    def get_type(self):
        return util.get_xml_path(self._XMLDesc(0), "/pool/@type")

    def get_target_path(self):
        return util.get_xml_path(self._XMLDesc(0), "/pool/target/path")

    def get_allocation(self):
        return long(util.get_xml_path(self._XMLDesc(0), "/pool/allocation"))

    def get_available(self):
        return long(util.get_xml_path(self._XMLDesc(0), "/pool/available"))

    def get_capacity(self):
        return long(util.get_xml_path(self._XMLDesc(0), "/pool/capacity"))

    def get_pretty_allocation(self):
        return util.pretty_bytes(self.get_allocation())

    def get_pretty_available(self):
        return util.pretty_bytes(self.get_available())

    def get_pretty_capacity(self):
        return util.pretty_bytes(self.get_capacity())

    def get_volumes(self):
        return self.pool.listVolumes()

    def get_volume(self, name):
        return self.pool.storageVolLookupByName(name)

    def get_volume_size(self, name):
        vol = self.get_volume(name)
        return vol.info()[1]

    def _vol_XMLDesc(self, name):
        vol = self.get_volume(name)
        return vol.XMLDesc(0)

    def del_volume(self, name):
        vol = self.pool.storageVolLookupByName(name)
        vol.delete(0)

    def get_volume_type(self, name):
        vol_xml = self._vol_XMLDesc(name)
        return util.get_xml_path(vol_xml, "/volume/target/format/@type")

    def refresh(self):
        self.pool.refresh(0)

    def update_volumes(self):
        try:
            self.refresh()
        except Exception as e:
            log_error(str(e))
        vols = self.get_volumes()
        vol_list = []

        for volname in vols:
            vol_list.append({
                'name': volname,
                'size': self.get_volume_size(volname),
                'type': self.get_volume_type(volname)
            })
        return vol_list

    def create_volume(self, name, size, vol_fmt='qcow2', metadata=False):
        size = int(size) * 1073741824
        storage_type = self.get_type()
        alloc = size
        if vol_fmt == 'unknown':
            vol_fmt = 'raw'
        if storage_type == 'dir':
            name += '.img'
            alloc = 0
        xml = """
            <volume>
                <name>%s</name>
                <capacity>%s</capacity>
                <allocation>%s</allocation>
                <target>
                    <format type='%s'/>
                </target>
            </volume>""" % (name, size, alloc, vol_fmt)
        self._createXML(xml, metadata)

    def clone_volume(self, name, clone, vol_fmt=None, metadata=False):
        storage_type = self.get_type()
        if storage_type == 'dir':
            clone += '.img'
        vol = self.get_volume(name)
        if not vol_fmt:
            vol_fmt = self.get_volume_type(name)
        xml = """
            <volume>
                <name>%s</name>
                <capacity>0</capacity>
                <allocation>0</allocation>
                <target>
                    <format type='%s'/>
                </target>
            </volume>""" % (clone, vol_fmt)
        self._createXMLFrom(xml, vol, metadata)
