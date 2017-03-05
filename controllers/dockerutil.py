#!/usr/bin/env python
# -*- coding:utf8 -*-
import docker
from models.virt import *
from helpers.logger import log_error
from configs import docker_config


class dockerutil:
    image = docker_config.get('base_image')

    def help(self, req, resp):
        h = '''
            ops dockerutil list -h 10.3.134.18  查看 10.3.134.18 的虚拟机列表
            ops dockerutil info -n test -h 10.3.134.18 查看 10.3.134.18 上的名为test的详情

            ops dockerutil create -m 8 -c 8 -d 100 -h 10.3.134.18 在10.3.134.18上创建100G磁盘8G内存8核cpu的虚拟机
            ops dockerutil delete -n test -h 10.3.134.18 删除 10.3.134.18 上的名为test的虚拟机
            ops dockerutil edit -n test -h 10.3.134.18 -m 8 -c 8 修改 10.3.134.18 上的名为test的虚拟机的cpu为8核内存8G

            ops dockerutil start -n test -h 10.3.134.18 开启 10.3.134.18 上的名为test的虚拟机
            ops dockerutil restart -n test -h 10.3.134.18 重启 10.3.134.18 上的名为test的虚拟机
            ops dockerutil shutdown -n test -h 10.3.134.18 关机 10.3.134.18 上的名为test的虚拟机

            ops dockerutil export -n test -h 10.3.134.18 查询 10.3.134.18 上的名为test的export情况
            ops dockerutil port -n test -h 10.3.134.18 查询 10.3.134.18 上的名为test的port情况

            ops dockerutil put_archive -n test -h 10.3.134.18 -p /test -d 1231 上传文件 10.3.134.18 上的名为test的虚拟机
            ops dockerutil get_archive -n test -h 10.3.134.18 -p /test 获取文件/test的内容 10.3.134.18 上的名为test的虚拟机
        '''
        return h

    def _client(self, req):
        base_url = req.get_param(name='h')
        tlscert = docker_config.get('tlscert')
        tlskey = docker_config.get('tlskey')
        tlscacert = docker_config.get('tlscacert')
        if tlscacert is None and tlscert is None and tlskey is None:
            return docker.Client(base_url=base_url)
        elif tlscacert is None and tlscert is not None and tlskey is not None:
            tls_config = docker.tls.TLSConfig(client_cert=(
                docker_config.get('tlscert'), docker_config.get('tlskey')))
        elif tlscacert is not None and tlscert is not None and tlskey is not None:
            tls_config = docker.tls.TLSConfig(
                client_cert=(docker_config.get('tlscert'),
                             docker_config.get('tlskey')),
                verify=docker_config.get('tlscacert'))
        elif tlscacert is not None and tlscert is None and tlskey is None:
            tls_config = docker.tls.TLSConfig(ca_cert=tlscacert)

        client = docker.Client(base_url=base_url, tls=tls_config)
        return client

    def list(self, req, resp):
        client = self._client(req)
        return client.containers()

    def stats(self, req, resp):
        client = self._client(req)
        return client.stats()

    def info(self, req, resp):
        client = self._client(req)
        container = req.get_param(name='n')
        if container is None:
            return '-n(container) need'
        return client.inspect_container(container=container)

    def create(self, req, resp):
        client = self._client(req)
        command = req.get_param(name='command')
        hostname = req.get_param(name='hostname')
        user = req.get_param(name='user')
        detach = req.get_param(name='detach')
        stdin_open = req.get_param(name='stdin_open')
        tty = req.get_param(name='tty')
        mem_limit = req.get_param(name='mem_limit')
        ports = req.get_param(name='ports')
        environment = req.get_param(name='environment')
        dns = req.get_param(name='dns')
        volumes = req.get_param(name='volumes')
        volumes_from = req.get_param(name='volumes_from')
        network_disabled = req.get_param(name='network_disabled')
        entrypoint = req.get_param(name='entrypoint')
        cpu_shares = req.get_param(name='cpu_shares')
        working_dir = req.get_param(name='working_dir')
        domainname = req.get_param(name='domainname')
        memswap_limit = req.get_param(name='memswap_limit')
        cpuset = req.get_param(name='cpuset')
        host_config = req.get_param(name='host_config')
        mac_address = req.get_param(name='mac_address')
        labels = req.get_param(name='labels')
        volume_driver = req.get_param(name='volume_driver')
        stop_signal = req.get_param(name='stop_signal')
        networking_config = req.get_param(name='networking_config')
        name = req.get_param(name='name')

        return client.create_container(
            image=self.image,
            command=command,
            hostname=hostname,
            user=user,
            detach=detach,
            stdin_open=stdin_open,
            tty=tty,
            mem_limit=mem_limit,
            ports=ports,
            environment=environment,
            dns=dns,
            volumes=volumes,
            volumes_from=volumes_from,
            network_disabled=network_disabled,
            name=name,
            entrypoint=entrypoint,
            cpu_shares=cpu_shares,
            working_dir=working_dir,
            domainname=domainname,
            memswap_limit=memswap_limit,
            cpuset=cpuset,
            host_config=host_config,
            mac_address=mac_address,
            labels=labels,
            volume_driver=volume_driver,
            stop_signal=stop_signal,
            networking_config=networking_config)

    def edit(self, req, resp):
        client = self._client(req)
        container = req.get_param(name='n')
        if container is None:
            return '-n(container) need'
        blkio_weight = req.get_param(name='blkio_weight')
        cpu_period = req.get_param(name='cpu_period')
        cpu_quota = req.get_param(name='cpu_quota')
        cpu_shares = req.get_param(name='cpu_shares')
        cpuset_cpus = req.get_param(name='cpuset_cpus')
        cpuset_mems = req.get_param(name='cpuset_mems')
        mem_limit = req.get_param(name='mem_limit')
        mem_reservation = req.get_param(name='mem_reservation')
        memswap_limit = req.get_param(name='memswap_limit')
        kernel_memory = req.get_param(name='kernel_memory')

        return client.update_container(
            container,
            blkio_weight=blkio_weight,
            cpu_period=cpu_period,
            cpu_quota=cpu_quota,
            cpu_shares=cpu_shares,
            cpuset_cpus=cpuset_cpus,
            cpuset_mems=cpuset_mems,
            mem_limit=mem_limit,
            mem_reservation=mem_reservation,
            memswap_limit=memswap_limit,
            kernel_memory=kernel_memory)

    def delete(self, req, resp):
        client = self._client(req)
        container = req.get_param(name='n')
        if container is None:
            return '-n(container) need'
        return client.kill(container=container)

    def start(self, req, resp):
        client = self._client(req)
        container = req.get_param(name='n')
        if container is None:
            return '-n(container) need'
        binds = req.get_param(name='b')
        port_bindings = req.get_param(name='p')
        links = req.get_param(name='l')
        privileged = req.get_param(name='r')
        volumes_from = req.get_param(name='v')
        network_mode = req.get_param(name='network_mode')
        restart_policy = req.get_param(name='restart_policy')
        cap_add = req.get_param(name='cap_add')
        cap_drop = req.get_param(name='cap_drop')
        devices = req.get_param(name='devices')
        extra_hosts = req.get_param(name='extra_hosts')
        read_only = req.get_param(name='read_only')
        pid_mode = req.get_param(name='pid_mode')
        ipc_mode = req.get_param(name='ipc_mode')
        security_opt = req.get_param(name='security_opt')
        ulimits = req.get_param(name='ulimits')
        lxc_conf = req.get_param(name='lxc_conf')
        publish_all_ports = req.get_param(name='publish_all_ports')
        dns_search = req.get_param(name='dns_search')
        dns = req.get_param(name='dns')
        return client.start(
            container=container,
            binds=binds,
            port_bindings=port_bindings,
            lxc_conf=lxc_conf,
            publish_all_ports=publish_all_ports,
            links=links,
            privileged=privileged,
            dns=dns,
            dns_search=dns_search,
            volumes_from=volumes_from,
            network_mode=network_mode,
            restart_policy=restart_policy,
            cap_add=cap_add,
            cap_drop=cap_drop,
            devices=devices,
            extra_hosts=extra_hosts,
            read_only=read_only,
            pid_mode=pid_mode,
            ipc_mode=ipc_mode,
            security_opt=security_opt,
            ulimits=ulimits)

    def restart(self, req, resp):
        client = self._client(req)
        container = req.get_param(name='n')
        if container is None:
            return '-n(container) need'
        return client.restart(container=container)

    def shutdown(self, req, resp):
        client = self._client(req)
        container = req.get_param(name='n')
        if container is None:
            return '-n(container) need'
        return client.stop(container=container)

    def export(self, req, resp):
        client = self._client(req)
        container = req.get_param(name='n')
        if container is None:
            return '-n(container) need'
        return client.export(container=container)

    def port(self, req, resp):
        client = self._client(req)
        container = req.get_param(name='n')
        if container is None:
            return '-n(container) need'
        return client.port(container=container)

    def put_archive(self, req, resp):
        client = self._client(req)
        path = req.get_param(name='p')
        data = req.get_param(name='d')
        if path is None:
            return '-p(path) need'
        if data is None:
            return '-d(data) need'
        container = req.get_param(name='n')
        if container is None:
            return '-n(container) need'
        return client.put_archive(container=container, path=path, data=data)

    def get_archive(self, req, resp):
        client = self._client(req)
        path = req.get_param(name='p')
        if path is None:
            return '-p(path) need'
        container = req.get_param(name='n')
        if container is None:
            return '-n(container) need'
        return client.get_archive(container=container, path=path)

    def rename(self, req, resp):
        client = self._client()
        return client.rename()

    def remove_container(self, req, resp):
        client = self._client()
        container = req.get_param(name='n')
        if container is None:
            return '-n(container) need'
        return client.remove_container(
            container=container, v=False, link=False, force=False)

    def remove_net(self, req, resp):
        client = self._client()
        net_id = req.get_param(name='i')
        if net_id is None:
            return '-i(net_id) need'
        return client.remove_network(net_id=net_id)

    def networks(self, req, resp):
        client = self._client(req)
        return client.networks(names=None, ids=None)

    def create_network(self, req, resp):
        client = self._client(req)
        container = req.get_param(name='n')
        if container is None:
            return '-n(container) need'
        return client.networks(
            container=container,
            driver=None,
            options=None,
            ipam=None,
            check_duplicate=None)

    def inspect_network(self, req, resp):
        client = self._client(req)
        net_id = req.get_param(name='i')
        if net_id is None:
            return '-i(net_id) need'
        return client.inspect_network(net_id=net_id)

    def connect_network(self, req, resp):
        client = self._client(req)
        container = req.get_param(name='n')
        ip4 = req.get_param(name='i')
        if container is None:
            return '-n(container) need'
        if ip4 is None:
            return '-i(ipv4) need'
        net_id = req.get_param(name='i')
        if net_id is None:
            return '-i(net_id) need'
        return client.networks(
            container=container,
            net_id=net_id,
            ipv4_address=ip4,
            ipv6_address=None,
            aliases=None,
            links=None)

    def disconnect_network(self, req, resp):
        client = self._client(req)
        container = req.get_param(name='n')
        if container is None:
            return '-n(container) need'
        net_id = req.get_param(name='i')
        if net_id is None:
            return '-i(net_id) need'
        return client.disconnect_container_from_network(
            container=container, net_id=net_id)

    def remove_volume(self, req, resp):
        client = self._client()
        name = req.get_param(name='n')
        if name is None:
            return '-n(name) need'
        return client.remove_volume(name=name)

    def create_volume(self, req, resp):
        client = self._client()
        name = req.get_param(name='n')
        if name is None:
            return '-n(name) need'

        driver = req.get_param(name='d')
        if driver is None:
            return '-d(driver) need'

        driver_opts = req.get_param(name='o')
        if driver_opts is None:
            return '-o(driver_opts) need'

        return client.create_volume(
            name=name, driver=driver, driver_opts=driver_opts)

    def inspect_volume(self, req, resp):
        client = self._client()
        name = req.get_param(name='n')
        if name is None:
            return '-n(name) need'
        return client.inspect_volume(name=name)

    def volumes(self, req, resp):
        client = self._client()
        return client.volumes()

    def logs(self, req, resp):
        client = self._client()
        container = req.get_param(name='n')
        if container is None:
            return '-n(container) need'
        return client.logs(
            container=container,
            stdout=True,
            stderr=True,
            stream=False,
            timestamps=False,
            tail='all',
            since=None,
            follow=None)
