#!/usr/bin/env python
# -*- coding:utf8 -*-

from library.kvm import *
from models.virt import *
from models.cmdb import *
from configs import kvm_config
from helpers.logger import *
from helpers.common import ssh_remote_execute


class kvm:
    def __init__(self):
        self.login = kvm_config.get('user')
        self.passwd = kvm_config.get('password')
        self.conn = 1
        self.strategy = ['max_use', 'diffrent_rack', 'diffrent_server']

    def help(self, req, resp):
        h = '''
                                    kvm管理(母机通过 uploads/virt/install_kvm.sh 安装libvirt等设置环境后再操作)

            ops kvm list_vm -h 172.16.119.180  查看 172.16.119.180 的虚拟机列表
            ops kvm info_vm -n test -h 172.16.119.180 查看 172.16.119.180 上的名为test的详情

            ops kvm create_instances --flavor v1 -c 10 --strategy default 创建10台v1的机器 默认分布在不同机柜
            ops kvm create_instance --flavor v1 -h 172.16.119.180 在172.16.119.180上创建机型为v1的虚拟机
            ops kvm del_instance -n test -h 172.16.119.180 删除 172.16.119.180 上的名为test的虚拟机
            ops kvm edit_instance -n test -h 172.16.119.180 -m 8 -c 8 修改 172.16.119.180 上的名为test的虚拟机的cpu为8核内存8G

            ops kvm clone_instance --flavor v1 -n test -h 172.16.119.180 克隆 172.16.119.180 上的名为test的虚拟机

            ops kvm migrate -n test -h 172.16.119.180 -t 10.3.134.19 迁移 172.16.119.180 上的名为test的虚拟机 到 10.3.134.19

            ops kvm start -n instance1 -h 172.16.119.180
            ops kvm restart -n instance1 -h 172.16.119.180
            ops kvm shutdown -n instance1 -h 172.16.119.180

            ops kvm net_device -n test -h 172.16.119.180
            ops kvm disk_device -n test -h 172.16.119.180
            ops kvm disk_usage -n test -h 172.16.119.180

            ops kvm list_storage_pool -h 172.16.119.180
            ops kvm create_storage_pool --storage_pool storage_pool --source /dev/vdc,/dev/vdd -h 172.16.119.180
            ops kvm del_storage_pool --storage_pool storage_pool -h 172.16.119.180
            ops kvm info_storage_pool --storage_pool storage_pool -h 172.16.119.180

            ops kvm list_volume --storage_pool storage_pool -h 172.16.119.180
            ops kvm info_volume --storage_pool storage_pool --volume_name test_volume -h 172.16.119.180
            ops kvm creaete_volume --storage_pool storage_pool --volume_name test_volume --disksize 10 -h 172.16.119.180
            ops kvm del_volume --storage_pool storage_pool --volume_name test_volume -h 172.16.119.180
            ops kvm clone_volume --from test --to test_clone --storage_pool storage_pool -h 172.16.119.180
            ops kvm update_volumes --storage_pool storage_pool -h 172.16.119.180

            ops kvm create_snapshot -s test_snapshot -n test -h 172.16.119.180 创建 172.16.119.180 上的名为test的虚拟机的快照
            ops kvm get_snapshot -n test -h 172.16.119.180 获取 172.16.119.180 上的名为test的虚拟机的快照详情
            ops kvm del_snapshot -s instance_snapshot -n test -h 172.16.119.180 删除 172.16.119.180 上的名为snapshot_test的快照
            ops kvm rever_snapshot -n test -s test_snapshot -h 172.16.119.180
            ops kvm list_snapshot -h 172.16.119.180
            ops kvm list_strategy 查看支持的创建虚拟机的分布策略

            ops kvm list_flavor 查看机型列表
            ops kvm add_flavor --label v1 -c 8 -m 8 -d 100 添加名为v1的8G内存100G硬盘8个cpu机型
            ops kvm edit_flavor --label v2 -c 8 -m 8 -d 100 修改名为v2的8G内存100G硬盘8个cpu机型
            ops kvm del_flavor --label v1 删除v1机型

            ops kvm list_network -h 172.16.119.180
            ops kvm list_iface -h 172.16.119.180
            ops kvm info_iface -n br0 -h 172.16.119.180
            ops kvm destroy_iface -n br205 -h 172.16.119.180
            ops kvm create_iface --itype bridge --iface_name br205 --netdev eth3 --ipv4_addr 10.3.205.33/24 --vlan_id 205 -h 172.16.119.180
            ops kvm create_iface --itype bridge --iface_name br204 --netdev eth4 --ipv4_addr 10.3.204.34/24 -h 172.16.119.180
            ops kvm create_iface --itype bond --iface_name bond0 --netdev eth4,eth5 --ipv4_addr 10.3.205.33/24 -h 172.16.119.180
        '''
        return h

    def del_flavor(self, req, resp):
        label = req.get_param(name='label')
        if label is None:
            return '--label(label) need'
        query = Flavor.delete().where(Flavor.label == label)
        return query.execute()

    def edit_flavor(self, req, resp):
        label = req.get_param(name='label')
        cpu = req.get_param(name='c')
        memory = req.get_param(name='m')
        disk = req.get_param(name='d')
        if label is None:
            return '--label(label) need'
        if cpu is None:
            return '-c(cpu) need'
        if memory is None:
            return '-m(memory) need'
        if disk is None:
            return '-d(disk) need'
        query = Flavor.update(
            vcpu=cpu, memory=memory, disk=disk).where(Flavor.label == label)
        return query.execute()

    def add_flavor(self, req, resp):
        label = req.get_param(name='label')
        cpu = req.get_param(name='c')
        memory = req.get_param(name='m')
        disk = req.get_param(name='d')
        if label is None:
            return '--label(label) need'
        if cpu is None:
            return '-c(cpu) need'
        if memory is None:
            return '-m(memory) need'
        if disk is None:
            return '-d(disk) need'
        flavor = Flavor()
        flavor.label = label
        flavor.vcpu = cpu
        flavor.memory = memory
        flavor.disk = disk
        return flavor.save()

    def list_flavor(self, req, resp):
        flavor = Flavor.select()
        result = []
        for item in flavor:
            result.append({
                'label': item.label,
                'memory': item.memory,
                'cpu': item.vcpu,
                'disk': item.disk,
            })
        return result

    def list_strategy(self, req, resp):
        return self.strategy

    def _get_client(self, req, instance_count=1, room=None,
                    strategy='max_use'):
        if instance_count > 1:
            result = []
            res = Ip.select().join(Device,on=(Device.assets==Ip.assets)) \
                .join(DeviceTemplate,on=(DeviceTemplate.template==Device.template)) \
                .join(Room,on=(Device.room==Room.room)) \
                .where((DeviceTemplate.server_type=='server') & (Device.logic_area=='virt')
                       & (Room.room_name_en==room) & (Device.device_status=='online')) \
                .limit(instance_count)

            for item in res:
                host = item.ip
                result.append(host)
            return result
        else:
            host = req.get_param(name='h')
            if host is None:
                log_error('-h(host) need')
                raise Exception('-h(host) need')
            return host

    def del_snapshot(self, req, resp):
        vm_name = req.get_param(name='n')
        snapshot_name = req.get_param(name='s')
        if vm_name is None:
            return '-n(vm_name) need'
        if snapshot_name is None:
            return '-s(snapshot_name) need'
        host = req.get_param(name='h')
        if host is None:
            return '-h(host) need'
        host = self._get_client(req)
        instance = wvmInstance(host=host, conn=self.conn, vname=vm_name)
        return instance.snapshot_delete(snapshot=snapshot_name)

    def rever_snapshot(self, req, resp):
        vm_name = req.get_param(name='n')
        snapshot_name = req.get_param(name='s')
        if vm_name is None:
            return '-n(vm_name) need'
        if snapshot_name is None:
            return '-s(snapshot_name) need'
        host = req.get_param(name='h')
        if host is None:
            return '-h(host) need'
        host = self._get_client(req)
        instance = wvmInstance(host=host, conn=self.conn, vname=vm_name)
        instance.snapshot_revert(snapshot_name)
        msg = "Successful revert snapshot: " + snapshot_name
        return msg

    def get_snapshot(self, req, resp):
        vm_name = req.get_param(name='n')
        if vm_name is None:
            return '-n(vm_name) need'
        host = req.get_param(name='h')
        if host is None:
            return '-h(host) need'
        host = req.get_param(name='h')
        if host is None:
            return '-h(host) need'
        host = self._get_client(req)
        instance = wvmInstance(host=host, conn=self.conn, vname=vm_name)
        return instance.get_snapshot()

    def list_snapshot(self, req, resp):
        host = req.get_param(name='h')
        if host is None:
            return '-h(host) need'
        host = self._get_client(req)
        instance = wvmConnect(host=host, conn=self.conn)
        return instance.get_snapshots()

    def create_snapshot(self, req, resp):
        host = req.get_param(name='h')
        if host is None:
            return '-h(host) need'
        vm_name = req.get_param(name='n')
        snapshot_name = req.get_param(name='s')
        if vm_name is None:
            return '-n(vm_name) need'
        if snapshot_name is None:
            return '-s(snapshot_name) need'
        host = self._get_client(req)
        instance = wvmInstance(host=host, conn=self.conn, vname=vm_name)
        return instance.create_snapshot(snapshot_name)

    def start(self, req, resp):
        host = req.get_param(name='h')
        if host is None:
            return '-h(host) need'
        vname = req.get_param(name='n')
        if vname is None:
            return '-n(vname) need'
        host = self._get_client(req)
        instance = wvmInstance(host=host, conn=self.conn, vname=vname)
        return instance.start()

    def restart(self, req, resp):
        host = req.get_param(name='h')
        if host is None:
            return '-h(host) need'
        vname = req.get_param(name='n')
        if vname is None:
            return '-n(vname) need'
        host = self._get_client(req)
        instance = wvmInstance(host=host, conn=self.conn, vname=vname)
        if instance.get_status() == 1:
            instance.force_shutdown()
        return instance.start()

    def shutdown(self, req, resp):
        host = req.get_param(name='h')
        if host is None:
            return '-h(host) need'
        vname = req.get_param(name='n')
        if vname is None:
            return '-n(vname) need'
        host = self._get_client(req)
        instance = wvmInstance(host=host, conn=self.conn, vname=vname)
        return instance.force_shutdown()

    def net_device(self, req, resp):
        host = req.get_param(name='h')
        if host is None:
            return '-h(host) need'
        vname = req.get_param(name='n')
        if vname is None:
            return '-n(vname) need'
        host = self._get_client(req)
        instance = wvmInstance(host=host, conn=self.conn, vname=vname)
        return instance.get_net_device()

    def disk_device(self, req, resp):
        host = req.get_param(name='h')
        if host is None:
            return '-h(host) need'
        vname = req.get_param(name='n')
        host = self._get_client(req)
        instance = wvmInstance(host=host, conn=self.conn, vname=vname)
        return instance.get_disk_device()

    def disk_usage(self, req, resp):
        host = req.get_param(name='h')
        if host is None:
            return '-h(host) need'
        vname = req.get_param(name='n')
        if vname is None:
            return '-n(vname) need'
        host = self._get_client(req)
        instance = wvmInstance(host=host, conn=self.conn, vname=vname)
        return instance.disk_usage()

    def list_vm(self, req, resp):
        host = req.get_param(name='h')
        if host is None:
            return '-h(host) need'
        host = self._get_client(req)
        instance = wvmConnect(host=host, conn=self.conn)
        return instance.get_instances()

    def info_vm(self, req, resp):
        host = req.get_param(name='h')
        if host is None:
            return '-h(host) need'
        host = self._get_client(req)
        vname = req.get_param(name='n')
        if vname is None:
            return '-n(vname) need'
        instance = wvmConnect(host=host, conn=self.conn)
        dom = instance.get_instance(name=vname)
        return {dom.name(): dom.info()}

    def list_storage_pool(self, req, resp):
        host = req.get_param(name='h')
        if host is None:
            return '-h(host) need'
        host = self._get_client(req)
        instance = wvmStorages(host=host, conn=self.conn)
        return instance.get_storages_info()

    def info_storage_pool(self, req, resp):
        host = req.get_param(name='h')
        if host is None:
            return '-h(host) need'
        host = self._get_client(req)
        storage_pool = req.get_param(
            name='storage_pool') or kvm_config.get('volume_group')
        if storage_pool is None:
            return '--storage_pool(storage_pool) need'
        instance = wvmStorage(host=host, conn=self.conn, pool=storage_pool)
        return instance.info()

    def list_network(self, req, resp):
        host = req.get_param(name='h')
        if host is None:
            return '-h(host) need'
        host = self._get_client(req)
        instance = wvmNetworks(host=host, conn=self.conn)
        return instance.get_networks_info()

    def list_iface(self, req, resp):
        host = req.get_param(name='h')
        if host is None:
            return '-h(host) need'
        host = self._get_client(req)
        instance = wvmConnect(host=host, conn=self.conn)
        return instance.get_ifaces()

    def info_iface(self, req, resp):
        host = req.get_param(name='h')
        if host is None:
            return '-h(host) need'
        host = self._get_client(req)
        vname = req.get_param(name='n')
        if vname is None:
            return '-n(vname) need'
        instance = wvmInterfaces(host=host, conn=self.conn)
        return instance.get_iface_info(name=vname)

    def destroy_iface(self, req, resp):
        host = req.get_param(name='h')
        if host is None:
            return '-h(host) need'
        host = self._get_client(req)
        vname = req.get_param(name='n')
        if vname is None:
            return '-n(vname) need'
        instance = wvmInterface(host=host, conn=self.conn, iface=vname)
        instance.stop_iface()
        return instance.delete_iface()

    def list_net_device(self, req, resp):
        host = req.get_param(name='h')
        if host is None:
            return '-h(host) need'
        host = self._get_client(req)
        instance = wvmConnect(host=host, conn=self.conn)
        return instance.get_net_device()

    def memory_usage(self, req, resp):
        host = req.get_param(name='h')
        if host is None:
            return '-h(host) need'
        host = self._get_client(req)
        instance = wvmHostDetails(host=host, conn=self.conn)
        return instance.get_memory_usage()

    def cpu_usage(self, req, resp):
        host = req.get_param(name='h')
        if host is None:
            return '-h(host) need'
        host = self._get_client(req)
        instance = wvmHostDetails(host=host, conn=self.conn)
        return instance.get_cpu_usage()

    def node_info(self, req, resp):
        host = req.get_param(name='h')
        if host is None:
            return '-h(host) need'
        host = self._get_client(req)
        instance = wvmHostDetails(host=host, conn=self.conn)
        return instance.get_node_info()

    def migrate(self, req, resp):
        host = req.get_param(name='h')
        if host is None:
            return '-h(host) need'
        name = req.get_param(name='n')
        host = self._get_client(req)
        to_host = req._params['t']
        if name is None:
            return '-n(name) need'
        if to_host is None:
            return '-t(to_host) need'
        undefine = kvm_config.get('migrate_undefine')
        unsafe = kvm_config.get('migrate_unsafe')
        live = kvm_config.get('migrate_live')
        instance = wvmInstance(host=host, conn=self.conn, vname=name)
        to_instance = wvmInstances(host=to_host, conn=self.conn)
        return to_instance.moveto(
            conn=instance,
            name=name,
            live=live,
            unsafe=unsafe,
            undefine=undefine)

    def create_storage_pool(self, req, resp):
        host = req.get_param(name='h')
        if host is None:
            return '-h(host) need'
        host = self._get_client(req)
        name = req.get_param(
            name='storage_pool') or kvm_config.get('volume_group')
        storage_type = req.get_param(name='storage_type') or 'default'
        stg_type = req.get_param(name='stg_type') or 'logical'
        source = req.get_param(name='source')
        target = req.get_param(name='target')
        ceph_pool = req.get_param(name='ceph_pool')
        ceph_host = req.get_param(name='ceph_host')
        ceph_user = req.get_param(name='ceph_user')
        secret = req.get_param(name='secret')
        netfs_host = req.get_param(name='netfs_host')
        source_format = req.get_param(name='source_format')
        if name is None:
            return '--name(name) need'
        if stg_type is None:
            return '--stg_type(stg_type) need'
        if target is None:
            target = name

        instance = wvmStorages(host=host, conn=self.conn)
        if storage_type == 'ceph':
            return instance.create_storage_ceph(stg_type, name, ceph_pool,
                                                ceph_host, ceph_user, secret)
        elif storage_type == 'netfs':
            return instance.create_storage_netfs(stg_type, name, netfs_host,
                                                 source, source_format, target)
        else:
            return instance.create_storage(stg_type, name, source, target)

    def creaete_volume(self, req, resp):
        host = req.get_param(name='h')
        if host is None:
            return '-h(host) need'
        host = self._get_client(req)
        storage_pool = req.get_param(
            name='storage_pool') or kvm_config.get('volume_group')
        volume_name = req.get_param(
            name='volume_name') or req.get_param('name')
        if storage_pool is None:
            return '--storage_pool(storage_pool) need'
        if volume_name is None:
            return '--volume_name(volume_name) need'
        disksize = req.get_param(name='disksize') or kvm_config.get('disksize')
        format = req.get_param(name='format') or 'xfs'
        return self._create_volume(
            host=host,
            volume_name=volume_name,
            disksize=disksize,
            storage_pool=storage_pool,
            format=format)

    def update_volumes(self, req, resp):
        host = req.get_param(name='h')
        if host is None:
            return '-h(host) need'
        host = self._get_client(req)
        storage_pool = req.get_param(
            name='storage_pool') or kvm_config.get('volume_group')
        if storage_pool is None:
            return '--storage_pool(storage_pool) need'
        instance = wvmStorage(host=host, conn=self.conn, pool=storage_pool)
        return instance.update_volumes()

    def clone_volume(self, req, resp):
        host = req.get_param(name='h')
        if host is None:
            return '-h(host) need'
        host = self._get_client(req)
        storage_pool = req.get_param(
            name='storage_pool') or kvm_config.get('volume_group')
        if storage_pool is None:
            return '--storage_pool(storage_pool) need'
        name = req.get_param(name='from')
        if name is None:
            return '--from(from) need'
        clone = req.get_param(name='to')
        if clone is None:
            return '--to(to) need'
        instance = wvmStorage(host=host, conn=self.conn, pool=storage_pool)
        return instance.clone_volume(name, clone, vol_fmt=None, metadata=False)

    def del_storage_pool(self, req, resp):
        host = req.get_param(name='h')
        if host is None:
            return '-h(host) need'
        host = self._get_client(req)
        storage_pool = req.get_param(
            name='storage_pool') or kvm_config.get('volume_group')
        if storage_pool is None:
            return '--storage_pool(storage_pool) need'
        instance = wvmStorage(host=host, conn=self.conn, pool=storage_pool)
        instance.stop()
        instance.destroy()
        return instance.delete()

    def list_volume(self, req, resp):
        host = req.get_param(name='h')
        if host is None:
            return '-h(host) need'
        host = self._get_client(req)
        storage_pool = req.get_param(
            name='storage_pool') or kvm_config.get('volume_group')
        if storage_pool is None:
            return '--storage_pool(storage_pool) need'
        instance = wvmStorage(host=host, conn=self.conn, pool=storage_pool)
        return instance.get_volumes()

    def info_volume(self, req, resp):
        host = req.get_param(name='h')
        if host is None:
            return '-h(host) need'
        host = self._get_client(req)
        storage_pool = req.get_param(
            name='storage_pool') or kvm_config.get('volume_group')
        volume_name = req.get_param(
            name='volume_name') or req.get_param('name')
        if storage_pool is None:
            return '--storage_pool(storage_pool) need'
        if volume_name is None:
            return '--volume_name(volume_name) need'
        instance = wvmStorage(host=host, conn=self.conn, pool=storage_pool)
        volume = instance.get_volume(name=volume_name)
        return volume.info()

    def del_volume(self, req, resp):
        host = req.get_param(name='h')
        if host is None:
            return '-h(host) need'
        host = self._get_client(req)
        storage_pool = req.get_param(
            name='storage_pool') or kvm_config.get('volume_group')
        volume_name = req.get_param(
            name='volume_name') or req.get_param('name')
        if storage_pool is None:
            return '--storage_pool(storage_pool) need'
        if volume_name is None:
            return '--volume_name(volume_name) need'
        instance = wvmStorage(host=host, conn=self.conn, pool=storage_pool)
        return instance.del_volume(name=volume_name)

    def _create_volume(self,
                       host,
                       volume_name,
                       disksize,
                       storage_pool=kvm_config.get('volume_group'),
                       format='qcow2',
                       metadata=False):
        if storage_pool is None:
            return '--storage_pool(storage pool) need'
        if volume_name is None:
            return '--volume_name(volume_name) need'
        if disksize is None:
            return '--disksize(disksize G) need'
        try:
            instance = wvmCreate(host=host, conn=self.conn)

            #check exist
            exist = instance.get_volume_path(volume=volume_name)
            if exist:
                return volume_name
            instance.create_volume(
                storage=storage_pool,
                name=volume_name,
                size=disksize,
                format=format,
                metadata=metadata)
            if format in ['xfs', 'ext4']:
                ssh_result = ssh_remote_execute(
                    host=host,
                    cmd="sudo mkfs.%s %s" %
                    (format, '/dev/' + storage_pool + '/' + volume_name))
                if ssh_result is None:
                    raise Exception('copy base dir %s error' % '/dev/' +
                                    storage_pool + '/' + volume_name)
            return volume_name
        except Exception as e:
            log_error(e)
            raise Exception(e)

    def create_iface(self, req, resp):
        host = req.get_param(name='h')
        if host is None:
            return '-h(host) need'
        host = self._get_client(req)
        itype = req.get_param(name='itype') or 'bridge'
        iface_name = req.get_param(name='iface_name')
        netdev = req.get_param(name='netdev') or kvm_config.get('netdev')
        ipv4_type = req.get_param(name='ipv4_type') or 'static'
        ipv4_addr = req.get_param(name='ipv4_addr')
        vlan_id = req.get_param(name='vlan_id')
        bond_mode = req.get_param(
            name='bond_mode') or kvm_config.get('bond_mode')
        return self._create_network(
            host=host,
            itype=itype,
            iface_name=iface_name,
            netdev=netdev,
            ipv4_type=ipv4_type,
            ipv4_addr=ipv4_addr,
            vlan_id=vlan_id,
            bond_mode=bond_mode)

    def _create_network(self,
                        host,
                        iface_name,
                        ipv4_addr,
                        vlan_id,
                        itype,
                        netdev,
                        ipv4_type,
                        bond_mode=None):
        if iface_name is None:
            return '--iface_name(iface_name) need'
        if netdev is None:
            return '--netdev(netdev) need'
        if ipv4_type is None:
            return '--ipv4_type(ipv4_type) need'
        if ipv4_addr is None:
            return '--ipv4_addr(ipv4_addr) need'

        netdev_list = netdev.split(',')
        if len(netdev) == 1:
            netdev = netdev_list[0]
        try:
            inter_instance = wvmInterfaces(host=host, conn=self.conn)

            #check exist
            try:
                exist = inter_instance.get_iface(name=iface_name)
                if exist:
                    return iface_name
            except Exception as e:
                log_error(e)
                inter_instance.create_iface(
                    name=iface_name,
                    itype=itype,
                    netdev=netdev,
                    vlan_id=vlan_id,
                    bond_mode=bond_mode,
                    ipv4_type=ipv4_type,
                    ipv4_addr=ipv4_addr)
                return iface_name
        except Exception as e:
            log_error(e)
            raise Exception(e)

    def __get_cpu_memory_disksize(self, flavor=None):
        if flavor is None:
            log_error(' flavor is empty')
            raise Exception(' flavor is empty')
        result = Flavor.select().where(Flavor.label == flavor)
        return result[0].vcpu, result[0].memory, result[0].disk

    def _get_ip(self, network_pool=None, count=1, room=None):
        result = []
        if network_pool is None:
            if room is not None:
                res = SegmentIpPool.select().join(Segment,on=(Segment.segment==SegmentIpPool.segment)).\
                    join(Room,on=(Room.room==Segment.room)).\
                    where((Room.room_name_en == room) & (Segment.status == 'enable') & (Segment.logic_area == 'virt') and (Segment.ip_type == 'internal') ).\
                    order_by(Segment.assigned.asc()).limit(count)
            else:
                res = SegmentIpPool.select().join(Segment,on=(Segment.segment==SegmentIpPool.segment)). \
                    where((Segment.status == 'enable') & (Segment.logic_area == 'virt') and (Segment.ip_type == 'internal') ). \
                    order_by(Segment.assigned.asc()).limit(count)

        else:
            segment_ip = network_pool.split('/')[0]
            if room is not None:
                res = SegmentIpPool.select().join(Segment,on=(Segment.segment==SegmentIpPool.segment)). \
                    join(Room,on=(Room.room==Segment.room)). \
                    where((Room.room_name_en == room) & (Segment.segment_ip == segment_ip) & (Segment.status == 'enable') & (Segment.logic_area == 'virt')
                          and (Segment.ip_type == 'internal')). \
                    order_by(Segment.assigned.asc()).limit(count)
            else:
                res = SegmentIpPool.select().join(Segment,on=(Segment.segment==SegmentIpPool.segment)). \
                    where((Segment.segment_ip == segment_ip) & (Segment.status == 'enable') & (Segment.logic_area == 'virt')
                          and (Segment.ip_type == 'internal')). \
                    order_by(Segment.assigned.asc()).limit(count)

        ip = {}
        for item in res:
            ip['ipv4_addr'] = item.ip
            ip['ipv4_gw'] = item.segment.gateway
            result.append(ip)
        return result

    def create_instances(self, req, resp):
        host = req.get_param(name='h')
        if host is None:
            return '-h(host) need'
        name = req.get_param(name='n')
        flavor = req.get_param(name='flavor')
        instance_count = req.get_param(name='instance_count')
        network_pool = req.get_param(name='network_pool')
        room = req.get_param(name='r')
        strategy = req.get_param(name='s') or 'max_use'
        root_image = req.get_param(
            name='root_image') or kvm_config.get('root_images_template')
        if name is None:
            return '-n(name) need'
        if flavor is None:
            return '--flavor(flavor) need'
        if instance_count is None or int(instance_count) < 1:
            return '--instance_count(instance_count) need'

        storage_pool = req.get_param(
            name='storage_pool') or kvm_config.get('volume_group')

        bridge = req.get_param(name='bridge') or kvm_config.get('bridge')
        netdev = req.get_param(name='netdev') or kvm_config.get('netdev')
        vlan_id = req.get_param(name='vlan_id')

        hosts = self._get_client(
            req, instance_count=instance_count, room=room, strategy=strategy)
        ips = self._get_ip(
            network_pool=network_pool, count=instance_count, room=room)

        if len(ips) < instance_count:
            return 'not have enough IP ,only have %d IP' % len(ips)
        if len(hosts) < instance_count:
            return 'not have enough host ,only have %d host' % len(hosts)

        result = []
        try:
            for key, item in enumerate(hosts):
                res = self.__create_instance_common(
                    host=item,
                    name=name + '_' + key,
                    flavor=flavor,
                    ipv4_addr=ips[key].ipv4_addr,
                    root_image=root_image,
                    storage_pool=storage_pool,
                    bridge=bridge,
                    netdev=netdev,
                    vlan_id=vlan_id)
                result.append(res)
            return result
        except Exception as e:
            log_error(e)
            raise Exception(e)

    def create_instance(self, req, resp):
        name = req.get_param(name='n')
        flavor = req.get_param(name='flavor')
        network_pool = req.get_param(name='network_pool')
        ipv4_addr = req.get_param(name='ipv4_addr')
        ipv4_gw = req.get_param(name='ipv4_gw')

        room = req.get_param(name='r')
        root_image = req.get_param(
            name='root_image') or kvm_config.get('root_images_template')

        if network_pool is not None:
            ips = self._get_ip(network_pool=network_pool, room=room)
            ipv4_addr = ips[0]['ipv4_addr']
            ipv4_gw = ips[0]['ipv4_gw']
        if name is None:
            return '-n(name) need'
        if flavor is None:
            return '--flavor(flavor) need'
        if ipv4_addr is None:
            return '--ipv4_addr(ipv4_addr) need'
        host = self._get_client(req, room=room)

        storage_pool = req.get_param(
            name='storage_pool') or kvm_config.get('volume_group')

        bridge = req.get_param(name='bridge') or kvm_config.get('bridge')
        netdev = req.get_param(name='netdev') or kvm_config.get('netdev')
        vlan_id = req.get_param(name='vlan_id')

        result = []
        try:
            res = self.__create_instance_common(
                host=host,
                name=name,
                flavor=flavor,
                ipv4_addr=ipv4_addr,
                root_image=root_image,
                storage_pool=storage_pool,
                bridge=bridge,
                netdev=netdev,
                vlan_id=vlan_id)
            result.append(res)
            return result
        except Exception as e:
            log_error(e)
            raise Exception(e)

    def __create_instance_common(self,
                                 host,
                                 name,
                                 flavor,
                                 ipv4_addr,
                                 root_image,
                                 storage_pool,
                                 bridge,
                                 netdev,
                                 vlan_id,
                                 format='xfs',
                                 metadata=False):
        uuid = util.randomUUID()
        mac = util.randomMAC()
        if flavor is None:
            return '--flavor(flavor) need'
        if host is None:
            return '-h(host) need'
        if name is None:
            return '-n(name) need'
        if ipv4_addr is None:
            return '--ipv4_addr(ipv4_addr) need'
        instance = wvmCreate(host=host, conn=self.conn)
        vcpu, memory, disksize = self.__get_cpu_memory_disksize(flavor=flavor)

        if vcpu is None:
            return '-c(vcpu) need'
        if memory is None:
            return '-d(memory) need'
        try:

            ###network
            self._create_network(
                host=host,
                itype='bridge',
                iface_name=bridge,
                netdev=netdev,
                ipv4_type='static',
                ipv4_addr=ipv4_addr,
                vlan_id=vlan_id)
            ###volume
            self._create_volume(
                host=host,
                volume_name=name,
                disksize=disksize,
                storage_pool=storage_pool,
                format=format)
            #copy base_image
            base_dir = kvm_config.get('kvm_data_rootdir') + '/' + name
            base_image = base_dir + '/' + uuid + '.qcow2'
            ssh_result = ssh_remote_execute(
                host=host,
                cmd="sudo mkdir -p %s && sudo cp %s %s && sudo chown -R qemu:qemu %s"
                % (base_dir, root_image, base_image, base_dir))
            if ssh_result is None:
                raise Exception('copy base dir %s error' % base_dir)
            root_image = base_image

            ###create
            instance.create_instance(
                name=name,
                vcpu=vcpu,
                memory=memory,
                root_image=root_image,
                uuid=uuid,
                mac=mac,
                bridge=bridge)
            vminstance = wvmInstance(host=host, conn=self.conn, vname=name)
            vminstance.start()
            vminstance.set_autostart(flag=2)
            return {
                'name': name,
                'uuid': uuid,
                'vcpu': vcpu,
                'memory': memory,
                'disksize': disksize,
                'mac': mac,
                'metal': host
            }
        except Exception as e:
            log_error(e)
            raise Exception(e)

    def clone_instance(self, req, resp):
        host = req.get_param(name='h')
        if host is None:
            return '-h(host) need'
        host = self._get_client(req)
        vname = req.get_param(name='n')
        clone_data = {}
        clone_data['name'] = req.get_param(name='clone_name')
        clone_data['disk'] = req.get_param(name='disk')
        clone_data['meta'] = req.get_param(name='meta')
        if vname is None:
            return '-n(vname) need'
        if clone_data['name'] is None:
            return '--clone_name(clone_name) need'
        if clone_data['disk'] is None:
            del (clone_data['disk'])
        if clone_data['meta'] is None:
            del (clone_data['meta'])

        instance = wvmInstance(host=host, conn=self.conn, vname=vname)
        return instance.clone_instance(clone_data=clone_data)

    def edit_instance(self, req, resp):
        host = req.get_param(name='h')
        if host is None:
            return '-h(host) need'
        host = self._get_client(req)
        vname = req.get_param(name='n')
        description = req.get_param(name='d')
        cur_memory = req.get_param(name='cur_memory')
        memory = req.get_param(name='m')
        cur_vcpu = req.get_param(name='cur_vcpu')
        vcpu = req.get_param(name='c')
        if vname is None:
            return '-n(vname) need'
        if description is None:
            return '-d(description) need'
        if cur_memory is None:
            return '--cur_memory(cur_memory) need'
        if memory is None:
            return '-m(memory) need'
        if cur_vcpu is None:
            return '--cur_vcpu(cur_vcpu) need'
        if vcpu is None:
            return '--vcpu(vcpu) need'

        instance = wvmInstance(host=host, conn=self.conn, vname=vname)
        return instance.change_settings(
            description=description,
            cur_memory=cur_memory,
            memory=memory,
            cur_vcpu=cur_vcpu,
            vcpu=vcpu)
