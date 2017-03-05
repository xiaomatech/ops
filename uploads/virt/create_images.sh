#!/usr/bin/env bash
#创建系统镜像

yum install -y wget virt-install

mkdir -p /data/kvm

#centos 6
qemu-img create -f qcow2 /tmp/centos6.qcow2 30G

wget wget http://mirrors.aliyun.com/centos/6.8/isos/x86_64/CentOS-6.8-x86_64-bin-DVD1.iso  -O /data/kvm/CentOS-6.8-x86_64-bin-DVD1.iso

virt-install --virt-type kvm --name centos6 --ram 2048 \
--disk /tmp/centos6.qcow2,format=qcow2 \
--network network=default \
--graphics vnc,listen=0.0.0.0 --noautoconsole \
--os-type=linux --os-variant=rhel6 \
--cdrom=/data/kvm/CentOS-6.8-x86_64-bin-DVD1.iso \
--force  --autostart

#然后通过vnc-viewer 连接 安装系统到/tmp/centos6.qcow2

#virsh undefine centos6


#centos 7
wget http://mirrors.aliyun.com/centos/7.2.1511/isos/x86_64/CentOS-7-x86_64-DVD-1511.iso -O /data/kvm/CentOS-7-x86_64-DVD-1511.iso
qemu-img create -f qcow2 /tmp/centos7.qcow2 30G

virt-install --virt-type kvm --name centos7 --ram 2048 \
--disk /tmp/centos7.qcow2,format=qcow2 \
--network network=default \
--graphics vnc,listen=0.0.0.0 --noautoconsole \
--os-type=linux --os-variant=rhel7 \
--cdrom=/data/kvm/CentOS-7-x86_64-DVD-1511.iso \
--force  --autostart

#然后通过vnc-viewer 连接 安装系统到/tmp/centos7.qcow2

#virsh undefine centos7