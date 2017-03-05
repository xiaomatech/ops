#!/usr/bin/env bash


#http://cbs.centos.org/repos/virt7-kvm-common-release/x86_64/os/Packages/
#qemu-kvm >=2.5 libvirt>=2.5 openvswitch>=2.6

yum install -y qemu-kvm libvirt bridge-utils lvm2 wget xfsprogs
sed -i 's/#LIBVIRTD_ARGS/LIBVIRTD_ARGS/g' /etc/sysconfig/libvirtd
sed -i 's/#listen_tls/listen_tls/g' /etc/libvirt/libvirtd.conf
sed -i 's/#listen_tcp/listen_tcp/g' /etc/libvirt/libvirtd.conf
sed -i 's/#auth_tcp/auth_tcp/g' /etc/libvirt/libvirtd.conf
sed -i 's/#vnc_listen/vnc_listen/g' /etc/libvirt/qemu.conf
sudo service libvirtd restart > /dev/null 2>&1
sudo service libvirt-guests restart > /dev/null 2>&1
sudo iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 16509 -j ACCEPT
sudo firewall-cmd --get-active-zones
sudo firewall-cmd --zone=public --add-port 16509/tcp --permanent
sudo firewall-cmd --reload
sudo chkconfig libvirtd on
sudo chkconfig libvirt-guests on

sudo service libvirtd start
virsh net-list
virsh net-destroy default
virsh net-undefine default

echo 325f6be6bf7e3e68d5b803068129673b|sudo saslpasswd2 -a libvirt -p ops

mkdir -p /data/kvm && chown -R qemu:qemu /data/kvm

sudo service libvirtd restart

