#!/usr/bin/env bash

#修改系统里的某些配置 使得跟母机一致

yum install -y libguestfs-tools


#centos 6
if [ -f /var/lib/libvirt/images/centos6.qcow2 ]; then
    mkdir -p /mnt/centos6
    guestmount -a /var/lib/libvirt/images/centos6.qcow2 -i --rw /mnt/centos6

    \cp /etc/sysconfig/i18n /mnt/centos6/etc/sysconfig/i18n
    \cp /etc/resolv.conf /mnt/centos6/etc/resolv.conf
    \cp /etc/localtime /mnt/centos6/etc/localtime
    \cp /etc/sudoers /mnt/centos6/etc/sudoers
    \cp /etc/ntp.conf /mnt/centos6/etc/ntp.conf
    rm -rf /mnt/centos6/etc/udev/rules.d/70-persistent-net.rules

    if [ -f /etc/yum.repos.d/config.repo ]; then
        \cp /etc/yum.repos.d/config.repo /mnt/centos6/etc/yum.repos.d/config.repo
    fi

    if [ -f /root/.ssh/authorized_keys ]; then
        mkdir --mode=700 /mnt/root/.ssh
        \cp /root/.ssh/authorized_keys /mnt/centos6/root/.ssh/authorized_keys
        chmod 600 /mnt/centos6/root/.ssh/authorized_keys
    fi

    umount /mnt/centos6

fi



#centos 7
if [ -f /var/lib/libvirt/images/centos7.qcow2 ]; then
    umount /mnt
    mkdir -p /mnt/centos7
    guestmount -a /var/lib/libvirt/images/centos7.qcow2 -i --rw /mnt/centos7

    cp /etc/sysconfig/i18n /mnt/centos7/etc/sysconfig/i18n
    cp /etc/resolv.conf /mnt/centos7/etc/resolv.conf
    cp /etc/localtime /mnt/centos7/etc/localtime
    cp /etc/sudoers /mnt/centos7/etc/sudoers
    cp /etc/ntp.conf /mnt/centos7/etc/ntp.conf

    if [ -f /etc/yum.repos.d/config.repo ]; then
        cp /etc/yum.repos.d/config.repo /mnt/centos7/etc/yum.repos.d/config.repo
    fi

    if [ -f /root/.ssh/authorized_keys ]; then
        mkdir --mode=700 /mnt/root/.ssh
        cp /root/.ssh/authorized_keys /mnt/centos7/root/.ssh/authorized_keys
        chmod 600 /mnt/centos7/root/.ssh/authorized_keys
    fi

    umount /mnt/centos7

fi

