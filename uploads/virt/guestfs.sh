#!/usr/bin/env bash

name=$1
ip=$2
hostname=$3
hwaddr_em2=$4
hwaddr_em1=$5

netmask=255.255.255.0

x=`echo $ip | awk -F. '{print $1"."$2"."$3}'`
gateway="$x.1"

# 定义虚拟机, 否则无法根据域修改镜像.
virsh define /etc/libvirt/qemu/$name.xml || exit 1

# 修改系统镜像, 包括:
# 1. 修改主机名;
# 2. 修改网卡设置(增加HWADDR的原因是系统可以把eth变成em);
# 3. 修改路由信息;
# 4. 删除/etc/udev/rules.d/70-persistent-net.rules;
# 然后启动

guestfish --rw -d $name <<_EOF_
run
mount /dev/domovg/root /
mount /dev/datavg/home /home/
command "sed -i 's/HOSTNAME=.*/HOSTNAME=${hostname}/g' /etc/sysconfig/network"

write /etc/sysconfig/network-scripts/ifcfg-em2 "DEVICE=em2\nHWADDR=${hwaddr_em2}\nBOOTPROTO=static\nIPADDR=$ip\nNETMASK=$netmask\nONBOOT=yes\nTYPE=Ethernet"

write /etc/sysconfig/network-scripts/ifcfg-em1 "DEVICE=em1\nHWADDR=${hwaddr_em1}"

write /etc/sysconfig/network-scripts/route-em2 "192.168.0.0/16 via 10.19.28.1\n10.0.0.0/8 via 10.19.28.1\n100.64.0.0/16 via 10.19.28.1\n0.0.0.0/0 via 10.19.28.1"

command "/bin/rm -rf /etc/udev/rules.d/70-persistent-net.rules"
_EOF_