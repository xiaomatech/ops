#!/usr/bin/env bash

#镜像压缩

#centos 6
virsh start centos6
virsh console centos6

dd if=/dev/zero of=/zerofile
rm /zerofile

virsh shutdown centos6
qemu-img convert -c -O qcow2 /tmp/centos6.qcow2 /tmp/centos6_compress.qcow2

#centos 7
virsh start centos7
virsh console centos7

dd if=/dev/zero of=/zerofile
rm /zerofile

virsh shutdown centos7
qemu-img convert -c -O qcow2 /tmp/centos7.qcow2 /tmp/centos7_compress.qcow2