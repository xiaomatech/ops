#!/usr/bin/env bash

yum install -y docker-io docker-lvm-plugin #docker-volume-glusterfs docker-volume-ceph
#disable docker0 bridge
ip link set dev docker0 down
brctl delbr docker0

# create docker vg
devs=`for dev in /dev/sd?;do echo $dev;done|grep -v sda`
pvcreate $devs
vgcreate docker-pool $devs
vgchange -a y docker-pool
# Create Logical Volumes for Docker
lvcreate -Zy -n metadata -l 1%VG  docker-pool
lvcreate -Wy -n data     -l 49%VG docker-pool
lvcreate -Wy -n volumes  -l 50%VG docker-pool
mkfs.xfs /dev/docker-pool/volumes
echo '/dev/docker-pool/volumes /volumes xfs defaults,data=ordered,nodirtime,noatime,usrquota,grpquota 0 2' >>/etc/fstab

# enforce insecure registry
# Disable Red Hat registry and Docker.io registry, enable private registry
echo -ne "
DD_REGISTRY="--add-registry dockerhub.meizu.mz"
BLOCK_REGISTRY="--block-registry docker.io"
INSECURE_REGISTRY="--insecure-registry dockerhub.meizu.mz"
" >>/etc/sysconfig/docker

# Use direct LVM instead of loop LVM
sed -i /etc/sysconfig/docker-storage \
    -e '/DOCKER_STORAGE_OPTIONS=/ c\DOCKER_STORAGE_OPTIONS="--storage-opt dm.datadev=/dev/docker-pool/data --storage-opt dm.metadatadev=/dev/docker-pool/metadata --storage-opt dm.blocksize=512K --storage-opt dm.basesize=20G --storage-opt dm.fs=xfs --storage-opt dm.mountopt=nodiscard --storage-opt dm.blkdiscard=false"'

#config docker network
sed -i /etc/sysconfig/docker-network \
    -e '/DOCKER_STORAGE_OPTIONS=/ c\DOCKER_STORAGE_OPTIONS="--insecure-registry dockerhub.meizu.mz --iptables=false --bridge=none --dns=dns.meizu.mz"'

service docker start
service docker-lvm-plugin start
chkconfig docker on
chkconfig docker-lvm-plugin on