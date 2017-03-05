#!/bin/bash
#
#
# NOTE
# 1. when creating vf, the NIC driver need to be restarted
# the network may be LOST temporarily
#

function check_ovs
{
    echo "checking openvswitch"
    if service openvswitch status; then
        echo "ovs installed"
        echo "ovs and sr-iov can't coexist, abort installation"
        exit 1
    fi
}

function check_iommu
{
    echo "checking iommu in grub"
    if ! egrep -q "^[[:space:]]*kernel.+intel_iommu" /etc/sysconfig/grub; then
        echo iommu not enabled, enabling
        echo 'GRUB_CMDLINE_LINUX_DEFAULT="iommu=pt intel_iommu=on transparent_hugepage=never default_hugepagesz=1GB hugepagesz=1G hugepages=8"'>>/etc/sysconfig/grub
        grub2-mkconfig -o /etc/grub2.cfg
        echo iommu enabled please reboot after install
    else
        echo OK
    fi
}

function check_mod
{
    echo checking ixgbe mod
    ret=$(lsmod | grep -c '^ixgbe')
    if [ $ret -eq 0 ]; then
        echo No mod ixgbe found
        exit 1
    else
        echo OK
    fi
}

function create_vf
{
    echo creating vf
    modprobe -r ixgbe
    modprobe ixgbe max_vfs=7
    modprobe ixgbevf 
    modprobe vfio_pci vfio_iommu_type1 vfio
    echo "options ixgbe max_vfs=7" >/etc/modprobe.d/enable_sriov.conf
    count=$(lspci | grep "Virtual Function")
    if [ $count -eq 0 ]; then
        echo No vf found
        exit
    fi
}

##
## after libvirt 0.10.0, directly use PCI address is not preferable,
## use the function below instead
##
function add_dev
{
    mkdir /tmp/sriov
    netpcis=`lspci|grep Ethernet|grep -v 'Virtual'|awk '{print $1}' | sed 's/[:\.]/_/g'`
    count=0
    for netpci in $netpcis;do
        ((count++))
        dev_str='pci_0000_'$netpci
        virsh nodedev-dumpxml $dev_str |grep address>/tmp/$netpci
        item=0
        cat /tmp/$netpci | while read addr 
        do
            ((item++))
            echo -e "<hostdev mode='subsystem' type='pci' managed='yes'>\n  <source>\n      $addr\n  </source>\n</hostdev>" > /tmp/sriov/unuse/if-vf$count$item.xml
        done
    done
}

#check_ovs
check_iommu
check_mod
create_vf
add_dev

