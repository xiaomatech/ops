#!/usr/bin/env bash
ovs-vsctl set-manager ptcp:6632
ovs-appctl -t ovsdb-server ovsdb-server/add-remote ptcp:6632
sed -i '/remote=punix/ {
a \        set \"\$@\" --remote=ptcp:6632
}/' /usr/share/openvswitch/scripts/ovs-ctl
sudo ovs-vsctl set-controller s1 "tcp:192.168.241.132:6633"

service openvswitch-switch restart