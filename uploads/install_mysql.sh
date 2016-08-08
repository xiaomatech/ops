#!/usr/bin/env bash

yum install -y Percona-Server-client-57 Percona-Server-server-57 Percona-Server-tokudb-57 percona-playback percona-toolkit percona-xtrabackup
yum install -y MySQL-python

echo never>/sys/kernel/mm/transparent_hugepage/enabled
echo never>/sys/kernel/mm/transparent_hugepage/defrag

#MHA node
yum install -y mha4mysql-node
