#!/usr/bin/env bash
sudo yum install -y git redis python-pip python-simplejson python-requests MySQL-python python-lxml libvirt-python libxml2-python python-dateutil ansible
sudo pip install --upgrade pip
sudo pip install gevent netmiko docker-py kazoo falcon peewee gunicorn pyzabbix redis kazoo pika kafka-python autojenkins upyun ldap3 boto psutil ansible elasticsearch libvirt-python simplejson requests python-dateutil lxml celery

service redis start

mkdir -p /data

cd /data
git clone git://github.com/xiaomatech/ops.git
git submodule update --init --recursive

