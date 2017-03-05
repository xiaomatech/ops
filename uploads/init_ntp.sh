#!/usr/bin/env bash

yum install -y ntpdate
ntpdate cn.pool.ntp.org
clock -w
