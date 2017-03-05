CREATE DATABASE IF NOT EXISTS `dns`;

# Dump of table dhcp
# ------------------------------------------------------------

DROP TABLE IF EXISTS `dhcp_host`;

CREATE TABLE `dhcp_host` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `hostname` varchar(50) DEFAULT NULL COMMENT '主机名',
  `mac` varchar(20) DEFAULT NULL COMMENT 'MAC地址',
  `ip` varchar(15) DEFAULT NULL COMMENT 'IP地址',
  `comment` varchar(30) DEFAULT NULL COMMENT '备注',
  `host_status` enum('allow','deny') NOT NULL DEFAULT 'allow',
  `create_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;



# Dump of table dhcp_pool
# ------------------------------------------------------------

DROP TABLE IF EXISTS `dhcp_pool`;

CREATE TABLE `dhcp_pool` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `pool_start` varchar(50) DEFAULT '' COMMENT 'DHCP地址池开始地址',
  `pool_stop` varchar(50) DEFAULT '' COMMENT 'DHCP地址池结束地址',
  `pool_netmask` varchar(50) DEFAULT '' COMMENT 'DHCP地址池子网掩码',
  `pool_lease` int(10) unsigned NOT NULL COMMENT 'DHCP租约',
  `create_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `pool_gw` varchar(50) DEFAULT 'yes' COMMENT 'DHCP默认网关',
  `pool_dns1` varchar(50) DEFAULT '' COMMENT 'DHCP主DNS服务器',
  `pool_dns2` varchar(50) DEFAULT '' COMMENT 'DHCP辅助DNS服务器',
  `pool_domain` varchar(50) DEFAULT '' COMMENT 'DHCP缺省域名',
  `pool_ntp` varchar(50) DEFAULT '' COMMENT 'DHCP时间服务器',
  `pool_comment` varchar(255) DEFAULT '' COMMENT 'DHCP地址池备注',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;



# Dump of table dns_domain
# ------------------------------------------------------------

DROP TABLE IF EXISTS `dns_domain`;

CREATE TABLE `dns_domain` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `domain` varchar(60) DEFAULT '' COMMENT '域名',
  `file` varchar(255) DEFAULT '' COMMENT '配置文件',
  `file_md5` varchar(64) DEFAULT '' COMMENT 'MD5值',
  `create_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '创建时间',
  `update_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
  `comment` varchar(255) DEFAULT '' COMMENT '备注',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;



# Dump of table dns_record
# ------------------------------------------------------------

DROP TABLE IF EXISTS `dns_record`;

CREATE TABLE `dns_record` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `did` int(10) unsigned NOT NULL COMMENT '域名ID',
  `record` varchar(50) DEFAULT '' COMMENT '主机记录',
  `type` varchar(10) DEFAULT '' COMMENT '记录类型',
  `value` varchar(50) DEFAULT '' COMMENT '记录值',
  `priority` int(10) unsigned NOT NULL DEFAULT '0' COMMENT 'MX优先级',
  `create_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '创建时间',
  `update_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
  `comment` varchar(255) DEFAULT NULL COMMENT '备注',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
