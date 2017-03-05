CREATE DATABASE IF NOT EXISTS `cmdb`;

# Dump of table asset_nic_mac
# ------------------------------------------------------------

DROP TABLE IF EXISTS `asset_nic_mac`;

CREATE TABLE `asset_nic_mac` (
  `nic_id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `assets_id` int(10) unsigned DEFAULT '0' COMMENT '资产id',
  `nic` varchar(20) DEFAULT NULL COMMENT '网卡',
  `mac` varchar(20) DEFAULT NULL COMMENT 'mac地址',
  PRIMARY KEY (`nic_id`),
  KEY `asset_id_nic` (`assets_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COMMENT='机器的网卡跟mac';



# Dump of table device
# ------------------------------------------------------------

DROP TABLE IF EXISTS `device`;

CREATE TABLE `device` (
  `assets_id` int(10) unsigned NOT NULL AUTO_INCREMENT COMMENT 'ID',
  `template_id` int(10) unsigned DEFAULT '0' COMMENT '设备模板id',
  `environment` varchar(25) DEFAULT NULL COMMENT '环境 dev,pro,test,staging',
  `tier` varchar(25) DEFAULT NULL COMMENT '属于哪个tier',
  `fqdn` varchar(255) DEFAULT NULL COMMENT '主机名称',
  `room_id` int(10) unsigned DEFAULT '0' COMMENT '机房id',
  `rack_id` int(10) unsigned NOT NULL DEFAULT '0' COMMENT '机架id',
  `seat` int(10) unsigned NOT NULL DEFAULT '0' COMMENT '机位',
  `logic_area` enum('virt','lvs','db','manage','big_data','external') DEFAULT 'virt' COMMENT '逻辑区域',
  `device_status` enum('online','dev','failure','recovery','test') NOT NULL DEFAULT 'online' COMMENT '状态',
  `sn` varchar(255) DEFAULT NULL COMMENT '产品SN号',
  `operator` varchar(100) NOT NULL DEFAULT '' COMMENT '维护人员',
  `uuid` varchar(255) DEFAULT NULL COMMENT 'UUID',
  `remarks` varchar(1024) DEFAULT NULL COMMENT '备注',
  `create_timestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  PRIMARY KEY (`assets_id`),
  KEY `template_id` (`template_id`),
  KEY `device_room_id` (`room_id`),
  KEY `device_rack_id` (`rack_id`),
  CONSTRAINT `device_rack_id` FOREIGN KEY (`rack_id`) REFERENCES `rack` (`rack_id`),
  CONSTRAINT `device_room_id` FOREIGN KEY (`room_id`) REFERENCES `room` (`room_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COMMENT='设备表';



# Dump of table device_template
# ------------------------------------------------------------

DROP TABLE IF EXISTS `device_template`;

CREATE TABLE `device_template` (
  `template_id` int(10) unsigned NOT NULL AUTO_INCREMENT COMMENT 'ID',
  `price` int(10) unsigned DEFAULT '0' COMMENT '价格',
  `server_type` enum('server','switch','router','firewall','virtual_machine') NOT NULL DEFAULT 'server' COMMENT '设备类型',
  `manufacturer_id` int(10) unsigned DEFAULT '0' COMMENT '厂商型号',
  `device_height` tinyint(4) NOT NULL DEFAULT '2' COMMENT '设备高度（U）',
  `warranty_time` int(10) unsigned DEFAULT '36' COMMENT '保修时间(月)',
  `create_timestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `os` varchar(255) DEFAULT NULL COMMENT '操作系统名称',
  `kernel` varchar(255) DEFAULT NULL COMMENT '内核版本',
  `disk_detail` text COMMENT '存储信息;硬盘空间信息',
  `cpu_detail` text COMMENT 'CPU信息',
  `memory` int(10) unsigned DEFAULT '0' COMMENT '内存',
  `cpu` int(10) unsigned DEFAULT '0' COMMENT 'cpu',
  `disk` int(10) unsigned DEFAULT '0' COMMENT '磁盘',
  PRIMARY KEY (`template_id`),
  KEY `manufacturer_id` (`manufacturer_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COMMENT='设备模板表';



# Dump of table ip
# ------------------------------------------------------------

DROP TABLE IF EXISTS `ip`;

CREATE TABLE `ip` (
  `ip_id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `assets_id` int(10) unsigned NOT NULL COMMENT '资产id',
  `ip` varchar(50) NOT NULL DEFAULT '' COMMENT 'IP',
  `netmask` varchar(50) NOT NULL DEFAULT '' COMMENT '子网掩码',
  `segment_ip` varchar(50) NOT NULL DEFAULT '' COMMENT '网段',
  `gateway` varchar(50) NOT NULL DEFAULT '' COMMENT '网关',
  `carriers` enum('internal','telecom','china_unicorm','edu_net','china_mobile','other') NOT NULL DEFAULT 'internal' COMMENT '运营商',
  `status` enum('enable','disable') NOT NULL DEFAULT 'enable' COMMENT '状态',
  PRIMARY KEY (`ip_id`),
  UNIQUE KEY `assets_id_ip_type` (`assets_id`,`ip`),
  KEY `assets` (`assets_id`),
  KEY `carriers` (`carriers`),
  KEY `segment_ip_ip` (`segment_ip`),
  KEY `ip_ip` (`ip`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COMMENT='ip';



# Dump of table manufacturer
# ------------------------------------------------------------

DROP TABLE IF EXISTS `manufacturer`;

CREATE TABLE `manufacturer` (
  `manufacturer_id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `manufacturer` varchar(100) DEFAULT NULL COMMENT '设备厂商名',
  `create_timestamp` timestamp NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`manufacturer_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COMMENT='设备厂商';



# Dump of table rack
# ------------------------------------------------------------

DROP TABLE IF EXISTS `rack`;

CREATE TABLE `rack` (
  `rack_id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `room_id` int(10) unsigned DEFAULT '0' COMMENT '机房id',
  `rack` varchar(100) DEFAULT NULL COMMENT '机架名',
  `create_timestamp` timestamp NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP COMMENT '添加时间',
  PRIMARY KEY (`rack_id`),
  KEY `room_id2` (`room_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COMMENT='机架情况';



# Dump of table room
# ------------------------------------------------------------

DROP TABLE IF EXISTS `room`;

CREATE TABLE `room` (
  `room_id` int(10) unsigned NOT NULL AUTO_INCREMENT COMMENT 'ID',
  `room_name` varchar(255) NOT NULL COMMENT '机房名称',
  `position` varchar(255) NOT NULL DEFAULT '''''' COMMENT '机房位置',
  `room_name_en` varchar(4) DEFAULT NULL COMMENT '机房名简写',
  `city` varchar(4) DEFAULT NULL COMMENT '城市名简写',
  `tel` varchar(4) DEFAULT NULL COMMENT '客服电话',
  `customer_service` varchar(4) DEFAULT NULL COMMENT '客服',
  `email` varchar(4) DEFAULT NULL COMMENT '客服email',
  PRIMARY KEY (`room_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COMMENT='机房信息';



# Dump of table seat
# ------------------------------------------------------------

DROP TABLE IF EXISTS `seat`;

CREATE TABLE `seat` (
  `seat_id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `room_id` int(10) unsigned DEFAULT '0' COMMENT '机房id',
  `rack_id` int(10) unsigned DEFAULT '0' COMMENT '机架id',
  `seat` int(10) unsigned DEFAULT '0' COMMENT '机位',
  `create_timestamp` timestamp NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP COMMENT '添加时间',
  PRIMARY KEY (`seat_id`),
  KEY `room_id` (`room_id`),
  KEY `frame_id` (`rack_id`),
  CONSTRAINT `frame_id` FOREIGN KEY (`rack_id`) REFERENCES `rack` (`rack_id`),
  CONSTRAINT `room_id` FOREIGN KEY (`room_id`) REFERENCES `room` (`room_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COMMENT='机位情况';



# Dump of table segment
# ------------------------------------------------------------

DROP TABLE IF EXISTS `segment`;

CREATE TABLE `segment` (
  `segment_id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `assets_id` int(10) unsigned NOT NULL DEFAULT '0' COMMENT '关联网络设备id',
  `segment_ip` varchar(255) NOT NULL COMMENT 'IP',
  `ip_type` enum('internal','external','vip') NOT NULL DEFAULT 'internal' COMMENT 'IP类型',
  `netmask` varchar(255) NOT NULL DEFAULT '' COMMENT '子网掩码',
  `gateway` varchar(255) NOT NULL COMMENT '网关',
  `vlan_id` int(10) unsigned DEFAULT '1' COMMENT 'VLAN ID',
  `total` int(10) unsigned NOT NULL DEFAULT '0' COMMENT 'IP总数',
  `assigned` int(10) unsigned NOT NULL DEFAULT '0' COMMENT '已分配',
  `carriers` enum('internal','telecom','china_unicorm','edu_net','china_mobile','other') DEFAULT 'internal' COMMENT '运营商',
  `remarks` varchar(255) DEFAULT NULL COMMENT 'remarks',
  `status` enum('enable','disable') NOT NULL DEFAULT 'enable' COMMENT '状态',
  `logic_area` enum('virt','lvs','db','manage','big_data','external') DEFAULT 'virt' COMMENT '逻辑区域',
  `room_id` int(10) unsigned DEFAULT '0' COMMENT '机房id',
  PRIMARY KEY (`segment_id`),
  UNIQUE KEY `segment_ip_mask` (`segment_ip`,`netmask`),
  KEY `ip_type` (`ip_type`),
  KEY `room_id` (`room_id`),
  CONSTRAINT `segment_room_id` FOREIGN KEY (`room_id`) REFERENCES `room` (`room_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COMMENT='网段';



# Dump of table segment_ip_pool
# ------------------------------------------------------------

DROP TABLE IF EXISTS `segment_ip_pool`;

CREATE TABLE `segment_ip_pool` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT COMMENT 'ID',
  `segment_id` int(10) unsigned NOT NULL DEFAULT '0' COMMENT '网段ID',
  `ip` varchar(100) NOT NULL COMMENT 'IP',
  `assigned` enum('enable','disable') NOT NULL DEFAULT 'enable' COMMENT '状态',
  PRIMARY KEY (`id`),
  UNIQUE KEY `ip` (`ip`),
  KEY `segment_id` (`segment_id`),
  CONSTRAINT `segment_id` FOREIGN KEY (`segment_id`) REFERENCES `segment` (`segment_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COMMENT='网段ip池';



# Dump of table server_tag
# ------------------------------------------------------------

DROP TABLE IF EXISTS `server_tag`;

CREATE TABLE `server_tag` (
  `server_tag_id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `server_tag_key` varchar(100) DEFAULT '0',
  `server_tag_value` varchar(100) DEFAULT '0',
  `create_timestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `assets_id` int(10) unsigned DEFAULT '0',
  PRIMARY KEY (`server_tag_id`),
  UNIQUE KEY `server_tag_asset` (`server_tag_key`,`server_tag_value`,`assets_id`),
  KEY `server_tag_id` (`server_tag_value`),
  KEY `asset_id1` (`assets_id`),
  CONSTRAINT `asset_id1` FOREIGN KEY (`assets_id`) REFERENCES `device` (`assets_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COMMENT='机器tag关联';



# Dump of table server_tag_user
# ------------------------------------------------------------

DROP TABLE IF EXISTS `server_tag_user`;

CREATE TABLE `server_tag_user` (
  `user_tag_id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `server_tag_id` int(10) unsigned DEFAULT '0' COMMENT 'tag id',
  `uid` int(11) DEFAULT '0' COMMENT '用户id',
  `user_name` varchar(100) DEFAULT NULL,
  `create_timestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`user_tag_id`),
  KEY `server_tag_id` (`server_tag_id`),
  CONSTRAINT `server_tag_id` FOREIGN KEY (`server_tag_id`) REFERENCES `server_tag` (`server_tag_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COMMENT='机器tag用户关联';



# Dump of table switch_mac_table
# ------------------------------------------------------------

DROP TABLE IF EXISTS `switch_mac_table`;

CREATE TABLE `switch_mac_table` (
  `switch_id` int(11) NOT NULL AUTO_INCREMENT,
  `port_id` int(11) NOT NULL,
  `interface_id` int(11) NOT NULL,
  `vlan` int(5) NOT NULL,
  `mac` char(17) NOT NULL,
  PRIMARY KEY (`switch_id`),
  KEY `switch_id` (`port_id`),
  KEY `interface_id` (`interface_id`),
  KEY `mac` (`mac`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

