
CREATE DATABASE IF NOT EXISTS `virt`;

# Dump of table flavor
# ------------------------------------------------------------

DROP TABLE IF EXISTS `flavor`;

CREATE TABLE `flavor` (
  `flavor_id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `memory` int(10) unsigned DEFAULT '0' COMMENT '内存大小M',
  `vcpu` int(10) unsigned DEFAULT '0' COMMENT 'cpu个数',
  `disk` int(10) unsigned DEFAULT '0' COMMENT '硬盘大小G',
  `label` varchar(100) DEFAULT NULL COMMENT '模板名',
  PRIMARY KEY (`flavor_id`),
  UNIQUE KEY `label` (`label`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COMMENT='机型';

LOCK TABLES `flavor` WRITE;
/*!40000 ALTER TABLE `flavor` DISABLE KEYS */;

INSERT INTO `flavor` (`flavor_id`, `memory`, `vcpu`, `disk`, `label`)
VALUES
	(1,1024,8,100,'v1'),
	(2,2048,8,100,'v3'),
	(12,2048,64,600,'v4'),
	(14,2048,32,600,'v5'),
	(15,2048,16,600,'v2');

/*!40000 ALTER TABLE `flavor` ENABLE KEYS */;
UNLOCK TABLES;


# Dump of table instance
# ------------------------------------------------------------

DROP TABLE IF EXISTS `instance`;

CREATE TABLE `instance` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(100) DEFAULT NULL COMMENT '实例名',
  `uuid` varchar(50) DEFAULT NULL COMMENT '实例uuid',
  `flavor_id` int(10) unsigned NOT NULL DEFAULT '0' COMMENT '模板id',
  `server_ip` varchar(30) DEFAULT NULL COMMENT '母机ip',
  `create_timestamp` timestamp NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP COMMENT '创建时间',
  PRIMARY KEY (`id`),
  KEY `instance_flavor` (`flavor_id`),
  CONSTRAINT `instance_flavor` FOREIGN KEY (`flavor_id`) REFERENCES `flavor` (`flavor_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COMMENT='虚拟机';



# Dump of table jobs
# ------------------------------------------------------------

DROP TABLE IF EXISTS `jobs`;

CREATE TABLE `jobs` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `ip_list` text COMMENT '母机ip列表',
  `flavor_id` int(10) unsigned NOT NULL DEFAULT '0' COMMENT '机型id',
  `instance_count` varchar(100) DEFAULT NULL COMMENT '虚机数量',
  `server_tag` varchar(100) DEFAULT NULL COMMENT '用途',
  `network_type` enum('bridge','sriov','ovs') DEFAULT 'bridge' COMMENT '网络类型',
  `virt_type` enum('kvm','docker') DEFAULT 'kvm' COMMENT '虚拟机类型 kvm,docker',
  `remarks` varchar(100) DEFAULT NULL COMMENT '备注',
  `create_timestamp` timestamp NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP COMMENT '创建时间',
  `operator` varchar(50) DEFAULT NULL COMMENT '操作人',
  PRIMARY KEY (`id`),
  KEY `job_flavor` (`flavor_id`),
  CONSTRAINT `job_flavor` FOREIGN KEY (`flavor_id`) REFERENCES `flavor` (`flavor_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;



# Dump of table tasks
# ------------------------------------------------------------

DROP TABLE IF EXISTS `tasks`;

CREATE TABLE `tasks` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `job_id` int(10) unsigned DEFAULT '0',
  `group` varchar(100) DEFAULT NULL COMMENT '分组名',
  `server_ip` varchar(30) DEFAULT NULL COMMENT '机器ip',
  `result_status` tinyint(1) DEFAULT '1' COMMENT '执行结果',
  `result_log` text COMMENT '执行日志',
  `create_timestamp` timestamp NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `job_id` (`job_id`),
  CONSTRAINT `job_id` FOREIGN KEY (`job_id`) REFERENCES `jobs` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COMMENT='jobs按每个ip产生的task';
