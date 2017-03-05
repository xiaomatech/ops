CREATE DATABASE IF NOT EXISTS `deploy`;

# Dump of table deploy_template
# ------------------------------------------------------------

DROP TABLE IF EXISTS `deploy_template`;

CREATE TABLE `deploy_template` (
  `template_id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `server_tag` varchar(100) DEFAULT NULL COMMENT '业务标识',
  `package_uri` varchar(100) DEFAULT NULL COMMENT '发布uri',
  `package_type` enum('git','svn','rsync','scp','download') DEFAULT 'git' COMMENT '发布类型',
  PRIMARY KEY (`template_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;



# Dump of table jobs
# ------------------------------------------------------------

DROP TABLE IF EXISTS `jobs`;

CREATE TABLE `jobs` (
  `job_id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `template_id` int(10) unsigned DEFAULT '0' COMMENT '业务发布模板id',
  `group_list` text COMMENT '业务ip 按组分好',
  `operator` varchar(50) DEFAULT NULL COMMENT '操作者',
  `release_version` varchar(100) DEFAULT NULL COMMENT '版本',
  `create_timestamp` timestamp NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP COMMENT '提交时间',
  PRIMARY KEY (`job_id`),
  KEY `template_id` (`template_id`),
  CONSTRAINT `template_id` FOREIGN KEY (`template_id`) REFERENCES `deploy_template` (`template_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COMMENT='发布任务';



# Dump of table tasks
# ------------------------------------------------------------

DROP TABLE IF EXISTS `tasks`;

CREATE TABLE `tasks` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `job_id` bigint unsigned DEFAULT '0',
  `group` varchar(30) DEFAULT NULL COMMENT '分组名',
  `server_ip` varchar(30) DEFAULT NULL COMMENT '机器ip',
  `result_status` tinyint(1) DEFAULT '2' COMMENT '执行结果',
  `result_log` text COMMENT '执行日志',
  `create_timestamp` timestamp NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `job_id` (`job_id`),
  CONSTRAINT `job_id` FOREIGN KEY (`job_id`) REFERENCES `jobs` (`job_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COMMENT='jobs按每个ip产生的task';
