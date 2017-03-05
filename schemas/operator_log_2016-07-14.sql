CREATE DATABASE IF NOT EXISTS `operator_log`;

# Dump of table ansible_log
# ------------------------------------------------------------

DROP TABLE IF EXISTS `ansible_log`;

CREATE TABLE `ansible_log` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `result` text COMMENT '提交的内容',
  `category` varchar(100) DEFAULT '' COMMENT '函数',
  `result_status` enum('sucess','fail') DEFAULT 'sucess' COMMENT '是否成功',
  `server_ip` varchar(50) DEFAULT NULL COMMENT '服务器ip',
  `create_timestamp` timestamp NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP COMMENT '提交时间',
  PRIMARY KEY (`id`),
  KEY `result_status` (`result_status`),
  KEY `server_ip` (`server_ip`),
  KEY `category` (`category`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COMMENT='ansible日志';



# Dump of table operator_log
# ------------------------------------------------------------

DROP TABLE IF EXISTS `operator_log`;

CREATE TABLE `operator_log` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `login_user` varchar(100) DEFAULT '0' COMMENT '登陆用户名',
  `login_uid` int(10) unsigned DEFAULT '0' COMMENT '登陆用户id',
  `login_gid` int(10) unsigned DEFAULT '0' COMMENT '用户gid',
  `exec_path` varchar(100) DEFAULT NULL COMMENT '执行路径',
  `server_ip` varchar(50) DEFAULT NULL COMMENT '服务器ip',
  `post_data` text COMMENT '提交的内容',
  `result` text COMMENT '执行的结果',
  `respone_timestamp` timestamp NULL DEFAULT NULL COMMENT '返回时间',
  `func` varchar(100) DEFAULT '' COMMENT '函数',
  `controller` varchar(100) DEFAULT NULL COMMENT '控制器',
  `request_id` bigint(20) unsigned DEFAULT NULL COMMENT '请求id',
  `create_timestamp` timestamp NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP COMMENT '提交时间',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COMMENT='操作日志';