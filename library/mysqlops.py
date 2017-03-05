#!/usr/bin/env python
# -*- coding:utf8 -*-

import boto
import datetime
import resource
import fcntl
import json
import shutil
import socket
import getpass
import MySQLdb
import MySQLdb.cursors
import re
import warnings
import multiprocessing
import os
import glob
import subprocess
import sys
import tempfile
import time
import urllib
import ConfigParser
import _mysql_exceptions
import boto.utils
import boto.ec2
import inspect
import pprint
import copy
import simplejson
import hashlib
import difflib
import traceback
import signal
import threading
import uuid
import psutil
import string
from contextlib import contextmanager

PEM_KEY = ''
S3_BINLOG_RETENTION = 0
S3_BINLOG_BUCKET = ''
S3_CSV_BUCKET = ''
S3_BUCKET = ''
PINFO_TEAM = ''

SSH_SECURITY_DEV = ''

SSH_SECURITY_SECURE = ''

SUPPORTED_HIERA_CONFIGS = {}
DR_ZK = {}
GEN_ZK = {}
DS_ZK = {}

HIERA_FORMAT = ''

CLASSIC_SECURE_SG = ''

SUPPORTED_HIERA_CONFIGS = ''

FLEXSHARD_DBS = {'shard_type': {'zk_prefix': ''}}

VPC_MIGRATION_MAP = {'replacement_config': {'classic_security_group': ''}}

FLEXSHARD_DBS = {'shard_type': {'example_shard_replica_set': ''}}

BINLOG_ARCHIVING_TABLE_NAME = {}

CHANGE_FEED_URL = {}

CLI_ROLES = {'privileges': {'role_modifier': ''}}

SHARDED_DBS_PREFIX_MAP = {'shard_type': {'example_shard': ''}}
VPC_SUBNET_SG_MAP = {}

PINFO_ENV = ''

RAID_MOUNT = ''

TERM_DIR = ''

SUPPORTED_AZ = ''

SUPPORTED_MYSQL_MAJOR_VERSIONS = ''

SUPPORTED_MYSQL_MINOR_VERSIONS = ''

VPC_SECURITY_GROUPS = {'vpc_security_group': {}}

VPC_AZ_SUBNET_MAP = {}
EC2_REGION = ''
SUPPORTED_HARDWARE = ''
CSV_BACKUP_LOG_TABLE = ''

INSTANCE_PROFILE_NAME = ''
SSH_SECURITY_MAP = {'subnet_name': {'iam': ''}}


def get_all_server_metadata():
    pass


def BufferingChatHandler():
    pass


def get_server_metadata(hostname):
    pass


def get_all_replica_set_servers(replica_set):
    pass


def get_csv_backup_paths(date, db, table):
    pass


def convert_shard_to_db(shard):
    pass


def generic_json_post():
    pass


def initialize_logger():
    pass


def get_kazoo_client():
    pass


def setup_logging_defaults(name):
    pass


def filter_tables_to_csv_backup():
    pass


AUTH_FILE = '/var/config/config.services.mysql_auth'
MYSQL_DS_ZK = '/var/config/config.services.dataservices.mysql_databases'
MYSQL_GEN_ZK = '/var/config/config.services.general_mysql_databases_config'
MASTER = 'master'
SLAVE = 'slave'
DR_SLAVE = 'dr_slave'
REPLICA_ROLES = [MASTER, SLAVE, DR_SLAVE]

BACKUP_FILE = 'mysql-{hostname}-{port}-{timestamp}.{backup_type}'
BACKUP_LOCK_FILE = '/tmp/backup_mysql.lock'
BACKUP_TYPE_LOGICAL = 'sql.gz'
BACKUP_TYPE_CSV = 'csv'
BACKUP_TYPE_XBSTREAM = 'xbstream'
BACKUP_TYPES = set(
    [BACKUP_TYPE_LOGICAL, BACKUP_TYPE_XBSTREAM, BACKUP_TYPE_CSV])
INNOBACKUPEX = '/usr/bin/innobackupex'
INNOBACKUP_OK = 'completed OK!'
MYSQLDUMP = '/usr/bin/mysqldump'
MYSQLDUMP_CMD = ' '.join(
    (MYSQLDUMP, '--master-data', '--single-transaction', '--events',
     '--all-databases', '--routines', '--user={dump_user}',
     '--password={dump_pass}', '--host={host}', '--port={port}'))
PIGZ = ['/usr/bin/pigz', '-p', '2']
PV = '/usr/bin/pv -peafbt'
S3_SCRIPT = '/usr/local/bin/gof3r'
USER_ROLE_MYSQLDUMP = 'mysqldump'
USER_ROLE_XTRABACKUP = 'xtrabackup'
XB_RESTORE_STATUS = ("CREATE TABLE IF NOT EXISTS test.xb_restore_status ("
                     "id                INT UNSIGNED NOT NULL AUTO_INCREMENT, "
                     "restore_source    VARCHAR(64), "
                     "restore_type      ENUM('s3', 'remote_server', "
                     "                       'local_file') NOT NULL, "
                     "test_restore      ENUM('normal', 'test') NOT NULL, "
                     "restore_destination   VARCHAR(64), "
                     "restore_date      DATE, "
                     "restore_port      SMALLINT UNSIGNED NOT NULL "
                     "                  DEFAULT 3306, "
                     "restore_file      VARCHAR(255), "
                     "replication       ENUM('SKIP', 'REQ', 'OK', 'FAIL'), "
                     "zookeeper         ENUM('SKIP', 'REQ', 'OK', 'FAIL'), "
                     "started_at        DATETIME NOT NULL, "
                     "finished_at       DATETIME, "
                     "restore_status    ENUM('OK', 'IPR', 'BAD') "
                     "                  DEFAULT 'IPR', "
                     "status_message    TEXT, "
                     "PRIMARY KEY(id), "
                     "INDEX (restore_type, started_at), "
                     "INDEX (restore_type, restore_status, "
                     "       started_at) )")

XTRABACKUP_CMD = ' '.join(
    (INNOBACKUPEX, '{datadir}', '--slave-info', '--safe-slave-backup',
     '--parallel=8', '--stream=xbstream', '--no-timestamp', '--compress',
     '--compress-threads=8', '--kill-long-queries-timeout=10',
     '--user={xtra_user}', '--password={xtra_pass}', '--defaults-file={cnf}',
     '--defaults-group={cnf_group}', '--port={port}'))
MINIMUM_VALID_BACKUP_SIZE_BYTES = 1024 * 1024

# Max IO thread lag in bytes. If more than NORMAL_IO_LAG refuse to modify zk, etc
# 10k bytes of lag is just a few seconds normally
NORMAL_IO_LAG = 10485760
# Max lag in seconds. If more than NORMAL_HEARTBEAT_LAG refuse to modify zk, or
# attempt a live master failover
NORMAL_HEARTBEAT_LAG = 120
HEARTBEAT_SAFETY_MARGIN = 10
# Max lag in second for a dead master failover
LOOSE_HEARTBEAT_LAG = 3600

CHECK_SQL_THREAD = 'sql'
CHECK_IO_THREAD = 'io'
CHECK_CORRECT_MASTER = 'master'
ALL_REPLICATION_CHECKS = set(
    [CHECK_SQL_THREAD, CHECK_IO_THREAD, CHECK_CORRECT_MASTER])
REPLICATION_THREAD_SQL = 'SQL'
REPLICATION_THREAD_IO = 'IO'
REPLICATION_THREAD_ALL = 'ALL'
REPLICATION_THREAD_TYPES = set(
    [REPLICATION_THREAD_SQL, REPLICATION_THREAD_IO, REPLICATION_THREAD_ALL])

AUTH_FILE = '/var/config/config.services.mysql_auth'
CONNECT_TIMEOUT = 2
INVALID = 'INVALID'
METADATA_DB = 'test'
MYSQL_DATETIME_TO_PYTHON = '%Y-%m-%dT%H:%M:%S.%f'
MYSQLADMIN = '/usr/bin/mysqladmin'
MYSQL_ERROR_ACCESS_DENIED = 1045
MYSQL_ERROR_CONN_HOST_ERROR = 2003
MYSQL_ERROR_HOST_ACCESS_DENIED = 1130
MYSQL_ERROR_NO_SUCH_TABLE = 1146
MYSQL_ERROR_NO_DEFINED_GRANT = 1141
MYSQL_ERROR_NO_SUCH_THREAD = 1094
MYSQL_ERROR_UNKNOWN_VAR = 1193
MYSQL_ERROR_FUNCTION_EXISTS = 1125
MYSQL_VERSION_COMMAND = '/usr/sbin/mysqld --version'
REPLICATION_TOLERANCE_NONE = 'None'
REPLICATION_TOLERANCE_NORMAL = 'Normal'
REPLICATION_TOLERANCE_LOOSE = 'Loose'


def check_mysql_replication(**args):
    slave_hostaddr = HostAddr(args.replica)

    if args.watch_for_catch_up:
        wait_replication_catch_up(slave_hostaddr)
    else:
        ret = calc_slave_lag(slave_hostaddr)
        print "Heartbeat_seconds_behind: {sbm}".format(sbm=ret['sbm'])
        print "Slave_IO_Running: {Slave_IO_Running} ".format(
            Slave_IO_Running=ret['ss']['Slave_IO_Running'])
        print "IO_lag_bytes: {io_bytes}".format(io_bytes=ret['io_bytes'])
        print "IO_lag_binlogs: {io_binlogs}".format(
            io_binlogs=ret['io_binlogs'])
        print "Slave_SQL_Running: {Slave_IO_Running} ".format(
            Slave_IO_Running=ret['ss']['Slave_SQL_Running'])
        print "SQL_lag_bytes: {sql_bytes}".format(sql_bytes=ret['sql_bytes'])
        print "SQL_lag_binlogs: {sql_binlogs}".format(
            sql_binlogs=ret['sql_binlogs'])


def find_shard_mismatches(instance=False):
    """ Find shards that are missing or unexpected in modhsarddb and sharddb

    Args:
    instance - If supplied, only check this instance.

    Returns:
    orphaned - A dict of unexpected and (according to table statistics)
               unused shards. Key is master instance, value is a set.
    orphaned_but_used - A dict of unexpected and but used shards.
                        Data strucutre is the same as orphaned.
    missing - A dict of expected but missing shards.
              Data strucutre is the same as orphaned.

    """
    orphaned = dict()
    orphaned_but_used = dict()
    missing_shards = dict()

    zk = MysqlZookeeper()
    host_shard_map = zk.get_host_shard_map()

    if instance:
        new_host_shard_map = dict()
        new_host_shard_map[instance.__str__()] = host_shard_map[
            instance.__str__()]
        host_shard_map = new_host_shard_map

    for master in host_shard_map:
        expected_shards = host_shard_map[master]
        instance = HostAddr(master)
        activity = get_dbs_activity(instance)
        actual_shards = get_dbs(instance)
        unexpected_shards = actual_shards.difference(expected_shards)
        missing = expected_shards.difference(actual_shards)
        if missing:
            missing_shards[master] = expected_shards.difference(actual_shards)

        for db in unexpected_shards:
            if activity[db]['ROWS_CHANGED'] != 0:
                if master not in orphaned_but_used:
                    orphaned_but_used[master] = set()
                orphaned_but_used[master].add(db)
            else:
                if master not in orphaned:
                    orphaned[master] = set()
                orphaned[master].add(db)

    return orphaned, orphaned_but_used, missing_shards


def get_db_host_prefix(hostname):
    """ This function finds the host prefix for a db host

    Argument:
    hostname - a hostname

    Returns:
    a prefix of the hostname
    """
    prefix_match = re.match('(.+db)', hostname)
    if prefix_match is None:
        prefix_match = re.match('([a-z]+)', hostname)
    if prefix_match is None:
        prefix = None
    else:
        prefix = prefix_match.group(0)
    return prefix


def find_unused_db_servers():
    """ Compare zk and AWS to determine which servers are likely not in use

    Returns:
    A set of hosts that appear to not be in use
    """

    # First find out what servers we know about from zk, and make a
    # of hostname prefixes that we think we own.
    zk = MysqlZookeeper()
    config = zk.get_all_mysql_config()
    zk_servers = set()
    zk_prefixes = set()
    mysql_aws_hosts = set()
    for db in config:
        for rtype in REPLICA_TYPES:
            if rtype in config[db]:
                host = config[db][rtype]['host']
                zk_servers.add(host)
                prefix = get_db_host_prefix(host)
                zk_prefixes.add(prefix)

    cmdb_servers = get_all_server_metadata()
    for host in cmdb_servers:
        match = False
        for prefix in zk_prefixes:
            if host.startswith(prefix):
                match = True
        if not match:
            continue

        # We need to give servers a chance to build and then add themselves
        # to zk, so we will ignore server for a week.
        creation = boto.utils.parse_ts(cmdb_servers[host]['launch_time'])
        if creation < datetime.datetime.now() - datetime.timedelta(weeks=1):
            mysql_aws_hosts.add(host)

    hosts_not_in_zk = mysql_aws_hosts.difference(zk_servers)
    hosts_not_protected = hosts_not_in_zk.difference(
        get_protected_hosts('set'))
    return hosts_not_protected


def find_unused_db_servers_main(**args):
    hosts_not_in_zk = find_unused_db_servers()
    for host in sorted(hosts_not_in_zk):
        if args.add_retirement_queue:
            add_to_queue(hostname=host, dry_run=False)
        else:
            print host


DB_PREPEND = 'dropme_'


def rename_db_to_drop(instance, dbs, verbose=False, dry_run=False):
    """ Create a new empty db and move the contents of the original db there

    Args:
    instance - a hostaddr object
    dbs -  a set of database names
    verbose - bool, will direct sql to stdout
    dry_run - bool, will make no changes to
    """
    # confirm db is not in zk and not in use
    orphaned, _, _ = find_shard_mismatches.find_shard_mismatches(instance)
    if not orphaned:
        print "Detected no orphans"
        sys.exit(1)

    instance_orphans = orphaned[instance.__str__()]
    unexpected = dbs.difference(instance_orphans)
    if unexpected:
        print ''.join(("Cowardly refusing to act on the following dbs: ",
                       ','.join(unexpected)))
        sys.exit(1)

    # confirm that renames would not be blocked by an existing table
    conn = connect_mysql(instance)

    cursor = conn.cursor()
    for db in dbs:
        renamed_db = ''.join((DB_PREPEND, db))

        sql = ''.join(("SELECT CONCAT(t2.TABLE_SCHEMA, \n",
                       "              '.', t2.TABLE_NAME) as tbl \n",
                       "FROM information_schema.tables t1 \n",
                       "INNER JOIN information_schema.tables t2 \n",
                       "    USING(TABLE_NAME) \n",
                       "WHERE t1.TABLE_SCHEMA = %(old_db)s AND \n"
                       "      t2.TABLE_SCHEMA = %(new_db)s;"))

        params = {'old_db': db, 'new_db': renamed_db}
        cursor = conn.cursor()
        cursor.execute(sql, params)
        dups = cursor.fetchall()

        if dups:
            for dup in dups:
                print "Table rename blocked by {tbl}".format(tbl=dup['tbl'])
            sys.exit(1)

        # We should be safe to create the new db and rename
        if not dry_run:
            create_db(instance, renamed_db)
        move_db_contents(
            instance,
            old_db=db,
            new_db=renamed_db,
            verbose=verbose,
            dry_run=dry_run)


def drop_db_after_rename(instance, dbs, verbose, dry_run):
    """ Drop the original empty db and a non-empty rename db

    Args:
    instance - a hostaddr object
    dbs -  a set of database names
    verbose - bool, will direct sql to stdout
    dry_run - bool, will make no changes to
    """

    # confirm db is not in zk and not in use
    orphaned, _, _ = find_shard_mismatches.find_shard_mismatches(instance)
    instance_orphans = orphaned[instance.__str__()]
    unexpected = dbs.difference(instance_orphans)
    if unexpected:
        print ''.join(("Cowardly refusing to act on the following dbs: ",
                       ','.join(unexpected)))
        sys.exit(1)

    # make sure the original db is empty
    for db in dbs:
        if get_tables(instance, db):
            print ''.join(("Cowardly refusing to drop non-empty db:", db))
            sys.exit(1)

    conn = connect_mysql(instance)
    cursor = conn.cursor()
    for db in dbs:
        # we should be good to drop the old empty dbs
        raw_sql = 'DROP DATABASE IF EXISTS `{db}`;'
        sql = raw_sql.format(db=db)
        if verbose:
            print sql
        if not dry_run:
            cursor.execute(sql)

        # and we should be ok to drop the non-empty 'dropme_' prepended db
        renamed_db = ''.join((DB_PREPEND, db))
        sql = raw_sql.format(db=renamed_db)
        if verbose:
            print sql
        if not dry_run:
            cursor.execute(sql)


LINE_TEMPLATE = ('{master_instance:<MSPC}'
                 '{instance:<RSPC}'
                 '{reported_at:<22}'
                 '{db:<DBSPC}'
                 '{tbl:<TSPC}'
                 '{row_count:<RCSPC}'
                 '{row_diffs:<DCSPC}'
                 '{checksum_status}')


def generate_format_string(checksums):
    """ Use the base template and proper string lengths to make the output
        look nicer.

        Args:
        checksums - a collection of checksum rows.

        Returns:
        format_str - a format string with spacing offsets filled in.
        line_length - the maximum length of the line + some extra space
    """
    # initial padding values
    padding = {
        'master_instance': len('Master'),
        'instance': len('Replica'),
        'db': len('Database'),
        'tbl': len('Table'),
        'reported_at': len('Date'),
        'row_count': len('Row Count'),
        'row_diffs': len('Diff Count'),
        'checksum_status': len('Status')
    }

    line_length = 40 + sum(padding.values())

    for checksum in checksums:
        # Humans don't care about false positives for diffs
        if (checksum['checksum_status'] == 'ROW_DIFFS_FOUND' and
                checksum['rows_checked'] == 'YES' and
                checksum['row_diffs'] == 0):
            checksum['checksum_status'] = 'GOOD'

        for key, value in padding.items():
            if len(str(checksum[key])) > padding[key]:
                line_length += len(str(checksum[key])) - padding[key]
                padding[key] = len(str(checksum[key]))

    # regenerate the output template based on padding.
    format_str = LINE_TEMPLATE.replace(
        'MSPC', str(padding['master_instance'] + 3)).replace(
            'RSPC', str(padding['instance'] + 3)).replace(
                'DBSPC', str(padding['db'] + 3)).replace(
                    'TSPC', str(padding['tbl'] + 3)).replace(
                        'RCSPC', str(padding['row_count'] + 3)).replace(
                            'DCSPC', str(padding['row_diffs'] + 3))

    return format_str, line_length


def get_checksums(instance, db=False):
    """ Get recent mysql replication checksums

    Args:
    instance - a hostaddr object for what server to pull results for
    db - a string of a data to for which to restrict results

    Returns:
    A list of dicts from a select * on the relevant rows
    """

    vars_for_query = dict()
    vars_for_query['instance'] = instance

    zk = MysqlZookeeper()
    host_shard_map = zk.get_host_shard_map()

    # extra SQL if this is a sharded data set.
    SHARD_DB_IN_SQL = ' AND db in ({sp}) '

    if db is False:
        cnt = 0
        shard_param_set = set()
        try:
            for entry in host_shard_map[instance.__str__()]:
                key = ''.join(('shard', str(cnt)))
                vars_for_query[key] = entry
                shard_param_set.add(key)
                cnt += 1
            shard_param = ''.join(('%(', ')s,%('.join(shard_param_set), ')s'))
        except KeyError:
            # if this is not a sharded data set, don't use this.
            shard_param = None

    else:
        shard_param = '%(shard1)s'
        vars_for_query['shard1'] = db

    # connect to the instance we care about and get some data.
    conn = connect_mysql(instance, 'scriptrw')

    # We only care about the most recent checksum
    cursor = conn.cursor()

    sql_base = ("SELECT detail.master_instance, "
                "       detail.instance, "
                "       detail.db, "
                "       detail.tbl, "
                "       detail.reported_at, "
                "       detail.checksum_status, "
                "       detail.rows_checked, "
                "       detail.row_count, "
                "       detail.row_diffs "
                "FROM "
                "  (SELECT master_instance,"
                "          instance, "
                "          db, "
                "          tbl, "
                "          MAX(reported_at) AS reported_at "
                "   FROM test.checksum_detail "
                "   WHERE master_instance=%(instance)s "
                "   {in_db}"
                "   GROUP BY 1,2,3,4 "
                "  ) AS most_recent "
                "JOIN test.checksum_detail AS detail "
                "USING(master_instance, instance, db, "
                "tbl, reported_at) ")

    # and then fill in the variables.
    if shard_param:
        sql = sql_base.format(in_db=SHARD_DB_IN_SQL.format(sp=shard_param))
    else:
        sql = sql_base.format(in_db='')

    cursor.execute(sql, vars_for_query)
    checksums = cursor.fetchall()
    return checksums


MIN_CMDB_RESULTS = 100
RESET_STATS = 'Reset statistics'
SHUTDOWN_MYSQL = 'Shutdown MySQL'
TERMINATE_INSTANCE = 'Terminate instance'
IGNORABLE_USERS = set([
    "admin", "ptkill", "monit", "#mysql_system#", 'ptchecksum', "replicant",
    "root", "heartbeat", "system user"
])

OUTPUT_FORMAT = ('{hostname:<34} '
                 '{instance_id:<18} '
                 '{happened:<20} '
                 '{state}')


def add_to_queue(hostname, dry_run, skip_production_check=False):
    """ Add an instance to the retirement queue

    Args:
    hostname - The hostname of the instance to add to the retirement queue
    """
    log.info('Adding server {hostname} to retirement '
             'queue'.format(hostname=hostname))

    if hostname in get_protected_hosts('set'):
        raise Exception('Host {hostname} is protected from '
                        'retirement'.format(hostname=hostname))

    # basic sanity check
    zk = MysqlZookeeper()
    for instance in zk.get_all_mysql_instances():
        if instance.hostname == hostname:
            if skip_production_check:
                log.warning("It appears {instance} is in zk but "
                            "skip_production_check is set so continuing."
                            "".format(instance=instance))
            else:
                raise Exception("It appears {instance} is in zk. This is "
                                "very dangerous!".format(instance=instance))
    all_servers = get_all_server_metadata()
    if hostname not in all_servers:
        raise Exception('Host {hostname} is not cmdb'.format(
            hostname=hostname))

    instance_metadata = all_servers[hostname]
    log.info(instance_metadata)
    username, password = get_mysql_user_for_role('admin')

    try:
        if check_for_user_activity(instance_metadata):
            log.info('Trying to reset user_statistics on ip '
                     '{ip}'.format(ip=instance_metadata['internal_ip']))
            with timeout.timeout(3):
                conn = MySQLdb.connect(
                    host=instance_metadata['internal_ip'],
                    user=username,
                    passwd=password,
                    cursorclass=MySQLdb.cursors.DictCursor)
            if not conn:
                raise Exception('timeout')
            if dry_run:
                log.info('In dry_run mode, not changing anything')
            else:
                enable_and_flush_activity_statistics(HostAddr(hostname))
        else:
            log.info("No recent user activity, skipping stats reset")

            # We still need to add it to the queue the first time.
            # Check if it was added recently and exit if it was
            if is_host_in_retirement_queue(hostname):
                return
        activity = RESET_STATS
    except MySQLdb.OperationalError as detail:
        (error_code, msg) = detail.args
        if error_code != MYSQL_ERROR_CONN_HOST_ERROR:
            raise
        log.info('Could not connect to '
                 '{ip}'.format(ip=instance_metadata['internal_ip']))
        activity = SHUTDOWN_MYSQL

        # We only want to add the host if it wasn't already in the queue
        if is_host_in_retirement_queue(hostname):
            return

    if dry_run:
        log.info('In dry_run mode, not changing anything')
    else:
        log_to_retirement_queue(hostname, instance_metadata['instance_id'],
                                activity)


def process_mysql_shutdown(hostname=None, dry_run=False):
    """ Check stats, and shutdown MySQL instances"""
    zk = MysqlZookeeper()
    username, password = get_mysql_user_for_role('admin')
    shutdown_instances = get_retirement_queue_servers(SHUTDOWN_MYSQL)

    if hostname:
        if hostname in shutdown_instances:
            log.info('Only acting on {hostname}'.format(hostname=hostname))
            shutdown_instances = {hostname: shutdown_instances[hostname]}
        else:
            log.info('Supplied host {hostname} is not ready '
                     'for shutdown'.format(hostname=hostname))
            return

    for instance in shutdown_instances:
        if instance in get_protected_hosts('set'):
            log.warning('Host {hostname} is protected from '
                        'retirement'.format(hostname=hostname))
            remove_from_retirement_queue(hostname)
            continue
        for active_instance in zk.get_all_mysql_instances():
            if active_instance.hostname == instance:
                log.warning("It appears {instance} is in zk. This is "
                            "very dangerous! If you got to here, you may be "
                            "trying to turn down a replica set. Please remove "
                            "it from zk and try again"
                            "".format(instance=instance))
                continue
        # check mysql activity
        if check_for_user_activity(shutdown_instances[instance]):
            continue

        # joining on a blank string as password must not have a space between
        # the flag and the arg
        if dry_run:
            log.info('In dry_run mode, not changing state')
        else:
            log.info('Shuting down mysql on {instance}'.format(
                instance=instance))
            shutdown_mysql(HostAddr(instance))
            log_to_retirement_queue(
                instance, shutdown_instances[instance]['instance_id'],
                SHUTDOWN_MYSQL)


def terminate_instances(hostname=None, dry_run=False):
    zk = MysqlZookeeper()
    username, password = get_mysql_user_for_role('admin')
    terminate_instances = get_retirement_queue_servers(TERMINATE_INSTANCE)
    conn = boto.ec2.connect_to_region('us-east-1')

    if hostname:
        if hostname in terminate_instances:
            log.info('Only acting on {hostname}'.format(hostname=hostname))
            terminate_instances = {hostname: terminate_instances[hostname]}
        else:
            log.info('Supplied host {hostname} is not ready '
                     'for termination'.format(hostname=hostname))
            return

    for hostname in terminate_instances:
        if hostname in get_protected_hosts('set'):
            log.warning('Host {hostname} is protected from '
                        'retirement'.format(hostname=hostname))
            remove_from_retirement_queue(hostname)
            continue
        for instance in zk.get_all_mysql_instances():
            if instance.hostname == hostname:
                log.warning("It appears {instance} is in zk. This is "
                            "very dangerous!".format(instance=instance))
                remove_from_retirement_queue(hostname)
                continue

        log.info('Confirming mysql is down on '
                 '{hostname}'.format(hostname=hostname))

        try:
            with timeout.timeout(3):
                conn = MySQLdb.connect(
                    host=terminate_instances[hostname]['internal_ip'],
                    user=username,
                    passwd=password,
                    cursorclass=MySQLdb.cursors.DictCursor)
            log.error('Did not get MYSQL_ERROR_CONN_HOST_ERROR')
            continue
        except MySQLdb.OperationalError as detail:
            (error_code, msg) = detail.args
            if error_code != MYSQL_ERROR_CONN_HOST_ERROR:
                raise
            log.info('MySQL is down')
        log.info('Terminating instance '
                 '{instance}'.format(instance=terminate_instances[hostname][
                     'instance_id']))
        if dry_run:
            log.info('In dry_run mode, not changing state')
        else:
            conn.terminate_instances(
                instance_ids=[terminate_instances[hostname]['instance_id']])
            log_to_retirement_queue(
                hostname, terminate_instances[hostname]['instance_id'],
                TERMINATE_INSTANCE)


def unprotect_host(hostname):
    """ Cause an host to able to be acted on by the retirement queue

    Args:
    hostname - The hostname to remove from protection
    """
    reporting_conn = get_mysqlops_connections()
    cursor = reporting_conn.cursor()
    sql = ("DELETE FROM mysqlops.retirement_protection "
           "WHERE hostname = %(hostname)s")
    cursor.execute(sql, {'hostname': hostname})
    reporting_conn.commit()
    log.info(cursor._executed)


def protect_host(hostname, reason):
    """ Cause an host to not be acted on by the retirement queue

    Args:
    hostname - The hostname to protect
    reason -  An explanation for why this host should not be retired
    dry_run - If set, don't modify state
    """
    protecting_user = get_user()
    if protecting_user == 'root':
        raise Exception('Can not modify retirement protection as root')

    reporting_conn = get_mysqlops_connections()
    cursor = reporting_conn.cursor()
    sql = ("INSERT INTO mysqlops.retirement_protection "
           "SET "
           "hostname = %(hostname)s, "
           "reason = %(reason)s, "
           "protecting_user = %(protecting_user)s")
    cursor.execute(sql, {
        'hostname': hostname,
        'reason': reason,
        'protecting_user': protecting_user
    })
    reporting_conn.commit()
    log.info(cursor._executed)


def show_queue():
    """ Show the servers in the queue and what state they are in.

    Args:
    None
    """

    recently_added = get_retirement_queue_servers(SHUTDOWN_MYSQL, True)
    recently_shutdown = get_retirement_queue_servers(TERMINATE_INSTANCE, True)
    ready_for_shutdown = get_retirement_queue_servers(SHUTDOWN_MYSQL)
    ready_for_termination = get_retirement_queue_servers(TERMINATE_INSTANCE)

    output = []
    for server in recently_added.itervalues():
        server['state'] = 'ADDED'
        output.append(OUTPUT_FORMAT.format(**server))

    for server in ready_for_shutdown.itervalues():
        server['state'] = 'READY_FOR_MYSQL_SHUTDOWN'
        output.append(OUTPUT_FORMAT.format(**server))

    for server in recently_shutdown.itervalues():
        server['state'] = 'MYSQL_SHUTDOWN'
        output.append(OUTPUT_FORMAT.format(**server))

    for server in ready_for_termination.itervalues():
        server['state'] = 'READY_FOR_TERMINATION'
        output.append(OUTPUT_FORMAT.format(**server))

    output.sort()
    log.info("The following servers are in the queue:\n%s", '\n'.join(output))

    return


def check_for_user_activity(instance):
    zk = MysqlZookeeper()
    username, password = get_mysql_user_for_role('admin')

    # check mysql activity
    log.info('Checking activity on {instance}'.format(instance=instance[
        'hostname']))
    with timeout.timeout(3):
        conn = MySQLdb.connect(
            host=instance['internal_ip'],
            user=username,
            passwd=password,
            cursorclass=MySQLdb.cursors.DictCursor)
    if not conn:
        raise Exception('Could not connect to {ip}'
                        ''.format(ip=instance['internal_ip']))

    activity = get_user_activity(HostAddr(instance['hostname']))
    unexpected = set(activity.keys()).difference(IGNORABLE_USERS)
    if unexpected:
        log.error('Unexpected activity on {instance} by user(s):'
                  '{unexpected}'.format(
                      instance=instance['hostname'],
                      unexpected=','.join(unexpected)))
        return True

    log.info('Checking current connections on '
             '{instance}'.format(instance=instance['hostname']))
    connected_users = get_connected_users(HostAddr(instance['hostname']))
    unexpected = connected_users.difference(IGNORABLE_USERS)
    if unexpected:
        log.error('Unexpected connection on {instance} by user(s):'
                  '{unexpected}'.format(
                      instance=instance['hostname'],
                      unexpected=','.join(unexpected)))
        return True
    return False


def get_protected_hosts(return_type='tuple'):
    """ Get data on all protected hosts

    Args:
    return_type - Options are:
                              'set'- return a set of protected hosts
                              'tuple' - returns all data regarding protected hosts

    Returns:
    A tuple which may be empty, with entries similar to:
    ({'protecting_user': 'rwultsch', 'reason': 'because', 'hostname': 'sharddb-14-4'},
     {'protecting_user': 'rwultsch', 'reason': 'because reasons', 'hostname': 'sharddb-14-5'})
    """
    if return_type != 'tuple' and return_type != 'set':
        raise Exception('Unsupported return_type '
                        '{return_type}'.format(return_type=return_type))

    reporting_conn = get_mysqlops_connections()
    cursor = reporting_conn.cursor()
    sql = "SELECT * FROM mysqlops.retirement_protection"
    cursor.execute(sql)
    results = cursor.fetchall()

    if return_type == 'tuple':
        return results
    elif return_type == 'set':
        results_set = set()
        for entry in results:
            results_set.add(entry['hostname'])

        return results_set


def get_retirement_queue_servers(next_state, recent=False):
    """ Pull instances in queue ready for termination

    Args:
    next_state - The desired next state of a server. Options are constants
                 SHUTDOWN_MYSQL and TERMINATE_INSTANCE.

    recent     - When True, return hosts that have recently transitioned to a
                 new state and are not currently eligible to have the next
                 operation performed on them.

    Returns:
    A dict of the same form as what is returned from the cmdbs
    """
    if next_state == SHUTDOWN_MYSQL:
        server_state = {
            'previous_state': RESET_STATS,
            'next_state': SHUTDOWN_MYSQL
        }
    elif next_state == TERMINATE_INSTANCE:
        server_state = {
            'previous_state': SHUTDOWN_MYSQL,
            'next_state': TERMINATE_INSTANCE
        }
    else:
        raise Exception('Invalid state param '
                        '"{next_state}"'.format(next_state=next_state))

    if recent:
        when = "    AND happened > now() - INTERVAL 1 DAY "
    else:
        when = ("    AND happened > now() - INTERVAL 3 WEEK "
                "    AND happened < now() - INTERVAL 1 DAY ")
    reporting_conn = get_mysqlops_connections()
    cursor = reporting_conn.cursor()
    sql = (
        "SELECT t1.hostname, t1.instance_id, t1.happened "
        "FROM ( "
        "    SELECT hostname, instance_id, happened "
        "    FROM mysqlops.retirement_queue "
        "    WHERE activity = %(previous_state)s " + when + "    ) t1 "
        "LEFT JOIN mysqlops.retirement_queue t2 on t1.instance_id = t2.instance_id "
        "AND t2.activity=%(next_state)s "
        "WHERE t2.hostname IS NULL;")
    cursor.execute(sql, server_state)
    instances = cursor.fetchall()

    all_servers = get_all_server_metadata()
    if len(all_servers) < MIN_CMDB_RESULTS:
        raise Exception('CMDB returned too few results')

    ret = dict()
    for instance in instances:
        if instance['hostname'] not in all_servers:
            log.error('Something killed {instance}, cleaning up '
                      'retirement queue now'.format(instance=instance))
            remove_from_retirement_queue(instance['hostname'])
        elif instance['instance_id'] != all_servers[instance['hostname']][
                'instance_id']:
            log.error('Possibly duplicate hostname for '
                      '{hostname}!'.format(hostname=instance['hostname']))
        else:
            ret[instance['hostname']] = all_servers[instance['hostname']]
            ret[instance['hostname']]['happened'] = str(instance['happened'])

    return ret


def is_host_in_retirement_queue(hostname):
    sql = ("SELECT hostname "
           "FROM mysqlops.retirement_queue "
           "WHERE hostname = %(hostname)s")
    reporting_conn = get_mysqlops_connections()
    cursor = reporting_conn.cursor()
    cursor.execute(sql, {'hostname': hostname})
    return cursor.rowcount > 0


def log_to_retirement_queue(hostname, instance_id, activity):
    """ Add a record to the retirement queue log

    Args:
    hostname - The hostname of the server to be acted upon
    instance_id - The aws instance id
    activity - What is the state to log

    """
    reporting_conn = get_mysqlops_connections()
    cursor = reporting_conn.cursor()

    # we are using a replace if we need to restart the process. That will
    # restart the clock on the replacement
    sql = ('REPLACE INTO mysqlops.retirement_queue '
           'SET '
           'hostname = %(hostname)s ,'
           'instance_id = %(instance_id)s, '
           'activity = %(activity)s, '
           'happened = now() ')
    cursor.execute(sql, {
        'hostname': hostname,
        'instance_id': instance_id,
        'activity': activity
    })
    log.info(cursor._executed)
    reporting_conn.commit()


def remove_from_retirement_queue(hostname):
    """ Remove an host from the retirement queue

    Args:
    hostname - the hostname to remove from the queue
    """
    reporting_conn = get_mysqlops_connections()
    cursor = reporting_conn.cursor()

    sql = ('DELETE FROM mysqlops.retirement_queue '
           'WHERE hostname = %(hostname)s')
    cursor.execute(sql, {'hostname': hostname})
    log.info(cursor._executed)
    reporting_conn.commit()


def schema_verifier(**args):
    zk_prefix = SHARDED_DBS_PREFIX_MAP[args.instance_type]['zk_prefix']
    seed_instance = HostAddr(args.seed_instance)
    desired = show_create_table(seed_instance, args.seed_db, args.table)
    tbl_hash = hashlib.md5(desired).hexdigest()
    print("Desired table definition:\n{desired}").format(desired=desired)
    incorrect = check_schema(zk_prefix, args.table, tbl_hash)
    if len(incorrect) == 0:
        print "It appears that all schema is synced"
        sys.exit(0)

    d = difflib.Differ()
    for problem in incorrect.iteritems():
        represenative = list(problem[1])[0].split(' ')
        hostaddr = HostAddr(represenative[0])
        create = show_create_table(hostaddr, represenative[1], args.table)
        diff = d.compare(desired.splitlines(), create.splitlines())
        print 'The following difference has been found:'
        print '\n'.join(diff)
        print "It is present on the following db's:"
        print '\n'.join(list(problem[1]))
    sys.exit(1)


def check_schema(zk_prefix, tablename, tbl_hash):
    """Verify that a table across an entire tier has the expected schema

    Args:
    zk_prefix - The prefix of the key ZK
    table - the name of the table to verify
    tbl_hash - the md5sum of the desired CREATE TABLE for the table

    Returns:
    A dictionary with keys that are the hash of the CREATE TABLE statement
    and the values are sets of hostname:port followed by a space and then the
    db one which the incorrect schema was found.
    """
    incorrect = dict()
    zk = MysqlZookeeper()
    for replica_set in zk.get_all_mysql_replica_sets():
        if not replica_set.startswith(zk_prefix):
            continue

        for role in REPLICA_TYPES:
            instance = zk.get_mysql_instance_from_replica_set(replica_set,
                                                              role)
            hashes = check_instance_table(instance, tablename, tbl_hash)
            for entry in hashes.iteritems():
                if entry[0] not in incorrect:
                    incorrect[entry[0]] = set()
                incorrect[entry[0]] = incorrect[entry[0]].union(entry[1])
    return incorrect


def check_instance_table(hostaddr, table, desired_hash):
    """ Check that a table on a MySQL instance has the expected schema

    Args:
    hostaddr - object describing which mysql instance to connect to
    table - the name of the table to verify
    desired_hash - the md5sum of the desired CREATE TABLE for the table

    Returns:
    A dictionary with keys that are the hash of the CREATE TABLE statement
    and the values are sets of hostname:port followed by a space and then the
    db one which the incorrect schema was found.
    """
    ret = dict()
    for db in get_dbs(hostaddr):
        definition = show_create_table(hostaddr, db, table)
        tbl_hash = hashlib.md5(definition).hexdigest()
        if tbl_hash != desired_hash:
            if tbl_hash not in ret:
                ret[tbl_hash] = set()
            ret[tbl_hash].add(''.join((hostaddr.__str__(), ' ', db)))
    return ret


def auto_add_instance_to_zk(instance, dry_run):
    """ Try to do right thing in adding a server to zk

    Args:
    instance - The replacement instance
    dry_run - If set, do not modify zk
    """
    try:
        conn = get_mysqlops_connections()
        log.info('Determining replacement for '
                 '{hostname}'.format(hostname=instance.hostname))
        server_metadata = get_server_metadata(instance.hostname)
        if not server_metadata:
            raise Exception('CMDB lacks knowledge of replacement host')
        instance_id = server_metadata['id']
        role = determine_replacement_role(conn, instance_id)
        log.info('Adding server as role: {role}'.format(role=role))
    except Exception, e:
        log.exception(e)
        raise
    add_replica_to_zk(instance, role, dry_run)

    if not dry_run:
        log.info('Updating host_replacement_log')
        update_host_replacement_log(conn, instance_id)


def determine_replacement_role(conn, instance_id):
    """ Try to determine the role an instance should be placed into

    Args:
    conn - A connection to the reporting server
    instance - The replacement instance

    Returns:
    The replication role which should be either 'slave' or 'dr_slave'
    """
    zk = MysqlZookeeper()
    cursor = conn.cursor()
    sql = ("SELECT old_host "
           "FROM mysqlops.host_replacement_log "
           "WHERE new_instance = %(new_instance)s ")
    params = {'new_instance': instance_id}
    cursor.execute(sql, params)
    log.info(cursor._executed)
    result = cursor.fetchone()
    if result is None:
        raise Exception('Could not determine replacement host')

    old_host = HostAddr(result['old_host'])
    log.info('Host to be replaced is {old_host}'
             ''.format(old_host=old_host.hostname))

    (_, repl_type) = zk.get_replica_set_from_instance(old_host)

    if repl_type == REPLICA_ROLE_MASTER:
        raise Exception('Corwardly refusing to replace a master!')
    elif repl_type is None:
        raise Exception('Could not determine replacement role')
    else:
        return repl_type


def get_zk_node_for_replica_set(kazoo_client, replica_set):
    """ Figure out what node holds the configuration of a replica set

    Args:
    kazoo_client - A kazoo_client
    replica_set - A name for a replica set

    Returns:
    zk_node - The node that holds the replica set
    parsed_data - The deserialized data from json in the node
    """
    for zk_node in [DS_ZK, GEN_ZK]:
        znode_data, meta = kazoo_client.get(zk_node)
        parsed_data = simplejson.loads(znode_data)
        if replica_set in parsed_data:
            return (zk_node, parsed_data, meta.version)
    raise Exception('Could not find replica_set {replica_set} '
                    'in zk_nodes'.format(replica_set=replica_set))


def remove_auth(zk_record):
    """ Remove passwords from zk records

    Args:
    zk_record - A dict which may or not have a passwd or userfield.

    Returns:
    A dict which if a passwd or user field is present will have the
    values redacted
    """
    ret = copy.deepcopy(zk_record)
    if 'passwd' in ret:
        ret['passwd'] = 'REDACTED'

    if 'user' in ret:
        ret['user'] = 'REDACTED'

    return ret


def add_replica_to_zk(instance, replica_type, dry_run):
    """ Add a replica to zk

    Args:
    instance - A hostaddr object of the replica to add to zk
    replica_type - Either 'slave' or 'dr_slave'.
    dry_run - If set, do not modify zk
    """
    try:
        if replica_type not in [REPLICA_ROLE_DR_SLAVE, REPLICA_ROLE_SLAVE]:
            raise Exception('Invalid value "{replica_type}" for argument '
                            "replica_type").format(replica_type=replica_type)

        zk_local = MysqlZookeeper()
        kazoo_client = get_kazoo_client()
        if not kazoo_client:
            raise Exception('Could not get a zk connection')

        log.info('Instance is {inst}'.format(inst=instance))
        assert_replication_sanity(instance)
        assert_replication_unlagged(instance, REPLICATION_TOLERANCE_NORMAL)
        master = get_master_from_instance(instance)
        if master not in zk_local.get_all_mysql_instances_by_type(
                REPLICA_ROLE_MASTER):
            raise Exception('Instance {master} is not a master in zk'
                            ''.format(master=master))

        log.info('Detected master of {instance} '
                 'as {master}'.format(
                     instance=instance, master=master))

        (replica_set, _) = zk_local.get_replica_set_from_instance(master)
        log.info('Detected replica_set as '
                 '{replica_set}'.format(replica_set=replica_set))

        if replica_type == REPLICA_ROLE_SLAVE:
            (zk_node, parsed_data, version) = get_zk_node_for_replica_set(
                kazoo_client, replica_set)
            log.info('Replica set {replica_set} is held in zk_node '
                     '{zk_node}'.format(
                         zk_node=zk_node, replica_set=replica_set))
            log.info('Existing config:')
            log.info(pprint.pformat(remove_auth(parsed_data[replica_set])))
            new_data = copy.deepcopy(parsed_data)
            new_data[replica_set][REPLICA_ROLE_SLAVE]['host'] = \
                instance.hostname
            new_data[replica_set][REPLICA_ROLE_SLAVE]['port'] = \
                instance.port
            log.info('New config:')
            log.info(pprint.pformat(remove_auth(new_data[replica_set])))

            if new_data == parsed_data:
                raise Exception('No change would be made to zk, '
                                'will not write new config')
            elif dry_run:
                log.info('dry_run is set, therefore not modifying zk')
            else:
                log.info('Pushing new configuration for '
                         '{replica_set}:'.format(replica_set=replica_set))
                kazoo_client.set(zk_node, simplejson.dumps(new_data), version)
        elif replica_type == REPLICA_ROLE_DR_SLAVE:
            znode_data, dr_meta = kazoo_client.get(DR_ZK)
            parsed_data = simplejson.loads(znode_data)
            new_data = copy.deepcopy(parsed_data)
            if replica_set in parsed_data:
                log.info('Existing dr config:')
                log.info(pprint.pformat(remove_auth(parsed_data[replica_set])))
            else:
                log.info('Replica set did not previously have a dr slave')

            new_data[replica_set] = \
                {REPLICA_ROLE_DR_SLAVE: {'host': instance.hostname,
                                                    'port': instance.port}}
            log.info('New dr config:')
            log.info(pprint.pformat(remove_auth(new_data[replica_set])))

            if new_data == parsed_data:
                raise Exception('No change would be made to zk, '
                                'will not write new config')
            elif dry_run:
                log.info('dry_run is set, therefore not modifying zk')
            else:
                log.info('Pushing new dr configuration for '
                         '{replica_set}:'.format(replica_set=replica_set))
                kazoo_client.set(DR_ZK,
                                 simplejson.dumps(new_data), dr_meta.version)
        else:
            # we should raise an exception above rather than getting to here
            pass
    except Exception, e:
        log.exception(e)
        raise


def swap_master_and_slave(instance, dry_run):
    """ Swap a master and slave in zk. Warning: this does not sanity checks
        and does nothing more than update zk. YOU HAVE BEEN WARNED!

    Args:
    instance - An instance in the replica set. This function will figure
               everything else out.
    dry_run - If set, do not modify configuration.
    """
    zk_local = MysqlZookeeper()
    kazoo_client = get_kazoo_client()
    if not kazoo_client:
        raise Exception('Could not get a zk connection')

    log.info('Instance is {inst}'.format(inst=instance))
    (replica_set, version) = zk_local.get_replica_set_from_instance(instance)
    log.info('Detected replica_set as '
             '{replica_set}'.format(replica_set=replica_set))
    (zk_node, parsed_data,
     version) = get_zk_node_for_replica_set(kazoo_client, replica_set)
    log.info('Replica set {replica_set} is held in zk_node '
             '{zk_node}'.format(
                 zk_node=zk_node, replica_set=replica_set))

    log.info('Existing config:')
    log.info(pprint.pformat(remove_auth(parsed_data[replica_set])))
    new_data = copy.deepcopy(parsed_data)
    new_data[replica_set][REPLICA_ROLE_MASTER] = \
        parsed_data[replica_set][REPLICA_ROLE_SLAVE]
    new_data[replica_set][REPLICA_ROLE_SLAVE] = \
        parsed_data[replica_set][REPLICA_ROLE_MASTER]

    log.info('New config:')
    log.info(pprint.pformat(remove_auth(new_data[replica_set])))

    if new_data == parsed_data:
        raise Exception('No change would be made to zk, '
                        'will not write new config')
    elif dry_run:
        log.info('dry_run is set, therefore not modifying zk')
    else:
        log.info('Pushing new configuration for '
                 '{replica_set}:'.format(replica_set=replica_set))
        kazoo_client.set(zk_node, simplejson.dumps(new_data), version)


def swap_slave_and_dr_slave(instance, dry_run):
    """ Swap a slave and a dr_slave in zk

    Args:
    instance - An instance that is either a slave or dr_slave
    """
    zk_local = MysqlZookeeper()
    kazoo_client = get_kazoo_client()
    if not kazoo_client:
        raise Exception('Could not get a zk connection')

    log.info('Instance is {inst}'.format(inst=instance))
    (replica_set, _) = zk_local.get_replica_set_from_instance(instance)
    log.info('Detected replica_set as '
             '{replica_set}'.format(replica_set=replica_set))
    (zk_node, parsed_data,
     version) = get_zk_node_for_replica_set(kazoo_client, replica_set)
    log.info('Replica set {replica_set} is held in zk_node '
             '{zk_node}'.format(
                 zk_node=zk_node, replica_set=replica_set))

    log.info('Existing config:')
    log.info(pprint.pformat(remove_auth(parsed_data[replica_set])))
    new_data = copy.deepcopy(parsed_data)

    dr_znode_data, dr_meta = kazoo_client.get(DR_ZK)
    dr_parsed_data = simplejson.loads(dr_znode_data)
    new_dr_data = copy.deepcopy(dr_parsed_data)
    if replica_set not in parsed_data:
        raise Exception('Replica set {replica_set} is not present '
                        'in dr_node'.format(replica_set=replica_set))
    log.info('Existing dr config:')
    log.info(pprint.pformat(remove_auth(dr_parsed_data[replica_set])))

    new_data[replica_set][REPLICA_ROLE_SLAVE] = \
        dr_parsed_data[replica_set][REPLICA_ROLE_DR_SLAVE]
    new_dr_data[replica_set][REPLICA_ROLE_DR_SLAVE] = \
        parsed_data[replica_set][REPLICA_ROLE_SLAVE]

    log.info('New config:')
    log.info(pprint.pformat(remove_auth(new_data[replica_set])))

    log.info('New dr config:')
    log.info(pprint.pformat(remove_auth(new_dr_data[replica_set])))

    if dry_run:
        log.info('dry_run is set, therefore not modifying zk')
    else:
        log.info('Pushing new configuration for '
                 '{replica_set}:'.format(replica_set=replica_set))
        kazoo_client.set(zk_node, simplejson.dumps(new_data), version)
        try:
            kazoo_client.set(DR_ZK,
                             simplejson.dumps(new_dr_data), dr_meta.version)
        except:
            raise Exception(
                'DR node is incorrect due to a different change '
                'blocking this change. You need to fix it yourself')


def update_host_replacement_log(conn, instance_id):
    """ Mark a replacement as completed

    conn - A connection to the reporting server
    instance - The replacement instance
    """
    cursor = conn.cursor()
    sql = ("UPDATE mysqlops.host_replacement_log "
           "SET is_completed = 1 "
           "WHERE new_instance = %(new_instance)s ")
    params = {'new_instance': instance_id}
    cursor.execute(sql, params)
    log.info(cursor._executed)
    conn.commit()


def mysql_backup(instance, backup_type=BACKUP_TYPE_XBSTREAM):
    """ Run a file based backup on a supplied local instance

    Args:
    instance - A hostaddr object
    """
    log.info('Confirming sanity of replication (if applicable)')
    zk = MysqlZookeeper()
    try:
        (_, replica_type) = zk.get_replica_set_from_instance(instance)
    except:
        # instance is not in production
        replica_type = None

    if replica_type and replica_type != REPLICA_ROLE_MASTER:
        assert_replication_sanity(instance)

    log.info('Logging initial status to mysqlops')
    start_timestamp = time.localtime()
    lock_handle = None
    backup_id = start_backup_log(instance, backup_type, start_timestamp)

    # Take a lock to prevent multiple backups from running concurrently
    try:
        log.info('Taking backup lock')
        lock_handle = take_flock_lock(BACKUP_LOCK_FILE)

        # Actually run the backup
        log.info('Running backup')
        if backup_type == BACKUP_TYPE_XBSTREAM:
            backup_file = xtrabackup_instance(instance, start_timestamp)
        elif backup_type == BACKUP_TYPE_LOGICAL:
            backup_file = logical_backup_instance(instance, start_timestamp)
        else:
            raise Exception('Unsupported backup type {backup_type}'
                            ''.format(backup_type=backup_type))
    finally:
        if lock_handle:
            log.info('Releasing lock')
            release_flock_lock(lock_handle)

    # Update database with additional info now that backup is done.
    if backup_id:
        log.info("Updating database log entry with final backup info")
        finalize_backup_log(backup_id, backup_file)
    else:
        log.info("The backup is complete, but we were not able to "
                 "write to the central log DB.")


BACKUP_OK_RETURN = 0
BACKUP_MISSING_RETURN = 1
BACKUP_NOT_IN_ZK_RETURN = 127
CSV_CHECK_PROCESSES = 8
CSV_STARTUP = datetime.time(0, 15)
CSV_COMPLETION_TIME = datetime.time(2, 30)
MISSING_BACKUP_VERBOSE_LIMIT = 20
CSV_BACKUP_LOG_TABLE_DEFINITION = """CREATE TABLE {db}.{tbl} (
 `backup_date` date NOT NULL,
 `completion` datetime DEFAULT NULL,
 PRIMARY KEY (`backup_date`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 """


def find_mysql_backup(replica_set, date, backup_type):
    """ Check whether or not a given replica set has a backup in S3

    Args:
        replica_set: The replica set we're checking for.
        date: The date to search for.

    Returns:
        location: The location of the backup for this replica set.
                  Returns None if not found.
    """
    zk = MysqlZookeeper()
    for repl_type in REPLICA_TYPES:
        instance = zk.get_mysql_instance_from_replica_set(replica_set,
                                                          repl_type)
        if instance:
            try:
                backup_file = get_s3_backup(instance, date, backup_type)
                if backup_file:
                    return backup_file
                break
            except:
                # we'll get a 404 if there was no s3 backup, but that's OK,
                # so we can just move on to the next one.
                pass
    return None


def verify_csv_backup(shard_type, date, instance=None):
    """ Verify csv backup(s)

    Args:
    shard_type - Type of mysql db
    date - date as a string
    instance - (optional) HostAddr instance

    Returns:
    True if backup is verified, false otherwise
    """
    if instance and csv_backup_success_logged(instance, date):
        print('Per csv backup success log, backup has already been '
              'verified')
        return True

    if instance and early_verification(date, instance):
        print 'Backups are currently running'
        return True

    if shard_type in SHARDED_DBS_PREFIX_MAP:
        ret = verify_sharded_csv_backup(shard_type, date, instance)
    elif shard_type in FLEXSHARD_DBS:
        ret = verify_flexsharded_csv_backup(shard_type, date, instance)
    else:
        ret = verify_unsharded_csv_backup(shard_type, date, instance)

    if instance and ret:
        log_csv_backup_success(instance, date)

    return ret


def verify_flexsharded_csv_backup(shard_type, date, instance=None):
    """ Verify that a flexsharded data set has been backed up to hive

    Args:
    shard_type -  i.e. 'commercefeeddb', etc
    date - The date to search for
    instance - Restrict the search to problem on a single instnace

    Returns True for no problems found, False otherwise.
    """
    success = True
    replica_sets = set()
    zk = MysqlZookeeper()
    if instance:
        replica_sets.add(zk.get_replica_set_from_instance(instance)[0])
    else:
        for replica_set in zk.get_all_mysql_replica_sets():
            if replica_set.startswith(FLEXSHARD_DBS[shard_type]['zk_prefix']):
                replica_sets.add(replica_set)

    schema_host = zk.get_mysql_instance_from_replica_set(
        FLEXSHARD_DBS[shard_type]['example_shard_replica_set'],
        repl_type=REPLICA_ROLE_SLAVE)

    boto_conn = boto.connect_s3()
    bucket = boto_conn.get_bucket(S3_CSV_BUCKET, validate=False)
    missing_uploads = set()

    for db in get_dbs(schema_host):
        for table in mysql_backup_csv.mysql_backup_csv(
                schema_host).get_tables_to_backup(db):
            if not verify_csv_schema_upload(shard_type, date, schema_host, db,
                                            [table]):
                success = False
                continue

            table_missing_uploads = set()
            for replica_set in replica_sets:
                chk_instance = zk.get_mysql_instance_from_replica_set(
                    replica_set)
                (_, data_path, success_path) = get_csv_backup_paths(
                    date, db, table, chk_instance.replica_type,
                    chk_instance.get_zk_replica_set()[0])
                if not bucket.get_key(data_path):
                    table_missing_uploads.add(data_path)
                    success = False

            if not table_missing_uploads and not instance:
                if not bucket.get_key(success_path):
                    print 'Creating success key {key}'.format(key=success_path)
                    key = bucket.new_key(success_path)
                    key.set_contents_from_string('')

            missing_uploads.update(table_missing_uploads)

    if missing_uploads:
        if len(missing_uploads) < MISSING_BACKUP_VERBOSE_LIMIT:
            print('Shard type {shard_type} is missing uploads:'
                  ''.format(shard_type=shard_type))
            pprint.pprint(missing_uploads)
        else:
            print('Shard type {shard_type} is missing {num} uploads'
                  ''.format(
                      num=len(missing_uploads), shard_type=shard_type))

    if not missing_uploads and not instance and success:
        print 'Shard type {shard_type} is backed up'.format(
            shard_type=shard_type)

    return success


def verify_sharded_csv_backup(shard_type, date, instance=None):
    """ Verify that a sharded data set has been backed up to hive

    Args:
    shard_type -  i.e. 'sharddb', etc
    date - The date to search for
    instance - Restrict the search to problem on a single instnace

    Returns True for no problems found, False otherwise.
    """
    zk = MysqlZookeeper()
    example_shard = SHARDED_DBS_PREFIX_MAP[shard_type]['example_shard']
    schema_host = zk.shard_to_instance(
        example_shard, repl_type=REPLICA_ROLE_SLAVE)
    tables = mysql_backup_csv.mysql_backup_csv(
        schema_host).get_tables_to_backup(convert_shard_to_db(example_shard))
    success = verify_csv_schema_upload(shard_type, date, schema_host,
                                       convert_shard_to_db(example_shard),
                                       tables)
    if instance:
        host_shard_map = zk.get_host_shard_map()
        (replica_set,
         replica_type) = zk.get_replica_set_from_instance(instance)
        master = zk.get_mysql_instance_from_replica_set(replica_set,
                                                        REPLICA_ROLE_MASTER)
        shards = host_shard_map[master.__str__()]
    else:
        shards = zk.get_shards_by_shard_type(shard_type)

    pool = multiprocessing.Pool(processes=CSV_CHECK_PROCESSES)
    pool_args = list()
    if not tables:
        raise Exception('No tables will be checked for backups')
    if not shards:
        raise Exception('No shards will be checked for backups')

    for table in tables:
        pool_args.append((table, shard_type, date, shards))
    results = pool.map(get_missing_uploads, pool_args)
    missing_uploads = set()
    for result in results:
        missing_uploads.update(result)

    if missing_uploads or not success:
        if len(missing_uploads) < MISSING_BACKUP_VERBOSE_LIMIT:
            print('Shard type {shard_type} is missing uploads:'
                  ''.format(shard_type=shard_type))
            pprint.pprint(missing_uploads)
        else:
            print('Shard type {shard_type} is missing {num} uploads'
                  ''.format(
                      num=len(missing_uploads), shard_type=shard_type))
        return False
    else:
        if instance:
            print 'Instance {instance} is backed up'.format(instance=instance)
        else:
            # we have checked all shards, all are good, create success files
            boto_conn = boto.connect_s3()
            bucket = boto_conn.get_bucket(S3_CSV_BUCKET, validate=False)
            for table in tables:
                (_, _, success_path) = get_csv_backup_paths(
                    date,
                    convert_shard_to_db(example_shard), table, shard_type)
                if not bucket.get_key(success_path):
                    print 'Creating success key {key}'.format(key=success_path)
                    key = bucket.new_key(success_path)
                    key.set_contents_from_string('')
            print 'Shard type {shard_type} is backed up'.format(
                shard_type=shard_type)

        return True


def get_missing_uploads(args):
    """ Check to see if all backups are present

    Args: A tuple which can be expanded to:
    table - table name
    shard_type -  sharddb, etc
    shards -  a set of shards

    Returns: a set of shards which are not backed up
    """
    (table, shard_type, date, shards) = args
    expected_s3_keys = set()
    prefix = None

    for shard in shards:
        (_, data_path, _) = get_csv_backup_paths(date,
                                                 convert_shard_to_db(shard),
                                                 table, shard_type)
        expected_s3_keys.add(data_path)
        if not prefix:
            prefix = os.path.dirname(data_path)

    boto_conn = boto.connect_s3()
    bucket = boto_conn.get_bucket(S3_CSV_BUCKET, validate=False)
    uploaded_keys = set()
    for key in bucket.list(prefix=prefix):
        uploaded_keys.add(key.name)

    missing_uploads = expected_s3_keys.difference(uploaded_keys)

    for entry in copy.copy(missing_uploads):
        # the list api occassionally has issues, so we will recheck any missing
        # entries. If any are actually missing we will quit checking because
        # there is definitely work that needs to be done
        if bucket.get_key(entry):
            print 'List method erronious did not return data for key:{entry}'.format(
                entry=entry)
            missing_uploads.discard(entry)
        else:
            return missing_uploads

    return missing_uploads


def verify_unsharded_csv_backup(shard_type, date, instance):
    """ Verify that a non-sharded db has been backed up to hive

    Args:
    shard_type - In this case, a hostname prefix
    date - The date to search for
    instance - The actual instance to inspect for backups being done

    Returns True for no problems found, False otherwise.
    """
    return_status = True
    boto_conn = boto.connect_s3()
    bucket = boto_conn.get_bucket(S3_CSV_BUCKET, validate=False)
    missing_uploads = set()
    for db in get_dbs(instance):
        tables = mysql_backup_csv.mysql_backup_csv(
            instance).get_tables_to_backup(db)
        for table in tables:
            if not verify_csv_schema_upload(shard_type, date, instance, db,
                                            set([table])):
                return_status = False
                print 'Missing schema for {db}.{table}'.format(
                    db=db, table=table)
                continue

            (_, data_path, success_path) = \
                get_csv_backup_paths(date, db, table,
                                                          instance.replica_type,
                                                          instance.get_zk_replica_set()[0])
            if not bucket.get_key(data_path):
                missing_uploads.add(data_path)
            else:
                # we still need to create a success file for the data
                # team for this table, even if something else is AWOL
                # later in the
                if bucket.get_key(success_path):
                    print 'Key already exists {key}'.format(key=success_path)
                else:
                    print 'Creating success key {key}'.format(key=success_path)
                    key = bucket.new_key(success_path)
                    key.set_contents_from_string('')

    if missing_uploads:
        if len(missing_uploads) < MISSING_BACKUP_VERBOSE_LIMIT:
            print 'Missing uploads: {uploads}'.format(uploads=missing_uploads)
        else:
            print 'Missing {num} uploads'.format(num=len(missing_uploads))
        return_status = False

    return return_status


def early_verification(date, instance):
    """ Just after UTC midnight we don't care about backups. For a bit after
        that we just care that backups are running

    Args:
    date - The backup date to check
    instance - What instance is being checked

    Returns:
    True if backups are running or it is too early, False otherwise
    """
    if (date == (datetime.datetime.utcnow().date() - datetime.timedelta(days=1)
                 ).strftime("%Y-%m-%d")):
        if datetime.datetime.utcnow().time() < CSV_STARTUP:
            print 'Backup startup time has not yet passed'
            # For todays date, we give CSV_STARTUP minutes before checking anything.
            return True

        if datetime.datetime.utcnow().time() < CSV_COMPLETION_TIME:
            # For todays date, until after CSV_COMPLETION_TIME it is good enough
            # to check if backups are running. If they are running, everything
            # is ok. If they are not running, we will do all the normal checks.
            if csv_backups_running(instance):
                print 'Backup running on {i}'.format(i=instance)
                return True


def csv_backups_running(instance):
    """ Check to see if csv dumps are running

    Args:
    instance - we will use this to determine the replica set

    Returns:
    True if backups are running, False otherwise
    """
    (dump_user, _) = get_mysql_user_for_role(USER_ROLE_MYSQLDUMP)
    replica_set = instance.get_zk_replica_set()[0]
    zk = MysqlZookeeper()

    for slave_role in [REPLICA_ROLE_DR_SLAVE, REPLICA_ROLE_SLAVE]:
        slave_instance = zk.get_mysql_instance_from_replica_set(replica_set,
                                                                slave_role)
        if not slave_instance:
            continue

        if dump_user in get_connected_users(slave_instance):
            return True

    return False


def log_csv_backup_success(instance, date):
    """ The CSV backup check can be expensive, so let's log that it is done

    Args:
    instance - A hostaddr object
    date - a string for the date
    """
    zk = MysqlZookeeper()
    replica_set = zk.get_replica_set_from_instance(instance)[0]
    master = zk.get_mysql_instance_from_replica_set(replica_set)
    conn = connect_mysql(master, 'scriptrw')
    cursor = conn.cursor()

    if not does_table_exist(master, METADATA_DB, CSV_BACKUP_LOG_TABLE):
        print 'Creating missing metadata table'
        cursor.execute(
            CSV_BACKUP_LOG_TABLE_DEFINITION.format(
                db=METADATA_DB, tbl=CSV_BACKUP_LOG_TABLE))

    sql = ('INSERT IGNORE INTO {METADATA_DB}.{CSV_BACKUP_LOG_TABLE} '
           'SET backup_date = %(date)s, '
           'completion = NOW()'
           ''.format(
               METADATA_DB=METADATA_DB,
               CSV_BACKUP_LOG_TABLE=CSV_BACKUP_LOG_TABLE))
    cursor.execute(sql, {'date': date})
    conn.commit()


def csv_backup_success_logged(instance, date):
    """ Check for log entries created by log_csv_backup_success

    Args:
    instance - A hostaddr object
    date - a string for the date

    Returns:
    True if already backed up, False otherwise
    """
    zk = MysqlZookeeper()
    replica_set = zk.get_replica_set_from_instance(instance)[0]
    master = zk.get_mysql_instance_from_replica_set(replica_set)
    conn = connect_mysql(master, 'scriptrw')
    cursor = conn.cursor()

    if not does_table_exist(master, METADATA_DB, CSV_BACKUP_LOG_TABLE):
        return False

    sql = ('SELECT COUNT(*) as "cnt" '
           'FROM {METADATA_DB}.{CSV_BACKUP_LOG_TABLE} '
           'WHERE backup_date = %(date)s '
           ''.format(
               METADATA_DB=METADATA_DB,
               CSV_BACKUP_LOG_TABLE=CSV_BACKUP_LOG_TABLE))
    cursor.execute(sql, {'date': date})
    if cursor.fetchone()["cnt"]:
        return True
    else:
        return False


def verify_csv_schema_upload(shard_type, date, instance, schema_db, tables):
    """ Confirm that schema files are uploaded

    Args:
    shard_type - In this case, a hostname or shard type (generally
                 one in the same)
    date - The date to search for
    schema_host - A host to examine to find which tables should exist
    schema_db - Which db to inxpect on schema_host
    tables - A set of which tables to check in schema_db for schema upload

    Returns True for no problems found, False otherwise.
    """
    return_status = True
    missing = set()
    boto_conn = boto.connect_s3()
    bucket = boto_conn.get_bucket(S3_CSV_BUCKET, validate=False)
    for table in tables:
        (path, _, _) = get_csv_backup_paths(date, schema_db, table,
                                            instance.replica_type,
                                            instance.get_zk_replica_set()[0])
        if not bucket.get_key(path):
            missing.add(path)
            return_status = False

    if missing:
        print 'Expected schema files are missing: {missing}'.format(
            missing=missing)
    return return_status


ACTIVE = 'active'
CSV_BACKUP_LOCK_TABLE_NAME = 'backup_locks'
CSV_BACKUP_LOCK_TABLE = """CREATE TABLE IF NOT EXISTS {db}.{tbl} (
  `lock_identifier` varchar(36) NOT NULL,
  `lock_active` enum('active') DEFAULT 'active',
  `created_at` datetime NOT NULL,
  `expires` datetime DEFAULT NULL,
  `released` datetime DEFAULT NULL,
  `db` varchar(64) NOT NULL,
  `hostname` varchar(90) NOT NULL DEFAULT '',
  `port` int(11) NOT NULL DEFAULT '0',
  PRIMARY KEY (`lock_identifier`),
  UNIQUE KEY `lock_active` (`db`,`lock_active`),
  INDEX `backup_location` (`hostname`, `port`),
  INDEX `expires` (`expires`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1"""
MAX_THREAD_ERROR = 5

PATH_PITR_DATA = 'pitr/{replica_set}/{db_name}/{date}'
SUCCESS_ENTRY = 'YAY_IT_WORKED'


class mysql_backup_csv:
    def __init__(self,
                 instance,
                 db=None,
                 force_table=None,
                 force_reupload=False):
        """ Init function for backup, takes all args

        Args:
        instance - A hostAddr obect of the instance to be baced up
        db - (option) backup only specified db
        force_table - (option) backup only specified table
        force_reupload - (optional) force reupload of backup
        """
        self.instance = instance
        self.timestamp = datetime.datetime.utcnow()
        # datestamp is for s3 files which are by convention -1 day
        self.datestamp = (
            self.timestamp - datetime.timedelta(days=1)).strftime("%Y-%m-%d")
        self.dbs_to_backup = multiprocessing.Queue()
        if db:
            self.dbs_to_put(db)
        else:
            for db in get_dbs(self.instance):
                self.dbs_to_put(db)

        self.force_table = force_table
        self.force_reupload = force_reupload

    def backup_instance(self):
        """ Back up a replica instance to s3 in csv """
        host_lock_handle = None
        try:
            log.info('Backup for instance {i} started at {t}'
                     ''.format(
                         t=str(self.timestamp), i=self.instance))
            log.info('Checking heartbeat to make sure replicaiton is not too '
                     'lagged.')
            self.check_replication_for_backup()

            log.info('Taking host backup lock')
            host_lock_handle = take_flock_lock(BACKUP_LOCK_FILE)

            log.info('Setting up export directory structure')
            self.setup_and_get_tmp_path()
            log.info('Will temporarily dump inside of {path}'
                     ''.format(path=self.dump_base_path))

            log.info('Releasing any invalid shard backup locks')
            self.ensure_backup_locks_sanity()

            log.info('Stopping replication SQL thread to get a snapshot')
            stop_replication(self.instance, REPLICATION_THREAD_SQL)

            workers = []
            for _ in range(multiprocessing.cpu_count() / 2):
                proc = multiprocessing.Process(
                    target=self.mysql_backup_csv_dbs)
                proc.daemon = True
                proc.start()
                workers.append(proc)
            # throw in a sleep to make sure all threads have started dumps
            time.sleep(2)
            log.info('Restarting replication')
            start_replication(self.instance, REPLICATION_THREAD_SQL)

            for worker in workers:
                worker.join()

            if not self.dbs_to_empty():
                raise Exception('All worker processes have completed, but '
                                'work remains in the queue')

            log.info('CSV backup is complete, will run a check')
            verify_csv_backup(self.instance.replica_type, self.datestamp,
                              self.instance)
        finally:
            if host_lock_handle:
                log.info('Releasing general host backup lock')
                release_flock_lock(host_lock_handle)

    def mysql_backup_csv_dbs(self):
        """ Worker for backing up a queue of dbs """
        proc_id = multiprocessing.current_process().name
        conn = connect_mysql(self.instance, USER_ROLE_MYSQLDUMP)
        start_consistent_snapshot(conn, read_only=True)
        pitr_data = get_pitr_data(self.instance)
        err_count = 0
        while not self.dbs_to_empty():
            db = self.dbs_to_get()
            try:
                self.mysql_backup_csv_db(db, conn, pitr_data)
            except:
                self.dbs_to_put(db)
                log.error('{proc_id}: Could not dump {db}, '
                          'error: {e}'.format(
                              db=db, e=traceback.format_exc(),
                              proc_id=proc_id))
                err_count = err_count + 1
                if err_count > MAX_THREAD_ERROR:
                    log.error(
                        '{proc_id}: Error count in thread > MAX_THREAD_ERROR. '
                        'Aborting :('.format(proc_id=proc_id))
                    return

    def mysql_backup_csv_db(self, db, conn, pitr_data):
        """ Back up a single db

        Args:
        db - the db to be backed up
        conn - a connection the the mysql instance
        pitr_data - data describing the position of the db data in replication
        """
        # attempt to take lock by writing a lock to the master
        proc_id = multiprocessing.current_process().name
        tmp_dir_db = None
        lock_identifier = None
        try:
            lock_identifier = self.take_backup_lock(db)
            if not lock_identifier:
                return

            if not self.force_reupload and self.already_backed_up(db):
                log.info('{proc_id}: {db} is already backed up, skipping'
                         ''.format(
                             proc_id=proc_id, db=db))
                return

            log.info('{proc_id}: {db} db backup start'
                     ''.format(
                         db=db, proc_id=proc_id))

            tmp_dir_db = os.path.join(self.dump_base_path, db)
            if not os.path.exists(tmp_dir_db):
                os.makedirs(tmp_dir_db)
            change_owner(tmp_dir_db, 'mysql', 'mysql')

            self.upload_pitr_data(db, pitr_data)

            for table in self.get_tables_to_backup(db):
                self.mysql_backup_csv_table(db, table, tmp_dir_db, conn)

            log.info('{proc_id}: {db} db backup complete'
                     ''.format(
                         db=db, proc_id=proc_id))
        finally:
            if lock_identifier:
                log.debug('{proc_id}: {db} releasing lock'
                          ''.format(
                              db=db, proc_id=proc_id))
                self.release_db_backup_lock(lock_identifier)

    def mysql_backup_csv_table(self, db, table, tmp_dir_db, conn):
        """ Back up a single table of a single db

        Args:
        db - the db to be backed up
        table - the table to be backed up
        tmp_dir_db - temporary storage used for all tables in the db
        conn - a connection the the mysql instance
        """
        proc_id = multiprocessing.current_process().name
        (_, data_path, _) = get_csv_backup_paths(
            self.datestamp, db, table, self.instance.replica_type,
            self.instance.get_zk_replica_set()[0])
        log.debug('{proc_id}: {db}.{table} dump to {path} started'
                  ''.format(
                      proc_id=proc_id, db=db, table=table, path=data_path))
        self.upload_schema(db, table, tmp_dir_db)
        fifo = os.path.join(tmp_dir_db, table)
        procs = dict()
        try:
            # giant try so we can try to clean things up in case of errors
            self.create_fifo(fifo)

            # Start creating processes
            procs['cat'] = subprocess.Popen(
                ['cat', fifo], stdout=subprocess.PIPE)
            procs['nullescape'] = subprocess.Popen(
                ['nullescape'],
                stdin=procs['cat'].stdout,
                stdout=subprocess.PIPE)
            procs['lzop'] = subprocess.Popen(
                ['lzop'],
                stdin=procs['nullescape'].stdout,
                stdout=subprocess.PIPE)

            # Start dump query
            return_value = set()
            query_thread = threading.Thread(
                target=self.run_dump_query,
                args=(db, table, fifo, conn, procs['cat'], return_value))
            query_thread.daemon = True
            query_thread.start()

            # And run the upload
            safe_upload(
                precursor_procs=procs,
                stdin=procs['lzop'].stdout,
                bucket=S3_CSV_BUCKET,
                key=data_path,
                check_func=self.check_dump_success,
                check_arg=return_value)
            os.remove(fifo)
            log.debug('{proc_id}: {db}.{table} clean up complete'
                      ''.format(
                          proc_id=proc_id, db=db, table=table))
        except:
            log.debug(
                '{proc_id}: in exception handling for failed table upload'
                ''.format(proc_id=proc_id))

            if os.path.exists(fifo):
                self.cleanup_fifo(fifo)

            kill_precursor_procs(procs)

            raise

    def create_fifo(self, fifo):
        """ Create a fifo to be used for dumping a mysql table

        Args:
        fifo - The path to the fifo
        """
        if os.path.exists(fifo):
            self.cleanup_fifo(fifo)

        log.debug('{proc_id}: creating fifo {fifo}'
                  ''.format(
                      proc_id=multiprocessing.current_process().name,
                      fifo=fifo))
        os.mkfifo(fifo)
        # Could not get os.mkfifo(fifo, 0777) to work due to umask
        change_owner(fifo, 'mysql', 'mysql')

    def cleanup_fifo(self, fifo):
        """ Safely cleanup a fifo that is an unknown state

        Args:
        fifo - The path to the fifo
        """
        log.debug('{proc_id}: Cleanup of {fifo} started'
                  ''.format(
                      proc_id=multiprocessing.current_process().name,
                      fifo=fifo))
        cat_proc = subprocess.Popen(
            'timeout 5 cat {fifo} >/dev/null'.format(fifo=fifo), shell=True)
        cat_proc.wait()
        os.remove(fifo)
        log.debug('{proc_id}: Cleanup of {fifo} complete'
                  ''.format(
                      proc_id=multiprocessing.current_process().name,
                      fifo=fifo))

    def run_dump_query(self, db, table, fifo, conn, cat_proc, return_value):
        """ Run a SELECT INTO OUTFILE into a fifo

        Args:
        db - The db to dump
        table - The table of the db to dump
        fifo - The fifo to dump the table.db into
        conn - The connection to MySQL
        cat_proc - The process reading from the fifo
        return_value - A set to be used to populated the return status. This is
                       a semi-ugly hack that is required because of the use of
                       threads not being able to return data, however being
                       able to modify objects (like a set).
        """
        log.debug('{proc_id}: {db}.{table} dump started'
                  ''.format(
                      proc_id=multiprocessing.current_process().name,
                      db=db,
                      table=table))
        sql = ("SELECT * "
               "INTO OUTFILE '{fifo}' "
               "FROM {db}.{table} "
               "").format(
                   fifo=fifo, db=db, table=table)
        cursor = conn.cursor()
        try:
            cursor.execute(sql)
        except Exception as detail:
            # if we have not output any data, then the cat proc will never
            # receive an EOF, so we will be stuck
            if psutil.pid_exists(cat_proc.pid):
                cat_proc.kill()
            log.error('{proc_id}: dump query encountered an error: {er}'
                      ''.format(
                          er=detail,
                          proc_id=multiprocessing.current_process().name))

        log.debug('{proc_id}: {db}.{table} dump complete'
                  ''.format(
                      proc_id=multiprocessing.current_process().name,
                      db=db,
                      table=table))
        return_value.add(SUCCESS_ENTRY)

    def check_dump_success(self, return_value):
        """ Check to see if a dump query succeeded

        Args:
        return_value -  A set which if it includes SUCCESS_ENTRY shows that
                        the query succeeded
        """
        if SUCCESS_ENTRY not in return_value:
            raise Exception('{proc_id}: dump failed'
                            ''.format(proc_id=multiprocessing.current_process()
                                      .name))

    def upload_pitr_data(self, db, pitr_data):
        """ Upload a file of PITR data to s3 for each schema

        Args:
        db - the db that was backed up.
        pitr_data - a dict of various data that might be helpful for running a
                    PITR
        """
        s3_path = PATH_PITR_DATA.format(
            replica_set=self.instance.get_zk_replica_set()[0],
            date=self.datestamp,
            db_name=db)
        log.debug('{proc_id}: {db} Uploading pitr data to {s3_path}'
                  ''.format(
                      s3_path=s3_path,
                      proc_id=multiprocessing.current_process().name,
                      db=db))
        boto_conn = boto.connect_s3()
        bucket = boto_conn.get_bucket(S3_CSV_BUCKET, validate=False)
        key = bucket.new_key(s3_path)
        key.set_contents_from_string(json.dumps(pitr_data))

    def upload_schema(self, db, table, tmp_dir_db):
        """ Upload the schema of a table to s3

        Args:
        db - the db to be backed up
        table - the table to be backed up
        tmp_dir_db - temporary storage used for all tables in the db
        """
        (schema_path, _, _) = get_csv_backup_paths(
            self.datestamp, db, table, self.instance.replica_type,
            self.instance.get_zk_replica_set()[0])
        create_stm = show_create_table(self.instance, db, table)
        log.debug('{proc_id}: Uploading schema to {schema_path}'
                  ''.format(
                      schema_path=schema_path,
                      proc_id=multiprocessing.current_process().name))
        boto_conn = boto.connect_s3()
        bucket = boto_conn.get_bucket(S3_CSV_BUCKET, validate=False)
        key = bucket.new_key(schema_path)
        key.set_contents_from_string(create_stm)

    def take_backup_lock(self, db):
        """ Write a lock row on to the master

        Args:
        db - the db to be backed up

        Returns:
        a uuid lock identifier
        """
        zk = MysqlZookeeper()
        (replica_set, _) = zk.get_replica_set_from_instance(self.instance)
        master = zk.get_mysql_instance_from_replica_set(replica_set,
                                                        REPLICA_ROLE_MASTER)
        master_conn = connect_mysql(master, role='scriptrw')
        cursor = master_conn.cursor()

        lock_identifier = str(uuid.uuid4())
        log.debug('Taking backup lock: {replica_set} {db} '
                  ''.format(
                      replica_set=replica_set, db=db))
        params = {
            'lock': lock_identifier,
            'db': db,
            'hostname': self.instance.hostname,
            'port': self.instance.port
        }
        sql = ("INSERT INTO {db}.{tbl} "
               "SET "
               "lock_identifier = %(lock)s, "
               "lock_active = 'active', "
               "created_at = NOW(), "
               "expires = NOW() + INTERVAL 1 HOUR, "
               "released = NULL, "
               "db = %(db)s,"
               "hostname = %(hostname)s,"
               "port = %(port)s"
               "").format(
                   db=METADATA_DB, tbl=CSV_BACKUP_LOCK_TABLE_NAME)
        cursor = master_conn.cursor()
        try:
            cursor.execute(sql, params)
            master_conn.commit()
        except _mysql_exceptions.IntegrityError:
            lock_identifier = None
            sql = ("SELECT hostname, port, expires "
                   "FROM {db}.{tbl} "
                   "WHERE "
                   "    lock_active = %(active)s AND "
                   "    db = %(db)s"
                   "").format(
                       db=METADATA_DB, tbl=CSV_BACKUP_LOCK_TABLE_NAME)
            cursor.execute(sql, {'db': db, 'active': ACTIVE})
            ret = cursor.fetchone()
            log.debug(
                'DB {db} is already being backed up on {hostname}:{port}, '
                'lock will expire at {expires}.'
                ''.format(
                    db=db,
                    hostname=ret['hostname'],
                    port=ret['port'],
                    expires=str(ret['expires'])))

        log.debug(cursor._executed)
        return lock_identifier

    def release_db_backup_lock(self, lock_identifier):
        """ Release a backup lock created by take_backup_lock

        Args:
        lock_identifier - a uuid to identify a lock row
        """
        zk = MysqlZookeeper()
        (replica_set, _) = zk.get_replica_set_from_instance(self.instance)
        master = zk.get_mysql_instance_from_replica_set(replica_set,
                                                        REPLICA_ROLE_MASTER)
        master_conn = connect_mysql(master, role='scriptrw')
        cursor = master_conn.cursor()

        params = {'lock_identifier': lock_identifier}
        sql = ('UPDATE {db}.{tbl} '
               'SET lock_active = NULL AND released = NOW() '
               'WHERE lock_identifier = %(lock_identifier)s'
               '').format(
                   db=METADATA_DB, tbl=CSV_BACKUP_LOCK_TABLE_NAME)
        cursor.execute(sql, params)
        master_conn.commit()
        log.debug(cursor._executed)

    def ensure_backup_locks_sanity(self):
        """ Release any backup locks that aren't valid. This means either expired
            or created by the same host as the caller. The instance level flock
            should allow this assumption to be correct.
        """
        zk = MysqlZookeeper()
        (replica_set, _) = zk.get_replica_set_from_instance(self.instance)
        master = zk.get_mysql_instance_from_replica_set(replica_set,
                                                        REPLICA_ROLE_MASTER)
        master_conn = connect_mysql(master, role='scriptrw')
        cursor = master_conn.cursor()

        if not does_table_exist(master, METADATA_DB,
                                CSV_BACKUP_LOCK_TABLE_NAME):
            log.debug('Creating missing metadata table')
            cursor.execute(
                CSV_BACKUP_LOCK_TABLE.format(
                    db=METADATA_DB, tbl=CSV_BACKUP_LOCK_TABLE_NAME))

        params = {
            'hostname': self.instance.hostname,
            'port': self.instance.port
        }
        sql = ('UPDATE {db}.{tbl} '
               'SET lock_active = NULL AND released = NOW() '
               'WHERE hostname = %(hostname)s AND '
               '     port = %(port)s'
               '').format(
                   db=METADATA_DB, tbl=CSV_BACKUP_LOCK_TABLE_NAME)
        cursor.execute(sql, params)
        master_conn.commit()

        sql = ('UPDATE {db}.{tbl} '
               'SET lock_active = NULL AND released = NOW() '
               'WHERE expires < NOW()'
               '').format(
                   db=METADATA_DB, tbl=CSV_BACKUP_LOCK_TABLE_NAME)
        cursor.execute(sql)
        master_conn.commit()
        log.debug(cursor._executed)

    def already_backed_up(self, db):
        """ Check to see if a db has already been uploaded to s3

        Args:
        db - The db to check for being backed up

        Returns:
        bool - True if the db has already been backed up, False otherwise
        """
        boto_conn = boto.connect_s3()
        bucket = boto_conn.get_bucket(S3_CSV_BUCKET, validate=False)
        for table in self.get_tables_to_backup(db):
            (_, data_path, _) = get_csv_backup_paths(
                self.datestamp, db, table, self.instance.replica_type,
                self.instance.get_zk_replica_set()[0])
            if not bucket.get_key(data_path):
                return False
        return True

    def get_tables_to_backup(self, db):
        """ Determine which tables should be backed up in a db

        Args:
        db -  The db for which we need a list of tables eligible for backup

        Returns:
        a set of table names
        """
        tables = filter_tables_to_csv_backup(
            self.instance, db, get_tables(
                self.instance, db, skip_views=True))
        if not self.force_table:
            return tables

        if self.force_table not in tables:
            raise Exception('Requested table {t} is not available to backup'
                            ''.format(t=self.force_table))
        else:
            return set([self.force_table])

    def check_replication_for_backup(self):
        """ Confirm that replication is caught up enough to run """
        while True:
            heartbeat = get_heartbeat(self.instance)
            if heartbeat.date() < self.timestamp.date():
                log.warning(
                    'Replicaiton is too lagged ({cur}) to run daily backup, '
                    'sleeping'.format(cur=heartbeat))
                time.sleep(10)
            elif heartbeat.date() > self.timestamp.date():
                raise Exception('Replication is later than expected day')
            else:
                log.info('Replicaiton is ok ({cur}) to run daily backup'
                         ''.format(cur=heartbeat))
                return

    def setup_and_get_tmp_path(self):
        """ Figure out where to temporarily store csv backups,
            and clean it up
        """
        tmp_dir_root = os.path.join(find_root_volume(), 'csv_export',
                                    str(self.instance.port))
        if not os.path.exists(tmp_dir_root):
            os.makedirs(tmp_dir_root)
        change_owner(tmp_dir_root, 'mysql', 'mysql')
        self.dump_base_path = tmp_dir_root


# These are used when running pt-table-checksum
CHECKSUM_DEFAULTS = ' '.join(
    ('--chunk-time=0.1', '--no-check-replication-filters',
     '--no-check-binlog-format', '--no-replicate-check', '--no-version-check',
     '--max-lag=1s', '--progress=time,30',
     '--replicate={METADATA_DB}.checksum')).format(METADATA_DB=METADATA_DB)

# These are used when running pt-table-sync, which we'll use if
# we found some chunk diffs during step 1.
CHECKSUM_SYNC_DEFAULTS = ' '.join(('--sync-to-master', '--chunk-size=500',
                                   '--print', '--verbose'))

# Arbitrary bounds on how many chunks can be different in a given
# table before we do or do not *not* to do a detailed comparison
# of the table.
MIN_DIFFS = 1
MAX_DIFFS = 5

# Check this fraction (1/K) of databases on an instance.
DB_CHECK_FRACTION = 10

CHECKSUM_TBL = 'checksum_detail'

TABLE_DEF = ("CREATE TABLE IF NOT EXISTS {db}.{tbl} ( "
             "id              INT UNSIGNED NOT NULL AUTO_INCREMENT,"
             "reported_at     DATETIME NOT NULL DEFAULT '0000-00-00 00:00:00',"
             "instance        VARCHAR(40) NOT NULL DEFAULT '',"
             "master_instance VARCHAR(40) NOT NULL DEFAULT '',"
             "db              VARCHAR(30) NOT NULL DEFAULT '',"
             "tbl             VARCHAR(64) NOT NULL DEFAULT '',"
             "elapsed_time_ms INT NOT NULL DEFAULT -1,"
             "chunk_count     INT NOT NULL DEFAULT -1,"
             "chunk_errors    INT NOT NULL DEFAULT -1,"
             "chunk_diffs     INT NOT NULL DEFAULT -1,"
             "chunk_skips     INT NOT NULL DEFAULT -1,"
             "row_count       INT NOT NULL DEFAULT -1,"
             "row_diffs       INT NOT NULL DEFAULT -1,"
             "rows_checked    ENUM('YES','NO') NOT NULL DEFAULT 'NO',"
             "checksum_status ENUM('GOOD', 'CHUNK_DIFFS_FOUND_BUT_OK',"
             "                     'ROW_DIFFS_FOUND', 'TOO_MANY_CHUNK_DIFFS',"
             "                     'CHUNKS_WERE_SKIPPED',"
             "                     'ERRORS_IN_CHECKSUM_PROCESS',"
             "                     'UNKNOWN') NOT NULL DEFAULT 'UNKNOWN',"
             "checksum_cmd    TEXT,"
             "checksum_stdout TEXT,"
             "checksum_stderr TEXT,"
             "checksum_rc     INT NOT NULL DEFAULT -1,"
             "sync_cmd        TEXT,"
             "sync_stdout     TEXT,"
             "sync_stderr     TEXT,"
             "sync_rc         INT NOT NULL DEFAULT -1,"
             "PRIMARY KEY(id),"
             "UNIQUE KEY(master_instance, instance, db, tbl, reported_at),"
             "INDEX(reported_at),"
             "INDEX(checksum_status, reported_at) )")


# create_checksum_detail_table
#
def create_checksum_detail_table(instance):
    """ Args:
            instance: the master instance for this replica set

        Returns: Nothing.  If this fails, throw an exception.
    """

    try:
        conn = connect_mysql(instance, 'scriptrw')
        cursor = conn.cursor()
        cursor.execute(TABLE_DEF.format(db=METADATA_DB, tbl=CHECKSUM_TBL))
        cursor.close()
        conn.close()
    except Exception as e:
        raise Exception("Failed to create checksum detail "
                        "table: {e}".format(e=e))


# parse_checksum_row
#
def parse_checksum_row(row):
    """ Args:
            row: a line of text from pt-table-checksum

        Returns: An array of elements, if the regex matches
            [ts, errors, diffs, rows, chunks, chunks_skipped,
             elapsed_time, db, tbl]

        Ex: [ '08-30T06:25:33', '0', '0', '28598', '60', '0', '0.547',
              'pbdata04159', 'userstats' ]

        If the regex doesn't match, return nothing.
    """

    p = re.compile(''.join("^(\d+-\d+T\d+:\d+:\d+)\s+(\d+)\s+(\d+)\s+"
                           "(\d+)\s+(\d+)\s+(\d+)\s+(\d+\.\d+)\s+"
                           "(.+?)\.(.+)$"))
    m = p.match(row)
    if m:
        return m.groups()


# parse_sync_row
#
def parse_sync_row(row):
    """ Args:
            row: a line of text from pt-table-sync

        Returns:
            diff_count: the number of diffs found

        Ex: 5L

        If the pattern doesn't match (or no diffs) found,
        return 0.
    """

    fields = row.split()
    diff_count = 0
    if len(fields) == 10 and fields[0] == "#":
        try:
            delete_count = fields[1]
            replace_count = fields[2]
            insert_count = fields[3]
            update_count = fields[4]

            diff_count = int(delete_count) + int(replace_count) + \
                         int(insert_count) + int(update_count)

        except ValueError, TypeError:
            pass

    return diff_count


# write_checksum_status
#
def write_checksum_status(instance, data):
    """ Args:
            instance: Host info for the master that we'll connect to.
            data: A dictionary containing the row to insert.  See
                  the table definition at the top of the script for info.

        Returns: Nothing
    """
    try:
        conn = connect_mysql(instance, 'scriptrw')
        cursor = conn.cursor()
        sql = ("INSERT INTO test.checksum_detail SET "
               "reported_at=NOW(), "
               "instance=%(instance)s, "
               "master_instance=%(master_instance)s, "
               "db=%(db)s, tbl=%(tbl)s, "
               "elapsed_time_ms=%(elapsed_time_ms)s, "
               "chunk_count=%(chunk_count)s, "
               "chunk_errors=%(chunk_errors)s, "
               "chunk_diffs=%(chunk_diffs)s, "
               "chunk_skips=%(chunk_skips)s, "
               "row_count=%(row_count)s, "
               "row_diffs=%(row_diffs)s, "
               "rows_checked=%(rows_checked)s, "
               "checksum_status=%(checksum_status)s, "
               "checksum_cmd=%(checksum_cmd)s, "
               "checksum_stdout=%(checksum_stdout)s, "
               "checksum_stderr=%(checksum_stderr)s, "
               "checksum_rc=%(checksum_rc)s, "
               "sync_cmd=%(sync_cmd)s, "
               "sync_stdout=%(sync_stdout)s, "
               "sync_stderr=%(sync_stderr)s, "
               "sync_rc=%(sync_rc)s")
        cursor.execute(sql, data)
    except Exception as e:
        log.error("Unable to write to the database: {e}".format(s=sql, e=e))
    finally:
        conn.commit()
        conn.close()


# check_one_replica
#
def check_one_replica(slave_instance, db, tbl):
    diff_count = -1
    elapsed_time_ms = -1

    try:
        conn = connect_mysql(slave_instance, 'scriptro')
        cursor = conn.cursor()

        # first, count the diffs
        sql = ("SELECT COUNT(*) AS diffs FROM test.checksum "
               "WHERE (master_cnt <> this_cnt "
               "OR master_crc <> this_crc "
               "OR ISNULL(master_crc) <> ISNULL(this_crc)) "
               "AND (db=%(db)s AND tbl=%(tbl)s)")
        cursor.execute(sql, {'db': db, 'tbl': tbl})
        row = cursor.fetchone()
        if row is not None:
            diff_count = row['diffs']

        # second, sum up the elapsed time.
        sql = ("SELECT ROUND(SUM(chunk_time)*1000) AS time_ms "
               "FROM test.checksum WHERE db=%(db)s AND tbl=%(tbl)s")
        cursor.execute(sql, {'db': db, 'tbl': tbl})
        row = cursor.fetchone()
        if row is not None:
            elapsed_time_ms = row['time_ms']
        cursor.close()
        conn.close()
    except Exception as e:
        raise Exception("An error occurred polling the "
                        "replica: {e}".format(e=e))

    return elapsed_time_ms, diff_count


# checksum_tbl
#
def checksum_tbl(instance, db, tbl):
    """ Args:
            instance: the master instance to run against
            db: the database to checksum
            tbl: the table within the database to checksum

        Returns:
            cmd: the command line(s) executed
            out: any output written to STDOUT
            err: any output written to STDERR
            ret: the return code of the checksum process
    """

    username, password = get_mysql_user_for_role('ptchecksum')
    cmd = (' '.join(
        ('/usr/bin/pt-table-checksum', CHECKSUM_DEFAULTS,
         '--tables={db}.{tbl}', '--user={username}', '--password={password}',
         '--host={host}', '--port={port}')).format(
             tbl=tbl,
             db=db,
             username=username,
             password=password,
             host=instance.hostname,
             port=instance.port))

    out, err, ret = shell_exec(cmd)
    return cmd.replace(password, 'REDACTED'), out, err, ret


# Run pt-table-sync in read-only (print, verbose) mode to find the
# actual number of rows which differ between master and slave.
#
def checksum_tbl_via_sync(instance, db, tbl):
    username, password = get_mysql_user_for_role('ptchecksum')
    cmd = (' '.join(('/usr/bin/pt-table-sync', CHECKSUM_SYNC_DEFAULTS,
                     '--tables={db}.{tbl}', '--user={username}',
                     '--password={password}', 'h={host},P={port}')).format(
                         db=db,
                         tbl=tbl,
                         username=username,
                         password=password,
                         host=instance.hostname,
                         port=instance.port))

    out, err, ret = shell_exec(cmd)

    diff_count = 0
    for line in out.split("\n"):
        diff_count += parse_sync_row(line)

    # strip out the password in case we are storing it in the DB.
    return cmd.replace(password, 'REDACTED'), out, err, ret, diff_count


def checksum(**args):
    instance = HostAddr(args.instance)
    zk = MysqlZookeeper()

    if instance not in \
            zk.get_all_mysql_instances_by_type(REPLICA_ROLE_MASTER):
        raise Exception("Instance is not a master in ZK")

    # If enabled, try to create the table that holds the checksum info.
    # If not enabled, make sure that the table exists.
    if not does_table_exist(instance, METADATA_DB, CHECKSUM_TBL):
        if args.create_table:
            create_checksum_detail_table(instance)
        else:
            raise Exception("Checksum table not found.  Unable to continue."
                            "Consider not using the -C option or create it "
                            "yourself.")

    # Determine what replica set we belong to and get a list of slaves.
    replica_set = zk.get_replica_set_from_instance(instance)[0]
    slaves = set()
    for rtype in REPLICA_ROLE_SLAVE, REPLICA_ROLE_DR_SLAVE:
        s = zk.get_mysql_instance_from_replica_set(replica_set, rtype)
        if s:
            slaves.add(s)

    if len(slaves) == 0:
        log.info("This server has no slaves.  Nothing to do.")
        sys.exit(0)

    # before we even start this, make sure replication is OK.
    for slave in slaves:
        assert_replication_sanity(slave)

    if args.dbs:
        db_to_check = set(args.dbs.split(','))
    else:
        dbs = get_dbs(instance)

        if args.all:
            db_to_check = dbs
        else:
            # default behaviour, check a given DB every N days based on
            # day of year.  minimizes month-boundary issues.
            db_to_check = set()
            check_modulus = int(time.strftime("%j")) % int(args.check_fraction)
            counter = 0
            for db in dbs:
                modulus = counter % int(args.check_fraction)
                if modulus == check_modulus:
                    db_to_check.add(db)
                counter = counter + 1

    # Iterate through the list of DBs and check one table at a time.
    # We do it this way to ensure more coverage in case pt-table-checksum
    # loses its DB connection and errors out before completing a full scan
    # of a given database.
    #
    for db in db_to_check:
        tables_to_check = get_tables(instance, db, skip_views=True)
        for tbl in tables_to_check:
            c_cmd, c_out, c_err, c_ret = checksum_tbl(instance, db, tbl)
            if not args.quiet:
                log.info("Checksum command executed was:\n{cmd}".format(
                    cmd=c_cmd))
                log.info("Standard out:\n{out}".format(out=c_out))
                log.info("Standard error:\n{err}".format(err=c_err))
                log.info("Return code: {ret}".format(ret=c_ret))

            # parse each line of STDOUT (there should only be one with
            # actual data).  We only care about errors, rows, chunks, and
            # skipped, since we'll need to figure out diffs separately for
            # each slave box.
            for line in c_out.split("\n"):
                results = parse_checksum_row(line)
                if results:
                    chunk_errors = int(results[1])
                    row_count = int(results[3])
                    chunk_count = int(results[4])
                    chunk_skips = int(results[5])

                    for slave in slaves:
                        rows_checked = 'NO'
                        sync_cmd = ""
                        sync_out = ""
                        sync_err = ""
                        sync_ret = -1
                        row_diffs = 0

                        elapsed_time_ms, \
                        chunk_diffs = check_one_replica(slave,
                                                        db, tbl)

                        # if we skipped some chunks or there were errors,
                        # this means we can't have complete information about the
                        # state of the replica. in the case of a hard error,
                        # we'll just stop.  in the case of a skipped chunk, we will
                        # treat it as a different chunk for purposes of deciding
                        # whether or not to do a more detailed analysis.
                        #
                        checkable_chunks = chunk_skips + chunk_diffs

                        if chunk_errors > 0:
                            checksum_status = 'ERRORS_IN_CHECKSUM_PROCESS'
                        elif checkable_chunks == 0:
                            checksum_status = 'GOOD'
                        else:
                            if checkable_chunks > int(args.max_diffs):
                                # too many chunk diffs, don't bother checking
                                # further.  not good.
                                checksum_status = 'TOO_MANY_CHUNK_DIFFS'
                            elif checkable_chunks < int(args.min_diffs):
                                # some diffs, but not enough that we care.
                                checksum_status = 'CHUNK_DIFFS_FOUND_BUT_OK'
                            else:
                                start_time = int(time.time() * 1000)
                                rows_checked = 'YES'

                                # set the proper status - did we do a sync-based check
                                # because of explicit diffs or because of skipped chunks?
                                if chunk_diffs > 0:
                                    checksum_status = 'ROW_DIFFS_FOUND'
                                else:
                                    checksum_status = 'CHUNKS_WERE_SKIPPED'

                                sync_cmd, sync_out, sync_err, sync_ret, \
                                row_diffs = checksum_tbl_via_sync(slave,
                                                                  db,
                                                                  tbl)

                                # Add in the time it took to do the sync.
                                elapsed_time_ms += int(time.time() *
                                                       1000) - start_time

                                if not args.quiet:
                                    log.info(
                                        "Sync command executed was:\n{cmd} ".
                                        format(cmd=sync_cmd))
                                    log.info("Standard out:\n {out}".format(
                                        out=sync_out))
                                    log.info("Standard error:\n {err}".format(
                                        err=sync_err))
                                    log.info("Return code: {ret}".format(
                                        ret=sync_ret))
                                    log.info("Row diffs found: {cnt}".format(
                                        cnt=row_diffs))

                        # Checksum process is complete, store the results.
                        #
                        data = {
                            'instance': slave,
                            'master_instance': instance,
                            'db': db,
                            'tbl': tbl,
                            'elapsed_time_ms': elapsed_time_ms,
                            'chunk_count': chunk_count,
                            'chunk_errors': chunk_errors,
                            'chunk_diffs': chunk_diffs,
                            'chunk_skips': chunk_skips,
                            'row_count': row_count,
                            'row_diffs': row_diffs,
                            'rows_checked': rows_checked,
                            'checksum_status': checksum_status,
                            'checksum_cmd': None,
                            'checksum_stdout': None,
                            'checksum_stderr': None,
                            'checksum_rc': c_ret,
                            'sync_cmd': None,
                            'sync_stdout': None,
                            'sync_stderr': None,
                            'sync_rc': sync_ret
                        }

                        if args.verbose:
                            data.update({
                                'checksum_cmd': c_cmd,
                                'checksum_stdout': c_out,
                                'checksum_stderr': c_err,
                                'sync_cmd': sync_cmd,
                                'sync_stdout': sync_out,
                                'sync_stderr': sync_err,
                                'sync_rc': sync_ret
                            })

                        write_checksum_status(instance, data)


MYSQL_CLI = ('/usr/bin/mysql -A -h {host} -P {port} '
             '--user={user} --password={password} '
             '--prompt="\h:\p \d \u> " {db}')

# if we just want to run a command and disconnect, no
# point in setting a prompt.
MYSQL_CLI_EX = ('/usr/bin/mysql -A -h {host} -P {port} '
                '--user={user} --password={password} '
                '{db} -e "{execute}"')

DEFAULT_ROLE = 'read-only'


def mysql_cli(**args):
    zk = MysqlZookeeper()
    host = None
    db = ''

    role_modifier = 'default'
    long_query = ''
    if args.longquery:
        role_modifier = 'long'
        long_query = '(long queries enabled)'

    # check if db exists in dns, if so the supplied argument will be considered
    # a hostname, otherwise a replica set.
    try:
        socket.gethostbyname(args.db)
        host = HostAddr(args.db)
        log.info('{db} appears to be a hostname'.format(db=args.db))
    except:
        log.info('{db} appears not to be a hostname'.format(db=args.db))

    # Maybe it is a replica set
    if not host:
        config = zk.get_all_mysql_config()
        if args.db in config:
            master = config[args.db]['master']
            log.info('{db} appears to be a replica set'.format(db=args.db))
            host = HostAddr(''.join((master['host'], ':', str(master['port'])
                                     )))
        else:
            log.info('{db} appears not to be a replica set'.format(db=args.db))

    # Perhaps a shard?
    if not host:
        shard_map = zk.get_host_shard_map()
        for master in shard_map:
            if args.db in shard_map[master]:
                log.info('{db} appears to be a shard'.format(db=args.db))
                host = HostAddr(master)
                db = convert_shard_to_db(args.db)
                break
        if not host:
            log.info('{db} appears not to be a shard'.format(db=args.db))

    if not host:
        raise Exception('Could not determine what host to connect to')

    log.info('Will connect to {host} with {privileges} '
             'privileges {lq}'.format(
                 host=host, privileges=args.privileges, lq=long_query))
    (username, password
     ) = get_mysql_user_for_role(CLI_ROLES[args.privileges][role_modifier])

    if args.execute:
        execute_escaped = string.replace(args.execute, '"', '\\"')
        cmd = MYSQL_CLI_EX.format(
            host=host.hostname,
            port=host.port,
            db=db,
            user=username,
            password=password,
            execute=execute_escaped)
    else:
        cmd = MYSQL_CLI.format(
            host=host.hostname,
            port=host.port,
            db=db,
            user=username,
            password=password)
    log.info(cmd)
    proc = subprocess.Popen(cmd, shell=True)
    proc.wait()


HOSTNAME_TAG = '__HOSTNAME__'
ROOTVOL_TAG = '__ROOT__'
CNF_DEFAULTS = 'default_my.cnf'
CONFIG_SUB_DIR = '../configs/mysql_cnf_config'
RELATIVE_DIR = os.path.join(
    os.path.dirname(os.path.realpath(__file__)), CONFIG_SUB_DIR)
ROOT_CNF = '/root/.my.cnf'
LOG_ROTATE_CONF_FILE = '/etc/logrotate.d/mysql_3306'
LOG_ROTATE_FILES = ['slow_query_log_file', 'log_error', 'general_log_file']
LOG_ROTATE_SETTINGS = ('size 1G', 'rotate 10', 'missingok', 'copytruncate',
                       'compress')
LOG_ROTATE_TEMPLATE = '\n'.join(("{files} {{", "\t{settings}", "}}"))
MYSQLD_SECTION = 'mysqld3306'
PT_HEARTBEAT_TEMPLATE = 'pt_heartbeat.template'
PT_HEARTBEAT_CONF_FILE = '/etc/pt-heartbeat-3306.conf'
PT_KILL_BUSY_TIME = 10
PT_KILL_TEMPLATE = 'pt_kill.template'
PT_KILL_CONF_FILE = '/etc/pt-kill.conf'
PT_KILL_IGNORE_USERS = [
    'admin', 'etl', 'longqueryro', 'longqueryrw', 'pbuser', 'mysqldump',
    'xtrabackup', 'ptchecksum'
]
REMOVE_SETTING_PREFIX = 'remove_'
READ_ONLY_OFF = 'OFF'
READ_ONLY_ON = 'ON'
SAFE_UPDATE_PREFIXES = set(['sharddb', 'modsharddb'])
SAFE_UPDATES_SQL = 'set global sql_safe_updates=on;'
TOUCH_FOR_NO_CONFIG_OVERWRITE = '/etc/mysql/no_write_config'
TOUCH_FOR_WRITABLE_IF_NOT_IN_ZK = '/etc/mysql/make_non_zk_server_writeable'
UPGRADE_OVERRIDE_SETTINGS = {
    'skip_slave_start': None,
    'skip_networking': None,
    'innodb_fast_shutdown': '0'
}
UPGRADE_REMOVAL_SETTINGS = set(
    ['enforce_storage_engine', 'init_file', 'disabled_storage_engines'])


def build_cnf(host=None, override_dir=None, override_mysql_version=None):
    # There are situations where we don't want to overwrite the
    # existing config file, because we are testing, etc...
    if os.path.isfile(TOUCH_FOR_NO_CONFIG_OVERWRITE):
        log.info('Found {path}.  Will not overwrite anything.\n'
                 'Exiting now.'.format(path=TOUCH_FOR_NO_CONFIG_OVERWRITE))
        return

    if not host:
        host = HostAddr(HOSTNAME)

    if override_mysql_version:
        major_version = override_mysql_version
    else:
        major_version = get_installed_mysqld_version()[:3]

    if major_version not in SUPPORTED_MYSQL_MAJOR_VERSIONS:
        log.info('CNF building is not supported in '
                 '{major_version}'.format(major_version=major_version))
        return

    config_files = list()
    parser = ConfigParser.RawConfigParser(allow_no_value=True)

    # Always use the local config files for the executing script
    RELATIVE_DIR = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), CONFIG_SUB_DIR)
    config_files.append(os.path.join(RELATIVE_DIR, CNF_DEFAULTS))

    log.info('MySQL major version detected as {major_version}'
             ''.format(major_version=major_version))
    config_files.append(os.path.join(RELATIVE_DIR, major_version))

    instance_type = get_instance_type()
    log.info('Hardware detected as {instance_type}'
             ''.format(instance_type=instance_type))
    config_files.append(os.path.join(RELATIVE_DIR, instance_type))

    log.info('Hostname "{hostname}" results in hostname prefix "{prefix}"'
             ''.format(
                 hostname=host.hostname, prefix=host.replica_type))
    config_files.append(os.path.join(RELATIVE_DIR, host.replica_type))

    # Using the config files, setup a config file parser
    log.info('Using config files {files}'.format(files=config_files))
    parser.read(config_files)

    # Set the server server_id based upon hostname
    server_id = hostname_to_server_id(host.hostname)
    log.info('Setting server_id to {server_id}'.format(server_id=server_id))
    parser.set(MYSQLD_SECTION, 'server_id', server_id)

    # Set read_only based upon service discovery
    parser.set(MYSQLD_SECTION, 'read_only', config_read_only(host))

    # If needed, turn on safe updates via an init_file
    create_init_sql(host.replica_type, parser, override_dir)

    # Set the hostname and root volume through the config
    replace_config_tag(parser, HOSTNAME_TAG, host.hostname)
    replace_config_tag(parser, ROOTVOL_TAG, find_root_volume())

    # Remove config elements as directed
    remove_config_by_override(parser)

    # Write out the mysql cnf files
    create_mysql_cnf_files(parser, override_dir)

    # Create log rotate conf for MySQL
    create_log_rotate_conf(parser, override_dir)

    # Create .my.cnf to set username/password defaults for local usage
    create_root_cnf(parser, override_dir)

    # Create pt heartbeat conf in order to be able to calculate replication lag
    create_pt_heartbeat_conf(override_dir)

    # Create pt kill conf in order to kill long running queries
    create_pt_kill_conf(override_dir)


def replace_config_tag(parser, tag, replace_value):
    """ Replace a tag in the config with some other value.
        Used, for example, to fill in the hostname or the root volume.

    Args:
    parser: A configParser object
    tag: The string (tag) to replace
    replace_value: The string to replace it with
    """
    for section in parser.sections():
        for item in parser.items(section):
            if type(item[1]) is str and tag in item[1]:
                parser.set(section, item[0],
                           item[1].replace(tag, replace_value))


def hostname_to_server_id(hostname):
    """ Convert a hostname to a MySQL server_id using its ip address

    Args:
    hostname - A string

    Returns:
    An integer to be used for the server_id
    """
    ip = socket.gethostbyname(hostname)
    parts = ip.split('.')
    return ((int(parts[0]) << 24) + (int(parts[1]) << 16) +
            (int(parts[2]) << 8) + int(parts[3]))


def config_read_only(host):
    """ Determine how read_only should be set in the cnf file

    Args:
    host - a hostaddr object

    Returns:
    The string value of READ_ONLY_OFF or READ_ONLY_ON.
    """
    zk = MysqlZookeeper()
    try:
        (_, replica_type) = zk.get_replica_set_from_instance(host)
    except:
        # If it is not in zk OR there is any other error, the safest thing is
        # to treat it as if it was not in zk and therefore read_only set to ON
        replica_type = None
    if replica_type == REPLICA_ROLE_MASTER:
        log.info('Server is considered a master, therefore read_only '
                 'should be OFF')
        return READ_ONLY_OFF
    elif replica_type in (REPLICA_ROLE_DR_SLAVE, REPLICA_ROLE_SLAVE):
        log.info('Server is considered a replica, therefore read_only '
                 'should be ON')
        return READ_ONLY_ON
    elif os.path.isfile(TOUCH_FOR_WRITABLE_IF_NOT_IN_ZK):
        log.info('Server is not in zk and {path} exists, therefore read_only '
                 'should be OFF'
                 ''.format(path=TOUCH_FOR_WRITABLE_IF_NOT_IN_ZK))
        return READ_ONLY_OFF
    else:
        log.info('Server is not in zk and {path} does not exist, therefore '
                 'read_only should be ON'
                 ''.format(path=TOUCH_FOR_WRITABLE_IF_NOT_IN_ZK))
        return READ_ONLY_ON


def remove_config_by_override(parser):
    """ Slightly ugly hack to allow removal of config entries.

    Args:
    parser - A ConfigParser object
    """
    for option in parser.options(MYSQLD_SECTION):
        if option.startswith(REMOVE_SETTING_PREFIX):
            option_to_remove = option[len(REMOVE_SETTING_PREFIX):]
            # first, get rid of the option we actually want to remove.
            if parser.has_option(MYSQLD_SECTION, option_to_remove):
                parser.remove_option(MYSQLD_SECTION, option_to_remove)

            # and then get rid of the remove flag for it.
            parser.remove_option(MYSQLD_SECTION, option)


def create_skip_replication_cnf(override_dir=None):
    """ Create a secondary cnf file that will allow for mysql to skip
        replication start. Useful for running mysql upgrade, etc...

    Args:
    override_dir - Write to this directory rather than CNF_DIR
    """
    skip_replication_parser = ConfigParser.RawConfigParser(allow_no_value=True)
    skip_replication_parser.add_section(MYSQLD_SECTION)
    skip_replication_parser.set(MYSQLD_SECTION, 'skip_slave_start', None)
    if override_dir:
        skip_slave_path = os.path.join(override_dir,
                                       os.path.basename(MYSQL_NOREPL_CNF_FILE))
    else:
        skip_slave_path = MYSQL_NOREPL_CNF_FILE
    log.info('Writing file {skip_slave_path}'
             ''.format(skip_slave_path=skip_slave_path))
    with open(skip_slave_path, "w") as skip_slave_handle:
        skip_replication_parser.write(skip_slave_handle)


def create_log_rotate_conf(parser, override_dir=None):
    """ Create log rotate conf for MySQL

    Args:
    override_dir - Write to this directory rather than default
    parser - A ConfigParser object of mysqld settings
    """
    files_to_rotate = ''
    for rotate_file in LOG_ROTATE_FILES:
        files_to_rotate = ' '.join((files_to_rotate,
                                    parser.get(MYSQLD_SECTION, rotate_file)))
    log_rotate_values = '\n\t'.join(LOG_ROTATE_SETTINGS)
    log_rotate_settings = LOG_ROTATE_TEMPLATE.format(
        files=files_to_rotate, settings=log_rotate_values)
    if override_dir:
        log_rotate_conf_file = os.path.join(
            override_dir, os.path.basename(LOG_ROTATE_CONF_FILE))
    else:
        log_rotate_conf_file = LOG_ROTATE_CONF_FILE

    log.info('Writing log rotate config {path}'.format(
        path=log_rotate_conf_file))
    with open(log_rotate_conf_file, "w") as log_rotate_conf_file_handle:
        log_rotate_conf_file_handle.write(log_rotate_settings)


def create_mysql_cnf_files(parser, override_dir=None):
    """ Write out various mysql cnf files

    Args:
    parser - A ConfigParser object of mysqld settings
    override_dir - Write to this directory rather than default
    """
    if override_dir:
        cnf_path = os.path.join(override_dir, os.path.basename(MYSQL_CNF_FILE))
        upgrade_cnf_path = os.path.join(
            override_dir, os.path.basename(MYSQL_UPGRADE_CNF_FILE))
    else:
        cnf_path = MYSQL_CNF_FILE
        upgrade_cnf_path = MYSQL_UPGRADE_CNF_FILE
    log.info('Writing file {cnf_path}'.format(cnf_path=cnf_path))
    with open(cnf_path, "w") as cnf_handle:
        parser.write(cnf_handle)

    # Next create the cnf used for version upgrads
    for option in UPGRADE_OVERRIDE_SETTINGS.keys():
        parser.set(MYSQLD_SECTION, option, UPGRADE_OVERRIDE_SETTINGS[option])

    for option in UPGRADE_REMOVAL_SETTINGS:
        parser.remove_option(MYSQLD_SECTION, option)

    log.info('Writing file {upgrade_cnf_path}'
             ''.format(upgrade_cnf_path=upgrade_cnf_path))
    with open(upgrade_cnf_path, "w") as upgrade_cnf_handle:
        parser.write(upgrade_cnf_handle)

    create_skip_replication_cnf(override_dir)


def create_init_sql(replica_set_type, parser, override_dir):
    """ Create a init.sql file if needed

    Args:
    replica_type - Hostname prefix of the db host to be configured
    parser -  A ConfigParser object of mysqld settings
    override_dir - Write to this directory rather than default
    """
    if replica_set_type in SAFE_UPDATE_PREFIXES:
        log.info('Turning on safe updates')
        if override_dir:
            init_file_path = os.path.join(override_dir,
                                          os.path.basename(MYSQL_INIT_FILE))
        else:
            init_file_path = MYSQL_INIT_FILE
        parser.set(MYSQLD_SECTION, 'init_file', init_file_path)
        with open(init_file_path, "w") as init_file_handle:
            init_file_handle.write(SAFE_UPDATES_SQL)


def create_root_cnf(cnf_parser, override_dir):
    """ Create a .my.cnf file to setup defaults for username/password

    Args:
    cnf_parser - A ConfigParser object of mysqld settings
    override_dir - Write to this directory rather than default
    """
    admin_user, admin_password = get_mysql_user_for_role('admin')
    dump_user, dump_password = get_mysql_user_for_role('mysqldump')
    parser = ConfigParser.RawConfigParser(allow_no_value=True)
    parser.add_section('mysql')
    parser.set('mysql', 'user', admin_user)
    parser.set('mysql', 'password', admin_password)
    parser.set('mysql', 'socket', cnf_parser.get(MYSQLD_SECTION, 'socket'))
    parser.add_section('mysqladmin')
    parser.set('mysqladmin', 'user', admin_user)
    parser.set('mysqladmin', 'password', admin_password)
    parser.set('mysqladmin', 'socket',
               cnf_parser.get(MYSQLD_SECTION, 'socket'))
    parser.add_section('mysqldump')
    parser.set('mysqldump', 'user', dump_user)
    parser.set('mysqldump', 'password', dump_password)
    parser.set('mysqldump', 'socket', cnf_parser.get(MYSQLD_SECTION, 'socket'))

    if override_dir:
        root_cnf_path = os.path.join(override_dir, os.path.basename(ROOT_CNF))
    else:
        root_cnf_path = ROOT_CNF
    log.info('Writing file {root_cnf_path}'
             ''.format(root_cnf_path=root_cnf_path))
    with open(root_cnf_path, "w") as root_cnf_handle:
        parser.write(root_cnf_handle)


def create_pt_heartbeat_conf(override_dir):
    """ Create the config file for pt-hearbeat

    Args:
    override_dir - Write to this directory rather than default
    """
    template_path = os.path.join(RELATIVE_DIR, PT_HEARTBEAT_TEMPLATE)
    with open(template_path, 'r') as f:
        template = f.read()

    heartbeat_user, heartbeat_password = get_mysql_user_for_role('ptheartbeat')

    if override_dir:
        heartbeat_cnf_path = os.path.join(
            override_dir, os.path.basename(PT_HEARTBEAT_CONF_FILE))
    else:
        heartbeat_cnf_path = PT_HEARTBEAT_CONF_FILE
    log.info('Writing file {heartbeat_cnf_path}'
             ''.format(heartbeat_cnf_path=heartbeat_cnf_path))
    with open(heartbeat_cnf_path, "w") as heartbeat_cnf_handle:
        heartbeat_cnf_handle.write(
            template.format(
                defaults_file=MYSQL_CNF_FILE,
                username=heartbeat_user,
                password=heartbeat_password,
                metadata_db=METADATA_DB))


def create_pt_kill_conf(override_dir):
    """ Create the config file for pt-kill

    Args:
    override_dir - Write to this directory rather than default
    """
    template_path = os.path.join(RELATIVE_DIR, PT_KILL_TEMPLATE)
    with open(template_path, 'r') as f:
        template = f.read()

    kill_user, kill_password = get_mysql_user_for_role('ptkill')

    if override_dir:
        kill_cnf_path = os.path.join(override_dir,
                                     os.path.basename(PT_KILL_CONF_FILE))
    else:
        kill_cnf_path = PT_KILL_CONF_FILE
    log.info('Writing file {kill_cnf_path}'
             ''.format(kill_cnf_path=kill_cnf_path))
    with open(kill_cnf_path, "w") as kill_cnf_handle:
        kill_cnf_handle.write(
            template.format(
                username=kill_user,
                password=kill_password,
                busy_time=PT_KILL_BUSY_TIME,
                ignore_users='|'.join(PT_KILL_IGNORE_USERS)))


MAX_ZK_WRITE_ATTEMPTS = 5
WAIT_TIME_CONFIRM_QUIESCE = 10


def mysql_failover(master, dry_run, skip_lock, ignore_dr_slave,
                   trust_me_its_dead, kill_old_master):
    """ Promote a new MySQL master

    Args:
    master - Hostaddr object of the master instance to be demoted
    dry_run - Do not change state, just do sanity testing and exit
    skip_lock - Do not take a promotion lock
    ignore_dr_slave - Ignore the existance of a dr_slave
    trust_me_its_dead - Do not test to see if the master is dead
    kill_old_master - Send a mysqladmin kill command to the old master

    Returns:
    new_master - The new master server
    """
    log.info('Master to demote is {master}'.format(master=master))

    zk = MysqlZookeeper()
    (replica_set, _) = zk.get_replica_set_from_instance(
        master, rtypes=['master'])
    log.info('Replica set is detected as '
             '{replica_set}'.format(replica_set=replica_set))

    # take a lock here to make sure nothing changes underneath us
    if not skip_lock and not dry_run:
        log.info('Taking promotion lock on replica set')
        lock_identifier = get_promotion_lock(replica_set)
    else:
        lock_identifier = None

    # giant try. If there any problems we roll back from the except
    try:
        master_conn = False
        slave = zk.get_mysql_instance_from_replica_set(
            replica_set=replica_set, repl_type=REPLICA_ROLE_SLAVE)
        log.info('Slave/new master is detected as {slave}'.format(slave=slave))

        if ignore_dr_slave:
            log.info('Intentionally ignoring a dr_slave')
            dr_slave = None
        else:
            dr_slave = zk.get_mysql_instance_from_replica_set(
                replica_set, REPLICA_ROLE_DR_SLAVE)
        log.info('DR slave is detected as {dr_slave}'.format(
            dr_slave=dr_slave))
        if dr_slave:
            if dr_slave == slave:
                raise Exception('Slave and dr_slave appear to be the same')

            replicas = set([slave, dr_slave])
        else:
            replicas = set([slave])

        # We use master_conn as a mysql connection to the master server, if
        # it is False, the master is dead
        if trust_me_its_dead:
            master_conn = None
        else:
            master_conn = is_master_alive(master, replicas)

        # Test to see if the slave is setup for replication. If not, we are hosed
        log.info('Testing to see if Slave/new master is setup to write '
                 'replication logs')
        get_master_status(slave)

        if kill_old_master and not dry_run:
            log.info('Killing old master, we hope you know what you are doing')
            shutdown_mysql(master)
            master_conn = None

        if master_conn:
            log.info('Master is considered alive')
            dead_master = False
            confirm_max_replica_lag(replicas, REPLICATION_TOLERANCE_NORMAL,
                                    dead_master)
        else:
            log.info('Master is considered dead')
            dead_master = True
            confirm_max_replica_lag(replicas, REPLICATION_TOLERANCE_LOOSE,
                                    dead_master)

        if dry_run:
            log.info('In dry_run mode, so exiting now')
            # Using os._exit in order to not get catch in the giant try
            os._exit(0)

        log.info('Preliminary sanity checks complete, starting promotion')

        if master_conn:
            log.info('Setting read_only on master')
            set_global_variable(master, 'read_only', True)
            log.info('Confirming no writes to old master')
            # If there are writes with the master in read_only mode then the
            # promotion can not proceed.
            # A likely reason is a client has the SUPER privilege.
            confirm_no_writes(master)
            log.info('Waiting for replicas to be caught up')
            confirm_max_replica_lag(replicas, REPLICATION_TOLERANCE_NONE,
                                    dead_master, True, NORMAL_HEARTBEAT_LAG)
            log.info('Setting up replication from old master ({master}) '
                     'to new master ({slave})'.format(
                         master=master, slave=slave))
            setup_replication(new_master=slave, new_replica=master)
        else:
            log.info('Starting up a zk connection to make sure we can connect')
            kazoo_client = get_kazoo_client()
            if not kazoo_client:
                raise Exception('Could not conect to zk')

            log.info('Confirming replica has processed all replication '
                     ' logs')
            confirm_no_writes(slave)
            log.info('Looks like no writes being processed by replica via '
                     'replication or other means')
            if len(replicas) > 1:
                log.info('Confirming replica servers are synced')
                confirm_max_replica_lag(replicas, REPLICATION_TOLERANCE_LOOSE,
                                        dead_master, True)
    except:
        log.info('Starting rollback')
        if master_conn:
            log.info('Releasing read_only on old master')
            set_global_variable(master, 'read_only', False)

            log.info('Clearing replication settings on old master')
            reset_slave(master)
        if lock_identifier:
            log.info('Releasing promotion lock')
            release_promotion_lock(lock_identifier)
        log.info('Rollback complete, reraising exception')
        raise

    if dr_slave:
        try:
            setup_replication(new_master=slave, new_replica=dr_slave)
        except Exception as e:
            log.error(e)
            log.error('Setting up replication on the dr_slave failed. '
                      'Failing forward!')

    log.info('Updating zk')
    zk_write_attempt = 0
    while True:
        try:
            swap_master_and_slave(slave, dry_run=False)
            break
        except:
            if zk_write_attempt > MAX_ZK_WRITE_ATTEMPTS:
                log.info('Final failure writing to zk, bailing')
                raise
            else:
                log.info('Write to zk failed, trying again')
                zk_write_attempt = zk_write_attempt + 1

    log.info('Removing read_only from new master')
    set_global_variable(slave, 'read_only', False)
    log.info('Removing replication configuration from new master')
    reset_slave(slave)
    if lock_identifier:
        log.info('Releasing promotion lock')
        release_promotion_lock(lock_identifier)

    log.info('Failover complete')

    # we don't really care if this fails, but we'll print a message anyway.
    try:
        generic_json_post(
            CHANGE_FEED_URL, {
                'type': 'MySQL Failover',
                'environment': replica_set,
                'description': "Failover from {m} to {s}".format(
                    m=master, s=slave),
                'author': get_user(),
                'automation': False,
                'source': "mysql_failover.py on {}".format(HOSTNAME)
            })
    except Exception as e:
        log.warning("Failover completed, but change feed "
                    "not updated: {}".format(e))

    if not master_conn:
        log.info('As master is dead, will try to launch a replacement. Will '
                 'sleep 20 seconds first to let things settle')
        time.sleep(20)
        launch_replacement_db_host.launch_replacement_db_host(master)


def get_promotion_lock(replica_set):
    """ Take a promotion lock

    Args:
    replica_set - The replica set to take the lock against

    Returns:
    A unique identifer for the lock
    """
    lock_identifier = str(uuid.uuid4())
    log.info('Promotion lock identifier is '
             '{lock_identifier}'.format(lock_identifier=lock_identifier))

    conn = get_mysqlops_connections()

    log.info('Releasing any expired locks')
    release_expired_promotion_locks(conn)

    log.info('Checking existing locks')
    check_promotion_lock(conn, replica_set)

    log.info('Taking lock against replica set: '
             '{replica_set}'.format(replica_set=replica_set))
    params = {
        'lock': lock_identifier,
        'localhost': HOSTNAME,
        'replica_set': replica_set,
        'user': get_user()
    }
    sql = ("INSERT INTO mysqlops.promotion_locks "
           "SET "
           "lock_identifier = %(lock)s, "
           "lock_active = 'active', "
           "created_at = NOW(), "
           "expires = NOW() + INTERVAL 12 HOUR, "
           "released = NULL, "
           "replica_set = %(replica_set)s, "
           "promoting_host = %(localhost)s, "
           "promoting_user = %(user)s ")
    cursor = conn.cursor()
    cursor.execute(sql, params)
    conn.commit()
    log.info(cursor._executed)
    return lock_identifier


def release_expired_promotion_locks(lock_conn):
    """ Release any locks which have expired

    Args:
    lock_conn - a mysql connection to the mysql instance storing locks
    """
    cursor = lock_conn.cursor()
    # There is a unique index on (replica_set,lock_active), so a replica set
    # may not have more than a single active promotion in flight. We therefore
    # can not set lock_active = 'inactive' as only a single entry would be
    # allowed for inactive.
    sql = ('UPDATE mysqlops.promotion_locks '
           'SET lock_active = NULL '
           'WHERE expires < now()')
    cursor.execute(sql)
    lock_conn.commit()
    log.info(cursor._executed)


def check_promotion_lock(lock_conn, replica_set):
    """ Confirm there are no active locks that would block taking a
        promotion lock

    Args:
    lock_conn - a mysql connection to the mysql instance storing locks
    replica_set - the replica set that should be locked
    """
    cursor = lock_conn.cursor()
    params = {'replica_set': replica_set}
    sql = ('SELECT lock_identifier, promoting_host, promoting_user '
           'FROM mysqlops.promotion_locks '
           "WHERE lock_active = 'active' AND "
           "replica_set = %(replica_set)s")
    cursor.execute(sql, params)
    ret = cursor.fetchone()
    if ret is not None:
        log.error('Lock is already held by {lock}'.format(lock=ret))
        log.error(('To relase this lock you can connect to the mysqlops '
                   'db by running: '))
        log.error('/usr/local/bin/mysql_utils/mysql_cli.py mysqlopsdb001 '
                  '-p read-write ')
        log.error('And then running the following query:')
        log.error(('UPDATE mysqlops.promotion_locks '
                   'SET lock_active = NULL AND released = NOW() '
                   'WHERE lock_identifier = '
                   "'{lock}';".format(lock=ret['lock_identifier'])))
        raise Exception('Can not take promotion lock')


def release_promotion_lock(lock_identifier):
    """ Release a promotion lock

    Args:
    lock_identifier - The lock to release
    """
    conn = get_mysqlops_connections()
    cursor = conn.cursor()

    params = {'lock_identifier': lock_identifier}
    sql = ('UPDATE mysqlops.promotion_locks '
           'SET lock_active = NULL AND released = NOW() '
           'WHERE lock_identifier = %(lock_identifier)s')
    cursor.execute(sql, params)
    conn.commit()
    log.info(cursor._executed)


def confirm_max_replica_lag(replicas,
                            lag_tolerance,
                            dead_master,
                            replicas_synced=False,
                            timeout=0):
    """ Test replication lag

    Args:
    replicas - A set of hostaddr object to be tested for replication lag
    max_lag - Max computed replication lag in seconds. If 0 is supplied,
              then exec position is compared from replica servers to the
              master rather than using a computed second behind as the
              heartbeat will be blocked by read_only.
    replicas_synced - Replica servers must have executed to the same
                      position in the binary log.
    timeout - How long to wait for replication to be in the desired state
    """
    start = time.time()
    if dead_master:
        replication_checks = set([CHECK_SQL_THREAD, CHECK_CORRECT_MASTER])
    else:
        replication_checks = ALL_REPLICATION_CHECKS

    while True:
        acceptable = True
        for replica in replicas:
            # Confirm threads are running, expected master
            try:
                assert_replication_sanity(replica, replication_checks)
            except Exception as e:
                log.warning(e)
                log.info('Trying to restart replication, then '
                         'sleep 20 seconds')
                restart_replication(replica)
                time.sleep(20)
                assert_replication_sanity(replica, replication_checks)

            try:
                assert_replication_unlagged(replica, lag_tolerance,
                                            dead_master)
            except Exception as e:
                log.warning(e)
                acceptable = False

        if replicas_synced and not confirm_replicas_in_sync(replicas):
            acceptable = False
            log.warning('Replica servers are not in sync and replicas_synced '
                        'is set')

        if acceptable:
            return
        elif (time.time() - start) > timeout:
            raise Exception('Replication is not in an acceptable state on '
                            'replica {r}'.format(r=replica))
        else:
            log.info('Sleeping for 5 second to allow replication to catch up')
            time.sleep(5)


def is_master_alive(master, replicas):
    """ Determine if the master is alive

    The function will:
    1. Attempt to connect to the master via the mysql protcol. If successful
       the master is considered alive.
    2. If #1 fails, check the io thread of the replica instance(s). If the io
       thread is not running, the master will be considered dead. If step #1
       fails and step #2 succeeds, we are in a weird state and will throw an
       exception.

    Args:
    master - A hostaddr object for the master instance
    replicas -  A set of hostaddr objects for the replica instances

    Returns:
    A mysql connection to the master if the master is alive, False otherwise.
    """
    if len(replicas) == 0:
        raise Exception('At least one replica must be present to determine '
                        'a master is dead')
    try:
        master_conn = connect_mysql(master)
        return master_conn
    except MySQLdb.OperationalError as detail:
        (error_code, msg) = detail.args
        if error_code != MYSQL_ERROR_CONN_HOST_ERROR:
            raise
        master_conn = False
        log.info('Unable to connect to current master {master} from '
                 '{hostname}, will check replica servers beforce declaring '
                 'the master dead'.format(
                     master=master, hostname=HOSTNAME))
    except:
        log.info('This is an unknown connection error. If you are very sure '
                 'that the master is dead, please put a "return False" at the '
                 'top of is_master_alive and then send rwultsch a stack trace')
        raise

    # We can not get a connection to the master, so poll the replica servers
    for replica in replicas:
        # If replication has not hit a timeout, a dead master can still have
        # a replica which thinks it is ok. "STOP SLAVE; START SLAVE" followed
        # by a sleep will get us truthyness.
        restart_replication(replica)
        try:
            assert_replication_sanity(replica)
            raise Exception('Replica {replica} thinks it can connect to '
                            'master {master}, but failover script can not. '
                            'Possible network partition!'
                            ''.format(
                                replica=replica, master=master))
        except:
            # The exception is expected in this case
            pass
        log.info('Replica {replica} also can not connect to master '
                 '{master}.'.format(
                     replica=replica, master=master))
    return False


def confirm_no_writes(instance):
    """ Confirm that a server is not receiving any writes

    Args:
    conn - A mysql connection
    """
    enable_and_flush_activity_statistics(instance)
    log.info('Waiting {length} seconds to confirm instance is no longer '
             'accepting writes'.format(length=WAIT_TIME_CONFIRM_QUIESCE))
    time.sleep(WAIT_TIME_CONFIRM_QUIESCE)
    db_activity = get_dbs_activity(instance)

    active_db = set()
    for db in db_activity:
        if db_activity[db]['ROWS_CHANGED'] != 0:
            active_db.add(db)

    if active_db:
        raise Exception('DB {dbs} has been modified when it should have '
                        'no activity'.format(dbs=active_db))

    log.info('No writes after sleep, looks like we are good to go')


def confirm_replicas_in_sync(replicas):
    """ Confirm that all replicas are in sync in terms of replication

    Args:
    replicas - A set of hostAddr objects
    """
    replication_progress = set()
    for replica in replicas:
        slave_status = get_slave_status(replica)
        replication_progress.add(':'.join((slave_status[
            'Relay_Master_Log_File'], str(slave_status['Exec_Master_Log_Pos'])
                                           )))

    if len(replication_progress) == 1:
        return True
    else:
        return False


def format_grant(grant):
    """ Convert a dict describing mysql grants into a GRANT command

    Args:
    grant - dict with keys string privileges, username, source_host, password
            and a bool grant_option

    Returns:
    sql - A GRANT command in string format
    """
    if grant['grant_option']:
        grant_option = ' WITH GRANT OPTION'
    else:
        grant_option = ''
    sql_format = "GRANT {privs} ON *.* TO `{user}`@`{host}` " + \
                 "IDENTIFIED BY '{password}' {grant_option};"
    sql = sql_format.format(
        privs=grant['privileges'],
        user=grant['username'],
        host=grant['source_host'],
        password=grant['password'],
        grant_option=grant_option)
    return sql


def parse_grant(raw_grant):
    """ Convert a MySQL GRANT into a dict

    Args:
    sql - A GRANT command in string format

    Returns:
    grant - dict with keys string privileges, username, source_host, password
            and a bool grant_option
    """
    ret = dict()
    pattern = "GRANT (?P<privileges>.+) ON (?:.+) TO '(?P<username>.+)'@'(?P<source_host>[^']+)'"
    match = re.match(pattern, raw_grant)
    ret['privileges'] = match.group(1)
    ret['username'] = match.group(2)
    ret['source_host'] = match.group(3)

    pattern = ".+PASSWORD '(?P<privileges>[^']+)'(?P<grant_option> WITH GRANT OPTION)?"
    match = re.match(pattern, raw_grant)
    if match:
        ret['hashed_password'] = match.group(1)
    else:
        ret['hashed_password'] = "NONE"

    pattern = ".+WITH GRANT OPTION+"
    match = re.match(pattern, raw_grant)
    if match:
        ret['grant_option'] = True
    else:
        ret['grant_option'] = False
    return ret


def manage_mysql_grants(instance, action):
    """ Nuke/import/check MySQL grants

    Args:
    instance - an object identify which host to act upon
    action - available options:
            check - check grants on the instance and ouput errors to stdout
            import - import grants on to the instance and then check
            nuke_then_import - delete all grants, reimport and then recheck

    Returns:
    problems -  a list of problems

    """
    try:
        conn = connect_mysql(instance)
    except MySQLdb.OperationalError as detail:
        (error_code, msg) = detail.args
        if (error_code != MYSQL_ERROR_HOST_ACCESS_DENIED and
                error_code != MYSQL_ERROR_ACCESS_DENIED):
            raise

        if instance.hostname == HOSTNAME.split('.')[0]:
            print('Could not connect to instance, but it looks like '
                  'instance is on localhost. Going to try defaults for '
                  'authentication.')
            conn = connect_mysql(instance, 'bootstrap')
        else:
            raise

    grants = get_all_mysql_grants()

    # nuke
    conn.query("SET SQL_LOG_BIN=0")
    if action == 'nuke_then_import':
        conn.query("SET SQL_SAFE_UPDATES = 0")
        conn.query("delete from mysql.user")
        conn.query("delete from mysql.db")
        conn.query("delete from mysql.proxies_priv")
    # import
    if action in ('import', 'nuke_then_import'):
        for grant in grants.iteritems():
            sql = format_grant(grant[1])
            conn.query(sql)
        conn.query('flush privileges')
    # check
    if action in ('check', 'import', 'nuke_then_import'):
        problems = []
        on_server = dict()
        cursor = conn.cursor()

        # PK on (user, host), so this returns all distinct users
        cursor.execute("SELECT user, host FROM mysql.user")
        users = cursor.fetchall()
        for row in users:
            user = "`{user}`@`{host}`".format(
                user=row['user'], host=row['host'])
            sql = "SHOW GRANTS FOR {user}".format(user=user)
            try:
                cursor.execute(sql)
            except MySQLdb.OperationalError as detail:
                (error_code, msg) = detail.args
                if error_code != MYSQL_ERROR_NO_DEFINED_GRANT:
                    raise

                problems.append('Grant {user} is not active, probably due to '
                                'skip-name-resolve being on'.format(user=user))
                continue
            returned_grants = cursor.fetchall()

            if len(returned_grants) > 1:
                problems.append('Grant for {user} is too complicated, '
                                'ignoring grant'.format(user=user))
                continue
            unparsed_grant = returned_grants[0][returned_grants[0].keys()[0]]
            on_server[user] = parse_grant(unparsed_grant)

        expected_users = set(grants.keys())
        active_users = set(on_server.keys())

        missing_users = expected_users.difference(active_users)
        for user in missing_users:
            problems.append('Missing user: {user}'.format(user=user))

        unexpected_user = active_users.difference(expected_users)
        for user in unexpected_user:
            problems.append('Unexpected user: {user}'.format(user=user))

        # need hashes from passwords. We could store this in zk, but it just
        # another thing to screw up
        for key in grants.keys():
            password = grants[key]['password']
            sql = "SELECT PASSWORD('{pw}') pw".format(pw=password)
            cursor.execute(sql)
            ret = cursor.fetchone()
            grants[key]['hashed_password'] = ret['pw']
            del grants[key]['password']

        for key in set(grants.keys()).intersection(set(on_server.keys())):
            if grants[key] != on_server[key]:
                diff = difflib.unified_diff(
                    pprint.pformat(on_server[key]).splitlines(),
                    pprint.pformat(grants[key]).splitlines())
                problems.append('Grant for user "{user}" does not match:'
                                '{problem}'.format(
                                    user=key, problem='\n'.join(diff)))

        return problems


DIRS_TO_CLEAR = ['log_bin', 'datadir', 'tmpdir']
DIRS_TO_CREATE = [
    'datadir', 'log_bin', 'log_error', 'slow_query_log_file', 'tmpdir'
]
# in MySQL 5.5+, log_slow_queries is deprecated in favor of
# slow_query_log_file
FILES_TO_CLEAR = ['log_slow_queries', 'log_error', 'slow_query_log_file']

# If MySQL 5.7+, don't use mysql_install_db
MYSQL_INSTALL_DB = '/usr/bin/mysql_install_db'
MYSQL_INITIALIZE = '/usr/sbin/mysqld --initialize-insecure'


def mysql_init_server(instance,
                      skip_production_check=False,
                      skip_locking=False,
                      skip_backup=True):
    """ Remove any data and initialize a MySQL instance

    Args:
    instance - A hostaddr object pointing towards localhost to act upon
    skip_production_check - Dangerous! will not run safety checks to protect
                            production data
    skip_locking - Do not take a lock on localhost. Useful when the caller has
                   already has taken the lock (ie mysql_restore_xtrabackup)
    skip_backup - Don't run a backup after the instance is setup
    """
    lock_handle = None
    if not skip_locking:
        # Take a lock to prevent multiple restores from running concurrently
        log.info('Taking a flock to block race conditions')
        lock_handle = take_flock_lock(BACKUP_LOCK_FILE)

    try:
        # sanity check
        zk = MysqlZookeeper()
        if (not skip_production_check and
                instance in zk.get_all_mysql_instances()):
            raise Exception("It appears {instance} is in use. This is"
                            " very dangerous!".format(instance=instance))

        log.info('Checking host for mounts, etc...')
        basic_host_sanity()

        log.info('(re)Generating MySQL cnf files')
        build_cnf()

        log.info('Creating any missing directories')
        create_and_chown_dirs(instance.port)

        log.info('Shutting down MySQL (if applicable)')
        stop_mysql(instance.port)

        log.info('Deleting existing MySQL data')
        delete_mysql_data(instance.port)

        log.info('Creating MySQL privileges tables')
        init_privileges_tables(instance.port)

        log.info('Clearing innodb log files')
        delete_innodb_log_files(instance.port)

        log.info('Starting up instance')
        start_mysql(instance.port)

        log.info('Importing MySQL users')
        manage_mysql_grants(instance, 'nuke_then_import')

        log.info('Creating test database')
        create_db(instance, 'test')

        log.info('Setting up query response time plugins')
        setup_response_time_metrics(instance)

        log.info('Setting up semi-sync replication plugins')
        setup_semisync_plugins(instance)

        log.info('Restarting pt daemons')
        restart_pt_daemons(instance.port)

        log.info('MySQL initalization complete')

    finally:
        if not skip_locking and lock_handle:
            log.info('Releasing lock')
            release_flock_lock(lock_handle)

    if not skip_backup:
        log.info('Taking a backup')
        mysql_backup(instance)


def basic_host_sanity():
    """ Confirm basic sanity (mounts, etc) on localhost """
    if get_pinfo_cloud() != TESTING_PINFO_CLOUD:
        for path in REQUIRED_MOUNTS:
            found = False
            for choice in path.split(':'):
                if os.path.ismount(choice):
                    found = True
                    break
            if not found:
                raise Exception('No acceptable options for {path} '
                                'are mounted'.format(path=path))

    for path in ZK_CACHE:
        if not os.path.isfile(path):
            raise Exception('ZK updater path {path} '
                            'is not present'.format(path=path))

    if not os.path.isfile(MYSQL_INSTALL_DB):
        raise Exception('MySQL install script {script} is not present'
                        ''.format(script=MYSQL_INSTALL_DB))


def create_and_chown_dirs(port):
    """ Create and chown any missing directories needed for mysql """
    for variable in DIRS_TO_CREATE:
        try:
            path = os.path.dirname(get_cnf_setting(variable, port))
        except ConfigParser.NoOptionError:
            # Not defined, so must not matter
            return
        if not os.path.isdir(path):
            log.info('Creating and chowning {path}'.format(path=path))
            os.makedirs(path)
            change_owner(path, 'mysql', 'mysql')


def delete_mysql_data(port):
    """ Purge all data on disk for a MySQL instance

    Args:
    port - The port on which to act upon on localhost
    """
    for dir_key in DIRS_TO_CLEAR:
        directory = get_cnf_setting(dir_key, port)
        if not os.path.isdir(directory):
            directory = os.path.dirname(directory)
        log.info('Removing contents of {dir}'.format(dir=directory))
        clean_directory(directory)

    # This should not bomb if one of the files to truncate
    # isn't specified in the config file.
    for file_keys in FILES_TO_CLEAR:
        try:
            del_file = get_cnf_setting(file_keys, port)
            log.info('Truncating {del_file}'.format(del_file=del_file))
            open(del_file, 'w').close()
            change_owner(del_file, 'mysql', 'mysql')
        except Exception:
            log.warning('Option {f} not specified '
                        'in my.cnf - continuing.'.format(f=file_keys))


def delete_innodb_log_files(port):
    """ Purge ib_log files

    Args:
    port - the port on which to act on localhost
    """
    try:
        ib_logs_dir = get_cnf_setting('innodb_log_group_home_dir', port)
    except ConfigParser.NoOptionError:
        ib_logs_dir = get_cnf_setting('datadir', port)
    glob_path = os.path.join(ib_logs_dir, 'ib_logfile')
    final_glob = ''.join((glob_path, '*'))
    for del_file in glob.glob(final_glob):
        log.info('Clearing {del_file}'.format(del_file=del_file))
        os.remove(del_file)


def init_privileges_tables(port):
    """ Bootstap a MySQL instance

    Args:
    port - the port on which to act upon on localhost
    """
    version = get_installed_mysqld_version()
    if version[0:3] < '5.7':
        install_command = MYSQL_INSTALL_DB
    else:
        install_command = MYSQL_INITIALIZE

    datadir = get_cnf_setting('datadir', port)
    cmd = ('{MYSQL_INSTALL_DB} --datadir={datadir}'
           ' --user=mysql'.format(
               MYSQL_INSTALL_DB=install_command, datadir=datadir))
    log.info(cmd)
    (std_out, std_err, return_code) = shell_exec(cmd)
    if return_code:
        raise Exception(
            "Return {return_code} != 0 \n"
            "std_err:{std_err}\n"
            "std_out:{std_out}".format(
                return_code=return_code, std_err=std_err, std_out=std_out))


OUTPUT_FORMAT = ('{replica_set:<RS}' '{replica_type:<12}' '{hostport}')

OUTPUT_FORMAT_EXTENDED = ('{replica_set:<RS}'
                          '{replica_type:<12}'
                          '{hostport:<HP}'
                          '{hw}\t'
                          '{az}\t'
                          '{sg:<SGL}'
                          '{id}')


def replica_mappings(**args):
    zk = MysqlZookeeper()
    config = zk.get_all_mysql_config()
    if args.extended:
        servers = get_all_server_metadata()

    output = list()
    max_rs_length = 10
    max_sg_length = 0

    # iterate through and find the longest replica set name and
    # security group, then use that to set the spacing
    for replica_set in config:
        for rtype in REPLICA_TYPES:
            if rtype in config[replica_set]:
                inst = config[replica_set][rtype]
                if len(replica_set) > max_rs_length:
                    max_rs_length = len(replica_set)
                if args.extended and inst['host'] in servers:
                    sg = ','.join(servers[inst['host']].get('security_groups',
                                                            'N/A'))
                    if len(sg) > max_sg_length:
                        max_sg_length = len(sg)

    max_rs_length += 4
    max_sg_length += 4
    hostport_length = max_rs_length + 6

    # dynamically generate padding
    format_str = OUTPUT_FORMAT.replace('RS', str(max_rs_length)).replace(
        'HP', str(hostport_length)).replace('SGL', str(max_sg_length))
    format_str_extended = OUTPUT_FORMAT_EXTENDED.replace(
        'RS', str(max_rs_length)).replace('HP', str(hostport_length)).replace(
            'SGL', str(max_sg_length))

    for replica_set in config:
        for rtype in REPLICA_TYPES:
            if rtype in config[replica_set]:
                inst = config[replica_set][rtype]

                if args.extended and inst['host'] in servers:
                    az = servers[inst['host']]['zone']
                    id = servers[inst['host']]['instance_id']
                    hw = servers[inst['host']]['instance_type']
                    try:
                        sg = ','.join(servers[inst['host']]['security_groups'])
                    except KeyError:
                        sg = '??VPC??'

                    output.append(
                        format_str_extended.format(
                            replica_set=replica_set,
                            replica_type=rtype,
                            hostport=':'.join(
                                [inst['host'], str(inst['port'])]),
                            az=az,
                            hw=hw,
                            sg=sg,
                            id=id))
                else:
                    output.append(
                        format_str.format(
                            replica_set=replica_set,
                            replica_type=rtype,
                            hostport=':'.join(
                                [inst['host'], str(inst['port'])])))

    output.sort()
    print '\n'.join(output)


# It might be better to eventually puppetize this, but
# for now, this will do.
TEST_BASE_PATH = "/backup/mysql_restore/data"
# By default, ignore backups older than DEFAULT_MAX_RESTORE_AGE days
DEFAULT_MAX_RESTORE_AGE = 5
SCARY_TIMEOUT = 20


def restore_instance(restore_source, destination, no_repl, date, add_to_zk,
                     skip_production_check):
    """ Restore a MySQL backup on to localhost

    Args:
    restore_source - A hostaddr object for where to pull a backup from
    destination -  A hostaddr object for where to restore the backup
    no_repl - Should  replication be not started. It will always be setup.
    date - What date should the backup be from
    add_to_zk - Should the instnace be added to zk. If so, the log from the
                host being launched will be consulted.
    skip_production_check - Do not check if the host is already in zk for
                            production use.
    """
    log.info('Supplied source is {source}'.format(source=restore_source))
    log.info('Supplied destination is {dest}'.format(dest=destination))
    log.info('Desired date of restore {date}'.format(date=date))

    # Try to prevent unintentional destruction of prod servers
    zk = MysqlZookeeper()
    try:
        (_, replica_type) = zk.get_replica_set_from_instance(destination)
    except:
        # instance is not in production
        replica_type = None
    if replica_type == REPLICA_ROLE_MASTER:
        # If the instance, we will refuse to run. No ifs, ands, or buts/
        raise Exception('Restore script must never run on a master')
    if replica_type:
        if skip_production_check:
            log.info('Ignoring production check. We hope you know what you '
                     'are doing and we will try to take a backup in case '
                     'you are wrong.')
            try:
                mysql_backup(destination)
            except Exception as e:
                log.error(e)
                log.warning('Unable to take a  We will give you {time} '
                            'seconds to change your mind and ^c.'
                            ''.format(time=SCARY_TIMEOUT))
                time.sleep(SCARY_TIMEOUT)
        else:
            raise Exception("It appears {instance} is in use. This is"
                            " very dangerous!".format(instance=destination))

    # Take a lock to prevent multiple restores from running concurrently
    log.info('Taking a flock to block another restore from starting')
    lock_handle = take_flock_lock(BACKUP_LOCK_FILE)

    log.info('Rebuilding cnf files just in case')
    build_cnf()

    create_and_chown_dirs(destination.port)

    # load some data from the mysql conf file
    datadir = get_cnf_setting('datadir', destination.port)

    (restore_source, restore_file, restore_size) = find_a_backup_to_restore(
        restore_source, destination, date)
    if restore_source.get_zk_replica_set():
        replica_set = restore_source.get_zk_replica_set()[0]
        master = zk.get_mysql_instance_from_replica_set(replica_set,
                                                        REPLICA_ROLE_MASTER)
    else:
        # ZK has no idea what this replica set is, probably a new replica set.
        master = restore_source

    # Start logging
    row_id = start_restore_log(master, {
        'restore_source': restore_source,
        'restore_port': destination.port,
        'restore_file': restore_file,
        'source_instance': destination.hostname,
        'restore_date': date,
        'replication': no_repl,
        'zookeeper': add_to_zk
    })
    # Giant try to allow logging if anything goes wrong.
    try:
        # If we hit an exception, this status will be used. If not, it will
        # be overwritten
        restore_log_update = {'restore_status': 'BAD'}
        log.info('Quick sanity check')
        basic_host_sanity()

        log.info('Shutting down MySQL')
        stop_mysql(destination.port)

        log.info('Removing any existing MySQL data')
        delete_mysql_data(destination.port)

        log.info('Unpacking {rfile} into {ddir}'.format(
            rfile=restore_file, ddir=datadir))
        xbstream_unpack(restore_file, destination.port, restore_source,
                        restore_size)

        log.info('Decompressing files in {path}'.format(path=datadir))
        innobackup_decompress(destination.port)

        # Determine how much RAM to use for applying logs based on the
        # system's total RAM size; all our boxes have 32G or more, so
        # this will always be better than before, but not absurdly high.
        log_apply_ram = psutil.phymem_usage()[0] / 1024 / 1024 / 1024 / 3
        log.info('Applying logs')
        apply_log(destination.port, memory='{}G'.format(log_apply_ram))

        log.info('Removing old innodb redo logs')
        delete_innodb_log_files(destination.port)

        log.info('Setting permissions for MySQL on {dir}'.format(dir=datadir))
        change_owner(datadir, 'mysql', 'mysql')

        log.info('Starting MySQL')
        upgrade_auth_tables(destination.port)
        restore_log_update = {'restore_status': 'OK'}

        log.info('Running MySQL upgrade')
        start_mysql(
            destination.port,
            options=DEFAULTS_FILE_EXTRA_ARG.format(
                defaults_file=MYSQL_NOREPL_CNF_FILE))

        if master == get_metadata_from_backup_file(restore_file)[0]:
            log.info('Pulling replication info from restore to backup source')
            (binlog_file, binlog_pos) = parse_xtrabackup_binlog_info(datadir)
        else:
            log.info('Pulling replication info from restore to '
                     'master of backup source')
            (binlog_file, binlog_pos) = parse_xtrabackup_slave_info(datadir)

        log.info('Setting up MySQL replication')
        restore_log_update['replication'] = 'FAIL'

        # Since we haven't started the slave yet, make sure we've got these
        # plugins installed, whether we use them or not.
        setup_semisync_plugins(destination)

        # Try to configure replication.
        change_master(
            destination,
            master,
            binlog_file,
            binlog_pos,
            no_start=(no_repl == 'SKIP'))
        wait_replication_catch_up(destination)
        restart_pt_daemons(destination.port)

        restore_log_update['replication'] = 'OK'

        setup_response_time_metrics(destination)

    except Exception as e:
        log.error(e)
        if row_id is not None:
            restore_log_update['status_message'] = e
            restore_log_update['finished_at'] = True
        raise
    finally:
        if lock_handle:
            log.info('Releasing lock')
            release_flock_lock(lock_handle)
        update_restore_log(master, row_id, restore_log_update)

    try:
        if add_to_zk == 'REQ':
            log.info('Adding instance to zk')
            auto_add_instance_to_zk(destination, dry_run=False)
            update_restore_log(master, row_id, {'zookeeper': 'OK'})
        else:
            log.info('add_to_zk is not set, therefore not adding to zk')
    except Exception as e:
        log.warning("An exception occurred: {e}".format(e=e))
        log.warning("If this is a DB issue, that's fine. "
                    "Otherwise, you should check ZK.")

    update_restore_log(master, row_id, {'finished_at': True})
    log.info('Starting a new backup')
    mysql_backup(destination)


def find_a_backup_to_restore(source, destination, date):
    """ Based on supplied constains, try to find a backup to restore

    Args:
    source - A hostaddr object for where to pull a backup from
    destination -  A hostaddr object for where to restore the backup
    date - What date should the backup be from

    Returns:
    restore_source - Where the backup was taken
    retore_file - Where the file exists on whichever storage
    restore_size - What is the size of the backup in bytes
    """
    zk = MysqlZookeeper()
    possible_sources = list()
    if source:
        # the souce may not be in zk because it is a new replica set
        possible_sources.append(source)
        if source.get_zk_replica_set():
            replica_set = source.get_zk_replica_set()[0]
        else:
            replica_set = None
    else:
        replica_set = destination.get_zk_replica_set()[0]
        for role in REPLICA_TYPES:
            possible_sources.append(
                zk.get_mysql_instance_from_replica_set(replica_set, role))
    log.info('Replica set detected as {replica_set}'.format(
        replica_set=replica_set))
    log.info('Possible source hosts:{possible_sources}'.format(
        possible_sources=possible_sources))

    if date:
        dates = [date]
    else:
        dates = []
        for days in range(0, DEFAULT_MAX_RESTORE_AGE):
            dates.append(datetime.date.today() - datetime.timedelta(days=days))

    # Find a backup file, preferably newer and less strong preferece on the master server
    restore_file = None
    for restore_date in dates:
        if restore_file:
            break

        log.info('Looking for a backup for {restore_date}'.format(
            restore_date=restore_date))
        for possible_source in possible_sources:
            try:
                (restore_file, restore_size) = get_s3_backup(possible_source,
                                                             str(restore_date))
                restore_source = possible_source
                break
            except:
                log.info('No backup found on in s3 for host {source} '
                         ' on date {date}'
                         ''.format(
                             source=possible_source, date=restore_date))

    if not restore_file:
        raise Exception('Could not find a backup to restore')

    log.info('Found a backup: {restore_file}'
             ''.format(restore_file=restore_file))

    return restore_source, restore_file, restore_size


OTHER_SLAVE_RUNNING_ETL = 0
OTHER_SLAVE_NOT_RUNNING_ETL = 1
ERROR = 3


def exit_other_slave_not_running_etl():
    print "OTHER_SLAVE_NOT_RUNNING_ETL"
    sys.exit(OTHER_SLAVE_NOT_RUNNING_ETL)


def exit_other_slave_running_etl():
    print "OTHER_SLAVE_RUNNING_ETL"
    sys.exit(OTHER_SLAVE_RUNNING_ETL)


def exit_unknown_error():
    print "UNKNOWN"
    sys.exit(ERROR)


def other_slave_running_etl(**args):
    instance = HostAddr(args.instance)

    zk = MysqlZookeeper()
    (replica_set, replica_type) = zk.get_replica_set_from_instance(instance)

    if replica_type == REPLICA_ROLE_DR_SLAVE:
        inst = zk.get_mysql_instance_from_replica_set(replica_set,
                                                      REPLICA_ROLE_SLAVE)
    elif replica_type == REPLICA_ROLE_SLAVE:
        inst = zk.get_mysql_instance_from_replica_set(replica_set,
                                                      REPLICA_ROLE_DR_SLAVE)
    else:
        exit_unknown_error()

    if not inst:
        # if there is not another slave in zk, there is not possibility
        # it is ok
        exit_other_slave_not_running_etl()
    try:
        running = csv_backups_running(instance)
    except:
        exit_other_slave_not_running_etl()

    if not running:
        exit_other_slave_not_running_etl()

    exit_other_slave_running_etl()


TOUCH_STOP_KILLING = '/etc/mysql/no_backup_killing'


def kill_mysql_backup(instance):
    """ Kill sql, csv and xtrabackup backups

    Args:
    instance - Instance to kill backups, does not apply to csv or sql
    """
    (username, _) = get_mysql_user_for_role(USER_ROLE_MYSQLDUMP)
    kill_user_queries(instance, username)
    kill_xtrabackup()


def kill_xtrabackup():
    """ Kill any running xtrabackup processes """
    subprocess.Popen('pkill -f xtrabackup', shell=True).wait()
    subprocess.Popen('pkill -f gof3r', shell=True).wait()


def launch_amazon_mysql_server(hostname,
                               instance_type,
                               vpc_security_group,
                               classic_security_group,
                               availability_zone,
                               mysql_major_version,
                               mysql_minor_version,
                               dry_run,
                               skip_name_check=False):
    """ Launch a mysql server in aws

    Args:
    hostname - hostname of new server
    instance_type - hardware type
    vpc_security_group - VPC firewall rules. This or classic_security_group
                         must be supplied, but not both.
    classic_security_group - AWS classic firewall rules. See vpc_security_group
    availability_zone - AWS availability zone
    mysql_major_version - MySQL major version. Example 5.5 or 5.6
    mysql_minor_version - Which "branch" to use. Values are 'stable', 'staging'
                          and 'latest'.
    dry_run - Do not actually launch a host, just show the expected config.
    skip_name_check - Do not check if a hostname has already been used or log
                      usage. The assumption is the caller has already done this

    Returns:
    An amazon instance id.
    """
    args, _, _, values = inspect.getargvalues(inspect.currentframe())
    for param in args:
        log.info("Requested {param} = {value}".format(
            param=param, value=values[param]))

    config = {
        'key_name': PEM_KEY,
        'placement': availability_zone,
        'instance_profile_name': INSTANCE_PROFILE_NAME,
        'image_id': SUPPORTED_HARDWARE[instance_type]['ami'],
        'instance_type': instance_type
    }

    if vpc_security_group and not classic_security_group:
        (subnet_name, config['subnet_id']) = \
            get_subnet_from_sg(vpc_security_group, availability_zone)
        ssh_security = SSH_SECURITY_MAP[subnet_name]['ssh']
        config['instance_profile_name'] = SSH_SECURITY_MAP[subnet_name]['iam']
        config['security_group_ids'] = [
            VPC_SECURITY_GROUPS[vpc_security_group]
        ]
    elif classic_security_group and not vpc_security_group:
        config['security_groups'] = [classic_security_group]
        if classic_security_group in CLASSIC_SECURE_SG:
            ssh_security = SSH_SECURITY_SECURE
        else:
            ssh_security = SSH_SECURITY_DEV
        config['instance_profile_name'] = INSTANCE_PROFILE_NAME
    else:
        raise Exception('One and only one of vpc_security_group and '
                        'classic_security_group must be specified. Received:\n'
                        'vpc_security_group: {vpc}, \n'
                        'classic_security_group: {classic_security_group}'
                        ''.format(
                            vpc=vpc_security_group,
                            classic_security_group=classic_security_group))

    hiera_config = HIERA_FORMAT.format(
        ssh_security=ssh_security,
        mysql_major_version=mysql_major_version.replace('.', ''),
        mysql_minor_version=mysql_minor_version)
    if hiera_config not in SUPPORTED_HIERA_CONFIGS:
        raise Exception('Hiera config {hiera_config} is not supported.'
                        'Supported configs are: {supported}'
                        ''.format(
                            hiera_config=hiera_config,
                            supported=SUPPORTED_HIERA_CONFIGS))
    config['user_data'] = ('#cloud-config\n'
                           'pinfo_team: {pinfo_team}\n'
                           'pinfo_env: {pinfo_env}\n'
                           'pinfo_role: {hiera_config}\n'
                           'hostname: {hostname}\n'
                           'raid: true\n'
                           'raid_fs: xfs\n'
                           'raid_mount: {raid_mount}'
                           ''.format(
                               pinfo_team=PINFO_TEAM,
                               pinfo_env=PINFO_ENV,
                               raid_mount=RAID_MOUNT,
                               hiera_config=hiera_config,
                               hostname=hostname))

    log.info('Config for new server:\n{config}'.format(config=config))
    conn = get_mysqlops_connections()
    if not skip_name_check and not is_hostname_new(hostname, conn):
        raise Exception('Hostname {hostname} has already been used!'
                        ''.format(hostname=hostname))
    if dry_run:
        log.info('In dry run mode, returning now')
        return
    else:
        conn = boto.ec2.connect_to_region(EC2_REGION)
        instance_id = conn.run_instances(**config).instances[0].id
        log.info('Launched instance {id}'.format(id=instance_id))
        return instance_id


def get_subnet_from_sg(sg, az):
    """ Given a VPC security group and a availiability zone
        return a subnet

    Args:
    sg - A security group
    az - An availibilty zone

    Returns - An AWS subnet
    """
    vpc_subnet = None
    for entry in VPC_SUBNET_SG_MAP.keys():
        if sg in VPC_SUBNET_SG_MAP[entry]:
            vpc_subnet = entry

    if not vpc_subnet:
        raise Exception('Could not determine subnet for sg:{sg}'.format(sg=sg))
    vpc_az_subnet = VPC_AZ_SUBNET_MAP[vpc_subnet][az]

    log.info(
        'Will use subnet "{vpc_az_subnet}" in "{vpc_subnet}" based upon '
        'security group {sg} and availibility zone {az}'
        ''.format(
            vpc_az_subnet=vpc_az_subnet, vpc_subnet=vpc_subnet, sg=sg, az=az))
    return (vpc_subnet, vpc_az_subnet)


DEFAULT_MYSQL_MAJOR_VERSION = '5.6'
DEFAULT_MYSQL_MINOR_VERSION = 'stable'
# After SERVER_BUILD_TIMEOUT we can assume that the build failed
# and automatically go into --replace_again mode
SERVER_BUILD_TIMEOUT = 7


def launch_replacement_db_host(original_server,
                               dry_run=False,
                               not_a_replacement=False,
                               overrides=dict(),
                               reason='',
                               replace_again=False):
    """ Launch a replacement db server

    Args:
    original_server - A hostAddr object for the server to be replaced
    dry_run - If True, do not actually launch a replacement
    not_a_replacement - If set, don't log the replacement, therefore
                        automation won't put it into prod use.
    overrides - A dict of overrides. Availible keys are
                'mysql_minor_version', 'hostname', 'vpc_security_group',
                'availability_zone', 'classic_security_group',
                'instance_type', and 'mysql_major_version'.
    reason - A description of why the host is being replaced. If the instance
             is still accessible and reason is not supply an exception will be
             thrown.
    replace_again - If True, ignore already existing replacements.
    """
    reasons = set()
    if reason:
        reasons.add(reason)

    log.info('Trying to launch a replacement for host {host} which is part '
             'of replica set is {replica_set}'.format(
                 host=original_server.hostname,
                 replica_set=original_server.get_zk_replica_set()[0]))

    zk = MysqlZookeeper()
    try:
        (_, replica_type) = zk.get_replica_set_from_instance(original_server)
    except:
        raise Exception('Can not replace an instance which is not in zk')
    if replica_type == REPLICA_ROLE_MASTER:
        # If the instance, we will refuse to run. No ifs, ands, or buts/
        raise Exception('Can not replace an instance which is a master in zk')

    # Open a connection to MySQL Ops and check if a replacement has already
    # been requested
    reporting_conn = get_mysqlops_connections()
    existing_replacement = find_existing_replacements(reporting_conn,
                                                      original_server)
    if existing_replacement and not not_a_replacement:
        log.info('A replacement has already been requested: '
                 '{re}'.format(re=existing_replacement))
        if replace_again:
            log.info('Argument replace_again is set, continuing on.')
        else:
            age_of_replacement = datetime.datetime.now(
            ) - existing_replacement['created_at']
            if age_of_replacement.days < SERVER_BUILD_TIMEOUT:
                raise Exception('Argument replace_again is not True but a '
                                'replacement already exists.')
            else:
                log.info("A replacement already exists, but was launched "
                         "{days} days ago. The timeout for servers builds is "
                         "{timeout} days so we are automatically setting "
                         "replace_again.".format(
                             days=age_of_replacement.days,
                             timeout=SERVER_BUILD_TIMEOUT))
                replace_again = True

    # Pull some information from cmdb.
    cmdb_data = get_server_metadata(original_server.hostname)
    if not cmdb_data:
        raise Exception('Could not find information about server to be '
                        'replaced in the cmdb')

    if 'aws_status.codes' in cmdb_data:
        reasons.add(cmdb_data['aws_status.codes'])

    log.info('Data from cmdb: {cmdb_data}'.format(cmdb_data=cmdb_data))
    replacement_config = {
        'availability_zone': cmdb_data['location'],
        'hostname':
        find_unused_server_name(original_server.get_standardized_replica_set(),
                                reporting_conn, dry_run),
        'instance_type': cmdb_data['config.instance_type'],
        'mysql_major_version': get_master_mysql_major_version(original_server),
        'mysql_minor_version': DEFAULT_MYSQL_MINOR_VERSION,
        'dry_run': dry_run,
        'skip_name_check': True
    }

    if cmdb_data.pop('cloud.aws.vpc_id', None):
        # Existing server is in VPC
        replacement_config['classic_security_group'] = None
        replacement_config['vpc_security_group'] = cmdb_data['security_groups']
    else:
        # Existing server is in Classic
        replacement_config['classic_security_group'] = cmdb_data[
            'security_groups']
        replacement_config['vpc_security_group'] = None

    # At this point, all our defaults should be good to go
    config_overridden = False
    if replacement_config['classic_security_group'] and overrides[
            'vpc_security_group']:
        # a VPC migration
        vpc_migration(replacement_config, overrides)
        reasons.add('vpc migration')
        config_overridden = True

    # All other overrides
    for key in overrides.keys():
        if key not in replacement_config:
            raise Exception('Invalid override {key}'.format(key=key))

        if overrides[key]:
            if replacement_config[key] == overrides[key]:
                log.info('Override for key {key} does not modify '
                         'configuration'.format(key=key))
            else:
                log.info('Overriding {key} to value {new} from {old}'
                         ''.format(
                             key=key,
                             old=replacement_config[key],
                             new=overrides[key]))
                reasons.add('changing {key} from {old} to '
                            '{new}'.format(
                                key=key,
                                old=replacement_config[key],
                                new=overrides[key]))
                replacement_config[key] = overrides[key]
                config_overridden = True

    if config_overridden:
        log.info('Configuration after overrides: {replacement_config}'
                 ''.format(replacement_config=replacement_config))

    # Check to see if MySQL is up on the host
    try:
        # This is not multi instance compatible. If we move to multiple
        # instances this will need to be updated
        conn = connect_mysql(original_server)
        conn.close()
        dead_server = False
    except MySQLdb.OperationalError as detail:
        dead_server = True
        (error_code, msg) = detail.args
        if error_code != MYSQL_ERROR_CONN_HOST_ERROR:
            raise
        log.info('MySQL is down, assuming hardware failure')
        reasons.add('hardware failure')

    if not dead_server:
        try:
            assert_replication_sanity(original_server)
        except Exception as e:
            log.info('Replication problem: {e}'.format(e=e))
            reasons.add('replication broken')

    # If we get to here and there is no reason, bail out
    if not reasons and not replacement_config['dry_run']:
        raise Exception(('MySQL appears to be up and no reason for '
                         'replacement is supplied. You can specify a reason '
                         'with the --reason argument'))
    reason = ', '.join(reasons)
    log.info('Reason for launch: {reason}'.format(reason=reason))

    new_instance_id = launch_amazon_mysql_server.launch_amazon_mysql_server(
        **replacement_config)
    if not (replacement_config['dry_run'] or not_a_replacement):
        log_replacement_host(reporting_conn, cmdb_data, new_instance_id,
                             replace_again, replacement_config, reason)


def find_unused_server_name(replica_set, conn, dry_run):
    """ Increment a db servers hostname

    The current naming convention for db servers is:
    {Shard Type}-{Shard number}-{Server number}


    Note: The current naming convention for db servers is:
    {Shard Type}{Shard number}{Server letter}

    The purpose of this function is to find the next server letter
    that is not used.

    Args:
    replica_set - The replica of the host to be replaced
    conn -  A mysql connection to the reporting server
    dry_run - don't log that a hostname will be used
    """
    cmdb_servers = get_all_replica_set_servers(replica_set)
    next_host_num = 1
    for server in cmdb_servers:
        host = HostAddr(server['config.name'])

        # We should be able to iterate over everything that came back from the
        # cmdb and find out the greatest host number in use for a replica set
        if not host.host_identifier:
            # unparsable, probably not previously under dba management
            continue

        if (len(host.host_identifier) == 1 and
                ord(host.host_identifier) in range(ord('a'), ord('z'))):
            # old style hostname
            continue

        if int(host.host_identifier) >= next_host_num:
            next_host_num = int(host.host_identifier) + 1
    new_hostname = '-'.join((replica_set, str(next_host_num)))

    while True:
        if is_hostname_new(new_hostname, conn):
            if not dry_run:
                log_new_hostname(new_hostname, conn)
            return new_hostname

        log.info('Hostname {hostname} has been logged to be in use but is not '
                 'in brood or dns'.format(hostname=new_hostname))
        next_host_num = next_host_num + 1
        new_hostname = '-'.join((replica_set, str(next_host_num)))


def is_hostname_new(hostname, conn):
    """ Determine if a hostname has ever been used

    Args:
    hostname - a hostname
    conn -  a mysql connection to the reporting server

    Returns:
    True if the hostname is availible for new use, False otherwise
    """
    cursor = conn.cursor()

    sql = ("SELECT count(*) as cnt "
           "FROM mysqlops.unique_hostname_index "
           "WHERE hostname = %(hostname)s ")
    params = {'hostname': hostname}
    cursor.execute(sql, params)
    ret = cursor.fetchone()

    if ret['cnt'] == 0:
        return True
    else:
        return False


def log_new_hostname(hostname, conn):
    """ Determine if a hostname has ever been used

    Args:
    hostname - a hostname
    conn -  a mysql connection to the reporting server

    Returns:
    True if the hostname is availible for new use, False otherwise
    """
    cursor = conn.cursor()

    sql = ("INSERT INTO mysqlops.unique_hostname_index "
           "SET hostname = %(hostname)s ")
    params = {'hostname': hostname}
    cursor.execute(sql, params)
    conn.commit()


def find_existing_replacements(reporting_conn, old_host):
    """ Determine if a request has already been requested

    Args:
    reporting_conn - A MySQL connect to the reporting server
    old_host - The hostname for the host to be replaced

    Returns:
    If a replacement has been requested, a dict with the following elements:
        new_host - The hostname of the new server
        new_instance - The instance id of the new server
        created_at - When the request was created

    If a replacement has not been requested, then return None.
    """
    cursor = reporting_conn.cursor()

    sql = ("SELECT new_host, new_instance, created_at "
           "FROM mysqlops.host_replacement_log "
           "WHERE old_host = %(old_host)s ")
    params = {'old_host': old_host.hostname}
    cursor.execute(sql, params)
    ret = cursor.fetchone()

    if ret:
        new_host = {
            'new_host': ret['new_host'],
            'new_instance': ret['new_instance'],
            'created_at': ret['created_at']
        }
        return new_host
    else:
        return None


def log_replacement_host(reporting_conn, original_server_data, new_instance_id,
                         replace_again, replacement_config, reason):
    """ Log to a central db the server being replaced and why

    Args:
    reporting_conn - A connection to MySQL Ops reporting server
    original_server_data - A dict of information regarding the server to be
                           replaced
    new_instance_id - The instance id of the replacement server
    replace_again - If set, replace an existing log entry for the replacement
    replacement_config - A dict of information regarding the replacement server
    reason - A string explaining why the server is being replaced
    """
    cursor = reporting_conn.cursor()

    sql = ("INSERT INTO mysqlops.host_replacement_log "
           "SET "
           "old_host = %(old_host)s, "
           "old_instance = %(old_instance)s, "
           "old_az = %(old_az)s, "
           "old_hw_type = %(old_hw_type)s, "
           "new_host = %(new_host)s, "
           "new_instance = %(new_instance)s, "
           "new_az = %(new_az)s, "
           "new_hw_type = %(new_hw_type)s, "
           "reason = %(reason)s ")

    if replace_again:
        sql = sql.replace('INSERT INTO', 'REPLACE INTO')

    params = {
        'old_host': original_server_data['config.name'],
        'old_instance': original_server_data['id'],
        'old_az': original_server_data['location'],
        'old_hw_type': original_server_data['config.instance_type'],
        'new_host': replacement_config['hostname'],
        'new_instance': new_instance_id,
        'new_az': replacement_config['availability_zone'],
        'new_hw_type': replacement_config['instance_type'],
        'reason': reason
    }
    try:
        cursor.execute(sql, params)
    except _mysql_exceptions.IntegrityError:
        raise Exception('A replacement has already been requested')
    reporting_conn.commit()


def get_master_mysql_major_version(instance):
    """ Given an instance, determine the mysql major version for the master
        of the replica set.

    Args:
    instance - a hostaddr object

    Returns - A string similar to '5.5' or '5.6'
   """
    zk = MysqlZookeeper()
    master = zk.get_mysql_instance_from_replica_set(
        instance.get_zk_replica_set()[0], repl_type=REPLICA_ROLE_MASTER)
    try:
        mysql_version = get_global_variables(master)['version'][:3]
    except _mysql_exceptions.OperationalError:
        raise Exception('Could not connect to master server {instance} in '
                        'order to determine MySQL version to launch with. '
                        'Perhaps run this script from there? This is likely '
                        'due to firewall rules.'
                        ''.format(instance=instance.hostname))
    return mysql_version


def vpc_migration(replacement_config, overrides):
    """ Figure out if a replacement is valid, and then update the
        replacement_config as needed

    Args:
    replacement_config - A dict of the default configuration for launching
                         a new server
    overrides - A dict of overrides for the default configuration
    """
    if overrides['vpc_security_group'] in \
            VPC_MIGRATION_MAP[replacement_config['classic_security_group']]:
        log.info('VPC migration: {classic} -> {vpc_sg}'.format(
            classic=replacement_config['classic_security_group'],
            vpc_sg=overrides['vpc_security_group']))
        replacement_config['vpc_security_group'] = overrides[
            'vpc_security_group']
        overrides['vpc_security_group'] = None
        replacement_config['classic_security_group'] = None
    else:
        raise Exception(
            'VPC security group {vpc_sg} is not a valid replacement '
            'for classic security group {classic_sg}. Valid options are:'
            '{options}'.format(
                vpc_sg=overrides['vpc_security_group'],
                classic_sg=replacement_config['classic_security_group'],
                options=VPC_MIGRATION_MAP[replacement_config[
                    'classic_security_group']]))


@contextmanager
def timeout(seconds):
    """ Wrapper for signals handling a timeout for being
    used as a decorator. """

    def timeout_handler(signum, frame):
        pass

    original_handler = signal.signal(signal.SIGALRM, timeout_handler)

    try:
        signal.alarm(seconds)
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, original_handler)


ATTEMPTS = 5
BLOCK = 262144
S3_SCRIPT = '/usr/local/bin/gof3r'
SLEEP_TIME = .25
TERM_DIR = 'repeater_lock_dir'
TERM_STRING = 'TIME_TO_DIE'


def get_exec_path():
    """ Get the path to this executable

    Returns:
    the path as a string of this script
    """
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), __file__)
    if path.endswith('.pyc'):
        return path[:-1]
    else:
        return path


def get_term_dir():
    """ Get the directory where we will place files to communicate, creating
        it if needed.

    Returns
    a directory
    """
    term_dir = os.path.join(RAID_MOUNT, TERM_DIR)
    if not os.path.exists(term_dir):
        os.mkdir(term_dir)
    return term_dir


def get_term_file():
    """ Get a path to a file in the TERM_DIR which can be used to communicate

    Returns
    a path to a file created by tempfile.mkstemp
    """
    term_dir = get_term_dir()
    (handle, path) = tempfile.mkstemp(dir=term_dir)
    os.close(handle)
    return path


def check_term_file(term_path):
    """ Check to see if a term file has been populated with a magic string
        meaning that the repeater code can terminate

    Returns
    True if the file has been populated, false otherwise
    """
    with open(term_path, 'r') as term_handle:
        contents = term_handle.read(len(TERM_STRING))
    if contents == TERM_STRING:
        return True
    else:
        return False


def safe_upload(precursor_procs,
                stdin,
                bucket,
                key,
                check_func=None,
                check_arg=None):
    """ For sures, safely upload a file to s3

    Args:
    precursor_procs - A dict of procs that will be monitored
    stdin - The stdout from the last proc in precursor_procs that will be
             uploaded
    bucket - The s3 bucket where we should upload the data
    key - The name of the key which will be the destination of the data
    check_func - An optional function that if supplied will be run after all
                 procs in precursor_procs have finished.
    check_args - The arguments to supply to the check_func
    """
    devnull = open(os.devnull, 'w')
    try:
        term_path = get_term_file()
        repeater = subprocess.Popen(
            [get_exec_path(), term_path], stdin=stdin, stdout=subprocess.PIPE)
        uploader = subprocess.Popen(
            [S3_SCRIPT, 'put', '-k', urllib.quote_plus(key), '-b', bucket],
            stdin=repeater.stdout,
            stderr=devnull)
        success = False
        while not success:
            success = True
            for proc in precursor_procs:
                ret = precursor_procs[proc].poll()
                if ret is None:
                    # process has not yet terminated
                    success = False
                elif ret != 0:
                    raise Exception(
                        '{proc_id}: {proc} encountered an error'
                        ''.format(
                            proc_id=multiprocessing.current_process().name,
                            proc=proc))

            # if we have success up to here, *and the term path does not exist* we
            # should run the check function and create the term_path.
            if success:
                if not check_term_file(term_path):
                    if check_func:
                        check_func(check_arg)
                    with open(term_path, 'w') as term_handle:
                        term_handle.write(TERM_STRING)

            # After checking the precursor_procs, next check the repeater
            ret = repeater.poll()
            if ret is None:
                success = False
            elif ret != 0:
                raise Exception(
                    '{proc_id}: repeater encountered an error'
                    ''.format(proc_id=multiprocessing.current_process().name))

            # Finally, check the uploader.
            ret = uploader.poll()
            if ret is None:
                success = False
            elif ret != 0:
                raise Exception(
                    '{proc_id}: uploader encountered an error'
                    ''.format(proc_id=multiprocessing.current_process().name))

            if not success:
                time.sleep(SLEEP_TIME)
    except:
        if uploader and psutil.pid_exists(uploader.pid):
            try:
                uploader.kill()
            except:
                pass
        if repeater and psutil.pid_exists(repeater.pid):
            try:
                repeater.kill()
            except:
                pass
        raise
    finally:
        os.remove(term_path)


def kill_precursor_procs(procs):
    """ In the case of a failure, we will need to kill off the precursor_procs

    Args:
    procs - a set of processes
    """
    for proc in procs:
        if procs[proc] and psutil.pid_exists(procs[proc].pid):
            try:
                procs[proc].kill()
            except:
                # process no longer exists, no big deal.
                pass


class ReplicationError(Exception):
    pass


class AuthError(Exception):
    pass


class InvalidVariableForOperation(Exception):
    pass


log = setup_logging_defaults(__name__)


def get_all_mysql_grants():
    """Fetch all MySQL grants

    Returns:
    A dictionary describing all MySQL grants.

    Example:
    {'`admin2`@`%`': {'grant_option': True,
                  'password': u'REDACTED',
                  'privileges': u'ALL PRIVILEGES',
                  'source_host': '%',
                  'username': u'admin2'},
     '`admin`@`%`': {'grant_option': True,
                 'password': u'REDACTED',
                 'privileges': u'ALL PRIVILEGES',
                 'source_host': '%',
                 'username': u'admin'},
     '`etl2`@`%`': {'grant_option': False,
                'password': u'REDACTED',
                'privileges': u'SELECT, SHOW DATABASES',
                'source_host': '%',
                'username': u'etl2'},
    ...
    """
    grants = {}
    for _, role in get_mysql_auth_roles().iteritems():
        source_hosts = role.get('source_hosts', '%')
        grant_option = role.get('grant_option', False)
        privileges = role['privileges']

        for user in role['users']:
            key = '`{user}`@`{host}`'.format(
                user=user['username'], host=source_hosts)

            if key in grants.keys():
                raise AuthError('Duplicate username defined for %s' % key)
            grants[key] = {
                'username': user['username'].encode('ascii', 'ignore'),
                'password': user['password'].encode('ascii', 'ignore'),
                'privileges': privileges.encode('ascii', 'ignore'),
                'grant_option': grant_option,
                'source_host': source_hosts.encode('ascii', 'ignore')
            }
    return grants


def get_mysql_user_for_role(role):
    """Fetch the credential for a role from a mysql role

    Args:
    role - a string of the name of the mysql role to use for username/password

    Returns:
    username - string of the username enabled for the role
    password - string of the password enabled for the role
    """
    grants = get_mysql_auth_roles()[role]
    for user in grants['users']:
        if user['enabled']:
            return user['username'], user['password']


def get_mysql_auth_roles():
    """Get all mysql roles from zk updater

    Returns:
    a dict describing the replication status.

    Example:
    {u'dataLayer': {u'privileges': u'SELECT',
                    u'users': [
                        {u'username': u'pbdataLayer',
                         u'password': u'REDACTED',
                         u'enabled': True},
                        {u'username': u'pbdataLayer2',
                         u'password': u'REDACTED',
                         u'enabled': False}]},
...
"""
    with open(AUTH_FILE) as f:
        json_grants = json.loads(f.read())
    return json_grants


def connect_mysql(instance, role='admin'):
    """Connect to a MySQL instance as admin

    Args:
    hostaddr - object describing which mysql instance to connect to
    role - a string of the name of the mysql role to use. A bootstrap role can
           be called for MySQL instances lacking any grants. This user does not
           exit in zk.

    Returns:
    a connection to the server as administrator
    """
    if role == 'bootstrap':
        socket = get_cnf_setting('socket', instance.port)
        username = 'root'
        password = ''
        db = MySQLdb.connect(
            unix_socket=socket,
            user=username,
            passwd=password,
            cursorclass=MySQLdb.cursors.DictCursor)

    else:
        username, password = get_mysql_user_for_role(role)
        db = MySQLdb.connect(
            host=instance.hostname,
            port=instance.port,
            user=username,
            passwd=password,
            cursorclass=MySQLdb.cursors.DictCursor,
            connect_timeout=CONNECT_TIMEOUT)
    return db


def get_master_from_instance(instance):
    """ Determine if an instance thinks it is a slave and if so from where

    Args:
    instance - A hostaddr object

    Returns:
    master - A hostaddr object or None
    """
    try:
        ss = get_slave_status(instance)
    except ReplicationError:
        return None

    return HostAddr(''.join((ss['Master_Host'], ':', str(ss['Master_Port']))))


def get_slave_status(instance):
    """ Get MySQL replication status

    Args:
    instance - A hostaddr object

    Returns:
    a dict describing the replication status.

    Example:
    {'Connect_Retry': 60L,
     'Exec_Master_Log_Pos': 98926487L,
     'Last_Errno': 0L,
     'Last_Error': '',
     'Last_IO_Errno': 0L,
     'Last_IO_Error': '',
     'Last_SQL_Errno': 0L,
     'Last_SQL_Error': '',
     'Master_Host': 'sharddb015e',
     'Master_Log_File': 'mysql-bin.000290',
     'Master_Port': 3306L,
     'Master_SSL_Allowed': 'No',
     'Master_SSL_CA_File': '',
     'Master_SSL_CA_Path': '',
     'Master_SSL_Cert': '',
     'Master_SSL_Cipher': '',
     'Master_SSL_Key': '',
     'Master_SSL_Verify_Server_Cert': 'No',
     'Master_Server_Id': 946544731L,
     'Master_User': 'replicant',
     'Read_Master_Log_Pos': 98926487L,
     'Relay_Log_File': 'mysqld_3306-relay-bin.000237',
     'Relay_Log_Pos': 98926633L,
     'Relay_Log_Space': 98926838L,
     'Relay_Master_Log_File': 'mysql-bin.000290',
     'Replicate_Do_DB': '',
     'Replicate_Do_Table': '',
     'Replicate_Ignore_DB': '',
     'Replicate_Ignore_Server_Ids': '',
     'Replicate_Ignore_Table': '',
     'Replicate_Wild_Do_Table': '',
     'Replicate_Wild_Ignore_Table': '',
     'Seconds_Behind_Master': 0L,
     'Skip_Counter': 0L,
     'Slave_IO_Running': 'Yes',
     'Slave_IO_State': 'Waiting for master to send event',
     'Slave_SQL_Running': 'Yes',
     'Until_Condition': 'None',
     'Until_Log_File': '',
     'Until_Log_Pos': 0L}
    """
    conn = connect_mysql(instance)
    cursor = conn.cursor()

    cursor.execute("SHOW SLAVE STATUS")
    slave_status = cursor.fetchone()
    if slave_status is None:
        raise ReplicationError('Server is not a replica')
    return slave_status


def flush_master_log(instance):
    """ Flush binary logs

    Args:
    instance - a hostAddr obect
    """
    conn = connect_mysql(instance)
    cursor = conn.cursor()
    cursor.execute("FLUSH BINARY LOGS")


def get_master_status(instance):
    """ Get poisition of most recent write to master replication logs

    Args:
    instance - a hostAddr object

    Returns:
    a dict describing the master status

    Example:
    {'Binlog_Do_DB': '',
     'Binlog_Ignore_DB': '',
     'File': 'mysql-bin.019324',
     'Position': 61559L}
    """
    conn = connect_mysql(instance)
    cursor = conn.cursor()

    cursor.execute("SHOW MASTER STATUS")
    master_status = cursor.fetchone()
    if master_status is None:
        raise ReplicationError('Server is not setup to write replication logs')
    return master_status


def get_master_logs(instance):
    """ Get MySQL binary log names and size

    Args
    db - a connection to the server as administrator

    Returns
    A tuple of dicts describing the replication status.

    Example:
    ({'File_size': 104857859L, 'Log_name': 'mysql-bin.000281'},
     {'File_size': 104858479L, 'Log_name': 'mysql-bin.000282'},
     {'File_size': 104859420L, 'Log_name': 'mysql-bin.000283'},
     {'File_size': 104859435L, 'Log_name': 'mysql-bin.000284'},
     {'File_size': 104858059L, 'Log_name': 'mysql-bin.000285'},
     {'File_size': 104859233L, 'Log_name': 'mysql-bin.000286'},
     {'File_size': 104858895L, 'Log_name': 'mysql-bin.000287'},
     {'File_size': 104858039L, 'Log_name': 'mysql-bin.000288'},
     {'File_size': 104858825L, 'Log_name': 'mysql-bin.000289'},
     {'File_size': 104857726L, 'Log_name': 'mysql-bin.000290'},
     {'File_size': 47024156L, 'Log_name': 'mysql-bin.000291'})
    """
    conn = connect_mysql(instance)
    cursor = conn.cursor()

    cursor.execute("SHOW MASTER LOGS")
    master_status = cursor.fetchall()
    return master_status


def get_binlog_archiving_lag(instance):
    """ Get date of creation of most recent binlog archived

    Args:
    instance - a hostAddr object

    Returns:
    A datetime object
    """
    conn = connect_mysql(instance)
    cursor = conn.cursor()
    sql = ("SELECT binlog_creation "
           "FROM {db}.{tbl} "
           "WHERE hostname= %(hostname)s  AND "
           "      port = %(port)s "
           "ORDER BY binlog_creation DESC "
           "LIMIT 1;").format(
               db=METADATA_DB, tbl=BINLOG_ARCHIVING_TABLE_NAME)
    params = {'hostname': instance.hostname, 'port': instance.port}
    cursor.execute(sql, params)
    res = cursor.fetchone()
    if res:
        return res['binlog_creation']
    else:
        return None


def calc_binlog_behind(log_file_num, log_file_pos, master_logs):
    """ Calculate replication lag in bytes

    Args:
    log_file_num - The integer of the binlog
    log_file_pos - The position inside of log_file_num
    master_logs - A tuple of dicts describing the replication status

    Returns:
    bytes_behind - bytes of lag across all log file
    binlogs_behind - number of binlogs lagged
    """
    binlogs_behind = 0
    bytes_behind = 0
    for binlog in master_logs:
        _, binlog_num = re.split('\.', binlog['Log_name'])
        if binlog_num >= log_file_num:
            if binlog_num == log_file_num:
                bytes_behind += binlog['File_size'] - log_file_pos
            else:
                binlogs_behind += 1
                bytes_behind += binlog['File_size']
    return bytes_behind, binlogs_behind


def get_global_variables(instance):
    """ Get MySQL global variables

    Args:
    instance - A hostAddr object

    Returns:
    A dict with the key the variable name
    """
    conn = connect_mysql(instance)
    ret = dict()
    cursor = conn.cursor()
    cursor.execute("SHOW GLOBAL VARIABLES")
    list_variables = cursor.fetchall()
    for entry in list_variables:
        ret[entry['Variable_name']] = entry['Value']

    return ret


def get_dbs(instance):
    """ Get MySQL databases other than mysql, information_schema,
    performance_schema and test

    Args:
    instance - A hostAddr object

    Returns
    A set of databases
    """
    conn = connect_mysql(instance)
    cursor = conn.cursor()
    ret = set()

    cursor.execute(' '.join(
        ("SELECT schema_name", "FROM information_schema.schemata",
         "WHERE schema_name NOT IN('mysql',",
         "                         'information_schema',",
         "                         'performance_schema',",
         "                         'test')", "ORDER BY schema_name")))
    dbs = cursor.fetchall()
    for db in dbs:
        ret.add(db['schema_name'])
    return ret


def does_table_exist(instance, db, table):
    """ Return True if a given table exists in a given database.

    Args:
    instance - A hostAddr object
    db - A string that contains the database name we're looking for
    table - A string containing the name of the table we're looking for

    Returns:
    True if the table was found.
    False if not or there was an exception.
    """
    conn = connect_mysql(instance)
    cursor = conn.cursor()
    table_exists = False

    try:
        sql = ("SELECT COUNT(*) AS cnt FROM information_schema.tables "
               "WHERE table_schema=%(db)s AND table_name=%(tbl)s")
        cursor.execute(sql, {'db': db, 'tbl': table})
        row = cursor.fetchone()
        if row['cnt'] == 1:
            table_exists = True
    except:
        # If it doesn't work, we can't know anything about the
        # state of the table.
        log.info('Ignoring an error checking for existance of '
                 '{db}.{table}'.format(
                     db=db, table=table))

    return table_exists


def get_tables(instance, db, skip_views=False):
    """ Get a list of tables and views in a given database or just
        tables.  Default to include views so as to maintain backward
        compatibility.

    Args:
    instance - A hostAddr object
    db - a string which contains a name of a db
    skip_views - true if we want tables only, false if we want everything

    Returns
    A set of tables
    """
    conn = connect_mysql(instance)
    cursor = conn.cursor()
    ret = set()

    param = {'db': db}
    sql = ''.join(("SELECT TABLE_NAME ", "FROM information_schema.tables ",
                   "WHERE TABLE_SCHEMA=%(db)s "))
    if skip_views:
        sql = sql + ' AND TABLE_TYPE="BASE TABLE" '

    cursor.execute(sql, param)
    for table in cursor.fetchall():
        ret.add(table['TABLE_NAME'])

    return ret


def get_columns_for_table(instance, db, table):
    """ Get a list of columns in a table

    Args:
    instance - a hostAddr object
    db - a string which contains a name of a db
    table - the name of the table to fetch columns

    Returns
    A list of columns
    """
    conn = connect_mysql(instance)
    cursor = conn.cursor()
    ret = list()

    param = {'db': db, 'table': table}
    sql = ("SELECT COLUMN_NAME "
           "FROM information_schema.columns "
           "WHERE TABLE_SCHEMA=%(db)s AND"
           "      TABLE_NAME=%(table)s")
    cursor.execute(sql, param)
    for column in cursor.fetchall():
        ret.append(column['COLUMN_NAME'])

    return ret


def setup_semisync_plugins(instance):
    """ Install the semi-sync replication plugins.  We may or may
        not actually use them on any given replica set, but this
        ensures that we've got them.  Semi-sync exists on all versions
        of MySQL that we might support, but we'll never use it on 5.5.

        Args:
        instance - A hostaddr object
    """
    conn = connect_mysql(instance)
    cursor = conn.cursor()

    version = get_global_variables(instance)['version']
    if version[0:3] == '5.5':
        return

    try:
        cursor.execute(
            "INSTALL PLUGIN rpl_semi_sync_master SONAME 'semisync_master.so'")
    except MySQLdb.OperationalError as detail:
        (error_code, msg) = detail.args
        if error_code != MYSQL_ERROR_FUNCTION_EXISTS:
            raise
            # already loaded, no work to do

    try:
        cursor.execute(
            "INSTALL PLUGIN rpl_semi_sync_slave SONAME 'semisync_slave.so'")
    except MySQLdb.OperationalError as detail:
        (error_code, msg) = detail.args
        if error_code != MYSQL_ERROR_FUNCTION_EXISTS:
            raise


def setup_response_time_metrics(instance):
    """ Add Query Response Time Plugins

    Args:
    instance -  A hostaddr object
    """
    conn = connect_mysql(instance)
    cursor = conn.cursor()

    version = get_global_variables(instance)['version']
    if version[0:3] < '5.6':
        return

    try:
        cursor.execute(
            "INSTALL PLUGIN QUERY_RESPONSE_TIME_AUDIT SONAME 'query_response_time.so'"
        )
    except MySQLdb.OperationalError as detail:
        (error_code, msg) = detail.args
        if error_code != MYSQL_ERROR_FUNCTION_EXISTS:
            raise
            # already loaded, no work to do

    try:
        cursor.execute(
            "INSTALL PLUGIN QUERY_RESPONSE_TIME SONAME 'query_response_time.so'"
        )
    except MySQLdb.OperationalError as detail:
        (error_code, msg) = detail.args
        if error_code != MYSQL_ERROR_FUNCTION_EXISTS:
            raise

    try:
        cursor.execute(
            "INSTALL PLUGIN QUERY_RESPONSE_TIME_READ SONAME 'query_response_time.so'"
        )
    except MySQLdb.OperationalError as detail:
        (error_code, msg) = detail.args
        if error_code != MYSQL_ERROR_FUNCTION_EXISTS:
            raise

    try:
        cursor.execute(
            "INSTALL PLUGIN QUERY_RESPONSE_TIME_WRITE SONAME 'query_response_time.so'"
        )
    except MySQLdb.OperationalError as detail:
        (error_code, msg) = detail.args
        if error_code != MYSQL_ERROR_FUNCTION_EXISTS:
            raise
    cursor.execute("SET GLOBAL QUERY_RESPONSE_TIME_STATS=ON")


def enable_and_flush_activity_statistics(instance):
    """ Reset counters for table statistics

    Args:
    instance - a hostAddr obect
    """
    conn = connect_mysql(instance)
    cursor = conn.cursor()

    global_vars = get_global_variables(instance)
    if global_vars['userstat'] != 'ON':
        set_global_variable(instance, 'userstat', True)

    sql = 'FLUSH TABLE_STATISTICS'
    log.info(sql)
    cursor.execute(sql)

    sql = 'FLUSH USER_STATISTICS'
    log.info(sql)
    cursor.execute(sql)


def get_dbs_activity(instance):
    """ Return rows read and changed from a MySQL instance by db

    Args:
    instance - a hostAddr object

    Returns:
    A dict with a key of the db name and entries for rows read and rows changed
    """
    conn = connect_mysql(instance)
    cursor = conn.cursor()
    ret = dict()

    global_vars = get_global_variables(instance)
    if global_vars['userstat'] != 'ON':
        raise InvalidVariableForOperation('Userstats must be enabled on ',
                                          'for table_statistics to function. '
                                          'Perhaps run "SET GLOBAL userstat = '
                                          'ON" to fix this.')

    sql = ("SELECT SCHEMA_NAME, "
           "    SUM(ROWS_READ) AS 'ROWS_READ', "
           "    SUM(ROWS_CHANGED) AS 'ROWS_CHANGED' "
           "FROM information_schema.SCHEMATA "
           "LEFT JOIN information_schema.TABLE_STATISTICS "
           "    ON SCHEMA_NAME=TABLE_SCHEMA "
           "GROUP BY SCHEMA_NAME ")
    cursor.execute(sql)
    raw_activity = cursor.fetchall()
    for row in raw_activity:
        if row['ROWS_READ'] is None:
            row['ROWS_READ'] = 0

        if row['ROWS_CHANGED'] is None:
            row['ROWS_CHANGED'] = 0

        ret[row['SCHEMA_NAME']] = {
            'ROWS_READ': int(row['ROWS_READ']),
            'ROWS_CHANGED': int(row['ROWS_CHANGED'])
        }
    return ret


def get_user_activity(instance):
    """ Return information about activity broken down by mysql user accoutn

    Args:
    instance - a hostAddr object

    Returns:
    a dict of user activity since last flush
    """
    conn = connect_mysql(instance)
    cursor = conn.cursor()
    ret = dict()

    global_vars = get_global_variables(instance)
    if global_vars['userstat'] != 'ON':
        raise InvalidVariableForOperation('Userstats must be enabled on ',
                                          'for table_statistics to function. '
                                          'Perhaps run "SET GLOBAL userstat = '
                                          'ON" to fix this.')

    sql = 'SELECT * FROM information_schema.USER_STATISTICS'
    cursor.execute(sql)
    raw_activity = cursor.fetchall()
    for row in raw_activity:
        user = row['USER']
        del (row['USER'])
        ret[user] = row

    return ret


def get_connected_users(instance):
    """ Get all currently connected users

    Args:
    instance - a hostAddr object

    Returns:
    a set of users
    """
    conn = connect_mysql(instance)
    cursor = conn.cursor()

    sql = ("SELECT user "
           "FROM information_schema.processlist "
           "GROUP BY user")
    cursor.execute(sql)
    results = cursor.fetchall()

    ret = set()
    for result in results:
        ret.add(result['user'])

    return ret


def show_create_table(instance, db, table, standardize=True):
    """ Get a standardized CREATE TABLE statement

    Args:
    instance - a hostAddr object
    db - the MySQL database to run against
    table - the table on the db database to run against
    standardize - Remove AUTO_INCREMENT=$NUM and similar

    Returns:
    A string of the CREATE TABLE statement
    """
    conn = connect_mysql(instance)
    cursor = conn.cursor()

    try:
        cursor.execute('SHOW CREATE TABLE `{db}`.`{table}`'.format(
            table=table, db=db))
        ret = cursor.fetchone()['Create Table']
        if standardize is True:
            ret = re.sub('AUTO_INCREMENT=[0-9]+ ', '', ret)
    except MySQLdb.ProgrammingError as detail:
        (error_code, msg) = detail.args
        if error_code != MYSQL_ERROR_NO_SUCH_TABLE:
            raise
        ret = ''

    return ret


def create_db(instance, db):
    """ Create a database if it does not already exist

    Args:
    instance - a hostAddr object
    db - the name of the to be created
    """
    conn = connect_mysql(instance)
    cursor = conn.cursor()

    sql = ('CREATE DATABASE IF NOT EXISTS ' '`{db}`;'.format(db=db))
    log.info(sql)

    # We don't care if the db already exists and this was a no-op
    warnings.filterwarnings('ignore', category=MySQLdb.Warning)
    cursor.execute(sql)
    warnings.resetwarnings()


def copy_db_schema(instance, old_db, new_db, verbose=False, dry_run=False):
    """ Copy the schema of one db into a different db

    Args:
    instance - a hostAddr object
    old_db - the source of the schema copy
    new_db - the destination of the schema copy
    verbose - print out SQL commands
    dry_run - do not change any state
    """
    conn = connect_mysql(instance)
    cursor = conn.cursor()

    tables = get_tables(instance, old_db)
    for table in tables:
        raw_sql = "CREATE TABLE IF NOT EXISTS `{new_db}`.`{table}` LIKE `{old_db}`.`{table}`"
        sql = raw_sql.format(old_db=old_db, new_db=new_db, table=table)
        if verbose:
            print sql

        if not dry_run:
            cursor.execute(sql)


def move_db_contents(instance, old_db, new_db, verbose=False, dry_run=False):
    """ Move the contents of one db into a different db

    Args:
    instance - a hostAddr object
    old_db - the source from which to move data
    new_db - the destination to move data
    verbose - print out SQL commands
    dry_run - do not change any state
    """
    conn = connect_mysql(instance)
    cursor = conn.cursor()

    tables = get_tables(instance, old_db)
    for table in tables:
        raw_sql = "RENAME TABLE `{old_db}`.`{table}` to `{new_db}`.`{table}`"
        sql = raw_sql.format(old_db=old_db, new_db=new_db, table=table)
        if verbose:
            print sql

        if not dry_run:
            cursor.execute(sql)


def setup_replication(new_master, new_replica):
    """ Set an instance as a slave of another

    Args:
    new_master - A hostaddr object for the new master
    new_slave - A hostaddr object for the new slave
    """
    log.info('Setting {new_replica} as a replica of new master '
             '{new_master}'.format(
                 new_master=new_master, new_replica=new_replica))
    new_master_coordinates = get_master_status(new_master)
    change_master(new_replica, new_master, new_master_coordinates['File'],
                  new_master_coordinates['Position'])


def restart_replication(instance):
    """ Stop then start replication

    Args:
    instance - A hostAddr object
    """
    stop_replication(instance)
    start_replication(instance)


def stop_replication(instance, thread_type=REPLICATION_THREAD_ALL):
    """ Stop replication, if running

    Args:
    instance - A hostAddr object
    thread - Which thread to stop. Options are in REPLICATION_THREAD_TYPES.
    """
    if thread_type not in REPLICATION_THREAD_TYPES:
        raise Exception('Invalid input for arg thread: {thread}'
                        ''.format(thread=thread_type))

    conn = connect_mysql(instance)
    cursor = conn.cursor()

    ss = get_slave_status(instance)
    if (ss['Slave_IO_Running'] != 'No' and ss['Slave_SQL_Running'] != 'No' and
            thread_type == REPLICATION_THREAD_ALL):
        cmd = 'STOP SLAVE'
    elif ss['Slave_IO_Running'] != 'No' and thread_type != REPLICATION_THREAD_SQL:
        cmd = 'STOP SLAVE IO_THREAD'
    elif ss['Slave_SQL_Running'] != 'No' and thread_type != REPLICATION_THREAD_IO:
        cmd = 'STOP SLAVE SQL_THREAD'
    else:
        log.info('Replication already stopped')
        return

    warnings.filterwarnings('ignore', category=MySQLdb.Warning)
    log.info(cmd)
    cursor.execute(cmd)
    warnings.resetwarnings()


def start_replication(instance, thread_type=REPLICATION_THREAD_ALL):
    """ Start replication, if not running

    Args:
    instance - A hostAddr object
    thread - Which thread to start. Options are in REPLICATION_THREAD_TYPES.
    """
    if thread_type not in REPLICATION_THREAD_TYPES:
        raise Exception('Invalid input for arg thread: {thread}'
                        ''.format(thread=thread_type))

    conn = connect_mysql(instance)
    cursor = conn.cursor()

    ss = get_slave_status(instance)
    if (ss['Slave_IO_Running'] != 'Yes' and
            ss['Slave_SQL_Running'] != 'Yes' and
            thread_type == REPLICATION_THREAD_ALL):
        cmd = 'START SLAVE'
    elif ss['Slave_IO_Running'] != 'Yes' and thread_type != REPLICATION_THREAD_SQL:
        cmd = 'START SLAVE IO_THREAD'
    elif ss['Slave_SQL_Running'] != 'Yes' and thread_type != REPLICATION_THREAD_IO:
        cmd = 'START SLAVE SQL_THREAD'
    else:
        log.info('Replication already running')
        return

    warnings.filterwarnings('ignore', category=MySQLdb.Warning)
    log.info(cmd)
    cursor.execute(cmd)
    warnings.resetwarnings()
    time.sleep(1)


def reset_slave(instance):
    """ Stop replicaion and remove all repl settings

    Args:
    instance - A hostAddr object
    """
    conn = connect_mysql(instance)
    cursor = conn.cursor()

    try:
        stop_replication(instance)
        cmd = 'RESET SLAVE ALL'
        log.info(cmd)
        cursor.execute(cmd)
    except ReplicationError:
        # SHOW SLAVE STATUS failed, previous state does not matter so pass
        pass


def change_master(slave_hostaddr,
                  master_hostaddr,
                  master_log_file,
                  master_log_pos,
                  no_start=False):
    """ Setup MySQL replication on new replica

    Args:
    slave_hostaddr -  hostaddr object for the new replica
    hostaddr - A hostaddr object for the master db
    master_log_file - Replication log file to begin streaming
    master_log_pos - Position in master_log_file
    no_start - Don't run START SLAVE after CHANGE MASTER
    """
    conn = connect_mysql(slave_hostaddr)
    cursor = conn.cursor()

    set_global_variable(slave_hostaddr, 'read_only', True)
    reset_slave(slave_hostaddr)
    master_user, master_password = get_mysql_user_for_role('replication')
    parameters = {
        'master_user': master_user,
        'master_password': master_password,
        'master_host': master_hostaddr.hostname,
        'master_port': master_hostaddr.port,
        'master_log_file': master_log_file,
        'master_log_pos': master_log_pos
    }
    sql = ''.join(("CHANGE MASTER TO "
                   "MASTER_USER=%(master_user)s, "
                   "MASTER_PASSWORD=%(master_password)s, "
                   "MASTER_HOST=%(master_host)s, "
                   "MASTER_PORT=%(master_port)s, "
                   "MASTER_LOG_FILE=%(master_log_file)s, "
                   "MASTER_LOG_POS=%(master_log_pos)s "))
    warnings.filterwarnings('ignore', category=MySQLdb.Warning)
    cursor.execute(sql, parameters)
    warnings.resetwarnings()
    log.info(cursor._executed)

    if not no_start:
        start_replication(slave_hostaddr)
        # Replication reporting is wonky for the first second
        time.sleep(1)
        # Avoid race conditions for zk update monitor
        assert_replication_sanity(slave_hostaddr,
                                  set([CHECK_SQL_THREAD, CHECK_IO_THREAD]))


def wait_replication_catch_up(slave_hostaddr):
    """ Watch replication until it is caught up

    Args:
    slave_hostaddr - A HostAddr object
    """
    last_sbm = None
    catch_up_sbm = NORMAL_HEARTBEAT_LAG - HEARTBEAT_SAFETY_MARGIN
    remaining_time = 'Not yet availible'
    sleep_duration = 5

    # Confirm that replication is setup at all
    get_slave_status(slave_hostaddr)

    try:
        assert_replication_sanity(slave_hostaddr)
    except:
        log.warning('Replication does not appear sane, going to sleep 60 '
                    'seconds in case things get better on their own.')
        time.sleep(60)
        assert_replication_sanity(slave_hostaddr)

    while True:
        replication = calc_slave_lag(slave_hostaddr)

        if replication['sbm'] is None or replication['sbm'] == INVALID:
            log.info('Computed seconds behind master is unavailable, going to '
                     'sleep for a minute and retry. A likely reason is that '
                     'there was a failover between when a backup was taken '
                     'and when a restore was run so there will not be a '
                     'entry until replication has caught up more. If this is '
                     'a new replica set, read_only is probably ON on the '
                     'master server.')
            time.sleep(60)
            continue

        if replication['sbm'] < catch_up_sbm:
            log.info('Replication computed seconds behind master {sbm} < '
                     '{catch_up_sbm}, which is "good enough".'
                     ''.format(
                         sbm=replication['sbm'], catch_up_sbm=catch_up_sbm))
            return

        # last_sbm is set at the end of the first execution and should always
        # be set from then on
        if last_sbm:
            catch_up_rate = (
                last_sbm - replication['sbm']) / float(sleep_duration)
            if catch_up_rate > 0:
                remaining_time = datetime.timedelta(seconds=(
                    (replication['sbm'] - catch_up_sbm) / catch_up_rate))
                if remaining_time.total_seconds() > 6 * 60 * 60:
                    sleep_duration = 5 * 60
                elif remaining_time.total_seconds() > 60 * 60:
                    sleep_duration = 60
                else:
                    sleep_duration = 5
            else:
                remaining_time = '> heat death of the universe'
                sleep_duration = 60
            log.info('Replication is lagged by {sbm} seconds, waiting '
                     'for < {catch_up}. Guestimate time to catch up: {eta}'
                     ''.format(
                         sbm=replication['sbm'],
                         catch_up=catch_up_sbm,
                         eta=str(remaining_time)))
        else:
            # first time through
            log.info('Replication is lagged by {sbm} seconds.'
                     ''.format(sbm=replication['sbm']))

        last_sbm = replication['sbm']
        time.sleep(sleep_duration)


def assert_replication_unlagged(instance, lag_tolerance, dead_master=False):
    """ Confirm that replication lag is less than tolerance, otherwise
        throw an exception

    Args:
    instance - A hostAddr object of the replica
    lag_tolerance - Possibly values (constants):
                    'REPLICATION_TOLERANCE_NONE'- no lag is acceptable
                    'REPLICATION_TOLERANCE_NORMAL' - replica can be slightly lagged
                    'REPLICATION_TOLERANCE_LOOSE' - replica can be really lagged
    """
    # Test to see if the slave is setup for replication. If not, we are hosed
    replication = calc_slave_lag(instance, dead_master)
    problems = set()
    if lag_tolerance == REPLICATION_TOLERANCE_NONE:
        if replication['sql_bytes'] != 0:
            problems.add('Replica {r} is not fully synced, bytes behind: {b}'
                         ''.format(
                             r=instance, b=replication['sql_bytes']))
    elif lag_tolerance == REPLICATION_TOLERANCE_NORMAL:
        if replication['sbm'] > NORMAL_HEARTBEAT_LAG:
            problems.add(
                'Replica {r} has heartbeat lag {sbm} > {sbm_limit} seconds'
                ''.format(
                    sbm=replication['sbm'],
                    sbm_limit=NORMAL_HEARTBEAT_LAG,
                    r=instance))

        if replication['io_bytes'] > NORMAL_IO_LAG:
            problems.add('Replica {r} has IO lag {io_bytes} > {io_limit} bytes'
                         ''.format(
                             io_bytes=replication['io_bytes'],
                             io_limit=NORMAL_IO_LAG,
                             r=instance))
    elif lag_tolerance == REPLICATION_TOLERANCE_LOOSE:
        if replication['sbm'] > LOOSE_HEARTBEAT_LAG:
            problems.addi(
                'Replica {r} has heartbeat lag {sbm} > {sbm_limit} seconds'
                ''.format(
                    sbm=replication['sbm'],
                    sbm_limit=LOOSE_HEARTBEAT_LAG,
                    r=instance))
    else:
        problems.add('Unkown lag_tolerance mode: {m}'.format(m=lag_tolerance))

    if problems:
        raise Exception(', '.join(problems))


def assert_replication_sanity(instance, checks=ALL_REPLICATION_CHECKS):
    """ Confirm that a replica has replication running and from the correct
        source if the replica is in zk. If not, throw an exception.

    args:
    instance - A hostAddr object
    """
    problems = set()
    slave_status = get_slave_status(instance)
    if (CHECK_IO_THREAD in checks and
            slave_status['Slave_IO_Running'] != 'Yes'):
        problems.add('Replica {r} has IO thread not running'
                     ''.format(r=instance))

    if (CHECK_SQL_THREAD in checks and
            slave_status['Slave_SQL_Running'] != 'Yes'):
        problems.add('Replcia {r} has SQL thread not running'
                     ''.format(r=instance))

    if CHECK_CORRECT_MASTER in checks:
        zk = MysqlZookeeper()
        try:
            (replica_set,
             replica_type) = zk.get_replica_set_from_instance(instance)
        except:
            # must not be in zk, returning
            return
        expected_master = zk.get_mysql_instance_from_replica_set(replica_set)
        actual_master = HostAddr(':'.join((slave_status['Master_Host'], str(
            slave_status['Master_Port']))))
        if expected_master != actual_master:
            problems.add('Master is {actual} rather than expected {expected}'
                         'for replica {r}'.format(
                             actual=actual_master,
                             expected=expected_master,
                             r=instance))

    if problems:
        raise Exception(', '.join(problems))


def calc_slave_lag(slave_hostaddr, dead_master=False):
    """ Determine MySQL replication lag in bytes and binlogs

    Args:
    slave_hostaddr - A HostAddr object for a replica

    Returns:
    io_binlogs - Number of undownloaded binlogs. This is only slightly useful
                 as io_bytes spans binlogs. It mostly exists for dba amussement
    io_bytes - Bytes of undownloaded replication logs.
    sbm - Number of seconds of replication lag as determined by computing
          the difference between current time and what exists in a heartbeat
          table as populated by replication
    sql_binlogs - Number of unprocessed binlogs. This is only slightly useful
                  as sql_bytes spans binlogs. It mostly exists for dba
                  amussement
    sql_bytes - Bytes of unprocessed replication logs
    ss - None or the results of running "show slave status'
    """

    ret = {
        'sql_bytes': INVALID,
        'sql_binlogs': INVALID,
        'io_bytes': INVALID,
        'io_binlogs': INVALID,
        'sbm': INVALID,
        'ss': {
            'Slave_IO_Running': INVALID,
            'Slave_SQL_Running': INVALID,
            'Master_Host': INVALID,
            'Master_Port': INVALID
        }
    }
    try:
        ss = get_slave_status(slave_hostaddr)
    except ReplicationError:
        # Not a slave, so return dict of INVALID
        return ret
    except MySQLdb.OperationalError as detail:
        (error_code, msg) = detail.args
        if error_code == MYSQL_ERROR_CONN_HOST_ERROR:
            # Host down, but exists.
            return ret
        else:
            # Host does not exist or something else funky
            raise

    ret['ss'] = ss
    slave_sql_pos = ss['Exec_Master_Log_Pos']
    slave_sql_binlog = ss['Relay_Master_Log_File']
    _, slave_sql_binlog_num = re.split('\.', slave_sql_binlog)
    slave_io_pos = ss['Read_Master_Log_Pos']
    slave_io_binlog = ss['Master_Log_File']
    _, slave_io_binlog_num = re.split('\.', slave_io_binlog)

    master_hostaddr = HostAddr(':'.join((ss['Master_Host'], str(ss[
        'Master_Port']))))
    if not dead_master:
        try:
            master_logs = get_master_logs(master_hostaddr)

            (ret['sql_bytes'], ret['sql_binlogs']) = calc_binlog_behind(
                slave_sql_binlog_num, slave_sql_pos, master_logs)
            (ret['io_bytes'], ret['io_binlogs']) = calc_binlog_behind(
                slave_io_binlog_num, slave_io_pos, master_logs)
        except _mysql_exceptions.OperationalError as detail:
            (error_code, msg) = detail.args
            if error_code != MYSQL_ERROR_CONN_HOST_ERROR:
                raise
                # we can compute real lag because the master is dead

    try:
        ret['sbm'] = calc_alt_sbm(slave_hostaddr, ss['Master_Server_Id'])
    except MySQLdb.ProgrammingError as detail:
        (error_code, msg) = detail.args
        if error_code != MYSQL_ERROR_NO_SUCH_TABLE:
            raise
        # We can not compute a real sbm, so the caller will get
        # None default
        pass
    return ret


def calc_alt_sbm(instance, master_server_id):
    """ Calculate seconds behind using heartbeat + time on slave server

    Args:
    instance - A hostAddr object of a slave server
    master_server_id - The server_id of the master server

    Returns:
    An int of the calculated seconds behind master or None
    """
    conn = connect_mysql(instance)
    cursor = conn.cursor()

    sql = ''.join(("SELECT TIMESTAMPDIFF(SECOND,ts, NOW()) AS 'sbm' "
                   "FROM {METADATA_DB}.heartbeat "
                   "WHERE server_id= %(Master_Server_Id)s"))

    cursor.execute(
        sql.format(METADATA_DB=METADATA_DB),
        {'Master_Server_Id': master_server_id})
    row = cursor.fetchone()
    if row:
        return row['sbm']
    else:
        return None


def get_heartbeat(instance):
    """ Get the most recent heartbeat on a slave

    Args:
    instance - A hostAddr object of a slave server

    Returns:
    A datetime.datetime object.
    """
    conn = connect_mysql(instance)
    cursor = conn.cursor()

    slave_status = get_slave_status(instance)
    sql = ''.join(("SELECT ts "
                   "FROM {METADATA_DB}.heartbeat "
                   "WHERE server_id= %(Master_Server_Id)s"))

    cursor.execute(sql.format(METADATA_DB=METADATA_DB), slave_status)
    row = cursor.fetchone()
    if not row:
        return None

    return datetime.datetime.strptime(row['ts'], MYSQL_DATETIME_TO_PYTHON)


def get_pitr_data(instance):
    """ Get all data needed to run a point in time recovery later on

    Args:
    instance - A hostAddr object of a server

    Returns:
    """
    ret = dict()
    ret['heartbeat'] = str(get_heartbeat(instance))
    ret['repl_positions'] = []
    master_status = get_master_status(instance)
    ret['repl_positions'].append(
        (master_status['File'], master_status['Position']))
    if 'Executed_Gtid_Set' in master_status:
        ret['Executed_Gtid_Set'] = master_status['Executed_Gtid_Set']
    else:
        ret['Executed_Gtid_Set'] = None

    try:
        ss = get_slave_status(instance)
        ret['repl_positions'].append(
            (ss['Relay_Master_Log_File'], ss['Exec_Master_Log_Pos']))
    except ReplicationError:
        # we are running on a master, don't care about this exception
        pass

    return ret


def set_global_variable(instance, variable, value):
    """ Modify MySQL global variables

    Args:
    instance - a hostAddr object
    variable - a string the MySQL global variable name
    value - a string or bool of the deisred state of the variable
    """
    conn = connect_mysql(instance)
    cursor = conn.cursor()

    # If we are enabling read only we need to kill all long running trx
    # so that they don't block the change
    if (variable == 'read_only' or variable == 'super_read_only') and value:
        gvars = get_global_variables(instance)
        if 'super_read_only' in gvars and gvars['super_read_only'] == 'ON':
            # no use trying to set something that is already turned on
            return
        kill_long_trx(instance)

    parameters = {'value': value}
    # Variable is not a string and can not be paramaretized as per normal
    sql = 'SET GLOBAL {variable} = %(value)s'.format(variable=variable)
    cursor.execute(sql, parameters)
    log.info(cursor._executed)


def start_consistent_snapshot(conn, read_only=False):
    """ Start a transaction with a consistent view of data

    Args:
    instance - a hostAddr object
    read_only - see the transaction to be read_only
    """
    if read_only:
        read_write_mode = 'READ ONLY'
    else:
        read_write_mode = 'READ WRITE'
    cursor = conn.cursor()
    cursor.execute("SET SESSION TRANSACTION ISOLATION "
                   "LEVEL REPEATABLE READ")
    cursor.execute(
        "START TRANSACTION /*!50625 WITH CONSISTENT SNAPSHOT, {rwm} */".format(
            rwm=read_write_mode))


def get_long_trx(instance):
    """ Get the thread id's of long (over 2 sec) running transactions

    Args:
    instance - a hostAddr object

    Returns -  A set of thread_id's
    """
    conn = connect_mysql(instance)
    cursor = conn.cursor()

    sql = ('SELECT trx_mysql_thread_id '
           'FROM information_schema.INNODB_TRX '
           'WHERE trx_started < NOW() - INTERVAL 2 SECOND ')
    cursor.execute(sql)
    transactions = cursor.fetchall()
    threads = set()
    for trx in transactions:
        threads.add(trx['trx_mysql_thread_id'])

    return threads


def kill_user_queries(instance, username):
    """ Kill a users queries

    Args:
    instance - The instance on which to kill the queries
    username - The name of the user to kill
    """
    conn = connect_mysql(instance)
    cursor = conn.cursor()
    sql = ("SELECT id "
           "FROM information_schema.processlist "
           "WHERE user= %(username)s ")
    cursor.execute(sql, {'username': username})
    queries = cursor.fetchall()
    for query in queries:
        log.info("Killing connection id {id}".format(id=query['id']))
        cursor.execute("kill %(id)s", {'id': query['id']})


def kill_long_trx(instance):
    """ Kill long running transaction.

    Args:
    instance - a hostAddr object
    """
    conn = connect_mysql(instance)
    cursor = conn.cursor()

    threads_to_kill = get_long_trx(instance)
    for thread in threads_to_kill:
        try:
            sql = 'kill %(thread)s'
            cursor.execute(sql, {'thread': thread})
            log.info(cursor._executed)
        except MySQLdb.OperationalError as detail:
            (error_code, msg) = detail.args
            if error_code != MYSQL_ERROR_NO_SUCH_THREAD:
                raise
            else:
                log.info('Thread {thr} no longer ' 'exists'.format(thr=thread))

    log.info('Confirming that long running transactions have gone away')
    while True:
        long_threads = get_long_trx(instance)
        not_dead = threads_to_kill.intersection(long_threads)

        if not_dead:
            log.info('Threads of not dead yet: '
                     '{threads}'.format(threads=not_dead))
            time.sleep(.5)
        else:
            log.info('All long trx are now dead')
            return


def shutdown_mysql(instance):
    """ Send a mysqladmin shutdown to an instance

    Args:
    instance - a hostaddr object
    """
    username, password = get_mysql_user_for_role('admin')
    cmd = ''.join((MYSQLADMIN, ' -u ', username, ' -p', password, ' -h ',
                   instance.hostname, ' -P ', str(instance.port), ' shutdown'))
    log.info(cmd)
    shell_exec(cmd)


def get_mysqlops_connections():
    """ Get a connection to mysqlops for reporting

    Returns:
    A mysql connection
    """
    (reporting_host, port, _, _) = get_mysql_connection('mysqlopsdb001')
    reporting = HostAddr(''.join((reporting_host, ':', str(port))))
    return connect_mysql(reporting, 'scriptrw')


def start_backup_log(instance, backup_type, timestamp):
    """ Start a log of a mysql backup

    Args:
    instance - A hostaddr object for the instance being backed up
    backup_type - Either xbstream or sql
    timestamp - The timestamp from when the backup began
    """
    row_id = None
    try:
        reporting_conn = get_mysqlops_connections()
        cursor = reporting_conn.cursor()

        sql = ("INSERT INTO mysqlops.mysql_backups "
               "SET "
               "hostname = %(hostname)s, "
               "port = %(port)s, "
               "started = %(started)s, "
               "backup_type = %(backup_type)s ")

        metadata = {
            'hostname': instance.hostname,
            'port': str(instance.port),
            'started': time.strftime('%Y-%m-%d %H:%M:%S', timestamp),
            'backup_type': backup_type
        }
        cursor.execute(sql, metadata)
        row_id = cursor.lastrowid
        reporting_conn.commit()
        log.info(cursor._executed)
    except Exception as e:
        log.warning("Unable to write log entry to "
                    "mysqlopsdb001: {e}".format(e=e))
        log.warning("However, we will attempt to continue with the ")
    return row_id


def finalize_backup_log(id, filename):
    """ Write final details of a mysql backup

    id - A pk from the mysql_backups table
    filename - The location of the resulting backup
    """
    try:
        reporting_conn = get_mysqlops_connections()
        cursor = reporting_conn.cursor()
        sql = ("UPDATE mysqlops.mysql_backups "
               "SET "
               "filename = %(filename)s, "
               "finished = %(finished)s "
               "WHERE id = %(id)s")
        metadata = {
            'filename': filename,
            'finished': time.strftime('%Y-%m-%d %H:%M:%S'),
            'id': id
        }
        cursor.execute(sql, metadata)
        reporting_conn.commit()
        reporting_conn.close()
        log.info(cursor._executed)
    except Exception as e:
        log.warning("Unable to update mysqlopsdb with "
                    "backup status: {e}".format(e=e))


def get_installed_mysqld_version():
    """ Get the version of mysqld installed on localhost

    Returns the numeric MySQL version

    Example: 5.6.22-72.0
    """
    (std_out, std_err, return_code) = shell_exec(MYSQL_VERSION_COMMAND)
    if return_code or not std_out:
        raise Exception('Could not determine installed mysql version: '
                        '{std_err}')
    return re.search('.+Ver ([0-9.-]+)', std_out).groups()[0]


ACCEPTABLE_ROOT_VOLUMES = ['/raid0', '/mnt']
OLD_CONF_ROOT = '/etc/mysql/my-{port}.cnf'
DEFAULTS_FILE_ARG = '--defaults-file={defaults_file}'
DEFAULTS_FILE_EXTRA_ARG = '--defaults-extra-file={defaults_file}'
HIERA_ROLE_FILE = '/etc/roles.txt'
DEFAULT_HIERA_ROLE = 'mlpv2'
DEFAULT_PINFO_CLOUD = 'undefined'
MASTERFUL_PUPPET_ROLES = ['singleshard', 'modshard']
HOSTNAME = socket.getfqdn().split('.')[0]
MYSQL_CNF_FILE = '/etc/mysql/my.cnf'
MYSQL_INIT_FILE = '/etc/mysql/init.sql'
MYSQL_UPGRADE_CNF_FILE = '/etc/mysql/mysql_upgrade.cnf'
MYSQL_NOREPL_CNF_FILE = '/etc/mysql/skip_slave_start.cnf'
MYSQL_DS_ZK = '/var/config/config.services.dataservices.mysql_databases'
MYSQL_DR_ZK = '/var/config/config.services.disaster_recoverydb'
MYSQL_GEN_ZK = '/var/config/config.services.general_mysql_databases_config'
MYSQL_MAX_WAIT = 120
MYSQL_STARTED = 0
MYSQL_STOPPED = 1
MYSQL_SUPERVISOR_PROC = 'mysqld-3306'
MYSQL_UPGRADE = '/usr/bin/mysql_upgrade'
REPLICA_ROLE_DR_SLAVE = 'dr_slave'
REPLICA_ROLE_MASTER = 'master'
REPLICA_ROLE_SLAVE = 'slave'
REPLICA_TYPES = [
    REPLICA_ROLE_MASTER, REPLICA_ROLE_SLAVE, REPLICA_ROLE_DR_SLAVE
]
TESTING_DATA_DIR = '/tmp/'
TESTING_PINFO_CLOUD = 'vagrant'

# /raid0 and /mnt are interchangable; use whichever one we have.
REQUIRED_MOUNTS = ['/raid0:/mnt']
SUPERVISOR_CMD = '/usr/local/bin/supervisorctl {action} mysql:mysqld-{port}'
INIT_CMD = '/etc/init.d/mysqld_multi {options} {action} {port}'
PTKILL_CMD = '/usr/sbin/service pt-kill-{port} {action}'
PTHEARTBEAT_CMD = '/usr/sbin/service pt-heartbeat-{port} {action}'
ZK_CACHE = [MYSQL_DS_ZK, MYSQL_DR_ZK, MYSQL_GEN_ZK]

log = setup_logging_defaults(__name__)


def take_flock_lock(file_name):
    """ Take a flock for throw an exception

    Args:
    file_name - The name of the file to flock

    Returns:
    file_handle - This will be passed to release_flock_lock for relase
    """
    success = False
    try:
        with timeout(1):
            file_handle = open(file_name, 'w')
            fcntl.flock(file_handle.fileno(), fcntl.LOCK_EX)
            log.info('Lock taken')
            success = True
    except:
        pass
        # If success has not been set we will raise an exception just below

    if not success:
        raise Exception('Could not attain lock '
                        'on {file_name}'.format(file_name=file_name))
    return file_handle


def release_flock_lock(file_handle):
    """ Release a lock created by take_flock_lock

    Args:
    file_handle - The return from take_flock_lock()
    """
    fcntl.flock(file_handle.fileno(), fcntl.LOCK_UN)


def find_root_volume():
    """ Figure out what top-level mount/directory we are installing to.
        Whichever one is a mount point is the valid one.  We take the
        first one that we find; /raid0 will eventually be going away
        in favor of /mnt with masterless puppet anyway.
    """
    root_volume = None
    for mount_point in ACCEPTABLE_ROOT_VOLUMES:
        if os.path.ismount(mount_point):
            root_volume = mount_point
            break

    if get_pinfo_cloud() == TESTING_PINFO_CLOUD:
        return TESTING_DATA_DIR

    if not root_volume:
        raise Exception("No acceptable root volume mount point was found.")
    else:
        return root_volume


def get_user():
    """ Return the username of the caller, or unknown if we can't
        figure it out (should never happen)
    """
    try:
        username = getpass.getuser()
    except:
        log.warning("Can't determine caller's username. Setting to unknown.")
        username = 'unknown'

    return username


def stop_mysql(port):
    """ Stop a MySQL instance

    Args:
    pid_file - A file with the pid of the MySQL instance
    """
    pid_file = get_cnf_setting('pid_file', port)
    log_error = get_cnf_setting('log_error', port)
    proc_pid = None
    if os.path.exists(pid_file):
        with open(pid_file) as f:
            pid = f.read().strip()
        proc_pid = os.path.join('/proc/', pid)

    if not proc_pid or not os.path.exists(proc_pid):
        log.info('It appears MySQL is not runnng, sending a kill anyways')
        proc_pid = None

    if os.path.isfile(log_error):
        st_results = os.stat(log_error)
        error_start = st_results[6]
    else:
        error_start = 0

    # send the kill
    if get_hiera_role() in MASTERFUL_PUPPET_ROLES:
        cmd = SUPERVISOR_CMD.format(action='stop', port=port)
    else:
        cmd = INIT_CMD.format(action='stop', port=port, options='')
    log.info(cmd)
    shell_exec(cmd)

    if proc_pid:
        ret = tail_mysql_log_for_start_stop(log_error, error_start)
        if ret != MYSQL_STOPPED:
            raise Exception('It appears MySQL shutdown rather than started up')
    else:
        log.info('Sleeping 10 seconds just to be safe')
        time.sleep(10)


def start_mysql(port, options=''):
    """ Start a MySQL instance

    Args:
    instance - A hostaddr object for the instance to be started
    """
    log_error = get_cnf_setting('log_error', port)
    # If MySQL has never been started, this file will not exist
    if os.path.isfile(log_error):
        st_results = os.stat(log_error)
        error_start = st_results[6]
    else:
        error_start = 0

    if get_hiera_role() in MASTERFUL_PUPPET_ROLES:
        cmd = SUPERVISOR_CMD.format(action='start', port=port)
    else:
        cmd = INIT_CMD.format(action='start', port=port, options=options)
    log.info(cmd)
    shell_exec(cmd)
    log.info('Waiting for MySQL on port {port} to start, '
             'tailing error log {log_error}'.format(
                 port=port, log_error=log_error))
    ret = tail_mysql_log_for_start_stop(log_error, error_start)
    if ret != MYSQL_STARTED:
        raise Exception('It appears MySQL shutdown rather than started up')


def tail_mysql_log_for_start_stop(log_error, start_pos=0):
    """ Tail a MySQL error log watching for a start or stop

    Args:
    log_error - The MySQL error log to tail watching for a start or stop
    start_pos - The position to start tailing the error log

    Returns:
    an int - if MySQL has started 0, if MySQL has ended 1
    """
    log.info('Tailing MySQL error log {log_error} starting from position '
             '{start_pos}'.format(
                 log_error=log_error, start_pos=start_pos))
    start = time.time()
    err = None
    while True:
        if (time.time() - start) > MYSQL_MAX_WAIT:
            log.error('Waited too long, giving up')
            raise Exception('MySQL did change state after {wait} seconds'
                            ''.format(wait=MYSQL_MAX_WAIT))

        if not err and os.path.isfile(log_error):
            err = open(log_error)
            err.seek(start_pos)

        if err:
            while True:
                line = err.readline()
                if line:
                    log.info(line.strip())
                    if 'ready for connections' in line:
                        log.info('MySQL is UP :)')
                        return MYSQL_STARTED
                    if 'mysqld: Shutdown complete' in line:
                        log.info('MySQL is DOWN :(')
                        return MYSQL_STOPPED
                    if 'A mysqld process already exists' in line:
                        raise Exception('Something attempted to start MySQL '
                                        ' while it was already up')
                else:
                    # break out of the inner while True, sleep for a bit...
                    break
        time.sleep(.5)


def restart_pt_daemons(port):
    """ Restart various daemons after a (re)start of MySQL

    Args:
    port - the of the mysql instance on localhost to act on
    """
    log.info('Restarting pt-heartbeat')
    cmd = PTHEARTBEAT_CMD.format(port=port, action='restart')
    log.info(cmd)
    (std_out, std_err, return_code) = shell_exec(cmd)
    log.info(std_out.rstrip())

    log.info('Restart pt-kill')
    cmd = PTKILL_CMD.format(port=port, action='restart')
    log.info(cmd)
    (std_out, std_err, return_code) = shell_exec(cmd)
    log.info(std_out.rstrip())


def upgrade_auth_tables(port):
    """ Run mysql_upgrade

    Args:
    port - the port of the instance on localhost to act on
    """
    start_mysql(
        port, DEFAULTS_FILE_ARG.format(defaults_file=MYSQL_UPGRADE_CNF_FILE))
    socket = get_cnf_setting('socket', port)
    username, password = get_mysql_user_for_role('admin')
    cmd = ''.join((MYSQL_UPGRADE, ' ', '--upgrade-system-tables ', '-S ',
                   socket, ' ', '-u ', username, ' ', '-p', password))
    log.info(cmd)
    (std_out, std_err, return_code) = shell_exec(cmd)
    log.info(std_out)
    if return_code != 0:
        log.warning(std_err)
        raise Exception('MySQL Upgrade failed with return code '
                        'of: {ret}'.format(ret=return_code))
    stop_mysql(port)


class MysqlZookeeper:
    """Class for reading MySQL settings stored on the filesystem"""

    def get_ds_mysql_config(self):
        """ Query for Data Services MySQL shard mappings.

        Returns:
        A dict of all Data Services MySQL replication configuration.

        Example:
        {u'db00001': {u'db': None,
                  u'master': {u'host': u'sharddb001h',
                              u'port': 3306},
                  u'passwd': u'redacted',
                  u'slave': {u'host': u'sharddb001i',
                              u'port': 3306},
                  u'user': u'pbuser'},
        ...
        """
        with open(MYSQL_DS_ZK) as f:
            ds = json.loads(f.read())

        return ds

    def get_gen_mysql_config(self):
        """ Query for non-Data Services MySQL shard mappings.

        Returns:
        A dict of all non-Data Services MySQL replication configuration.

        Example:
        {u'abexperimentsdb001': {u'db': u'abexperimentsdb',
                                 u'master': {u'host': u'abexperimentsdb001a',
                                             u'port': 3306},
                                u'passwd': u'redacted',
                                u'slave': {u'host': u'abexperimentsdb001b',
                                           u'port': 3306},
                                u'user': u'redacted'},
        ...
        """
        with open(MYSQL_GEN_ZK) as f:
            gen = json.loads(f.read())

        return gen

    def get_dr_mysql_config(self):
        """ Query for disaster recovery MySQL shard mappings.

        Returns:
        A dict of all MySQL disaster recovery instances.

        Example:
        {u'db00018': {u'dr_slave': {u'host': u'sharddb018h', u'port': 3306}},
         u'db00015': {u'dr_slave': {u'host': u'sharddb015g', u'port': 3306}},
        ...
        """
        with open(MYSQL_DR_ZK) as f:
            dr = json.loads(f.read())

        return dr

    def get_all_mysql_config(self):
        """ Get all MySQL shard mappings.

        Returns:
        A dict of all MySQL replication configuration.

        Example:
        {u'db00001': {u'db': None,
                  u'master': {u'host': u'sharddb001h',
                              u'port': 3306},
                  u'passwd': u'redacted',
                  u'slave': {u'host': u'sharddb001i',
                              u'port': 3306},
                  u'dr_slave': {u'host': u'sharddb001j',
                              u'port': 3306},
                  u'user': u'pbuser'},
         u'abexperimentsdb001': {u'db': u'abexperimentsdb',
                                 u'master': {u'host': u'abexperimentsdb001a',
                                             u'port': 3306},
                                u'passwd': u'redacted',
                                u'slave': {u'host': u'abexperimentsdb001b',
                                           u'port': 3306},
                                u'user': u'redacted'},
        ...
        """
        mapping_dict = self.get_gen_mysql_config()
        mapping_dict.update(self.get_ds_mysql_config())

        dr = self.get_dr_mysql_config()
        for key in dr:
            mapping_dict[key][REPLICA_ROLE_DR_SLAVE] = \
                dr[key][REPLICA_ROLE_DR_SLAVE]

        return mapping_dict

    def get_all_mysql_replica_sets(self):
        """ Get a list of all MySQL replica sets

        Returns:
        A set of all replica sets
        """
        return set(self.get_all_mysql_config().keys())

    def get_all_mysql_instances_by_type(self, repl_type):
        """ Query for all MySQL dr_slaves

        Args:
        repl_type - A replica type, valid options are entries in REPLICA_TYPES

        Returns:
        A list of all MySQL instances of the type repl_type

        Example:
        set([u'sharddb017g:3306',
             u'sharddb014d:3306',
             u'sharddb004h:3306',
        """

        if repl_type not in REPLICA_TYPES:
            raise Exception('Invalid repl_type {repl_type}. Valid options are'
                            '{REPLICA_TYPES}'.format(
                                repl_type=repl_type,
                                REPLICA_TYPES=REPLICA_TYPES))
        hosts = set()
        for replica_set in self.get_all_mysql_config().iteritems():
            if repl_type in replica_set[1]:
                host = replica_set[1][repl_type]
                hostaddr = HostAddr(':'.join((host['host'], str(host['port'])
                                              )))
                hosts.add(hostaddr)

        return hosts

    def get_all_mysql_instances(self):
        """ Query ZooKeeper for all MySQL instances

        Returns:
        A list of all MySQL instances.

        Example:
        set([u'sharddb017g:3306',
             u'sharddb017h:3306',
             u'sharddb004h:3306',
        """

        hosts = set()
        config = self.get_all_mysql_config()
        for replica_set in config:
            for rtype in REPLICA_TYPES:
                if rtype in config[replica_set]:
                    host = config[replica_set][rtype]
                    hostaddr = HostAddr(''.join((host['host'], ':', str(host[
                        'port']))))
                    hosts.add(hostaddr)

        return hosts

    def get_mysql_instance_from_replica_set(self,
                                            replica_set,
                                            repl_type=REPLICA_ROLE_MASTER):
        """ Get an instance for a mysql replica set by replica type

        Args:
        replica_set - string name of a replica set, ie db00666
        repl_type - Optional, a replica type with valid options are entries
                    in REPLICA_TYPES. Default is 'master'.

        Returns:
        A hostaddr object or None
        """
        if repl_type not in REPLICA_TYPES:
            raise Exception('Invalid repl_type {repl_type}. Valid options are'
                            '{REPLICA_TYPES}'.format(
                                repl_type=repl_type,
                                REPLICA_TYPES=REPLICA_TYPES))

        all_config = self.get_all_mysql_config()
        if replica_set not in all_config:
            raise Exception('Unknown replica set '
                            '{replica_set}'.format(replica_set=replica_set))

        if repl_type not in all_config[replica_set]:
            return None

        instance = all_config[replica_set][repl_type]
        hostaddr = HostAddr(':'.join((instance['host'], str(instance['port'])
                                      )))
        return hostaddr

    def get_replica_set_from_instance(self, instance, rtypes=REPLICA_TYPES):
        """ Get the replica set based on zk info

        Args:
        instance - a hostaddr object
        rtypes - a list of replica types to check, default is REPLICA_TYPES

        Returns:
        (replica_set, replica_type)
        replica_set - A replica set which the instance is part
        replica_type - The role of the instance in the replica_set
        """
        config = self.get_all_mysql_config()
        for replica_set in config:
            for rtype in rtypes:
                if rtype in config[replica_set]:
                    if (instance.hostname == config[replica_set][rtype]['host']
                            and instance.port ==
                            config[replica_set][rtype]['port']):
                        return (replica_set, rtype)
        raise Exception('{instance} is not in zk for replication '
                        'role(s): {rtypes}'.format(
                            instance=instance, rtypes=rtypes))

    def get_host_shard_map(self, repl_type=REPLICA_ROLE_MASTER):
        """ Get a mapping of what shards exist on MySQL master servers

        Args:
        repl_type: optionally specify a replica type

        Returns:
        A dict with a key of the MySQL master instance and the value a set
        of shards
        """
        global_shard_map = dict()
        for sharded_db in SHARDED_DBS_PREFIX_MAP.values():
            shard_map = self.compute_shard_map(sharded_db['mappings'],
                                               sharded_db['prefix'],
                                               sharded_db['zpad'])
            for entry in shard_map:
                if entry in global_shard_map:
                    global_shard_map[entry].update(shard_map[entry])
                else:
                    global_shard_map[entry] = shard_map[entry]

        host_shard_map = dict()
        for replica_set in global_shard_map:
            instance = self.get_mysql_instance_from_replica_set(replica_set,
                                                                repl_type)
            host_shard_map[instance.__str__()] = global_shard_map[replica_set]

        return host_shard_map

    def compute_shard_map(self, mapping, prefix, zpad):
        """ Get mapping of shards to replica_sets

        Args:
        mapping - A list of dicts representing shard ranges mapping to
                  a replica set. Example:
                  {'range':(    0,   63), 'host':'db00001'}
        preface - The preface of the db name. Formula for dbname is
                  preface + z padded shard number
        zpad - The amount of z padding to use

        Returns:
        A dict with a key of the replica set name and the value being
        a set of strings which are shard names
        """
        shard_mapping = dict()
        # Note there may be multiple ranges for each replica set
        for replica_set in mapping:
            for shard_num in range(replica_set['range'][0],
                                   replica_set['range'][1] + 1):
                shard_name = ''.join((prefix, str(shard_num).zfill(zpad)))
                # Note: host in this context means replica set name
                if replica_set['host'] not in shard_mapping:
                    shard_mapping[replica_set['host']] = set()
                shard_mapping[replica_set['host']].add(shard_name)

        return shard_mapping

    def shard_to_instance(self, shard, repl_type=REPLICA_ROLE_MASTER):
        """ Convert a shard to  hostname

        Args:
        shard - A shard name
        repl_type - Replica type, master is default

        Returns:
        A hostaddr object for an instance of the replica set
        """
        shard_map = self.get_host_shard_map(repl_type)
        for instance in shard_map:
            if shard in shard_map[instance]:
                return HostAddr(instance)

        raise Exception(
            'Could not determine shard replica set for shard {shard}'.format(
                shard=shard))

    def get_shards_by_shard_type(self, shard_type):
        """ Get a set of all shards in a shard type

        Args:
        shard_type - The type of shards, i.e. 'sharddb'

        Returns:
        A set of all shard names
        """
        sharding_info = SHARDED_DBS_PREFIX_MAP[shard_type]
        shards = set()
        for replica_set in sharding_info['mappings']:
            for shard_num in range(replica_set['range'][0],
                                   replica_set['range'][1] + 1):
                shards.add(''.join((sharding_info['prefix'], str(shard_num)
                                    .zfill(sharding_info['zpad']))))
        return shards


class HostAddr:
    """Basic abtraction for hostnames"""

    def __init__(self, host):
        """
        Args:
        host - A hostname. We have two fully supported formats:
               {replicaType}-{replicaSetNum}-{hostNum} - new style
               {replicaType}{replicaSetNum}{hostLetter} - old style
        """
        self.replica_type = None
        self.replica_set_num = None
        self.host_identifier = None

        host_params = re.split(':', host)
        self.hostname = re.split('\.', host_params[0])[0]
        if len(host_params) > 1:
            self.port = int(host_params[1])
        else:
            self.port = 3306

        # New style hostnames are of the form replicaType-replicaSetNum-hostNum
        # ie: sharddb-1-1
        try:
            (self.replica_type, self.replica_set_num,
             self.host_identifier) = self.hostname.split('-')
        except ValueError:
            # Maybe a old sytle hostname
            # form is replicaTypereplicaSetNumhostLetter
            # ie: sharddb001a
            replica_set_match = re.match('([a-zA-z]+)0+([0-9]+)([a-z])',
                                         self.hostname)
            if replica_set_match:
                try:
                    (self.replica_type, self.replica_set_num, self.host_identifier) \
                        = replica_set_match.groups()
                except ValueError:
                    # Not an old style hostname either, weird.
                    pass
            else:
                replica_set_match = re.match(
                    '([a-zA-z0-9]+db)0+([0-9]+)([a-z])', self.hostname)
                try:
                    (self.replica_type, self.replica_set_num, self.host_identifier) \
                        = replica_set_match.groups()
                    self.replica_type = ''.join((self.replica_type, 'db'))
                except:
                    pass

    def get_standardized_replica_set(self):
        """ Return an easily parsible replica set name

        Returns:
        A replica set name which is hyphen seperated with the first part
        being the replica set type (ie sharddb), followed by a the replica
        set identifier. If this is not availible, return None.
        """
        if self.replica_type and self.replica_set_num:
            return '-'.join((self.replica_type, self.replica_set_num))
        else:
            return None

    def get_zk_replica_set(self):
        """ Determine what replica set a host would belong to

        Returns:
        A replica set name
        """
        zk = MysqlZookeeper()
        for master in zk.get_all_mysql_instances_by_type(REPLICA_ROLE_MASTER):
            if self.get_standardized_replica_set(
            ) == master.get_standardized_replica_set():
                return zk.get_replica_set_from_instance(master)

    def __str__(self):
        """
        Returns
        a  human readible string version of object similar to
        'shardb123a:3309'
        """
        return ''.join((self.hostname, ':', str(self.port)))

    def __repr__(self):
        return str(self)

    def __eq__(self, other):
        if (self.hostname == other.hostname and self.port == other.port):
            return 1
        else:
            return 0

    def __ne__(self, other):
        if (self.hostname != other.hostname or self.port != other.port):
            return 1
        else:
            return 0

    def __hash__(self):
        return hash(''.join((self.hostname, ':', str(self.port))))


def shell_exec(cmd):
    """ Run a shell command

    Args:
    cmd - String to execute via a shell. DO NOT use this if the stdout or stderr
          will be very large (more than 100K bytes or so)

    Returns:
    std_out - Standard out results from the execution of the command
    std_err - Standard error results from the execution of the command
    return_code - Return code from the execution of the command
    """
    proc = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc.wait()
    std_out = proc.stdout.read()
    std_err = proc.stderr.read()
    return_code = proc.returncode

    return (std_out, std_err, return_code)


def get_cnf_setting(variable, port):
    """ Get the value of a variab from a mysql cnf

    Args:
    variable - a MySQL variable located in configuration file
    port - Which instance of mysql, ie 3306.

    Returns:
    The value of the variable in the configuration file
    """
    if get_hiera_role() in MASTERFUL_PUPPET_ROLES:
        cnf = OLD_CONF_ROOT.format(port=str(port))
        group = 'mysqld'
    else:
        cnf = MYSQL_CNF_FILE
        group = 'mysqld{port}'.format(port=port)
    parser = ConfigParser.RawConfigParser(allow_no_value=True)
    if not os.path.exists(cnf):
        raise Exception("MySQL conf {cnf} does not exist".format(cnf=cnf))
    parser.read(cnf)

    try:
        value = parser.get(group, variable)
    except ConfigParser.NoOptionError:
        if '_' in variable:
            variable = variable.replace('_', '-')
            value = parser.get(group, variable)
        else:
            raise
    return value


def change_owner(directory, user, group):
    """ Chown a directory

    Args:
    directory - A string of the directored to be chown -R
    user - The string of the username of a user
    group - The string of the groupname of a group

    """
    path = os.path.realpath(directory)
    cmd = '/bin/chown -R {user}:{group} {path}'.format(
        user=user, group=group, path=path)
    log.debug(cmd)
    (out, err, ret) = shell_exec(cmd)
    if ret != 0:
        print err
        raise Exception("Error chown'ing directory:{err}".format(err=err))


def change_perms(directory, numeric_perms):
    """ Chmod a directory

    Aruments:
    directory - The directory to be chmod -R'ed
    numeric_perms - The numeric permissions desired
    """
    path = os.path.realpath(directory)
    cmd = '/bin/chmod -R {perms} {path}'.format(
        perms=str(numeric_perms), path=path)
    log.debug(cmd)
    (out, err, ret) = shell_exec(cmd)
    if ret != 0:
        print err
        raise Exception("Error chown'ing directory:{err}".format(err=err))


def clean_directory(directory):
    """ Remove all contents of a directory

    Args:
    directory - The directored to be emptied
    """
    for entry in os.listdir(directory):
        path = os.path.join(directory, entry)
        if os.path.isfile(path):
            os.unlink(path)
        if os.path.isdir(path):
            shutil.rmtree(path)


def get_local_instance_id():
    """ Get the aws instance_id

    Returns:
    A string with the aws instance_id or None
    """
    (out, err, ret) = shell_exec('ec2metadata --instance-id')
    if out.strip():
        return out.strip()
    else:
        return None


def get_hiera_role():
    """ Pull the hiera role for the localhost

    Returns:
    A string with the hiera role
    """
    if not os.path.exists(HIERA_ROLE_FILE):
        return DEFAULT_HIERA_ROLE

    with open(HIERA_ROLE_FILE) as f:
        return f.read().strip()


def get_pinfo_cloud():
    """ Get the value of the variable of pinfo_cloud from facter

    Returns pinfo_cloud
    """
    (std_out, std_err, return_code) = shell_exec('facter pinfo_cloud')

    if not std_out:
        return DEFAULT_PINFO_CLOUD

    return std_out.strip()


def get_instance_type():
    """ Get the name of the hardware type in use

    Returns:
    A string describing the hardware of the server
    """

    (std_out, std_err, return_code) = shell_exec('facter ec2_instance_type')

    if not std_out:
        raise Exception('Could not determine hardware, error:'
                        '{std_err}'.format(std_err=std_err))

    return std_out.strip()


def get_mysql_connection(replica_set_name,
                         writeable=False,
                         user_role=None,
                         replica_set_role=None):
    """ Get MySQL connection information. This code also exists in
    the wiki and is copied numberous places across the pinterest code base.

    Args:
    replica_set_name - The name of a replica set in zk, ie db00047
                       or blackopsdb001.
    writeable - If the connection should be writeable.
    user_role - A named user role to pull. If this is supplied, writeable
                is not respected.
    replica_set_role - Default role is master, can also be slave or dr_slave.
                       If this is supplied, writeable is not respected.

    Returns:
    hostname - (str) The master host of the named replica set
    port - The port of the named replica set. Please do not assume 3306.
    username - The MySQL username to be used.
    password - The password that corrosponds to the username
    """
    hostname = None
    port = None
    password = None
    username = None

    if user_role is None:
        if (replica_set_role == MASTER or writeable is True):
            user_role = 'scriptrw'
        else:
            user_role = 'scriptro'

    if replica_set_role is None:
        replica_set_role = MASTER

    with open(MYSQL_DS_ZK) as f:
        ds = json.loads(f.read())

    for entry in ds.iteritems():
        if replica_set_name == entry[0]:
            hostname = entry[1][replica_set_role]['host']
            port = entry[1][replica_set_role]['port']

    if hostname is None or port is None:
        with open(MYSQL_GEN_ZK) as f:
            gen = json.loads(f.read())

        for entry in gen.iteritems():
            if replica_set_name == entry[0]:
                hostname = entry[1][replica_set_role]['host']
                port = entry[1][replica_set_role]['port']

    if hostname is None or port is None:
        err = ("Replica set '{rs}' does not exist in zk"
               ''.format(rs=replica_set_name))
        raise NameError(err)

    with open(AUTH_FILE) as f:
        grants = json.loads(f.read())

    for entry in grants.iteritems():
        if user_role == entry[0]:
            for user in entry[1]['users']:
                if user['enabled'] is True:
                    username = user['username']
                    password = user['password']

    if username is None or password is None:
        err = ("Userrole '{role}' does not exist in zk"
               ''.format(role=user_role))
        raise NameError(err)
    return hostname, port, username, password


log = setup_logging_defaults(__name__)


def parse_xtrabackup_slave_info(datadir):
    """ Pull master_log and master_log_pos from a xtrabackup_slave_info file
    NOTE: This file has its data as a CHANGE MASTER command. Example:
    CHANGE MASTER TO MASTER_LOG_FILE='mysql-bin.006233', MASTER_LOG_POS=863

    Args:
    datadir - the path to the restored datadir

    Returns:
    binlog_file - Binlog file to start reading from
    binlog_pos - Position in binlog_file to start reading
    """
    file_path = os.path.join(datadir, 'xtrabackup_slave_info')
    with open(file_path) as f:
        data = f.read()

    file_pattern = ".*MASTER_LOG_FILE='([a-z0-9-.]+)'.*"
    pos_pattern = ".*MASTER_LOG_POS=([0-9]+).*"
    res = re.match(file_pattern, data)
    binlog_file = res.group(1)
    res = re.match(pos_pattern, data)
    binlog_pos = int(res.group(1))

    log.info('Master info: binlog_file: {binlog_file},'
             ' binlog_pos: {binlog_pos}'.format(
                 binlog_file=binlog_file, binlog_pos=binlog_pos))
    return (binlog_file, binlog_pos)


def parse_xtrabackup_binlog_info(datadir):
    """ Pull master_log and master_log_pos from a xtrabackup_slave_info file
    Note: This file stores its data as two strings in a file
          deliminted by a tab. Example: "mysql-bin.006231\t1619"

    Args:
    datadir - the path to the restored datadir

    Returns:
    binlog_file - Binlog file to start reading from
    binlog_pos - Position in binlog_file to start reading
    """
    file_path = os.path.join(datadir, 'xtrabackup_binlog_info')
    with open(file_path) as f:
        data = f.read()

    fields = data.strip().split("\t")
    if len(fields) != 2:
        raise Exception(('Error: Invalid format in '
                         'file {file_path}').format(file_path=file_path))
    binlog_file = fields[0].strip()
    binlog_pos = int(fields[1].strip())

    log.info('Master info: binlog_file: {binlog_file},'
             ' binlog_pos: {binlog_pos}'.format(
                 binlog_file=binlog_file, binlog_pos=binlog_pos))
    return (binlog_file, binlog_pos)


def get_metadata_from_backup_file(full_path):
    """ Parse the filename of a backup to determine the source of a backup

    Note: there is a strong assumption that the port number matches 330[0-9]

    Args:
    full_path - Path to a backup file.
                Example: /backup/tmp/mysql-legaldb001c-3306-2014-06-06.xbstream
                Example: /backup/tmp/mysql-legaldb-1-1-3306-2014-06-06.xbstream

    Returns:
    host - A hostaddr object
    creation - a datetime object describing creation date
    extension - file extension
    """
    filename = os.path.basename(full_path)
    pattern = 'mysql-([a-z0-9-]+)-(330[0-9])-(\d{4})-(\d{2})-(\d{2}).*\.(.+)'
    res = re.match(pattern, filename)
    host = HostAddr(':'.join((res.group(1), res.group(2))))
    creation = datetime.date(
        int(res.group(3)), int(res.group(4)), int(res.group(5)))
    extension = res.group(6)
    return host, creation, extension


def logical_backup_instance(instance, timestamp):
    """ Take a compressed mysqldump backup

    Args:
    instance - A hostaddr instance
    timestamp - A timestamp which will be used to create the backup filename

    Returns:
    A string of the path to the finished backup
    """
    dump_file = BACKUP_FILE.format(
        hostname=instance.hostname,
        port=instance.port,
        timestamp=time.strftime('%Y-%m-%d-%H:%M:%S', timestamp),
        backup_type=BACKUP_TYPE_LOGICAL)
    (dump_user, dump_pass) = get_mysql_user_for_role(USER_ROLE_MYSQLDUMP)
    dump_cmd = MYSQLDUMP_CMD.format(
        dump_user=dump_user,
        dump_pass=dump_pass,
        host=instance.hostname,
        port=instance.port)
    procs = dict()
    try:
        procs['mysqldump'] = subprocess.Popen(
            dump_cmd.split(), stdout=subprocess.PIPE)
        procs['pigz'] = subprocess.Popen(
            PIGZ, stdin=procs['mysqldump'].stdout, stdout=subprocess.PIPE)
        log.info('Uploading backup to {buk}/{key}'
                 ''.format(
                     buk=S3_BUCKET, key=dump_file))
        safe_upload(
            precursor_procs=procs,
            stdin=procs['pigz'].stdout,
            bucket=S3_BUCKET,
            key=dump_file)
        log.info('mysqldump was successful')
    except:
        kill_precursor_procs(procs)
        raise


def xtrabackup_instance(instance, timestamp):
    """ Take a compressed mysql backup

    Args:
    instance - A hostaddr instance
    timestamp - A timestamp which will be used to create the backup filename

    Returns:
    A string of the path to the finished backup
    """
    # Prevent issues with too many open files
    resource.setrlimit(resource.RLIMIT_NOFILE, (131072, 131072))
    backup_file = BACKUP_FILE.format(
        hostname=instance.hostname,
        port=instance.port,
        timestamp=time.strftime('%Y-%m-%d-%H:%M:%S', timestamp),
        backup_type=BACKUP_TYPE_XBSTREAM)

    tmp_log = os.path.join(
        RAID_MOUNT,
        'log',
        'xtrabackup_{ts}.log'.format(
            ts=time.strftime('%Y-%m-%d-%H:%M:%S', timestamp)))
    tmp_log_handle = open(tmp_log, "w")
    procs = dict()
    try:
        procs['xtrabackup'] = subprocess.Popen(
            create_xtrabackup_command(instance, timestamp, tmp_log),
            stdout=subprocess.PIPE,
            stderr=tmp_log_handle)
        log.info('Uploading backup to {buk}/{loc}'
                 ''.format(
                     buk=S3_BUCKET, loc=backup_file))
        safe_upload(
            precursor_procs=procs,
            stdin=procs['xtrabackup'].stdout,
            bucket=S3_BUCKET,
            key=backup_file,
            check_func=check_xtrabackup_log,
            check_arg=tmp_log)
        log.info('Xtrabackup was successful')
    except:
        kill_precursor_procs(procs)
        raise


def check_xtrabackup_log(tmp_log):
    """ Confirm that a xtrabackup backup did not have problems

    Args:
    tmp_log - The path of the log file
    """
    with open(tmp_log, 'r') as log_file:
        xtra_log = log_file.readlines()
        if INNOBACKUP_OK not in xtra_log[-1]:
            raise Exception('innobackupex failed. '
                            'log_file: {tmp_log}'.format(tmp_log=tmp_log))


def create_xtrabackup_command(instance, timestamp, tmp_log):
    """ Create a xtrabackup command

    Args:
    instance - A hostAddr object
    timestamp - A timestamp
    tmp_log - A path to where xtrabackup should log

    Returns:
    a list that can be easily ingested by subprocess
    """
    if get_hiera_role() in MASTERFUL_PUPPET_ROLES:
        cnf = OLD_CONF_ROOT.format(port=instance.port)
        cnf_group = 'mysqld'
    else:
        cnf = MYSQL_CNF_FILE
        cnf_group = 'mysqld{port}'.format(port=instance.port)
    datadir = get_cnf_setting('datadir', instance.port)
    (xtra_user, xtra_pass) = get_mysql_user_for_role(USER_ROLE_XTRABACKUP)
    return XTRABACKUP_CMD.format(
        datadir=datadir,
        xtra_user=xtra_user,
        xtra_pass=xtra_pass,
        cnf=cnf,
        cnf_group=cnf_group,
        port=instance.port,
        tmp_log=tmp_log).split()


def xbstream_unpack(xbstream, port, restore_source, size=None):
    """ Decompress an xbstream filename into a directory.

    Args:
    xbstream - A string which is the path to the xbstream file
    port - The port on which to act on on localhost
    host - A string which is a hostname if the xbstream exists on a remote host
    size - An int for the size in bytes for remote unpacks for a progress bar
    """
    datadir = get_cnf_setting('datadir', port)

    cmd = ('{s3_script} get --no-md5 -b {bucket} -k {xbstream} '
           '2>/dev/null ').format(
               s3_script=S3_SCRIPT,
               bucket=S3_BUCKET,
               xbstream=urllib.quote_plus(xbstream))
    if size:
        cmd = ' | '.join((cmd, '{pv} -s {size}'.format(pv=PV, size=str(size))))
    # And finally pipe everything into xbstream to unpack it
    cmd = ' | '.join((cmd, '/usr/bin/xbstream -x -C {}'.format(datadir)))
    log.info(cmd)

    extract = subprocess.Popen(cmd, shell=True)
    if extract.wait() != 0:
        raise Exception("Error: Xbstream decompress did not succeed, aborting")


def innobackup_decompress(port, threads=8):
    """ Decompress an unpacked backup compressed with xbstream.

    Args:
    port - The port of the instance on which to act
    threads - A int which signifies how the amount of parallelism. Default is 8
    """
    datadir = get_cnf_setting('datadir', port)

    cmd = ' '.join(('/usr/bin/innobackupex', '--parallel={threads}',
                    '--decompress', datadir)).format(threads=threads)

    err_log = os.path.join(datadir, 'xtrabackup-decompress.err')
    out_log = os.path.join(datadir, 'xtrabackup-decompress.log')

    with open(err_log, 'w+') as err_handle, open(out_log, 'w') as out_handle:
        verbose = '{cmd} 2>{err_log} >{out_log}'.format(
            cmd=cmd, err_log=err_log, out_log=out_log)
        log.info(verbose)
        decompress = subprocess.Popen(
            cmd, shell=True, stdout=out_handle, stderr=err_handle)
        if decompress.wait() != 0:
            raise Exception('Fatal error: innobackupex decompress '
                            'did not return 0')

        err_handle.seek(0)
        log_data = err_handle.readlines()
        if INNOBACKUP_OK not in log_data[-1]:
            msg = ('Fatal error: innobackupex decompress did not end with '
                   '"{}"'.format(INNOBACKUP_OK))
            raise Exception(msg)


def apply_log(port, memory='10G'):
    """ Apply redo logs for an unpacked and uncompressed instance

    Args:
    path - The port of the instance on which to act
    memory - A string of how much memory can be used to apply logs. Default 10G
    """
    datadir = get_cnf_setting('datadir', port)
    cmd = ' '.join(('/usr/bin/innobackupex', '--apply-log',
                    '--use-memory={memory}', datadir)).format(memory=memory)

    log_file = os.path.join(datadir, 'xtrabackup-apply-logs.log')
    with open(log_file, 'w+') as log_handle:
        verbose = '{cmd} >{log_file}'.format(cmd=cmd, log_file=log_file)
        log.info(verbose)
        apply_logs = subprocess.Popen(cmd, shell=True, stderr=log_handle)
        if apply_logs.wait() != 0:
            raise Exception('Fatal error: innobackupex apply-logs did not '
                            'return return 0')

        log_handle.seek(0)
        log_data = log_handle.readlines()
        if INNOBACKUP_OK not in log_data[-1]:
            msg = ('Fatal error: innobackupex apply-log did not end with '
                   '"{}"'.format(INNOBACKUP_OK))
            raise Exception(msg)


def get_s3_backup(hostaddr, date=None, backup_type=BACKUP_TYPE_XBSTREAM):
    """ Find the most recent xbstream file for an instance on s3

    Args:
    hostaddr - A hostaddr object for the desired instance
    date - Desired date of restore file

    Returns:
    filename - The path to the most recent backup file
    """
    prefix = 'mysql-{host}-{port}'.format(
        host=hostaddr.hostname, port=hostaddr.port)
    if date:
        prefix = ''.join((prefix, '-', date))
    log.debug('looking for backup with prefix {prefix}'.format(prefix=prefix))
    conn = boto.connect_s3()
    bucket = conn.get_bucket(S3_BUCKET, validate=False)
    bucket_items = bucket.list(prefix=prefix)

    latest_backup = None
    for elem in bucket_items:
        if elem.name.endswith(backup_type):
            # xbstream files need to be larger than
            # MINIMUM_VALID_BACKUP_SIZE_BYTES
            if (backup_type != BACKUP_TYPE_XBSTREAM) or\
               (elem.size > MINIMUM_VALID_BACKUP_SIZE_BYTES):
                latest_backup = elem
    if not latest_backup:
        msg = ('Unable to find a valid backup for '
               '{instance}').format(instance=hostaddr)
        raise Exception(msg)
    log.debug('Found a s3 backup {s3_path} with a size of '
              '{size}'.format(
                  s3_path=latest_backup.name, size=latest_backup.size))
    return (latest_backup.name, latest_backup.size)


def restore_logical(s3_key, size):
    """ Restore a compressed mysqldump file from s3 to localhost, port 3306

    Args:
    s3_key - A string which is the path to the compressed dump
    port - The port on which to act on on localhost
    size - An int for the size in bytes for remote unpacks for a progress bar
    """
    cmd = ('{s3_script} get --no-md5 -b {bucket} -k {s3_key} 2>/dev/null'
           '| {pv} -s {size}'
           '| zcat '
           '| mysql ').format(
               s3_script=S3_SCRIPT,
               bucket=S3_BUCKET,
               s3_key=urllib.quote_plus(s3_key),
               pv=PV,
               size=size)
    log.info(cmd)
    import_proc = subprocess.Popen(cmd, shell=True)
    if import_proc.wait() != 0:
        raise Exception("Error: Import failed")


def start_restore_log(instance, params):
    """ Create a record in xb_restore_status at the start of a restore
    """
    try:
        conn = connect_mysql(instance)
    except Exception as e:
        log.warning("Unable to connect to master to log "
                    "our progress: {e}.  Attempting to "
                    "continue with restore anyway.".format(e=e))
        return None

    if not does_table_exist(instance, 'test', 'xb_restore_status'):
        create_status_table(conn)
    sql = ("REPLACE INTO test.xb_restore_status "
           "SET "
           "restore_source = %(restore_source)s, "
           "restore_type = 's3', "
           "restore_file = %(restore_file)s, "
           "restore_destination = %(source_instance)s, "
           "restore_date = %(restore_date)s, "
           "restore_port = %(restore_port)s, "
           "replication = %(replication)s, "
           "zookeeper = %(zookeeper)s, "
           "started_at = NOW()")
    cursor = conn.cursor()
    try:
        cursor.execute(sql, params)
        log.info(cursor._executed)
        row_id = cursor.lastrowid
    except Exception as e:
        log.warning("Unable to log restore_status: {e}".format(e=e))
        row_id = None

    cursor.close()
    conn.commit()
    conn.close()
    return row_id


def update_restore_log(instance, row_id, params):
    try:
        conn = connect_mysql(instance)
    except Exception as e:
        log.warning("Unable to connect to master to log "
                    "our progress: {e}.  Attempting to "
                    "continue with restore anyway.".format(e=e))
        return

    updates_fields = []

    if 'finished_at' in params:
        updates_fields.append('finished_at=NOW()')
    if 'restore_status' in params:
        updates_fields.append('restore_status=%(restore_status)s')
    if 'status_message' in params:
        updates_fields.append('status_message=%(status_message)s')
    if 'replication' in params:
        updates_fields.append('replication=%(replication)s')
    if 'zookeeper' in params:
        updates_fields.append('zookeeper=%(zookeeper)s')
    if 'finished_at' in params:
        updates_fields.append('finished_at=NOW()')

    sql = ("UPDATE test.xb_restore_status SET "
           "{} WHERE id=%(row_id)s".format(', '.join(updates_fields)))
    params['row_id'] = row_id
    cursor = conn.cursor()
    cursor.execute(sql, params)
    log.info(cursor._executed)
    cursor.close()
    conn.commit()
    conn.close()


def get_most_recent_restore(instance):
    conn = connect_mysql(instance)
    cursor = conn.cursor()
    sql = ("SELECT * "
           "FROM test.xb_restore_status "
           "WHERE restore_status='OK' ")
    try:
        cursor.execute(sql)
    except Exception as e:
        print("UNKNOWN: Cannot query restore status table: {e}".format(e=e))
        sys.exit(3)
    return cursor.fetchall()


def create_status_table(conn):
    """ Create the restoration status table if it isn't already there.

        Args:
            conn: A connection to the master server for this replica set.

        Returns:
            nothing
    """
    try:
        cursor = conn.cursor()
        cursor.execute(XB_RESTORE_STATUS)
        cursor.close()
    except Exception as e:
        log.error("Unable to create replication status table "
                  "on master: {e}".format(e=e))
        log.error("We will attempt to continue anyway.")


def quick_test_replication(instance):
    start_replication(instance)
    assert_replication_sanity(instance)


MAX_AGE = 600


def rotate_binlogs_if_needed(port, dry_run):
    instance = HostAddr(':'.join((HOSTNAME, str(port))))
    log_bin_dir = get_cnf_setting('log_bin', port)
    binlog = os.path.join(
        os.path.dirname(log_bin_dir), get_master_status(instance)['File'])
    # We don't update access time, so this is creation time.
    creation = datetime.datetime.fromtimestamp(os.stat(binlog).st_atime)
    age = (datetime.datetime.utcnow() - creation).seconds
    if age > MAX_AGE:
        log.info('Age of current binlog is {age} which is greater than '
                 ' MAX_AGE ({MAX_AGE})'.format(
                     age=age, MAX_AGE=MAX_AGE))
        if not dry_run:
            log.info('Flushing bin log')
            flush_master_log(instance)
    else:
        log.info('Age of current binlog is {age} which is less than '
                 ' MAX_AGE ({MAX_AGE})'.format(
                     age=age, MAX_AGE=MAX_AGE))


BINLOG_ARCHIVING_TABLE = """CREATE TABLE IF NOT EXISTS {db}.{tbl} (
  `hostname` varchar(90) NOT NULL,
  `port` int(11) NOT NULL,
  `binlog` varchar(90) NOT NULL,
  `binlog_creation` datetime NULL,
  `uploaded` datetime NOT NULL,
  PRIMARY KEY (`binlog`),
  INDEX `instance` (`hostname`, `port`),
  INDEX `uploaded` (`uploaded`),
  INDEX `binlog_creation` (`binlog_creation`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1"""
STANDARD_RETENTION_BINLOG_S3_DIR = 'standard_retention'
BINLOG_LOCK_FILE = '/tmp/archive_mysql_binlogs.lock'
BINLOG_INFINITE_REPEATER_TERM_FILE = '/tmp/archive_mysql_binlogs_infinite.die'
MAX_ERRORS = 5
TMP_DIR = '/tmp/'


def archive_mysql_binlogs(port, dry_run):
    """ Flush logs and upload all binary logs that don't exist to s3

    Arguments:
    port - Port of the MySQL instance on which to act
    dry_run - Display output but do not uplad
    """
    rotate_binlogs_if_needed(port, dry_run)
    zk = MysqlZookeeper()
    instance = HostAddr(':'.join((HOSTNAME, str(port))))

    if zk.get_replica_set_from_instance(instance)[0] is None:
        log.info('Instance is not in production, exiting')
        return

    lock_handle = None
    ensure_binlog_archiving_table_sanity(instance)
    try:
        log.info('Taking binlog archiver lock')
        lock_handle = take_flock_lock(BINLOG_LOCK_FILE)
        log_bin_dir = get_cnf_setting('log_bin', port)
        bin_logs = get_master_logs(instance)
        logged_uploads = get_logged_binlog_uploads(instance)
        for binlog in bin_logs[:-1]:
            err_count = 0
            local_file = os.path.join(
                os.path.dirname(log_bin_dir), binlog['Log_name'])
            if already_uploaded(instance, local_file, logged_uploads):
                continue
            success = False
            while not success:
                try:
                    upload_binlog(instance, local_file, dry_run)
                    success = True
                except:
                    if err_count > MAX_ERRORS:
                        log.error('Error count in thread > MAX_THREAD_ERROR. '
                                  'Aborting :(')
                        raise

                    log.error('error: {e}'.format(e=traceback.format_exc()))
                    err_count = err_count + 1
                    time.sleep(err_count * 2)
        log.info('Archiving complete')
    finally:
        if lock_handle:
            log.info('Releasing lock')
            release_flock_lock(lock_handle)


def already_uploaded(instance, binlog, logged_uploads):
    """ Check to see if a binlog has already been uploaded

    Args:
    instance - a hostAddr object
    binlog - the full path to the binlog file
    logged_uploads - a set of all uploaded binlogs for this instance

    Returns True if already uplaoded, False otherwise.
    """
    if os.path.basename(binlog) in logged_uploads:
        log.debug('Binlog already logged as uploaded')
        return True

    # we should hit this code rarely, only when uploads have not been logged
    boto_conn = boto.connect_s3()
    bucket = boto_conn.get_bucket(S3_BINLOG_BUCKET, validate=False)
    if bucket.get_key(s3_binlog_path(instance, os.path.basename((binlog)))):
        log.debug("Binlog already uploaded but not logged {b}".format(
            b=binlog))
        log_binlog_upload(instance, binlog)
        return True

    return False


def upload_binlog(instance, binlog, dry_run):
    """ Upload a binlog file to s3

    Args:
    instance - a hostAddr object
    binlog - the full path to the binlog file
    dry_run - if set, do not actually upload a binlog
    """
    s3_upload_path = s3_binlog_path(instance, binlog)
    log.info('Local file {local_file} will uploaded to {s3_upload_path}'
             ''.format(
                 local_file=binlog, s3_upload_path=s3_upload_path))

    if dry_run:
        log.info('In dry_run mode, skipping compression and upload')
        return

    procs = dict()
    try:
        procs['lzop'] = subprocess.Popen(
            ['lzop', binlog, '--to-stdout'], stdout=subprocess.PIPE)
        safe_upload(
            precursor_procs=procs,
            stdin=procs['lzop'].stdout,
            bucket=S3_BINLOG_BUCKET,
            key=s3_upload_path)
    except:
        log.debug('In exception handling for failed binlog upload')
        kill_precursor_procs(procs)
        raise
    log_binlog_upload(instance, binlog)


def check_upload_procs(procs, term_path):
    """ Watch process and throw exceptions in case of failures

    Args:
    procs - An array of processes
    term_path - Path to touch to kill repater.

    Returns:
    True if all process have finished successfully,
    False if some are still running.
    """
    success = True
    # explicitly order the for loop
    for proc in ['lzop', 'repeater', 'upload']:
        if (proc == 'repeater' and success and not os.path.exists(term_path)):
            log.debug('creating term file {term_path}'
                      ''.format(
                          proc_id=multiprocessing.current_process().name,
                          term_path=term_path))
            open(term_path, 'w').close()

        ret = procs[proc].poll()
        if ret is None:
            success = False
        elif ret != 0:
            raise Exception('{proc} encountered an error' ''.format(proc=proc))

    return success


def log_binlog_upload(instance, binlog):
    """ Log to the master that a binlog has been uploaded

    Args:
    instance - a hostAddr object
    binlog - the full path to the binlog file
    """
    zk = MysqlZookeeper()
    binlog_creation = datetime.datetime.fromtimestamp(os.stat(binlog).st_atime)
    replica_set = zk.get_replica_set_from_instance(instance)[0]
    master = zk.get_mysql_instance_from_replica_set(replica_set)
    conn = connect_mysql(master, 'scriptrw')
    cursor = conn.cursor()
    sql = ("REPLACE INTO {metadata_db}.{tbl} "
           "SET hostname = %(hostname)s, "
           "    port = %(port)s, "
           "    binlog = %(binlog)s, "
           "    binlog_creation = %(binlog_creation)s, "
           "    uploaded = NOW() ").format(
               metadata_db=METADATA_DB, tbl=BINLOG_ARCHIVING_TABLE_NAME)
    metadata = {
        'hostname': instance.hostname,
        'port': str(instance.port),
        'binlog': os.path.basename(binlog),
        'binlog_creation': binlog_creation
    }
    cursor.execute(sql, metadata)
    conn.commit()


def get_logged_binlog_uploads(instance):
    """ Get all binlogs that have been logged as uploaded

    Args:
    instance - a hostAddr object to run against and check

    Returns:
    A set of binlog file names
    """
    conn = connect_mysql(instance, 'scriptro')
    cursor = conn.cursor()
    sql = ("SELECT binlog "
           "FROM {metadata_db}.{tbl} "
           "WHERE hostname = %(hostname)s AND "
           "      port = %(port)s "
           "".format(
               metadata_db=METADATA_DB, tbl=BINLOG_ARCHIVING_TABLE_NAME))
    cursor.execute(
        sql, {'hostname': instance.hostname,
              'port': str(instance.port)})
    ret = set()
    for binlog in cursor.fetchall():
        ret.add(binlog['binlog'])

    return ret


def ensure_binlog_archiving_table_sanity(instance):
    """ Create binlog archiving log table if missing, purge old data

    Args:
    instance - A hostAddr object. Note: this function will find the master of
               the instance if the instance is not a master
    """
    zk = MysqlZookeeper()
    replica_set = zk.get_replica_set_from_instance(instance)[0]
    master = zk.get_mysql_instance_from_replica_set(replica_set)
    conn = connect_mysql(master, 'scriptrw')
    cursor = conn.cursor()
    if not does_table_exist(master, METADATA_DB, BINLOG_ARCHIVING_TABLE_NAME):
        log.debug('Creating missing metadata table')
        cursor.execute(
            BINLOG_ARCHIVING_TABLE.format(
                db=METADATA_DB, tbl=BINLOG_ARCHIVING_TABLE_NAME))
    sql = ("DELETE FROM {metadata_db}.{tbl} "
           "WHERE binlog_creation < now() - INTERVAL {d} DAY"
           "").format(
               metadata_db=METADATA_DB,
               tbl=BINLOG_ARCHIVING_TABLE_NAME,
               d=(S3_BINLOG_RETENTION + 1))
    log.info(sql)
    cursor.execute(sql)
    conn.commit()


def s3_binlog_path(instance, binlog):
    """ Determine the path in s3 for a binlog

    Args:
    instance - A hostAddr instance
    binlog - A binlog filename

    Returns:
    A path in S3 where the file should be stored.
    """
    # At some point in the near future we will probably use reduced
    # retention for pinlater
    return os.path.join(STANDARD_RETENTION_BINLOG_S3_DIR,
                        instance.replica_type, instance.hostname,
                        str(instance.port), ''.join((os.path.basename(binlog),
                                                     '.lzo')))
