from peewee import *
from playhouse.pool import PooledMySQLDatabase
from configs import common_db_config
max_connections = common_db_config.get('max_connections')
if max_connections is not None:
    database = PooledMySQLDatabase('db', **common_db_config)
else:
    database = MySQLDatabase('db', **common_db_config)


class UnknownField(object):
    pass


class BaseModel(Model):
    class Meta:
        database = database


class HostReplacementLog(BaseModel):
    created_at = DateTimeField()
    is_completed = IntegerField(null=True)
    new_az = CharField()
    new_host = CharField()
    new_hw_type = CharField()
    new_instance = CharField(unique=True)
    old_az = CharField()
    old_host = CharField()
    old_hw_type = CharField(null=True)
    old_instance = CharField(primary_key=True)
    reason = CharField(null=True)

    class Meta:
        db_table = 'host_replacement_log'


class MysqlBackups(BaseModel):
    backup_type = CharField(null=True)
    filename = CharField(index=True, null=True)
    finished = DateTimeField(null=True)
    hostname = CharField()
    port = IntegerField()
    size = BigIntegerField()
    started = DateTimeField()

    class Meta:
        db_table = 'mysql_backups'
        indexes = ((('hostname', 'port', 'finished'), False), )


class PromotionLocks(BaseModel):
    created_at = DateTimeField()
    expires = DateTimeField(null=True)
    lock_active = CharField(null=True)
    lock_identifier = CharField(primary_key=True)
    promoting_host = CharField()
    promoting_user = CharField()
    released = DateTimeField(null=True)
    replica_set = CharField()

    class Meta:
        db_table = 'promotion_locks'
        indexes = ((('replica_set', 'lock_active'), True), )


class RetirementProtection(BaseModel):
    hostname = CharField(primary_key=True)
    protecting_user = CharField(null=True)
    reason = TextField(null=True)

    class Meta:
        db_table = 'retirement_protection'


class RetirementQueue(BaseModel):
    activity = CharField(null=True)
    happened = DateTimeField(null=True)
    hostname = CharField()
    instance = CharField(db_column='instance_id')

    class Meta:
        db_table = 'retirement_queue'
        indexes = ((('instance', 'activity'), True), )


class UniqueHostnameIndex(BaseModel):
    hostname = CharField(primary_key=True)

    class Meta:
        db_table = 'unique_hostname_index'
