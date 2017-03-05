from peewee import *
from playhouse.pool import PooledMySQLDatabase
from configs import common_db_config
max_connections = common_db_config.get('max_connections')
if max_connections is not None:
    database = PooledMySQLDatabase('virt', **common_db_config)
else:
    database = MySQLDatabase('virt', **common_db_config)


class UnknownField(object):
    pass


class BaseModel(Model):
    class Meta:
        database = database


class Flavor(BaseModel):
    disk = IntegerField(null=True)
    flavor = PrimaryKeyField(db_column='flavor_id')
    label = CharField(null=True, unique=True)
    memory = IntegerField(null=True)
    vcpu = IntegerField(null=True)

    class Meta:
        db_table = 'flavor'


class Instance(BaseModel):
    create_timestamp = DateTimeField(null=True)
    flavor = ForeignKeyField(
        db_column='flavor_id', rel_model=Flavor, to_field='flavor')
    instance = PrimaryKeyField(db_column='instance_id')
    name = CharField(null=True)
    server_ip = CharField(null=True)
    uuid = CharField(null=True)

    class Meta:
        db_table = 'instance'


class Jobs(BaseModel):
    create_timestamp = DateTimeField(null=True)
    flavor = ForeignKeyField(
        db_column='flavor_id', rel_model=Flavor, to_field='flavor')
    instance_count = CharField(null=True)
    ip_list = TextField(null=True)
    job = PrimaryKeyField(db_column='job_id')
    network_type = CharField(null=True)
    operator = CharField(null=True)
    remarks = CharField(null=True)
    server_tag = CharField(null=True)
    virt_type = CharField(null=True)

    class Meta:
        db_table = 'jobs'


class Tasks(BaseModel):
    create_timestamp = DateTimeField(null=True)
    group = CharField(null=True)
    job = ForeignKeyField(
        db_column='job_id', null=True, rel_model=Jobs, to_field='job')
    result_log = TextField(null=True)
    result_status = IntegerField(null=True)
    server_ip = CharField(null=True)
    task = PrimaryKeyField(db_column='task_id')

    class Meta:
        db_table = 'tasks'
