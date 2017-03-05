from peewee import *
from playhouse.pool import PooledMySQLDatabase
from configs import common_db_config
max_connections = common_db_config.get('max_connections')
if max_connections is not None:
    database = PooledMySQLDatabase('deploy', **common_db_config)
else:
    database = MySQLDatabase('deploy', **common_db_config)


class UnknownField(object):
    pass


class BaseModel(Model):
    class Meta:
        database = database


class DeployTemplate(BaseModel):
    package_type = CharField(null=True)
    package_uri = CharField(null=True)
    server_tag = CharField(null=True)
    template = PrimaryKeyField(db_column='template_id')

    class Meta:
        db_table = 'deploy_template'


class Jobs(BaseModel):
    create_timestamp = DateTimeField(null=True)
    group_list = TextField(null=True)
    job = BigIntegerField(db_column='job_id', primary_key=True)
    operator = CharField(null=True)
    release_version = CharField(null=True)
    template = ForeignKeyField(
        db_column='template_id',
        null=True,
        rel_model=DeployTemplate,
        to_field='template')

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

    class Meta:
        db_table = 'tasks'
