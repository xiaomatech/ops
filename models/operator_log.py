from peewee import *
from playhouse.pool import PooledMySQLDatabase
from configs import common_db_config
max_connections = common_db_config.get('max_connections')
if max_connections is not None:
    database = PooledMySQLDatabase('operator_log', **common_db_config)
else:
    database = MySQLDatabase('operator_log', **common_db_config)


class UnknownField(object):
    pass


class BaseModel(Model):
    class Meta:
        database = database


class AnsibleLog(BaseModel):
    category = CharField(index=True, null=True)
    create_timestamp = DateTimeField(null=True)
    result = TextField(null=True)
    result_status = CharField(index=True, null=True)
    server_ip = CharField(index=True, null=True)

    class Meta:
        db_table = 'ansible_log'


class OperatorLog(BaseModel):
    controller = CharField(null=True)
    create_timestamp = DateTimeField(null=True)
    exec_path = CharField(null=True)
    func = CharField(null=True)
    login_gid = IntegerField(null=True)
    login_uid = IntegerField(null=True)
    login_user = CharField(null=True)
    post_data = TextField(null=True)
    result = TextField(null=True)
    respone_timestamp = DateTimeField(null=True)
    request = BigIntegerField(db_column='request_id', null=True)
    server_ip = CharField(null=True)

    class Meta:
        db_table = 'operator_log'
