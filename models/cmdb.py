from peewee import *
from playhouse.pool import PooledMySQLDatabase
from configs import common_db_config
max_connections = common_db_config.get('max_connections')
if max_connections is not None:
    database = PooledMySQLDatabase('cmdb', **common_db_config)
else:
    database = MySQLDatabase('cmdb', **common_db_config)


class UnknownField(object):
    pass


class BaseModel(Model):
    class Meta:
        database = database


class AssetNicMac(BaseModel):
    assets = IntegerField(db_column='assets_id', index=True, null=True)
    mac = CharField(null=True)
    nic = CharField(null=True)
    nic_id = PrimaryKeyField()

    class Meta:
        db_table = 'asset_nic_mac'


class Rack(BaseModel):
    create_timestamp = DateTimeField(null=True)
    rack = CharField(null=True)
    rack_id = PrimaryKeyField()
    room = IntegerField(db_column='room_id', index=True, null=True)

    class Meta:
        db_table = 'rack'


class Room(BaseModel):
    city = CharField(null=True)
    customer_service = CharField(null=True)
    email = CharField(null=True)
    position = CharField()
    room = PrimaryKeyField(db_column='room_id')
    room_name = CharField()
    room_name_en = CharField(null=True)
    tel = CharField(null=True)

    class Meta:
        db_table = 'room'


class Device(BaseModel):
    assets = PrimaryKeyField(db_column='assets_id')
    create_timestamp = DateTimeField()
    device_status = CharField()
    environment = CharField(null=True)
    fqdn = CharField(null=True)
    logic_area = CharField(null=True)
    operator = CharField()
    rack = ForeignKeyField(
        db_column='rack_id', rel_model=Rack, to_field='rack_id')
    remarks = CharField(null=True)
    room = ForeignKeyField(
        db_column='room_id', null=True, rel_model=Room, to_field='room')
    seat = IntegerField()
    sn = CharField(null=True)
    template = IntegerField(db_column='template_id', index=True, null=True)
    tier = CharField(null=True)
    uuid = CharField(null=True)

    class Meta:
        db_table = 'device'


class DeviceTemplate(BaseModel):
    cpu = IntegerField(null=True)
    cpu_detail = TextField(null=True)
    create_timestamp = DateTimeField()
    device_height = IntegerField()
    disk = IntegerField(null=True)
    disk_detail = TextField(null=True)
    kernel = CharField(null=True)
    manufacturer = IntegerField(
        db_column='manufacturer_id', index=True, null=True)
    memory = IntegerField(null=True)
    os = CharField(null=True)
    price = IntegerField(null=True)
    server_type = CharField()
    template = PrimaryKeyField(db_column='template_id')
    warranty_time = IntegerField(null=True)

    class Meta:
        db_table = 'device_template'


class Ip(BaseModel):
    assets = IntegerField(db_column='assets_id', index=True)
    carriers = CharField(index=True)
    gateway = CharField()
    ip = CharField(index=True)
    ip_id = PrimaryKeyField()
    netmask = CharField()
    segment_ip = CharField(index=True)
    status = CharField()

    class Meta:
        db_table = 'ip'
        indexes = ((('assets', 'ip'), True), )


class Manufacturer(BaseModel):
    create_timestamp = DateTimeField(null=True)
    manufacturer = CharField(null=True)
    manufacturer_id = PrimaryKeyField()

    class Meta:
        db_table = 'manufacturer'


class Seat(BaseModel):
    create_timestamp = DateTimeField(null=True)
    rack = ForeignKeyField(
        db_column='rack_id', null=True, rel_model=Rack, to_field='rack_id')
    room = ForeignKeyField(
        db_column='room_id', null=True, rel_model=Room, to_field='room')
    seat = IntegerField(null=True)
    seat_id = PrimaryKeyField()

    class Meta:
        db_table = 'seat'


class Segment(BaseModel):
    assets = IntegerField(db_column='assets_id')
    assigned = IntegerField()
    carriers = CharField(null=True)
    gateway = CharField()
    ip_type = CharField(index=True)
    logic_area = CharField(null=True)
    netmask = CharField()
    remarks = CharField(null=True)
    room = ForeignKeyField(
        db_column='room_id', null=True, rel_model=Room, to_field='room')
    segment = PrimaryKeyField(db_column='segment_id')
    segment_ip = CharField()
    status = CharField()
    total = IntegerField()
    vlan = IntegerField(db_column='vlan_id', null=True)

    class Meta:
        db_table = 'segment'
        indexes = ((('segment_ip', 'netmask'), True), )


class SegmentIpPool(BaseModel):
    assigned = CharField()
    ip = CharField(unique=True)
    segment = ForeignKeyField(
        db_column='segment_id', rel_model=Segment, to_field='segment')

    class Meta:
        db_table = 'segment_ip_pool'


class ServerTag(BaseModel):
    assets = ForeignKeyField(
        db_column='assets_id', null=True, rel_model=Device, to_field='assets')
    create_timestamp = DateTimeField()
    server_tag = PrimaryKeyField(db_column='server_tag_id')
    server_tag_key = CharField(null=True)
    server_tag_value = CharField(index=True, null=True)

    class Meta:
        db_table = 'server_tag'
        indexes = ((('server_tag_key', 'server_tag_value', 'assets'), True), )


class ServerTagUser(BaseModel):
    create_timestamp = DateTimeField()
    server_tag = ForeignKeyField(
        db_column='server_tag_id',
        null=True,
        rel_model=ServerTag,
        to_field='server_tag')
    uid = IntegerField(null=True)
    user_name = CharField(null=True)
    user_tag = PrimaryKeyField(db_column='user_tag_id')

    class Meta:
        db_table = 'server_tag_user'


class SwitchMacTable(BaseModel):
    interface = IntegerField(db_column='interface_id', index=True)
    mac = CharField(index=True)
    port = IntegerField(db_column='port_id', index=True)
    switch = PrimaryKeyField(db_column='switch_id')
    vlan = IntegerField()

    class Meta:
        db_table = 'switch_mac_table'
