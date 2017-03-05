from peewee import *
from playhouse.pool import PooledMySQLDatabase
from configs import zabbix_db_config
max_connections = zabbix_db_config.get('max_connections')
if max_connections is not None:
    database = PooledMySQLDatabase('zabbix', **zabbix_db_config)
else:
    database = MySQLDatabase('zabbix', **zabbix_db_config)


class UnknownField(object):
    pass


class BaseModel(Model):
    class Meta:
        database = database


class Events(BaseModel):
    acknowledged = IntegerField()
    clock = IntegerField()
    eventid = BigIntegerField(primary_key=True)
    ns = IntegerField()
    object = IntegerField()
    objectid = BigIntegerField()
    source = IntegerField()
    value = IntegerField()

    class Meta:
        db_table = 'events'
        indexes = (
            (('source', 'object', 'clock'), False),
            (('source', 'object', 'objectid', 'clock'), False), )


class Users(BaseModel):
    alias = CharField(unique=True)
    attempt_clock = IntegerField()
    attempt_failed = IntegerField()
    attempt_ip = CharField()
    autologin = IntegerField()
    autologout = IntegerField()
    lang = CharField()
    name = CharField()
    passwd = CharField()
    refresh = IntegerField()
    rows_per_page = IntegerField()
    surname = CharField()
    theme = CharField()
    type = IntegerField()
    url = CharField()
    userid = BigIntegerField(primary_key=True)

    class Meta:
        db_table = 'users'


class Acknowledges(BaseModel):
    acknowledgeid = BigIntegerField(primary_key=True)
    clock = IntegerField(index=True)
    eventid = ForeignKeyField(
        db_column='eventid', rel_model=Events, to_field='eventid')
    message = CharField()
    userid = ForeignKeyField(
        db_column='userid', rel_model=Users, to_field='userid')

    class Meta:
        db_table = 'acknowledges'


class Actions(BaseModel):
    actionid = BigIntegerField(primary_key=True)
    def_longdata = TextField()
    def_shortdata = CharField()
    esc_period = IntegerField()
    evaltype = IntegerField()
    eventsource = IntegerField()
    formula = CharField()
    name = CharField(unique=True)
    r_longdata = TextField()
    r_shortdata = CharField()
    recovery_msg = IntegerField()
    status = IntegerField()

    class Meta:
        db_table = 'actions'
        indexes = ((('eventsource', 'status'), False), )


class MediaType(BaseModel):
    description = CharField(unique=True)
    exec_params = CharField()
    exec_path = CharField()
    gsm_modem = CharField()
    mediatypeid = BigIntegerField(primary_key=True)
    passwd = CharField()
    smtp_authentication = IntegerField()
    smtp_email = CharField()
    smtp_helo = CharField()
    smtp_port = IntegerField()
    smtp_security = IntegerField()
    smtp_server = CharField()
    smtp_verify_host = IntegerField()
    smtp_verify_peer = IntegerField()
    status = IntegerField()
    type = IntegerField()
    username = CharField()

    class Meta:
        db_table = 'media_type'


class Alerts(BaseModel):
    actionid = ForeignKeyField(
        db_column='actionid', rel_model=Actions, to_field='actionid')
    alertid = BigIntegerField(primary_key=True)
    alerttype = IntegerField()
    clock = IntegerField(index=True)
    error = CharField()
    esc_step = IntegerField()
    eventid = ForeignKeyField(
        db_column='eventid', rel_model=Events, to_field='eventid')
    mediatypeid = ForeignKeyField(
        db_column='mediatypeid',
        null=True,
        rel_model=MediaType,
        to_field='mediatypeid')
    message = TextField()
    retries = IntegerField()
    sendto = CharField()
    status = IntegerField()
    subject = CharField()
    userid = ForeignKeyField(
        db_column='userid', null=True, rel_model=Users, to_field='userid')

    class Meta:
        db_table = 'alerts'
        indexes = ((('status', 'retries'), False), )


class Maintenances(BaseModel):
    active_since = IntegerField()
    active_till = IntegerField()
    description = TextField()
    maintenance_type = IntegerField()
    maintenanceid = BigIntegerField(primary_key=True)
    name = CharField(unique=True)

    class Meta:
        db_table = 'maintenances'
        indexes = ((('active_since', 'active_till'), False), )


class Hosts(BaseModel):
    available = IntegerField()
    description = TextField()
    disable_until = IntegerField()
    error = CharField()
    errors_from = IntegerField()
    flags = IntegerField()
    host = CharField(index=True)
    hostid = BigIntegerField(primary_key=True)
    ipmi_authtype = IntegerField()
    ipmi_available = IntegerField()
    ipmi_disable_until = IntegerField()
    ipmi_error = CharField()
    ipmi_errors_from = IntegerField()
    ipmi_password = CharField()
    ipmi_privilege = IntegerField()
    ipmi_username = CharField()
    jmx_available = IntegerField()
    jmx_disable_until = IntegerField()
    jmx_error = CharField()
    jmx_errors_from = IntegerField()
    lastaccess = IntegerField()
    maintenance_from = IntegerField()
    maintenance_status = IntegerField()
    maintenance_type = IntegerField()
    maintenanceid = ForeignKeyField(
        db_column='maintenanceid',
        null=True,
        rel_model=Maintenances,
        to_field='maintenanceid')
    name = CharField(index=True)
    proxy_hostid = ForeignKeyField(
        db_column='proxy_hostid',
        null=True,
        rel_model='self',
        to_field='hostid')
    snmp_available = IntegerField()
    snmp_disable_until = IntegerField()
    snmp_error = CharField()
    snmp_errors_from = IntegerField()
    status = IntegerField(index=True)
    templateid = ForeignKeyField(
        db_column='templateid',
        null=True,
        rel_model='self',
        related_name='hosts_templateid_set',
        to_field='hostid')
    tls_accept = IntegerField()
    tls_connect = IntegerField()
    tls_issuer = CharField()
    tls_psk = CharField()
    tls_psk_identity = CharField()
    tls_subject = CharField()

    class Meta:
        db_table = 'hosts'


class Interface(BaseModel):
    bulk = IntegerField()
    dns = CharField()
    hostid = ForeignKeyField(
        db_column='hostid', rel_model=Hosts, to_field='hostid')
    interfaceid = BigIntegerField(primary_key=True)
    ip = CharField()
    main = IntegerField()
    port = CharField()
    type = IntegerField()
    useip = IntegerField()

    class Meta:
        db_table = 'interface'
        indexes = (
            (('hostid', 'type'), False),
            (('ip', 'dns'), False), )


class Valuemaps(BaseModel):
    name = CharField(unique=True)
    valuemapid = BigIntegerField(primary_key=True)

    class Meta:
        db_table = 'valuemaps'


class Items(BaseModel):
    authtype = IntegerField()
    data_type = IntegerField()
    delay = IntegerField()
    delay_flex = CharField()
    delta = IntegerField()
    description = TextField()
    error = CharField()
    evaltype = IntegerField()
    flags = IntegerField()
    formula = CharField()
    history = IntegerField()
    hostid = ForeignKeyField(
        db_column='hostid', rel_model=Hosts, to_field='hostid')
    interfaceid = ForeignKeyField(
        db_column='interfaceid',
        null=True,
        rel_model=Interface,
        to_field='interfaceid')
    inventory_link = IntegerField()
    ipmi_sensor = CharField()
    itemid = BigIntegerField(primary_key=True)
    key_ = CharField()
    lastlogsize = BigIntegerField()
    lifetime = CharField()
    logtimefmt = CharField()
    mtime = IntegerField()
    multiplier = IntegerField()
    name = CharField()
    params = TextField()
    password = CharField()
    port = CharField()
    privatekey = CharField()
    publickey = CharField()
    snmp_community = CharField()
    snmp_oid = CharField()
    snmpv3_authpassphrase = CharField()
    snmpv3_authprotocol = IntegerField()
    snmpv3_contextname = CharField()
    snmpv3_privpassphrase = CharField()
    snmpv3_privprotocol = IntegerField()
    snmpv3_securitylevel = IntegerField()
    snmpv3_securityname = CharField()
    state = IntegerField()
    status = IntegerField(index=True)
    templateid = ForeignKeyField(
        db_column='templateid', null=True, rel_model='self', to_field='itemid')
    trapper_hosts = CharField()
    trends = IntegerField()
    type = IntegerField()
    units = CharField()
    username = CharField()
    value_type = IntegerField()
    valuemapid = ForeignKeyField(
        db_column='valuemapid',
        null=True,
        rel_model=Valuemaps,
        to_field='valuemapid')

    class Meta:
        db_table = 'items'
        indexes = ((('hostid', 'key_'), True), )


class ApplicationPrototype(BaseModel):
    application_prototypeid = BigIntegerField(primary_key=True)
    itemid = ForeignKeyField(
        db_column='itemid', rel_model=Items, to_field='itemid')
    name = CharField()
    templateid = ForeignKeyField(
        db_column='templateid',
        null=True,
        rel_model='self',
        to_field='application_prototypeid')

    class Meta:
        db_table = 'application_prototype'


class Applications(BaseModel):
    applicationid = BigIntegerField(primary_key=True)
    flags = IntegerField()
    hostid = ForeignKeyField(
        db_column='hostid', rel_model=Hosts, to_field='hostid')
    name = CharField()

    class Meta:
        db_table = 'applications'
        indexes = ((('hostid', 'name'), True), )


class ApplicationDiscovery(BaseModel):
    application_discoveryid = BigIntegerField(primary_key=True)
    application_prototypeid = ForeignKeyField(
        db_column='application_prototypeid',
        rel_model=ApplicationPrototype,
        to_field='application_prototypeid')
    applicationid = ForeignKeyField(
        db_column='applicationid',
        rel_model=Applications,
        to_field='applicationid')
    lastcheck = IntegerField()
    name = CharField()
    ts_delete = IntegerField()

    class Meta:
        db_table = 'application_discovery'


class ApplicationTemplate(BaseModel):
    application_templateid = BigIntegerField(primary_key=True)
    applicationid = ForeignKeyField(
        db_column='applicationid',
        rel_model=Applications,
        to_field='applicationid')
    templateid = ForeignKeyField(
        db_column='templateid',
        rel_model=Applications,
        related_name='applications_templateid_set',
        to_field='applicationid')

    class Meta:
        db_table = 'application_template'
        indexes = ((('applicationid', 'templateid'), True), )


class Auditlog(BaseModel):
    action = IntegerField()
    auditid = BigIntegerField(primary_key=True)
    clock = IntegerField(index=True)
    details = CharField()
    ip = CharField()
    resourceid = BigIntegerField()
    resourcename = CharField()
    resourcetype = IntegerField()
    userid = ForeignKeyField(
        db_column='userid', rel_model=Users, to_field='userid')

    class Meta:
        db_table = 'auditlog'
        indexes = ((('userid', 'clock'), False), )


class AuditlogDetails(BaseModel):
    auditdetailid = BigIntegerField(primary_key=True)
    auditid = ForeignKeyField(
        db_column='auditid', rel_model=Auditlog, to_field='auditid')
    field_name = CharField()
    newvalue = TextField()
    oldvalue = TextField()
    table_name = CharField()

    class Meta:
        db_table = 'auditlog_details'


class AutoregHost(BaseModel):
    autoreg_hostid = BigIntegerField(primary_key=True)
    host = CharField()
    host_metadata = CharField()
    listen_dns = CharField()
    listen_ip = CharField()
    listen_port = IntegerField()
    proxy_hostid = ForeignKeyField(
        db_column='proxy_hostid',
        null=True,
        rel_model=Hosts,
        to_field='hostid')

    class Meta:
        db_table = 'autoreg_host'
        indexes = ((('proxy_hostid', 'host'), False), )


class Conditions(BaseModel):
    actionid = ForeignKeyField(
        db_column='actionid', rel_model=Actions, to_field='actionid')
    conditionid = BigIntegerField(primary_key=True)
    conditiontype = IntegerField()
    operator = IntegerField()
    value = CharField()

    class Meta:
        db_table = 'conditions'


class Groups(BaseModel):
    flags = IntegerField()
    groupid = BigIntegerField(primary_key=True)
    internal = IntegerField()
    name = CharField(index=True)

    class Meta:
        db_table = 'groups'


class Usrgrp(BaseModel):
    debug_mode = IntegerField()
    gui_access = IntegerField()
    name = CharField(unique=True)
    users_status = IntegerField()
    usrgrpid = BigIntegerField(primary_key=True)

    class Meta:
        db_table = 'usrgrp'


class Config(BaseModel):
    alert_usrgrpid = ForeignKeyField(
        db_column='alert_usrgrpid',
        null=True,
        rel_model=Usrgrp,
        to_field='usrgrpid')
    authentication_type = IntegerField()
    blink_period = IntegerField()
    configid = BigIntegerField(primary_key=True)
    default_inventory_mode = IntegerField()
    default_theme = CharField()
    discovery_groupid = ForeignKeyField(
        db_column='discovery_groupid', rel_model=Groups, to_field='groupid')
    dropdown_first_entry = IntegerField()
    dropdown_first_remember = IntegerField()
    event_ack_enable = IntegerField()
    event_expire = IntegerField()
    event_show_max = IntegerField()
    hk_audit = IntegerField()
    hk_audit_mode = IntegerField()
    hk_events_autoreg = IntegerField()
    hk_events_discovery = IntegerField()
    hk_events_internal = IntegerField()
    hk_events_mode = IntegerField()
    hk_events_trigger = IntegerField()
    hk_history = IntegerField()
    hk_history_global = IntegerField()
    hk_history_mode = IntegerField()
    hk_services = IntegerField()
    hk_services_mode = IntegerField()
    hk_sessions = IntegerField()
    hk_sessions_mode = IntegerField()
    hk_trends = IntegerField()
    hk_trends_global = IntegerField()
    hk_trends_mode = IntegerField()
    ldap_base_dn = CharField()
    ldap_bind_dn = CharField()
    ldap_bind_password = CharField()
    ldap_host = CharField()
    ldap_port = IntegerField()
    ldap_search_attribute = CharField()
    max_in_table = IntegerField()
    ok_ack_color = CharField()
    ok_ack_style = IntegerField()
    ok_period = IntegerField()
    ok_unack_color = CharField()
    ok_unack_style = IntegerField()
    problem_ack_color = CharField()
    problem_ack_style = IntegerField()
    problem_unack_color = CharField()
    problem_unack_style = IntegerField()
    refresh_unsupported = IntegerField()
    search_limit = IntegerField()
    server_check_interval = IntegerField()
    severity_color_0 = CharField()
    severity_color_1 = CharField()
    severity_color_2 = CharField()
    severity_color_3 = CharField()
    severity_color_4 = CharField()
    severity_color_5 = CharField()
    severity_name_0 = CharField()
    severity_name_1 = CharField()
    severity_name_2 = CharField()
    severity_name_3 = CharField()
    severity_name_4 = CharField()
    severity_name_5 = CharField()
    snmptrap_logging = IntegerField()
    work_period = CharField()

    class Meta:
        db_table = 'config'


class Dbversion(BaseModel):
    mandatory = IntegerField()
    optional = IntegerField()

    class Meta:
        db_table = 'dbversion'


class Drules(BaseModel):
    delay = IntegerField()
    druleid = BigIntegerField(primary_key=True)
    iprange = CharField()
    name = CharField(unique=True)
    nextcheck = IntegerField()
    proxy_hostid = ForeignKeyField(
        db_column='proxy_hostid',
        null=True,
        rel_model=Hosts,
        to_field='hostid')
    status = IntegerField()

    class Meta:
        db_table = 'drules'


class Dchecks(BaseModel):
    dcheckid = BigIntegerField(primary_key=True)
    druleid = ForeignKeyField(
        db_column='druleid', rel_model=Drules, to_field='druleid')
    key_ = CharField()
    ports = CharField()
    snmp_community = CharField()
    snmpv3_authpassphrase = CharField()
    snmpv3_authprotocol = IntegerField()
    snmpv3_contextname = CharField()
    snmpv3_privpassphrase = CharField()
    snmpv3_privprotocol = IntegerField()
    snmpv3_securitylevel = IntegerField()
    snmpv3_securityname = CharField()
    type = IntegerField()
    uniq = IntegerField()

    class Meta:
        db_table = 'dchecks'


class Dhosts(BaseModel):
    dhostid = BigIntegerField(primary_key=True)
    druleid = ForeignKeyField(
        db_column='druleid', rel_model=Drules, to_field='druleid')
    lastdown = IntegerField()
    lastup = IntegerField()
    status = IntegerField()

    class Meta:
        db_table = 'dhosts'


class Dservices(BaseModel):
    dcheckid = ForeignKeyField(
        db_column='dcheckid', rel_model=Dchecks, to_field='dcheckid')
    dhostid = ForeignKeyField(
        db_column='dhostid', rel_model=Dhosts, to_field='dhostid')
    dns = CharField()
    dserviceid = BigIntegerField(primary_key=True)
    ip = CharField()
    key_ = CharField()
    lastdown = IntegerField()
    lastup = IntegerField()
    port = IntegerField()
    status = IntegerField()
    type = IntegerField()
    value = CharField()

    class Meta:
        db_table = 'dservices'
        indexes = ((('dcheckid', 'type', 'key_', 'ip', 'port'), True), )


class Escalations(BaseModel):
    actionid = BigIntegerField()
    esc_step = IntegerField()
    escalationid = BigIntegerField(primary_key=True)
    eventid = BigIntegerField(null=True)
    itemid = BigIntegerField(null=True)
    nextcheck = IntegerField()
    r_eventid = BigIntegerField(null=True)
    status = IntegerField()
    triggerid = BigIntegerField(null=True)

    class Meta:
        db_table = 'escalations'
        indexes = ((('actionid', 'triggerid', 'itemid', 'escalationid'),
                    True), )


class Regexps(BaseModel):
    name = CharField(unique=True)
    regexpid = BigIntegerField(primary_key=True)
    test_string = TextField()

    class Meta:
        db_table = 'regexps'


class Expressions(BaseModel):
    case_sensitive = IntegerField()
    exp_delimiter = CharField()
    expression = CharField()
    expression_type = IntegerField()
    expressionid = BigIntegerField(primary_key=True)
    regexpid = ForeignKeyField(
        db_column='regexpid', rel_model=Regexps, to_field='regexpid')

    class Meta:
        db_table = 'expressions'


class Triggers(BaseModel):
    comments = TextField()
    description = CharField()
    error = CharField()
    expression = CharField()
    flags = IntegerField()
    lastchange = IntegerField()
    priority = IntegerField()
    state = IntegerField()
    status = IntegerField(index=True)
    templateid = ForeignKeyField(
        db_column='templateid',
        null=True,
        rel_model='self',
        to_field='triggerid')
    triggerid = BigIntegerField(primary_key=True)
    type = IntegerField()
    url = CharField()
    value = IntegerField()

    class Meta:
        db_table = 'triggers'
        indexes = ((('value', 'lastchange'), False), )


class Functions(BaseModel):
    function = CharField()
    functionid = BigIntegerField(primary_key=True)
    itemid = ForeignKeyField(
        db_column='itemid', rel_model=Items, to_field='itemid')
    parameter = CharField()
    triggerid = ForeignKeyField(
        db_column='triggerid', rel_model=Triggers, to_field='triggerid')

    class Meta:
        db_table = 'functions'
        indexes = ((('itemid', 'function', 'parameter'), False), )


class Globalmacro(BaseModel):
    globalmacroid = BigIntegerField(primary_key=True)
    macro = CharField(unique=True)
    value = CharField()

    class Meta:
        db_table = 'globalmacro'


class Globalvars(BaseModel):
    globalvarid = BigIntegerField(primary_key=True)
    snmp_lastsize = IntegerField()

    class Meta:
        db_table = 'globalvars'


class Graphs(BaseModel):
    flags = IntegerField()
    graphid = BigIntegerField(primary_key=True)
    graphtype = IntegerField()
    height = IntegerField()
    name = CharField(index=True)
    percent_left = FloatField()
    percent_right = FloatField()
    show_3d = IntegerField()
    show_legend = IntegerField()
    show_triggers = IntegerField()
    show_work_period = IntegerField()
    templateid = ForeignKeyField(
        db_column='templateid',
        null=True,
        rel_model='self',
        to_field='graphid')
    width = IntegerField()
    yaxismax = FloatField()
    yaxismin = FloatField()
    ymax_itemid = ForeignKeyField(
        db_column='ymax_itemid', null=True, rel_model=Items, to_field='itemid')
    ymax_type = IntegerField()
    ymin_itemid = ForeignKeyField(
        db_column='ymin_itemid',
        null=True,
        rel_model=Items,
        related_name='items_ymin_itemid_set',
        to_field='itemid')
    ymin_type = IntegerField()

    class Meta:
        db_table = 'graphs'


class GraphDiscovery(BaseModel):
    graphid = ForeignKeyField(
        db_column='graphid',
        primary_key=True,
        rel_model=Graphs,
        to_field='graphid')
    parent_graphid = ForeignKeyField(
        db_column='parent_graphid',
        rel_model=Graphs,
        related_name='graphs_parent_graphid_set',
        to_field='graphid')

    class Meta:
        db_table = 'graph_discovery'


class GraphTheme(BaseModel):
    backgroundcolor = CharField()
    graphcolor = CharField()
    graphthemeid = BigIntegerField(primary_key=True)
    gridbordercolor = CharField()
    gridcolor = CharField()
    highlightcolor = CharField()
    leftpercentilecolor = CharField()
    maingridcolor = CharField()
    nonworktimecolor = CharField()
    rightpercentilecolor = CharField()
    textcolor = CharField()
    theme = CharField(unique=True)

    class Meta:
        db_table = 'graph_theme'


class GraphsItems(BaseModel):
    calc_fnc = IntegerField()
    color = CharField()
    drawtype = IntegerField()
    gitemid = BigIntegerField(primary_key=True)
    graphid = ForeignKeyField(
        db_column='graphid', rel_model=Graphs, to_field='graphid')
    itemid = ForeignKeyField(
        db_column='itemid', rel_model=Items, to_field='itemid')
    sortorder = IntegerField()
    type = IntegerField()
    yaxisside = IntegerField()

    class Meta:
        db_table = 'graphs_items'


class GroupPrototype(BaseModel):
    group_prototypeid = BigIntegerField(primary_key=True)
    groupid = ForeignKeyField(
        db_column='groupid', null=True, rel_model=Groups, to_field='groupid')
    hostid = ForeignKeyField(
        db_column='hostid', rel_model=Hosts, to_field='hostid')
    name = CharField()
    templateid = ForeignKeyField(
        db_column='templateid',
        null=True,
        rel_model='self',
        to_field='group_prototypeid')

    class Meta:
        db_table = 'group_prototype'


class GroupDiscovery(BaseModel):
    groupid = ForeignKeyField(
        db_column='groupid',
        primary_key=True,
        rel_model=Groups,
        to_field='groupid')
    lastcheck = IntegerField()
    name = CharField()
    parent_group_prototypeid = ForeignKeyField(
        db_column='parent_group_prototypeid',
        rel_model=GroupPrototype,
        to_field='group_prototypeid')
    ts_delete = IntegerField()

    class Meta:
        db_table = 'group_discovery'


class History(BaseModel):
    clock = IntegerField()
    itemid = BigIntegerField()
    ns = IntegerField()
    value = FloatField()

    class Meta:
        db_table = 'history'
        indexes = ((('itemid', 'clock'), False), )


class HistoryLog(BaseModel):
    clock = IntegerField()
    id = BigIntegerField(primary_key=True)
    itemid = BigIntegerField()
    logeventid = IntegerField()
    ns = IntegerField()
    severity = IntegerField()
    source = CharField()
    timestamp = IntegerField()
    value = TextField()

    class Meta:
        db_table = 'history_log'
        indexes = (
            (('itemid', 'clock'), False),
            (('itemid', 'id'), True), )


class HistoryStr(BaseModel):
    clock = IntegerField()
    itemid = BigIntegerField()
    ns = IntegerField()
    value = CharField()

    class Meta:
        db_table = 'history_str'
        indexes = ((('itemid', 'clock'), False), )


class HistoryText(BaseModel):
    clock = IntegerField()
    id = BigIntegerField(primary_key=True)
    itemid = BigIntegerField()
    ns = IntegerField()
    value = TextField()

    class Meta:
        db_table = 'history_text'
        indexes = (
            (('itemid', 'clock'), False),
            (('itemid', 'id'), True), )


class HistoryUint(BaseModel):
    clock = IntegerField()
    itemid = BigIntegerField()
    ns = IntegerField()
    value = BigIntegerField()

    class Meta:
        db_table = 'history_uint'
        indexes = ((('itemid', 'clock'), False), )


class HostDiscovery(BaseModel):
    host = CharField()
    hostid = ForeignKeyField(
        db_column='hostid',
        primary_key=True,
        rel_model=Hosts,
        to_field='hostid')
    lastcheck = IntegerField()
    parent_hostid = ForeignKeyField(
        db_column='parent_hostid',
        null=True,
        rel_model=Hosts,
        related_name='hosts_parent_hostid_set',
        to_field='hostid')
    parent_itemid = ForeignKeyField(
        db_column='parent_itemid',
        null=True,
        rel_model=Items,
        to_field='itemid')
    ts_delete = IntegerField()

    class Meta:
        db_table = 'host_discovery'


class HostInventory(BaseModel):
    alias = CharField()
    asset_tag = CharField()
    chassis = CharField()
    contact = TextField()
    contract_number = CharField()
    date_hw_decomm = CharField()
    date_hw_expiry = CharField()
    date_hw_install = CharField()
    date_hw_purchase = CharField()
    deployment_status = CharField()
    hardware = CharField()
    hardware_full = TextField()
    host_netmask = CharField()
    host_networks = TextField()
    host_router = CharField()
    hostid = ForeignKeyField(
        db_column='hostid',
        primary_key=True,
        rel_model=Hosts,
        to_field='hostid')
    hw_arch = CharField()
    installer_name = CharField()
    inventory_mode = IntegerField()
    location = TextField()
    location_lat = CharField()
    location_lon = CharField()
    macaddress_a = CharField()
    macaddress_b = CharField()
    model = CharField()
    name = CharField()
    notes = TextField()
    oob_ip = CharField()
    oob_netmask = CharField()
    oob_router = CharField()
    os = CharField()
    os_full = CharField()
    os_short = CharField()
    poc_1_cell = CharField()
    poc_1_email = CharField()
    poc_1_name = CharField()
    poc_1_notes = TextField()
    poc_1_phone_a = CharField()
    poc_1_phone_b = CharField()
    poc_1_screen = CharField()
    poc_2_cell = CharField()
    poc_2_email = CharField()
    poc_2_name = CharField()
    poc_2_notes = TextField()
    poc_2_phone_a = CharField()
    poc_2_phone_b = CharField()
    poc_2_screen = CharField()
    serialno_a = CharField()
    serialno_b = CharField()
    site_address_a = CharField()
    site_address_b = CharField()
    site_address_c = CharField()
    site_city = CharField()
    site_country = CharField()
    site_notes = TextField()
    site_rack = CharField()
    site_state = CharField()
    site_zip = CharField()
    software = CharField()
    software_app_a = CharField()
    software_app_b = CharField()
    software_app_c = CharField()
    software_app_d = CharField()
    software_app_e = CharField()
    software_full = TextField()
    tag = CharField()
    type = CharField()
    type_full = CharField()
    url_a = CharField()
    url_b = CharField()
    url_c = CharField()
    vendor = CharField()

    class Meta:
        db_table = 'host_inventory'


class Hostmacro(BaseModel):
    hostid = ForeignKeyField(
        db_column='hostid', rel_model=Hosts, to_field='hostid')
    hostmacroid = BigIntegerField(primary_key=True)
    macro = CharField()
    value = CharField()

    class Meta:
        db_table = 'hostmacro'
        indexes = ((('hostid', 'macro'), True), )


class HostsGroups(BaseModel):
    groupid = ForeignKeyField(
        db_column='groupid', rel_model=Groups, to_field='groupid')
    hostgroupid = BigIntegerField(primary_key=True)
    hostid = ForeignKeyField(
        db_column='hostid', rel_model=Hosts, to_field='hostid')

    class Meta:
        db_table = 'hosts_groups'
        indexes = ((('hostid', 'groupid'), True), )


class HostsTemplates(BaseModel):
    hostid = ForeignKeyField(
        db_column='hostid', rel_model=Hosts, to_field='hostid')
    hosttemplateid = BigIntegerField(primary_key=True)
    templateid = ForeignKeyField(
        db_column='templateid', rel_model='self', to_field='hostid')

    class Meta:
        db_table = 'hosts_templates'
        indexes = ((('hostid', 'templateid'), True), )


class Housekeeper(BaseModel):
    field = CharField()
    housekeeperid = BigIntegerField(primary_key=True)
    tablename = CharField()
    value = BigIntegerField()

    class Meta:
        db_table = 'housekeeper'


class Httptest(BaseModel):
    agent = CharField()
    applicationid = ForeignKeyField(
        db_column='applicationid',
        null=True,
        rel_model=Applications,
        to_field='applicationid')
    authentication = IntegerField()
    delay = IntegerField()
    headers = TextField()
    hostid = ForeignKeyField(
        db_column='hostid', rel_model=Hosts, to_field='hostid')
    http_password = CharField()
    http_proxy = CharField()
    http_user = CharField()
    httptestid = BigIntegerField(primary_key=True)
    name = CharField()
    nextcheck = IntegerField()
    retries = IntegerField()
    ssl_cert_file = CharField()
    ssl_key_file = CharField()
    ssl_key_password = CharField()
    status = IntegerField(index=True)
    templateid = ForeignKeyField(
        db_column='templateid',
        null=True,
        rel_model='self',
        to_field='httptestid')
    variables = TextField()
    verify_host = IntegerField()
    verify_peer = IntegerField()

    class Meta:
        db_table = 'httptest'
        indexes = ((('hostid', 'name'), True), )


class Httpstep(BaseModel):
    follow_redirects = IntegerField()
    headers = TextField()
    httpstepid = BigIntegerField(primary_key=True)
    httptestid = ForeignKeyField(
        db_column='httptestid', rel_model=Httptest, to_field='httptestid')
    name = CharField()
    no = IntegerField()
    posts = TextField()
    required = CharField()
    retrieve_mode = IntegerField()
    status_codes = CharField()
    timeout = IntegerField()
    url = CharField()
    variables = TextField()

    class Meta:
        db_table = 'httpstep'


class Httpstepitem(BaseModel):
    httpstepid = ForeignKeyField(
        db_column='httpstepid', rel_model=Httpstep, to_field='httpstepid')
    httpstepitemid = BigIntegerField(primary_key=True)
    itemid = ForeignKeyField(
        db_column='itemid', rel_model=Items, to_field='itemid')
    type = IntegerField()

    class Meta:
        db_table = 'httpstepitem'
        indexes = ((('httpstepid', 'itemid'), True), )


class Httptestitem(BaseModel):
    httptestid = ForeignKeyField(
        db_column='httptestid', rel_model=Httptest, to_field='httptestid')
    httptestitemid = BigIntegerField(primary_key=True)
    itemid = ForeignKeyField(
        db_column='itemid', rel_model=Items, to_field='itemid')
    type = IntegerField()

    class Meta:
        db_table = 'httptestitem'
        indexes = ((('httptestid', 'itemid'), True), )


class Images(BaseModel):
    image = TextField()
    imageid = BigIntegerField(primary_key=True)
    imagetype = IntegerField()
    name = CharField(unique=True)

    class Meta:
        db_table = 'images'


class IconMap(BaseModel):
    default_iconid = ForeignKeyField(
        db_column='default_iconid', rel_model=Images, to_field='imageid')
    iconmapid = BigIntegerField(primary_key=True)
    name = CharField(unique=True)

    class Meta:
        db_table = 'icon_map'


class IconMapping(BaseModel):
    expression = CharField()
    iconid = ForeignKeyField(
        db_column='iconid', rel_model=Images, to_field='imageid')
    iconmapid = ForeignKeyField(
        db_column='iconmapid', rel_model=IconMap, to_field='iconmapid')
    iconmappingid = BigIntegerField(primary_key=True)
    inventory_link = IntegerField()
    sortorder = IntegerField()

    class Meta:
        db_table = 'icon_mapping'


class Ids(BaseModel):
    field_name = CharField()
    nextid = BigIntegerField()
    table_name = CharField()

    class Meta:
        db_table = 'ids'
        indexes = ((('table_name', 'field_name'), True), )
        primary_key = CompositeKey('field_name', 'table_name')


class InterfaceDiscovery(BaseModel):
    interfaceid = ForeignKeyField(
        db_column='interfaceid',
        primary_key=True,
        rel_model=Interface,
        to_field='interfaceid')
    parent_interfaceid = ForeignKeyField(
        db_column='parent_interfaceid',
        rel_model=Interface,
        related_name='interface_parent_interfaceid_set',
        to_field='interfaceid')

    class Meta:
        db_table = 'interface_discovery'


class ItemApplicationPrototype(BaseModel):
    application_prototypeid = ForeignKeyField(
        db_column='application_prototypeid',
        rel_model=ApplicationPrototype,
        to_field='application_prototypeid')
    item_application_prototypeid = BigIntegerField(primary_key=True)
    itemid = ForeignKeyField(
        db_column='itemid', rel_model=Items, to_field='itemid')

    class Meta:
        db_table = 'item_application_prototype'
        indexes = ((('application_prototypeid', 'itemid'), True), )


class ItemCondition(BaseModel):
    item_conditionid = BigIntegerField(primary_key=True)
    itemid = ForeignKeyField(
        db_column='itemid', rel_model=Items, to_field='itemid')
    macro = CharField()
    operator = IntegerField()
    value = CharField()

    class Meta:
        db_table = 'item_condition'


class ItemDiscovery(BaseModel):
    itemdiscoveryid = BigIntegerField(primary_key=True)
    itemid = ForeignKeyField(
        db_column='itemid', rel_model=Items, to_field='itemid')
    key_ = CharField()
    lastcheck = IntegerField()
    parent_itemid = ForeignKeyField(
        db_column='parent_itemid',
        rel_model=Items,
        related_name='items_parent_itemid_set',
        to_field='itemid')
    ts_delete = IntegerField()

    class Meta:
        db_table = 'item_discovery'
        indexes = ((('itemid', 'parent_itemid'), True), )


class ItemsApplications(BaseModel):
    applicationid = ForeignKeyField(
        db_column='applicationid',
        rel_model=Applications,
        to_field='applicationid')
    itemappid = BigIntegerField(primary_key=True)
    itemid = ForeignKeyField(
        db_column='itemid', rel_model=Items, to_field='itemid')

    class Meta:
        db_table = 'items_applications'
        indexes = ((('applicationid', 'itemid'), True), )


class MaintenancesGroups(BaseModel):
    groupid = ForeignKeyField(
        db_column='groupid', rel_model=Groups, to_field='groupid')
    maintenance_groupid = BigIntegerField(primary_key=True)
    maintenanceid = ForeignKeyField(
        db_column='maintenanceid',
        rel_model=Maintenances,
        to_field='maintenanceid')

    class Meta:
        db_table = 'maintenances_groups'
        indexes = ((('maintenanceid', 'groupid'), True), )


class MaintenancesHosts(BaseModel):
    hostid = ForeignKeyField(
        db_column='hostid', rel_model=Hosts, to_field='hostid')
    maintenance_hostid = BigIntegerField(primary_key=True)
    maintenanceid = ForeignKeyField(
        db_column='maintenanceid',
        rel_model=Maintenances,
        to_field='maintenanceid')

    class Meta:
        db_table = 'maintenances_hosts'
        indexes = ((('maintenanceid', 'hostid'), True), )


class Timeperiods(BaseModel):
    day = IntegerField()
    dayofweek = IntegerField()
    every = IntegerField()
    month = IntegerField()
    period = IntegerField()
    start_date = IntegerField()
    start_time = IntegerField()
    timeperiod_type = IntegerField()
    timeperiodid = BigIntegerField(primary_key=True)

    class Meta:
        db_table = 'timeperiods'


class MaintenancesWindows(BaseModel):
    maintenance_timeperiodid = BigIntegerField(primary_key=True)
    maintenanceid = ForeignKeyField(
        db_column='maintenanceid',
        rel_model=Maintenances,
        to_field='maintenanceid')
    timeperiodid = ForeignKeyField(
        db_column='timeperiodid',
        rel_model=Timeperiods,
        to_field='timeperiodid')

    class Meta:
        db_table = 'maintenances_windows'
        indexes = ((('maintenanceid', 'timeperiodid'), True), )


class Mappings(BaseModel):
    mappingid = BigIntegerField(primary_key=True)
    newvalue = CharField()
    value = CharField()
    valuemapid = ForeignKeyField(
        db_column='valuemapid', rel_model=Valuemaps, to_field='valuemapid')

    class Meta:
        db_table = 'mappings'


class Media(BaseModel):
    active = IntegerField()
    mediaid = BigIntegerField(primary_key=True)
    mediatypeid = ForeignKeyField(
        db_column='mediatypeid', rel_model=MediaType, to_field='mediatypeid')
    period = CharField()
    sendto = CharField()
    severity = IntegerField()
    userid = ForeignKeyField(
        db_column='userid', rel_model=Users, to_field='userid')

    class Meta:
        db_table = 'media'


class Scripts(BaseModel):
    command = CharField()
    confirmation = CharField()
    description = TextField()
    execute_on = IntegerField()
    groupid = ForeignKeyField(
        db_column='groupid', null=True, rel_model=Groups, to_field='groupid')
    host_access = IntegerField()
    name = CharField(unique=True)
    scriptid = BigIntegerField(primary_key=True)
    type = IntegerField()
    usrgrpid = ForeignKeyField(
        db_column='usrgrpid', null=True, rel_model=Usrgrp, to_field='usrgrpid')

    class Meta:
        db_table = 'scripts'


class Operations(BaseModel):
    actionid = ForeignKeyField(
        db_column='actionid', rel_model=Actions, to_field='actionid')
    esc_period = IntegerField()
    esc_step_from = IntegerField()
    esc_step_to = IntegerField()
    evaltype = IntegerField()
    operationid = BigIntegerField(primary_key=True)
    operationtype = IntegerField()

    class Meta:
        db_table = 'operations'


class Opcommand(BaseModel):
    authtype = IntegerField()
    command = TextField()
    execute_on = IntegerField()
    operationid = ForeignKeyField(
        db_column='operationid',
        primary_key=True,
        rel_model=Operations,
        to_field='operationid')
    password = CharField()
    port = CharField()
    privatekey = CharField()
    publickey = CharField()
    scriptid = ForeignKeyField(
        db_column='scriptid',
        null=True,
        rel_model=Scripts,
        to_field='scriptid')
    type = IntegerField()
    username = CharField()

    class Meta:
        db_table = 'opcommand'


class OpcommandGrp(BaseModel):
    groupid = ForeignKeyField(
        db_column='groupid', rel_model=Groups, to_field='groupid')
    opcommand_grpid = BigIntegerField(primary_key=True)
    operationid = ForeignKeyField(
        db_column='operationid', rel_model=Operations, to_field='operationid')

    class Meta:
        db_table = 'opcommand_grp'


class OpcommandHst(BaseModel):
    hostid = ForeignKeyField(
        db_column='hostid', null=True, rel_model=Hosts, to_field='hostid')
    opcommand_hstid = BigIntegerField(primary_key=True)
    operationid = ForeignKeyField(
        db_column='operationid', rel_model=Operations, to_field='operationid')

    class Meta:
        db_table = 'opcommand_hst'


class Opconditions(BaseModel):
    conditiontype = IntegerField()
    opconditionid = BigIntegerField(primary_key=True)
    operationid = ForeignKeyField(
        db_column='operationid', rel_model=Operations, to_field='operationid')
    operator = IntegerField()
    value = CharField()

    class Meta:
        db_table = 'opconditions'


class Opgroup(BaseModel):
    groupid = ForeignKeyField(
        db_column='groupid', rel_model=Groups, to_field='groupid')
    operationid = ForeignKeyField(
        db_column='operationid', rel_model=Operations, to_field='operationid')
    opgroupid = BigIntegerField(primary_key=True)

    class Meta:
        db_table = 'opgroup'
        indexes = ((('operationid', 'groupid'), True), )


class Opinventory(BaseModel):
    inventory_mode = IntegerField()
    operationid = ForeignKeyField(
        db_column='operationid',
        primary_key=True,
        rel_model=Operations,
        to_field='operationid')

    class Meta:
        db_table = 'opinventory'


class Opmessage(BaseModel):
    default_msg = IntegerField()
    mediatypeid = ForeignKeyField(
        db_column='mediatypeid',
        null=True,
        rel_model=MediaType,
        to_field='mediatypeid')
    message = TextField()
    operationid = ForeignKeyField(
        db_column='operationid',
        primary_key=True,
        rel_model=Operations,
        to_field='operationid')
    subject = CharField()

    class Meta:
        db_table = 'opmessage'


class OpmessageGrp(BaseModel):
    operationid = ForeignKeyField(
        db_column='operationid', rel_model=Operations, to_field='operationid')
    opmessage_grpid = BigIntegerField(primary_key=True)
    usrgrpid = ForeignKeyField(
        db_column='usrgrpid', rel_model=Usrgrp, to_field='usrgrpid')

    class Meta:
        db_table = 'opmessage_grp'
        indexes = ((('operationid', 'usrgrpid'), True), )


class OpmessageUsr(BaseModel):
    operationid = ForeignKeyField(
        db_column='operationid', rel_model=Operations, to_field='operationid')
    opmessage_usrid = BigIntegerField(primary_key=True)
    userid = ForeignKeyField(
        db_column='userid', rel_model=Users, to_field='userid')

    class Meta:
        db_table = 'opmessage_usr'
        indexes = ((('operationid', 'userid'), True), )


class Optemplate(BaseModel):
    operationid = ForeignKeyField(
        db_column='operationid', rel_model=Operations, to_field='operationid')
    optemplateid = BigIntegerField(primary_key=True)
    templateid = ForeignKeyField(
        db_column='templateid', rel_model=Hosts, to_field='hostid')

    class Meta:
        db_table = 'optemplate'
        indexes = ((('operationid', 'templateid'), True), )


class Profiles(BaseModel):
    idx = CharField()
    idx2 = BigIntegerField()
    profileid = BigIntegerField(primary_key=True)
    source = CharField()
    type = IntegerField()
    userid = ForeignKeyField(
        db_column='userid', rel_model=Users, to_field='userid')
    value = BigIntegerField(db_column='value_id')
    value_int = IntegerField()
    value_str = CharField()

    class Meta:
        db_table = 'profiles'
        indexes = (
            (('userid', 'idx', 'idx2'), False),
            (('userid', 'profileid'), False), )


class ProxyAutoregHost(BaseModel):
    clock = IntegerField(index=True)
    host = CharField()
    host_metadata = CharField()
    id = BigIntegerField(primary_key=True)
    listen_dns = CharField()
    listen_ip = CharField()
    listen_port = IntegerField()

    class Meta:
        db_table = 'proxy_autoreg_host'


class ProxyDhistory(BaseModel):
    clock = IntegerField(index=True)
    dcheckid = BigIntegerField(null=True)
    dns = CharField()
    druleid = BigIntegerField()
    id = BigIntegerField(primary_key=True)
    ip = CharField()
    key_ = CharField()
    port = IntegerField()
    status = IntegerField()
    type = IntegerField()
    value = CharField()

    class Meta:
        db_table = 'proxy_dhistory'


class ProxyHistory(BaseModel):
    clock = IntegerField(index=True)
    flags = IntegerField()
    id = BigIntegerField(primary_key=True)
    itemid = BigIntegerField()
    lastlogsize = BigIntegerField()
    logeventid = IntegerField()
    mtime = IntegerField()
    ns = IntegerField()
    severity = IntegerField()
    source = CharField()
    state = IntegerField()
    timestamp = IntegerField()
    value = TextField()

    class Meta:
        db_table = 'proxy_history'


class Rights(BaseModel):
    groupid = ForeignKeyField(
        db_column='groupid', rel_model=Usrgrp, to_field='usrgrpid')
    id = ForeignKeyField(db_column='id', rel_model=Groups, to_field='groupid')
    permission = IntegerField()
    rightid = BigIntegerField(primary_key=True)

    class Meta:
        db_table = 'rights'


class Screens(BaseModel):
    hsize = IntegerField()
    name = CharField()
    private = IntegerField()
    screenid = BigIntegerField(primary_key=True)
    templateid = ForeignKeyField(
        db_column='templateid', null=True, rel_model=Hosts, to_field='hostid')
    userid = ForeignKeyField(
        db_column='userid', null=True, rel_model=Users, to_field='userid')
    vsize = IntegerField()

    class Meta:
        db_table = 'screens'


class ScreenUser(BaseModel):
    permission = IntegerField()
    screenid = ForeignKeyField(
        db_column='screenid', rel_model=Screens, to_field='screenid')
    screenuserid = BigIntegerField(primary_key=True)
    userid = ForeignKeyField(
        db_column='userid', rel_model=Users, to_field='userid')

    class Meta:
        db_table = 'screen_user'
        indexes = ((('screenid', 'userid'), True), )


class ScreenUsrgrp(BaseModel):
    permission = IntegerField()
    screenid = ForeignKeyField(
        db_column='screenid', rel_model=Screens, to_field='screenid')
    screenusrgrpid = BigIntegerField(primary_key=True)
    usrgrpid = ForeignKeyField(
        db_column='usrgrpid', rel_model=Usrgrp, to_field='usrgrpid')

    class Meta:
        db_table = 'screen_usrgrp'
        indexes = ((('screenid', 'usrgrpid'), True), )


class ScreensItems(BaseModel):
    application = CharField()
    colspan = IntegerField()
    dynamic = IntegerField()
    elements = IntegerField()
    halign = IntegerField()
    height = IntegerField()
    max_columns = IntegerField()
    resourceid = BigIntegerField()
    resourcetype = IntegerField()
    rowspan = IntegerField()
    screenid = ForeignKeyField(
        db_column='screenid', rel_model=Screens, to_field='screenid')
    screenitemid = BigIntegerField(primary_key=True)
    sort_triggers = IntegerField()
    style = IntegerField()
    url = CharField()
    valign = IntegerField()
    width = IntegerField()
    x = IntegerField()
    y = IntegerField()

    class Meta:
        db_table = 'screens_items'


class Services(BaseModel):
    algorithm = IntegerField()
    goodsla = FloatField()
    name = CharField()
    serviceid = BigIntegerField(primary_key=True)
    showsla = IntegerField()
    sortorder = IntegerField()
    status = IntegerField()
    triggerid = ForeignKeyField(
        db_column='triggerid',
        null=True,
        rel_model=Triggers,
        to_field='triggerid')

    class Meta:
        db_table = 'services'


class ServiceAlarms(BaseModel):
    clock = IntegerField(index=True)
    servicealarmid = BigIntegerField(primary_key=True)
    serviceid = ForeignKeyField(
        db_column='serviceid', rel_model=Services, to_field='serviceid')
    value = IntegerField()

    class Meta:
        db_table = 'service_alarms'
        indexes = ((('serviceid', 'clock'), False), )


class ServicesLinks(BaseModel):
    linkid = BigIntegerField(primary_key=True)
    servicedownid = ForeignKeyField(
        db_column='servicedownid', rel_model=Services, to_field='serviceid')
    serviceupid = ForeignKeyField(
        db_column='serviceupid',
        rel_model=Services,
        related_name='services_serviceupid_set',
        to_field='serviceid')
    soft = IntegerField()

    class Meta:
        db_table = 'services_links'
        indexes = ((('serviceupid', 'servicedownid'), True), )


class ServicesTimes(BaseModel):
    note = CharField()
    serviceid = ForeignKeyField(
        db_column='serviceid', rel_model=Services, to_field='serviceid')
    timeid = BigIntegerField(primary_key=True)
    ts_from = IntegerField()
    ts_to = IntegerField()
    type = IntegerField()

    class Meta:
        db_table = 'services_times'
        indexes = ((('serviceid', 'type', 'ts_from', 'ts_to'), False), )


class Sessions(BaseModel):
    lastaccess = IntegerField()
    sessionid = CharField(primary_key=True)
    status = IntegerField()
    userid = ForeignKeyField(
        db_column='userid', rel_model=Users, to_field='userid')

    class Meta:
        db_table = 'sessions'
        indexes = ((('userid', 'status'), False), )


class Slideshows(BaseModel):
    delay = IntegerField()
    name = CharField(unique=True)
    private = IntegerField()
    slideshowid = BigIntegerField(primary_key=True)
    userid = ForeignKeyField(
        db_column='userid', rel_model=Users, to_field='userid')

    class Meta:
        db_table = 'slideshows'


class Slides(BaseModel):
    delay = IntegerField()
    screenid = ForeignKeyField(
        db_column='screenid', rel_model=Screens, to_field='screenid')
    slideid = BigIntegerField(primary_key=True)
    slideshowid = ForeignKeyField(
        db_column='slideshowid', rel_model=Slideshows, to_field='slideshowid')
    step = IntegerField()

    class Meta:
        db_table = 'slides'


class SlideshowUser(BaseModel):
    permission = IntegerField()
    slideshowid = ForeignKeyField(
        db_column='slideshowid', rel_model=Slideshows, to_field='slideshowid')
    slideshowuserid = BigIntegerField(primary_key=True)
    userid = ForeignKeyField(
        db_column='userid', rel_model=Users, to_field='userid')

    class Meta:
        db_table = 'slideshow_user'
        indexes = ((('slideshowid', 'userid'), True), )


class SlideshowUsrgrp(BaseModel):
    permission = IntegerField()
    slideshowid = ForeignKeyField(
        db_column='slideshowid', rel_model=Slideshows, to_field='slideshowid')
    slideshowusrgrpid = BigIntegerField(primary_key=True)
    usrgrpid = ForeignKeyField(
        db_column='usrgrpid', rel_model=Usrgrp, to_field='usrgrpid')

    class Meta:
        db_table = 'slideshow_usrgrp'
        indexes = ((('slideshowid', 'usrgrpid'), True), )


class Sysmaps(BaseModel):
    backgroundid = ForeignKeyField(
        db_column='backgroundid',
        null=True,
        rel_model=Images,
        to_field='imageid')
    expand_macros = IntegerField()
    expandproblem = IntegerField()
    grid_align = IntegerField()
    grid_show = IntegerField()
    grid_size = IntegerField()
    height = IntegerField()
    highlight = IntegerField()
    iconmapid = ForeignKeyField(
        db_column='iconmapid',
        null=True,
        rel_model=IconMap,
        to_field='iconmapid')
    label_format = IntegerField()
    label_location = IntegerField()
    label_string_host = CharField()
    label_string_hostgroup = CharField()
    label_string_image = CharField()
    label_string_map = CharField()
    label_string_trigger = CharField()
    label_type = IntegerField()
    label_type_host = IntegerField()
    label_type_hostgroup = IntegerField()
    label_type_image = IntegerField()
    label_type_map = IntegerField()
    label_type_trigger = IntegerField()
    markelements = IntegerField()
    name = CharField(unique=True)
    private = IntegerField()
    severity_min = IntegerField()
    show_unack = IntegerField()
    sysmapid = BigIntegerField(primary_key=True)
    userid = ForeignKeyField(
        db_column='userid', rel_model=Users, to_field='userid')
    width = IntegerField()

    class Meta:
        db_table = 'sysmaps'


class SysmapsElements(BaseModel):
    application = CharField()
    areatype = IntegerField()
    elementid = BigIntegerField()
    elementsubtype = IntegerField()
    elementtype = IntegerField()
    height = IntegerField()
    iconid_disabled = ForeignKeyField(
        db_column='iconid_disabled',
        null=True,
        rel_model=Images,
        to_field='imageid')
    iconid_maintenance = ForeignKeyField(
        db_column='iconid_maintenance',
        null=True,
        rel_model=Images,
        related_name='images_iconid_maintenance_set',
        to_field='imageid')
    iconid_off = ForeignKeyField(
        db_column='iconid_off',
        null=True,
        rel_model=Images,
        related_name='images_iconid_off_set',
        to_field='imageid')
    iconid_on = ForeignKeyField(
        db_column='iconid_on',
        null=True,
        rel_model=Images,
        related_name='images_iconid_on_set',
        to_field='imageid')
    label = CharField()
    label_location = IntegerField()
    selementid = BigIntegerField(primary_key=True)
    sysmapid = ForeignKeyField(
        db_column='sysmapid', rel_model=Sysmaps, to_field='sysmapid')
    use_iconmap = IntegerField()
    viewtype = IntegerField()
    width = IntegerField()
    x = IntegerField()
    y = IntegerField()

    class Meta:
        db_table = 'sysmaps_elements'


class SysmapElementUrl(BaseModel):
    name = CharField()
    selementid = ForeignKeyField(
        db_column='selementid',
        rel_model=SysmapsElements,
        to_field='selementid')
    sysmapelementurlid = BigIntegerField(primary_key=True)
    url = CharField()

    class Meta:
        db_table = 'sysmap_element_url'
        indexes = ((('selementid', 'name'), True), )


class SysmapUrl(BaseModel):
    elementtype = IntegerField()
    name = CharField()
    sysmapid = ForeignKeyField(
        db_column='sysmapid', rel_model=Sysmaps, to_field='sysmapid')
    sysmapurlid = BigIntegerField(primary_key=True)
    url = CharField()

    class Meta:
        db_table = 'sysmap_url'
        indexes = ((('sysmapid', 'name'), True), )


class SysmapUser(BaseModel):
    permission = IntegerField()
    sysmapid = ForeignKeyField(
        db_column='sysmapid', rel_model=Sysmaps, to_field='sysmapid')
    sysmapuserid = BigIntegerField(primary_key=True)
    userid = ForeignKeyField(
        db_column='userid', rel_model=Users, to_field='userid')

    class Meta:
        db_table = 'sysmap_user'
        indexes = ((('sysmapid', 'userid'), True), )


class SysmapUsrgrp(BaseModel):
    permission = IntegerField()
    sysmapid = ForeignKeyField(
        db_column='sysmapid', rel_model=Sysmaps, to_field='sysmapid')
    sysmapusrgrpid = BigIntegerField(primary_key=True)
    usrgrpid = ForeignKeyField(
        db_column='usrgrpid', rel_model=Usrgrp, to_field='usrgrpid')

    class Meta:
        db_table = 'sysmap_usrgrp'
        indexes = ((('sysmapid', 'usrgrpid'), True), )


class SysmapsLinks(BaseModel):
    color = CharField()
    drawtype = IntegerField()
    label = CharField()
    linkid = BigIntegerField(primary_key=True)
    selementid1 = ForeignKeyField(
        db_column='selementid1',
        rel_model=SysmapsElements,
        to_field='selementid')
    selementid2 = ForeignKeyField(
        db_column='selementid2',
        rel_model=SysmapsElements,
        related_name='sysmaps_elements_selementid2_set',
        to_field='selementid')
    sysmapid = ForeignKeyField(
        db_column='sysmapid', rel_model=Sysmaps, to_field='sysmapid')

    class Meta:
        db_table = 'sysmaps_links'


class SysmapsLinkTriggers(BaseModel):
    color = CharField()
    drawtype = IntegerField()
    linkid = ForeignKeyField(
        db_column='linkid', rel_model=SysmapsLinks, to_field='linkid')
    linktriggerid = BigIntegerField(primary_key=True)
    triggerid = ForeignKeyField(
        db_column='triggerid', rel_model=Triggers, to_field='triggerid')

    class Meta:
        db_table = 'sysmaps_link_triggers'
        indexes = ((('linkid', 'triggerid'), True), )


class Trends(BaseModel):
    clock = IntegerField()
    itemid = BigIntegerField()
    num = IntegerField()
    value_avg = FloatField()
    value_max = FloatField()
    value_min = FloatField()

    class Meta:
        db_table = 'trends'
        indexes = ((('itemid', 'clock'), True), )
        primary_key = CompositeKey('clock', 'itemid')


class TrendsUint(BaseModel):
    clock = IntegerField()
    itemid = BigIntegerField()
    num = IntegerField()
    value_avg = BigIntegerField()
    value_max = BigIntegerField()
    value_min = BigIntegerField()

    class Meta:
        db_table = 'trends_uint'
        indexes = ((('itemid', 'clock'), True), )
        primary_key = CompositeKey('clock', 'itemid')


class TriggerDepends(BaseModel):
    triggerdepid = BigIntegerField(primary_key=True)
    triggerid_down = ForeignKeyField(
        db_column='triggerid_down', rel_model=Triggers, to_field='triggerid')
    triggerid_up = ForeignKeyField(
        db_column='triggerid_up',
        rel_model=Triggers,
        related_name='triggers_triggerid_up_set',
        to_field='triggerid')

    class Meta:
        db_table = 'trigger_depends'
        indexes = ((('triggerid_down', 'triggerid_up'), True), )


class TriggerDiscovery(BaseModel):
    parent_triggerid = ForeignKeyField(
        db_column='parent_triggerid', rel_model=Triggers, to_field='triggerid')
    triggerid = ForeignKeyField(
        db_column='triggerid',
        primary_key=True,
        rel_model=Triggers,
        related_name='triggers_triggerid_set',
        to_field='triggerid')

    class Meta:
        db_table = 'trigger_discovery'


class UsersGroups(BaseModel):
    id = BigIntegerField(primary_key=True)
    userid = ForeignKeyField(
        db_column='userid', rel_model=Users, to_field='userid')
    usrgrpid = ForeignKeyField(
        db_column='usrgrpid', rel_model=Usrgrp, to_field='usrgrpid')

    class Meta:
        db_table = 'users_groups'
        indexes = ((('usrgrpid', 'userid'), True), )
