#!/usr/bin/env python
# -*- coding:utf8 -*-

import base64
import hmac
import json
import urllib
import urllib2
import uuid
from hashlib import sha1
import collections
from helpers.logger import log_debug, log_error
from configs import aliyun_config
import datetime
import dateutil.parser
import time
from random import Random

BLOCK_TILL_RUNNING_SECS = 600


def abort(msg):
    raise Exception(msg)


class Error(Exception):
    pass


class Connection(object):
    def __init__(self, region_id='cn-hangzhou', service='cdn'):
        """Constructor.
        If the access and secret key are not provided the credentials are
        looked for in $HOME/.aliyun.cfg or /etc/aliyun.cfg.
        Args:
            region_id (str): The id of the region to connect to.
            service (str): The service to connect to. Current supported are:
                ecs, dns, slb.
            access_key_id (str): The access key id.
            secret_access_key (str): The secret access key.
        """
        if region_id is not None:
            self.region_id = region_id
        if not service:
            raise Exception('service is required')

        self.region_id = region_id
        if service == 'ecs':
            self.service = 'https://ecs.aliyuncs.com'
            self.version = '2014-05-26'
        elif service == 'slb':
            self.service = 'https://slb.aliyuncs.com'
            self.version = '2014-05-15'
        elif service == 'dns':
            self.service = 'https://dns.aliyuncs.com'
            self.version = '2015-01-09'
        elif service == 'rds':
            self.service = 'https://rds.aliyuncs.com'
            self.version = '2014-08-15'
        elif service == 'ess':
            self.service = 'https://ess.aliyuncs.com'
            self.version = '2014-08-28'
        elif service == 'cdn':
            self.service = 'https://cdn.aliyuncs.com'
            self.version = '2014-11-11'
        elif service == 'vpc':
            self.service = 'https://vpc.aliyuncs.com'
            self.version = '2016-04-28'
        else:
            raise NotImplementedError(
                'Currently only "ecs", "dns", "rds" and "slb" and "cdn" are supported.'
            )

        self.access_key_id = aliyun_config.get('access_key_id')
        self.secret_access_key = aliyun_config.get('secret_access_key')

        log_debug("%s connection to %s created", service, region_id)

    def _percent_encode(self, request, encoding=None):
        encoding = encoding or 'utf8'

        try:
            s = unicode(request, encoding)
        except TypeError:
            if not isinstance(request, unicode):
                # We accept int etc. types as well
                s = unicode(request)
            else:
                s = request

        res = urllib.quote(s.encode('utf8'), safe='~')
        return res

    def _compute_signature(self, parameters, encoding=None):
        sorted_params = sorted(parameters.items())

        # This is pretty convoluted. urllib.urlencode does almost the same
        # and is faster, so if we switched signature version we could do
        # that instead
        canonicalized_query_string = '&'.join([
            '%s=%s' % (self._percent_encode(k, encoding),
                       self._percent_encode(v, encoding))
            for k, v in sorted_params
        ])

        string_to_sign = 'GET&%2F&' + self._percent_encode(
            canonicalized_query_string, encoding)

        h = hmac.new(self.secret_access_key + "&", string_to_sign, sha1)
        signature = base64.b64encode(h.digest())
        return signature

    def _build_request(self, params, encoding=None):
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        # Use defaults...
        parameters = {
            'Format': 'JSON',
            'Version': self.version,
            'AccessKeyId': self.access_key_id,
            'SignatureVersion': '1.0',
            'SignatureMethod': 'HMAC-SHA1',
            'SignatureNonce': str(uuid.uuid4()),
            'TimeStamp': timestamp,
            'RegionId': self.region_id
        }
        # And overwrite some...
        parameters.update(params)
        # 'RegionId' is not needed for DNS requests
        if 'DomainName' in parameters:
            parameters.pop('RegionId')

        signature = self._compute_signature(parameters, encoding=encoding)
        parameters['Signature'] = signature

        url = "%s/?%s" % (self.service, urllib.urlencode(parameters))
        request = urllib2.Request(url)
        return request

    def _get(self, request):
        log_debug('URL requested: %s', request.get_full_url())
        try:
            conn = urllib2.urlopen(request)
            response = conn.read()
            encoding = conn.headers['content-type'].split('charset=')[-1]
            unicode_response = unicode(response, encoding)
            log_debug('URL response: %s', unicode_response)
            return json.loads(unicode_response)
        except urllib2.HTTPError as e:
            log_error('Error GETing URL: %s', request.get_full_url())
            raise Exception(e.read())

    def _get_remaining_pages(self, total_count):
        """Get the remaining pages for the given count.
        Args:
            total_count: The total count of items.
        """
        if total_count <= 50:
            return 0

        pages = (total_count - 50) / 50
        return (pages + 1 if ((total_count - 50) % 50) > 0 else pages)

    def _perform_paginated_queries(self, params):
        """Perform paginated queries with the given params.
        Args:
            params: The params for the queries, without the PageSize and
                PageNumber.
        Return:
            The list of responses - one response for each page.
        """
        responses = []
        params['PageSize'] = str(50)
        resp = self.get(params)
        total_count = resp['TotalCount']
        if total_count == 0:
            return [resp]

        responses.append(resp)

        remaining_pages = self._get_remaining_pages(total_count)
        i = 1
        while i <= remaining_pages:
            params['PageNumber'] = str(i + 1)
            responses.append(self.get(params))
            i += 1

        return responses

    def random_str(self, randomlength=30):
        str = ''
        chars = 'AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0123456789'
        length = len(chars) - 1
        random = Random()
        for i in range(randomlength):
            str += chars[random.randint(0, length)]
        return str

    def get(self, params, paginated=False, encoding=None):
        """Make a get request to the API.
        Args:
            params (dict): The parameters to the request. Keys and values
                           should be string types.
            paginated (bool): Should the results be paginated.
            encoding (str): Encoding of the parameters. By default reads
                            stdin encoding, or failing that default encoding,
                            or failing that utf8.
        Return:
            Parsed result.
        """
        if paginated:
            return self._perform_paginated_queries(params)

        request = self._build_request(params, encoding=encoding)
        return self._get(request)


class DnsConnection(Connection):
    """A connection to Aliyun DNS service.
    Args:
        region_id (str): NOT IN USE FOR DNS
                         But needed for backward comptibility
                         The id of the region to connect to.
        access_key_id (str): The access key id.
        secret_access_key (str): The secret access key.
    """

    def __init__(self,
                 region_id='cn-hangzhou',
                 access_key_id=None,
                 secret_access_key=None):
        super(DnsConnection, self).__init__(region_id, 'dns')

    def add_record(self, rr=None, rrtype='A', value=None, domainname=None):
        """
        Add a DNS record to specified Domain.
        Args:
            rr (str): Resource Record to add.
            value (str): The IP address of the RR.
            rrtype (str): Type of the Resource Record, A, PTR, CNAME for instance.
            domainname (str): The domain name the rr will be added into.

        Returns:
        """

        if rr is None or value is None:
            abort("ERROR: Both RR and its value MUST be supplied.")

        params = {'Action': 'AddDomainRecord', \
                  'Type': rrtype, \
                  'DomainName': domainname, \
                  'RR': rr, \
                  'value': value, \
                  }
        return self.get(params)

    def get_all_records(self, domainname=None):
        """
        Get all records of the Domain.
        Args:
            domainname (str): The domain name that all records belong.
        Returns: All records in the Domain.
        """
        all_records = []
        params = {'Action': 'DescribeDomainRecords', \
                  'DomainName': domainname, \
                  }

        for resp in self.get(params, paginated=True):
            for item in resp['DomainRecords']['Record']:
                all_records.append(item)
        return all_records

    def get_record_id(self, rr, value, rrtype='A', domainname=None):
        """
        Get the RecordId of the specified RR & Value pair.
        Args:
            rr (str): Resource Record to query, such as www
            value (str): The IP address of the RR
            rrtype (str): The Resource Record Type, such as A, CNAME, MX
            domainname (str): The domain name the rr will be added into
        Returns: The RecordId
        """

        if rr is None or value is None:
            abort("ERROR: Please specify the RR and its IP address.")

        params = {'Action': 'DescribeDomainRecords', \
                  'DomainName': domainname, \
                  'RRKeyWord': rr, \
                  'TypeKeyWord': rrtype, \
                  'ValueKeyWord': value, \
                  }
        return self.get(params)['DomainRecords']['Record'][0]['RecordId']

    def delete_record(self, rr=None, value=None, rrtype='A', domainname=None):
        """
        Delete the specified record.

        Args:
            rr (str): Resource Record to query, such as www
            value (str): The IP address of the RR.
            domainname (str): The domain name the rr will be added into.
        """

        if rr is None or value is None:
            abort("ERROR: Please specify the RR and its IP address.")

        record_id = self.get_record_id(rr, value, rrtype, domainname)
        if record_id:
            params = {'Action': 'DeleteDomainRecord', \
                      'RecordId': record_id, \
                      }
            return self.get(params)
        else:
            log_debug('No such record.')


class ScalingGroup(object):
    """Scaling Group for Aliyun ESS.
    Collection of automatically-managed ECS instances and their associations
    with SLB load balancer instances and RDS database instances.
    Args:
        scaling_group_id (str): Scaling Group ID from ESS.
        scaling_group_name (str): Name of the Scaling Group.
        active_scaling_configuration_id (str): ID of the associated
            :class:`.model.ScalingConfiguration`.
        region_id (str): ID of associated :class:`.model.Region`.
        min_size (int): Minimum number of ECS instances allowed.
        max_size (int): Maximum number of ECS instances allowed.
        default_cooldown (int): Number of seconds between scaling activities.
        removal_policies (list): List of removal policies. See
            :func:`.connection.EssConnection.create_scaling_group`.
        load_balancer_id (str): ID of associated
            :class:`aliyun.slb.model.LoadBalancer`.
        db_instance_ids (list): List of RDS DB Instance Ids
        lifecycle_state (str): Current lifecycle state. One of 'Inactive',
            'Active', or 'Deleting'.
        total_capacity (int): Total number of ECS instances managed in the
            scaling group.
        active_capacity (int): Number of ECS instances attached and running in
            the scaling group.
        pending_capacity (int): Number of ECS instances joining the group.
        removing_capacity (int): Number of ECS instances leaving the group and
            being released.
        creation_time (datetime): Time the scaling group was created.
    """

    def __init__(self, scaling_group_id, scaling_group_name,
                 active_scaling_configuration_id, region_id, min_size,
                 max_size, default_cooldown, removal_policies,
                 load_balancer_id, db_instance_ids, lifecycle_state,
                 total_capacity, active_capacity, pending_capacity,
                 removing_capacity, creation_time):

        self.scaling_group_id = scaling_group_id
        self.scaling_group_name = scaling_group_name
        self.active_scaling_configuration_id = active_scaling_configuration_id
        self.region_id = region_id
        self.min_size = min_size
        self.max_size = max_size
        self.default_cooldown = default_cooldown
        self.removal_policies = removal_policies
        self.load_balancer_id = load_balancer_id
        self.db_instance_ids = db_instance_ids
        self.lifecycle_state = lifecycle_state
        self.total_capacity = total_capacity
        self.active_capacity = active_capacity
        self.pending_capacity = pending_capacity
        self.removing_capacity = removing_capacity
        self.creation_time = creation_time

    def __repr__(self):
        return u'<ScalingGroup {name} ({id}) at {mem}'.format(
            name=self.scaling_group_name,
            id=self.scaling_group_id,
            mem=id(self))

    def __eq__(self, other):
        print self.__dict__
        print other.__dict__
        return (self.__class__ == other.__class__ and
                self.__dict__ == other.__dict__)


class EssConnectionError(Error):
    pass


class EssConnection(Connection):
    """A connection to Aliyun ESS service.
    Args:
        region_id (str): The id of the region to connect to.
        access_key_id (str): The Aliyun API Access Key ID.
        secret_access_key (str): The Aliyun API Secret Access Key
    """

    ACTIONS = [
        'CreateScalingGroup', 'ModifyScalingGroup', 'DescribeScalingGroups',
        'EnableScalingGroup', 'DisableScalingGroup', 'DeleteScalingGroup',
        'DescribeScalingInstances', 'CreateScalingConfiguration',
        'DescribeScalingConfigurations', 'DeleteScalingConfigurations',
        'CreateScalingRule', 'ModifyScalingRule', 'DescribeScalingRules',
        'DeleteScalingRule', 'ExecuteScalingRule', 'AttachInstances',
        'RemoveInstances', 'CreateScheduledTask', 'ModifyScheduledTask',
        'DescribeScheduledTasks', 'DeleteScheduledTask',
        'DescribeScalingActivities'
    ]

    def __init__(self, region_id, access_key_id=None, secret_access_key=None):
        super(EssConnection, self).__init__(region_id, 'ess')

    def create_scaling_group(self,
                             max_size,
                             min_size,
                             scaling_group_name=None,
                             default_cooldown=None,
                             removal_policies=None,
                             load_balancer_id=None,
                             db_instance_ids=None):
        """Create a scaling group.
        Create a collection of ECS instances with a minimum and maximum number.
        A load balancer and multiple database instances can be kept in-sync
        with the changes in the instances.
        Args:
            max_size (int): Maximum number of ECS instances. Between 0 and 100.
            min_size (int): Minimum number of ECS instances. Between 0 and 100.
            scaling_group_name (str): Name of the scaling group.
            default_cooldown (int): Number of seconds to wait between scaling
                activities. Between 0 and 86400, ESS default of 300.
            removal_policies (list): List of removal policies. Choices are:
                OldestInstance, NewestInstance, OldestScalingConfiguration.
                ESS default is ['OldestScalingConfiguration', 'OldestInstance']
            load_balancer_id (str): ID of associated
                :class:`aliyun.slb.model.LoadBalancer`.
            db_instance_ids (list): List of up to 3 RDS database instances.
        """
        params = {
            'Action': 'CreateScalingGroup',
            'MaxSize': max_size,
            'MinSize': min_size
        }

        if scaling_group_name:
            params['ScalingGroupName'] = scaling_group_name
        if default_cooldown:
            params['DefaultCooldown'] = default_cooldown
        if removal_policies and isinstance(removal_policies, list):
            for n, policy in enumerate(removal_policies):
                params['RemovalPolicy.' + str(n + 1)] = policy
        if load_balancer_id:
            params['LoadBalancerId'] = load_balancer_id
        if db_instance_ids and isinstance(db_instance_ids, list):
            for n, db in enumerate(db_instance_ids):
                params['DBInstanceId.' + str(n + 1)] = db

        return self.get(params)

    def modify_scaling_group(self,
                             scaling_group_id,
                             scaling_group_name=None,
                             active_scaling_configuration_id=None,
                             min_size=None,
                             max_size=None,
                             default_cooldown=None,
                             removal_policies=None):
        '''Modify an existing Scaling Group.
        Adjust an existing scaling group's name, configuration, size, cooldown,
        or removal policy. Leave parameters blank to leave the value unchanged
        in the scaling group.
        Args:
            scaling_group_id (str): ID of the ScalingGroup to modify.
            scaling_group_name (str): New name of the scaling group.
            active_scaling_configuration_id (str): ID of the desired
                configuration.
            min_size (int): The new minimum size.
            max_size (int): The new maximum size.
            default_cooldown (int): The new time between scaling activities.
            removal_policies (list): The new list of instance removal policies.
        '''
        params = {
            'Action': 'ModifyScalingGroup',
            'ScalingGroupId': scaling_group_id
        }
        if scaling_group_name:
            params['ScalingGroupName'] = scaling_group_name
        if active_scaling_configuration_id:
            params[
                'ActiveScalingConfigurationId'] = active_scaling_configuration_id  # NOQA
        if min_size:
            params['MinSize'] = min_size
        if max_size:
            params['MaxSize'] = max_size
        if default_cooldown:
            params['DefaultCooldown'] = default_cooldown
        if removal_policies and isinstance(removal_policies, list):
            for n, policy in enumerate(removal_policies):
                params['RemovalPolicy.' + str(n + 1)] = policy

        return self.get(params)

    def describe_scaling_groups(self,
                                scaling_group_ids=None,
                                scaling_group_names=None):
        '''Describe scaling groups, optionally with specific IDs or names.
        Args:
            scaling_group_ids (list): List of scaling group IDs to find.
            scaling_group_names (list): List of scaling group names to find.
        Return: list of :class:`.model.ScalingGroup`'''

        params = {'Action': 'DescribeScalingGroups'}
        if scaling_group_ids and isinstance(scaling_group_ids, list):
            for n, scaling_group_id in enumerate(scaling_group_ids):
                params['ScalingGroupId.' + str(n + 1)] = scaling_group_id

        if scaling_group_names and isinstance(scaling_group_names, list):
            for n, scaling_group_name in enumerate(scaling_group_names):
                params['ScalingGroupName.' + str(n + 1)] = scaling_group_name
        groups = []
        for page in self.get(params, paginated=True):
            for g in page['ScalingGroups']['ScalingGroups']:
                groups.append(
                    ScalingGroup(
                        scaling_group_id=g['ScalingGroupId'],
                        scaling_group_name=g['ScalingGroupName'],
                        active_scaling_configuration_id=g[
                            'ActiveScalingConfigurationId'],  # NOQA
                        region_id=g['RegionId'],
                        min_size=g['MinSize'],
                        max_size=g['MaxSize'],
                        default_cooldown=g['DefaultCooldown'],
                        removal_policies=g['RemovalPolicies']['RemovalPolicy'],
                        load_balancer_id=g['LoadBalancerId'],
                        db_instance_ids=g.get('DBInstanceIds', {}).get(
                            'DBInstanceId', None),
                        lifecycle_state=g['LifecycleState'],
                        total_capacity=g['TotalCapacity'],
                        active_capacity=g['ActiveCapacity'],
                        pending_capacity=g['PendingCapacity'],
                        removing_capacity=g['RemovingCapacity'],
                        creation_time=dateutil.parser.parse(g[
                            'CreationTime'])))
        return groups

    def get_all_scaling_group_ids(self,
                                  scaling_group_ids=None,
                                  scaling_group_names=None):
        '''Get IDs of all existing scaling groups.
        This is a wrapper around :func:`.describe_scaling_groups`.
        Args:
            scaling_group_ids (list): Optional list of ids to find ids... for.
            scaling_group_names (list): Optional list of names to find ids for.
        Return: list of :class:`.model.ScalingGroup` IDs.'''

        groups = self.describe_scaling_groups(
            scaling_group_ids=scaling_group_ids,  # NOQA
            scaling_group_names=scaling_group_names)  # NOQA
        return [g.scaling_group_id for g in groups]


class Region(object):
    def __init__(self, region_id, local_name):
        """Constructor.
        Args:
            region_id (str): The id of the region.
            local_name (str): The local name of the region.
        """
        self.region_id = region_id
        self.local_name = local_name

    def __repr__(self):
        return u'<Region %s (%s) at %s>' % (self.region_id, self.local_name,
                                            id(self))

    def __eq__(self, other):
        return (self.__class__ == other.__class__ and
                self.__dict__ == other.__dict__)


class Instance(object):
    """An Aliyun ECS instance."""

    def __init__(self, instance_id, name, image_id, region_id, instance_type,
                 hostname, status, security_group_ids, public_ip_addresses,
                 internal_ip_addresses, internet_charge_type,
                 internet_max_bandwidth_in, internet_max_bandwidth_out,
                 creation_time, expired_time, instance_charge_type,
                 description, cluster_id, operation_locks, zone_id):
        """"Constructor.
        Args:
            instance_id (str): The id of the instance.
            name (str): The name of the instance.
            image_id (str): The id of the image used to create the instance.
            region_id (str): The id of the region in which the instance lies.
            instance_type (str): The type of the instance.
            hostname (str): The hostname of the instance.
            status (str): The status of the instance.
            security_group_ids (list): The security group ids for the instance.
            public_ip_addresses (list): Its public ip addresses.
            internal_ip_addresses (list): Its internal ip addresses.
            internet_charge_type (str): The accounting method of network use.
            internet_max_bandwidth_in (int): The max incoming bandwidth.
            internet_max_bandwidth_out (int): The max outgoing bandwidth.
            creation_time (datetime): Its creation time.
            expired_time (datetime): The expired time for PrePaid instances.
            instance_charge_type: The charge type of instance, either PrePaid or PostPaid.
            description (str): A long description of the instance.
            operation_locks (list of str): Any held operation locks. 'security'
                                           and/or 'financial'
            zone_id (str): The ID of the Availability Zone this instance is in.
        """
        self.instance_id = instance_id
        self.name = name
        self.image_id = image_id
        self.region_id = region_id
        self.instance_type = instance_type
        self.hostname = hostname
        self.status = status
        self.security_group_ids = security_group_ids
        self.public_ip_addresses = public_ip_addresses
        self.internal_ip_addresses = internal_ip_addresses
        self.internet_charge_type = internet_charge_type
        self.internet_max_bandwidth_in = internet_max_bandwidth_in
        self.internet_max_bandwidth_out = internet_max_bandwidth_out
        self.creation_time = creation_time
        self.expired_time = expired_time
        self.instance_charge_type = instance_charge_type
        self.description = description
        self.operation_locks = operation_locks
        self.zone_id = zone_id

    def __repr__(self):
        return '<Instance %s at %s>' % (self.instance_id, id(self))

    def __eq__(self, other):
        return (self.__class__ == other.__class__ and
                self.__dict__ == other.__dict__)


class InstanceStatus(object):
    def __init__(self, instance_id, status):
        """Constructor.
        Args:
            instance_id (str): The id of the instance.
            status (str): The status of the instance.
        """
        self.instance_id = instance_id
        self.status = status

    def __repr__(self):
        return u'<InstanceId %s is %s at %s>' % (self.instance_id, self.status,
                                                 id(self))

    def __eq__(self, other):
        return (self.__class__ == other.__class__ and
                self.__dict__ == other.__dict__)


class InstanceType(object):
    def __init__(self, instance_type_id, cpu_core_count, memory_size):
        """Constructor.
        Args:
            instance_type_id (str): The instance type id.
            cpu_core_count (int): The number of cpus.
            memory_size (int): The memory size in GB.
        """
        self.instance_type_id = instance_type_id
        self.cpu_core_count = cpu_core_count
        self.memory_size = memory_size

    def __repr__(self):
        return u'<InstanceType %s has %s cores and %sGB memory at %s>' % (
            self.instance_type_id, self.cpu_core_count, self.memory_size,
            id(self))

    def __eq__(self, other):
        return (self.__class__ == other.__class__ and
                self.__dict__ == other.__dict__)


class Snapshot(object):
    def __init__(self,
                 snapshot_id,
                 snapshot_name,
                 progress,
                 creation_time,
                 description=None,
                 source_disk_id=None,
                 source_disk_type=None,
                 source_disk_size=None):
        """Snapshot for ECS Disk.
        snapshot_id (str): The id of the snapshot.
        snapshot_name (str): The name of the snapshot.
        progress (int): The progress ready percentage.
        creation_time (datetime): Its creation time.
        source_disk_id (str): ID of the original disk.
        source_disk_type (str): "data" or "system", for the original disk.
        source_disk_size (int): size of the original disk in GB.
        """
        self.snapshot_id = snapshot_id
        self.snapshot_name = snapshot_name
        self.progress = progress
        self.creation_time = creation_time
        self.source_disk_id = source_disk_id
        self.source_disk_type = source_disk_type
        self.source_disk_size = source_disk_size

    def __repr__(self):
        return u'<Snapshot %s is %s%% ready at %s>' % (self.snapshot_id,
                                                       self.progress, id(self))

    def __eq__(self, other):
        print self.__dict__
        print other.__dict__
        return (self.__class__ == other.__class__ and
                self.__dict__ == other.__dict__)


class AutoSnapshotPolicy(object):
    def __init__(self, system_disk_enabled, system_disk_time_period,
                 system_disk_retention_days, system_disk_retention_last_week,
                 data_disk_enabled, data_disk_time_period,
                 data_disk_retention_days, data_disk_retention_last_week):
        '''AutoSnapshotPolicy describing how to manage snapshot rotation.
        The policy is composed of a system- and data-disk policy, but the API
        does not handle them independently, so this object combines them too.
        Arguments:
            system_disk_enabled (bool): wether the policy is on for SystemDisk
            system_disk_time_period (int): the time period during which to
                                           auto-snapshot. There are 4 choices:
                                           1, 2, 3 or 4. These correspond to
                                           these time periods:
                                           1: 1:00 - 7:00
                                           2: 7:00 - 13:00
                                           3: 13:00 - 19:00
                                           4: 19:00 - 1:00
                                           All times Beijing Time.
            system_disk_retention_days (int): number of days to retain.
                                              must be between 1 and 3, inclusive
            system_disk_retention_last_week (bool): wether to retain a weekly
                                                    snapshot from Sundays.
            data_disk_enabled (bool): wether the policy is on for DataDisk
            data_disk_time_period (int): the time period during which to
                                         auto-snapshot. There are 4 choices: 1,
                                         2, 3 or 4. These correspond to these
                                         time periods:
                                         1: 1:00 - 7:00
                                         2: 7:00 - 13:00
                                         3: 13:00 - 19:00
                                         4: 19:00 - 1:00
                                         All times Beijing Time.
            data_disk_retention_days (int): number of days to retain.
                                              must be between 1 and 3, inclusive
            data_disk_retention_last_week (bool): wether to retain a weekly
                                                    snapshot from Sundays.
        '''
        self.system_disk_enabled = system_disk_enabled
        self.system_disk_time_period = system_disk_time_period
        self.system_disk_retention_days = system_disk_retention_days
        self.system_disk_retention_last_week = system_disk_retention_last_week
        self.data_disk_enabled = data_disk_enabled
        self.data_disk_time_period = data_disk_time_period
        self.data_disk_retention_days = data_disk_retention_days
        self.data_disk_retention_last_week = data_disk_retention_last_week

    def __repr__(self):
        return u'<AutoSnapshotPolicy at %s>' % id(self)

    def __eq__(self, other):
        print self.__dict__
        print other.__dict__
        return (self.__class__ == other.__class__ and
                self.__dict__ == other.__dict__)


class AutoSnapshotExecutionStatus(object):
    def __init__(self, system_disk_execution_status,
                 data_disk_execution_status):
        '''Description of the status of the auto-snapshot policy's executions.
        The arguments are either 'Standby', 'Executed', or 'Failed'.
            Standby: The policy is created, but disabled.
            Executed: The latest auto-snapshot was successful.
            Failed: The latest auto-snapshot was unsuccessful.
        These are separated by system- or data-disk types since they can work
        independently.
        Args:
            system_disk_execution_status (str): Standby|Executed|Failed
            data_disk_execution_status (str): Standby|Executed|Failed
        '''

        self.system_disk_execution_status = system_disk_execution_status
        self.data_disk_execution_status = data_disk_execution_status

    def __repr__(self):
        return u'<AutoSnapshotExecutionStatus at %s>' % id(self)

    def __eq__(self, other):
        return (self.__class__ == other.__class__ and
                self.__dict__ == other.__dict__)


class AutoSnapshotPolicyStatus(object):
    def __init__(self, status, policy):
        self.status = status
        self.policy = policy

    def __repr__(self):
        return u'<AutoSnapshotPolicyStatus at %s>' % id(self)

    def __eq__(self, other):
        return (self.__class__ == other.__class__ and
                self.__dict__ == other.__dict__)


class Disk(object):
    def __init__(self,
                 disk_id,
                 disk_type,
                 disk_category,
                 disk_size,
                 attached_time=None,
                 creation_time=None,
                 delete_auto_snapshot=None,
                 delete_with_instance=None,
                 description=None,
                 detached_time=None,
                 device=None,
                 image_id=None,
                 instance_id=None,
                 operation_locks=None,
                 portable=None,
                 product_code=None,
                 snapshot_id=None,
                 status=None,
                 zone_id=None):
        """ECS Disk object. Required arguments are always required when creating
        an ECS disk.
        Args:
            disk_id (str): The id of the disk.
            disk_type (str): The type of disk.
                Values can be system or data.
            disk_category (str): The category of the disk.
                Values can be cloud, ephemeral
            disk_size (int): Its size in GB.
            attached_time (datetime): The time the disk was last attached.
            creation_time (datetime): The time the disk was created.
            delete_auto_snapshot (bool): Whether the AutoSnapshotPolicy will be
                                         deleted with the disk.
            delete_with_instance (bool): Whether the Disk will be deleted with
                                         its associated Instance.
            description (str): A long description of the disk.
            detached_time (datetie): The time the disk was last detached.
            device (str): The device path if attached. E.g. /dev/xvdb
            image_id (str): The Image id the Disk was created with.
            instance_id (str): The Instance id the disk is attached to.
            operation_locks (list): The locks on the resource. It can be
                                    'Financial' and/or 'Security'.
            portable (bool): Whether the Disk can be detached and re-attached
                             elsewhere.
            product_code (str): ID of the Disk in the ECS Mirror Market.
            snapshot_id (str): ID of the snapshot the Disk was created from.
            status (str): The status of the disk. E.g. "In_use", "Creating", &c.
            zone_id (str): The Availability Zone of the Disk.
        """
        if operation_locks is None:
            operation_locks = []
        self.disk_id = disk_id
        self.disk_type = disk_type
        self.disk_category = disk_category
        self.disk_size = disk_size
        self.attached_time = attached_time
        self.creation_time = creation_time
        self.delete_auto_snapshot = delete_auto_snapshot
        self.delete_with_instance = delete_with_instance
        self.description = description
        self.detached_time = detached_time
        self.device = device
        self.image_id = image_id
        self.instance_id = instance_id
        self.operation_locks = operation_locks
        self.portable = portable
        self.product_code = product_code
        self.snapshot_id = snapshot_id
        self.status = status
        self.zone_id = zone_id

    def __repr__(self):
        return u'<Disk %s of type %s is %sGB at %s>' % (
            self.disk_id, self.disk_type, self.disk_size, id(self))

    def __eq__(self, other):
        print self.__dict__
        print other.__dict__
        return (self.__class__ == other.__class__ and
                self.__dict__ == other.__dict__)


class DiskMappingError(Exception):
    """DiskMappingError"""


class DiskMapping(object):
    def __init__(self,
                 category,
                 size=None,
                 snapshot_id=None,
                 name=None,
                 description=None,
                 device=None):
        """DiskMapping used to create and attach a disk to an instance.
        The disk can be created from either a size parameter or a snapshot_id.
        Different disk categories support different disk sizes, and snapshots
        need to be from the same category of disk you are creating. "cloud"
        disks support sizes between 5 and 2000 GB. "ephemeral" disks support 5
        to 1024 GB sizes.
        Args:
            category (str): "cloud" or "ephemeral". Usually "cloud". Check the
                            output of :method:`aliyun.ecs.connection.EcsConnection.describe_zones`
                            to see which categories of disks your zone supports.
            size (int): The size of the disk. Limits depend on category.
            snapshot_id (str): ID of :class:`.model.Snapshot` to create disk of.
            name (str): A short name for the disk, between 2 and 128 characters.
            description (str): A longer description of the disk. Between 2 and
                               256 characters.
            device (str): System device string. Leave None to defer to the system.
                          Valid choices are from /dev/xvdb to /dev/xvdz.
        Raises:
            DiskMappingError: If both size and snapshot are specified.
        """
        if None not in (size, snapshot_id):
            raise DiskMappingError(
                "DiskMapping does not support both size AND snapshot. Choose one."
            )

        self.category = category
        self.size = size
        self.snapshot_id = snapshot_id
        self.name = name
        self.description = description
        self.device = device

    def api_dict(self, ordinal=1):
        """Serialize for insertion into API request parameters.
        Args:
            ordinal (int): The number of the data disk to serialize as.
        Returns:
            dict: A dictionary of URL GET query parameters to create the disk.
                  E.g.::
                      {
                          'DataDisk.1.Category': 'cloud',
                          'DataDisk.1.Size': 2000
                      }
        """
        ddisk = 'DataDisk.%s.' % ordinal
        out = {ddisk + 'Category': self.category}
        if self.size:
            out[ddisk + 'Size'] = self.size
        if self.snapshot_id:
            out[ddisk + 'SnapshotId'] = self.snapshot_id
        if self.name:
            out[ddisk + 'DiskName'] = self.name
        if self.description:
            out[ddisk + 'Description'] = self.description
        if self.device:
            out[ddisk + 'Device'] = self.device

        return out

    def __repr__(self):
        return u'<DiskMapping %s type %s at %s>' % (self.name, self.category,
                                                    id(self))

    def __eq__(self, other):
        return (self.__class__ == other.__class__ and
                self.__dict__ == other.__dict__)


class Image(object):
    def __init__(self, image_id, image_version, name, description, size,
                 architecture, owner_alias, os_name):
        """Constructor.
        Args:
            image_id (str): The id of the image.
            image_version (str): The version of the image.
            name (str): Name of the image.
            description (str): The description.
            size (int): Its size in GB.
            architecture (str): The architecture - either i386 or x86_64.
            owner_alias (str): system, else or others.
            os_name (str): The os name.
        """
        self.image_id = image_id
        self.image_version = image_version
        self.description = description
        self.size = size
        self.architecture = architecture
        self.owner_alias = owner_alias
        self.os_name = os_name

    def __repr__(self):
        return u'<Image %s(%s) for platform %s and arch %s at %s>' % (
            self.image_id, self.description, self.os_name, self.architecture,
            id(self))

    def __eq__(self, other):
        return (self.__class__ == other.__class__ and
                self.__dict__ == other.__dict__)


class SecurityGroupInfo(object):
    def __init__(self, security_group_id, description):
        """Constructor.
        Args:
            security_group_id (str): The id of the security group.
            description (str): The description of the security group.
        """
        self.security_group_id = security_group_id
        self.description = description

    def __repr__(self):
        return u'<SecurityGroupInfo %s, %s at %s>' % (
            self.security_group_id, self.description, id(self))

    def __eq__(self, other):
        return (self.__class__ == other.__class__ and
                self.__dict__ == other.__dict__)


class SecurityGroupPermission(object):
    def __init__(self, ip_protocol, port_range, source_cidr_ip,
                 source_group_id, policy, nic_type):
        """Constructor.
        Args:
            ip_protocol (str): TCP, UDP, ICMP, GRE or ALL
            port_range (str): For tcp/udp range is 1 to 65535. Else -1/-1.
            source_cidr_ip (str): Source IP address range.
            source_group_id (str): Source security group.
            policy (str): Accept, Drop or Reject.
            nic_type (str): internet or intranet.
        """
        self.ip_protocol = ip_protocol
        self.port_range = port_range
        self.source_cidr_ip = source_cidr_ip
        self.source_group_id = source_group_id
        self.policy = policy
        self.nic_type = nic_type

    def __repr__(self):
        return u'<SecurityGroupPermission %s %s %s from %s at %s>' % (
            self.policy, self.ip_protocol, self.port_range, self.source_cidr_ip
            if self.source_cidr_ip else self.source_group_id, id(self))

    def __eq__(self, other):
        return (self.__class__ == other.__class__ and
                self.__dict__ == other.__dict__)


class SecurityGroup(object):
    def __init__(self, region_id, security_group_id, description, permissions):
        """Constructor.
        Args:
            region_id (str): The id of the region for the security group.
            security_group_id (str): The id of the security group.
            description (str): The description of the security group.
            permission (list): List of SecurityGroupPermission.
        """
        self.region_id = region_id
        self.security_group_id = security_group_id
        self.description = description
        self.permissions = permissions

    def __repr__(self):
        return u'<SecurityGroup %s, %s at %s>' % (self.security_group_id,
                                                  self.description, id(self))

    def __eq__(self, other):
        return (self.__class__ == other.__class__ and
                self.__dict__ == other.__dict__)


class Zone(object):
    def __init__(self,
                 zone_id,
                 local_name,
                 available_resource_creation=None,
                 available_disk_types=None):
        """Constructor.
        Args:
            zone_id (str): The id of the zone.
            local_name (str): The local name of the zone.
            available_resource_creation (list of 'Instance' and/or 'Disk'): The resource types which can be created in this zone.
            available_disk_types (list of 'cloud' and/or 'ephemeral'): The types of disks which can be created in the zone.
        """
        if available_resource_creation is None:
            available_resource_creation = []
        if available_disk_types is None:
            available_disk_types = []
        self.zone_id = zone_id
        self.local_name = local_name
        self.available_resource_creation = available_resource_creation
        self.available_disk_types = available_disk_types

    def __repr__(self):
        return u'<Zone %s (%s) at %s>' % (self.zone_id, self.local_name,
                                          id(self))

    def disk_supported(self, disk_type):
        """Convenience method to say whether a disk type is supported.
        Args:
            disk_type (str): either 'cloud' or 'ephemeral'.
        Returns:
            boolean
        """
        return disk_type in self.available_disk_types

    def resource_creation_supported(self, resource_type):
        """Convenience method to say whether a resource can be created.
        Args:
            resource_type (str): either 'Instance' or 'Disk'
        Returns:
            Boolean. True if the resource creation is supported.
        """
        return resource_type in self.available_resource_creation

    def __eq__(self, other):
        return (self.__class__ == other.__class__ and
                self.__dict__ == other.__dict__)


class EcsConnection(Connection):
    """A connection to Aliyun ECS service.
    Args:
        region_id (str): The id of the region to connect to.
        access_key_id (str): The access key id.
        secret_access_key (str): The secret access key.
    """

    def __init__(self, region_id, access_key_id=None, secret_access_key=None):
        super(EcsConnection, self).__init__(region_id, 'ecs')

    def get_all_regions(self):
        """Get all regions.
        Returns:
            list: A list of :class:`aliyun.ecs.model.Region`
        """
        resp = self.get({'Action': 'DescribeRegions'})
        regions = []
        for region in resp['Regions']['Region']:
            regions.append(Region(region['RegionId'], region['LocalName']))
        return regions

    def get_all_region_ids(self):
        """Get all the region ids.
        Returns:
            List of region ids.
        """
        return [x.region_id for x in self.get_all_regions()]

    def get_all_zones(self):
        """Get all availability zones in the region.
        Returns:
            List of :class:`.model.Zone`.
        """
        resp = self.get({'Action': 'DescribeZones'})
        zones = []
        for zone in resp['Zones']['Zone']:
            zid = zone['ZoneId']
            zname = zone['LocalName']
            resources = zone['AvailableResourceCreation']['ResourceTypes']
            disks = zone['AvailableDiskCategories']['DiskCategories']
            zones.append(Zone(zid, zname, resources, disks))
        return zones

    def get_all_zone_ids(self):
        """Get all availability zone ids in the region.
        Returns:
            List of zone id strings.
        """
        return [z.zone_id for z in self.get_all_zones()]

    def get_all_clusters(self):
        """Get a list of ECS clusters in the region.
        Returns:
            List of cluster IDs.
        """
        params = {'Action': 'DescribeClusters'}
        clusters = []
        for cluster in self.get(params)['Clusters']['Cluster']:
            clusters.append(cluster['ClusterId'])
        return clusters

    def get_all_instance_status(self, zone_id=None):
        """Get the instance statuses.
        Args:
            zone_id (str, optional): A specific zone id to get instances from.
        Returns:
            The list of :class:`.model.InstanceStatus`.
        """
        instance_status = []
        params = {'Action': 'DescribeInstanceStatus'}

        if zone_id is not None:
            params.update({'ZoneId': zone_id})

        for resp in self.get(params, paginated=True):
            for item in resp['InstanceStatuses']['InstanceStatus']:
                instance_status.append(
                    InstanceStatus(item['InstanceId'], item['Status']))
        return instance_status

    def get_all_instance_ids(self, zone_id=None):
        """Get all the instance ids in a region.
        Args:
            zone_id (str, optional): The Zone ID to get instance ids from.
        Returns:
            The list of instance ids.
        """
        return [x.instance_id for x in self.get_all_instance_status(zone_id)]

    def get_instance(self, instance_id):
        """Get an instance.
        Args:
            instance_id (str): The id of the instance.
        Returns:
            :class:`.model.Instance` if found.
        Raises:
            Error: if not found.
        """
        resp = self.get({
            'Action': 'DescribeInstanceAttribute',
            'InstanceId': instance_id
        })
        return Instance(
            resp['InstanceId'], resp['InstanceName'], resp['ImageId'],
            resp['RegionId'], resp['InstanceType'], resp['HostName'],
            resp['Status'],
            [x for x in resp['SecurityGroupIds']['SecurityGroupId']],
            [x for x in resp['PublicIpAddress']['IpAddress']],
            [x for x in resp['InnerIpAddress']['IpAddress']],
            resp['InternetChargeType'],
            int(resp['InternetMaxBandwidthIn']),
            int(resp['InternetMaxBandwidthOut']),
            dateutil.parser.parse(resp['CreationTime']),
            dateutil.parser.parse(resp['ExpiredTime']),
            resp['InstanceChargeType'], resp['Description'], resp['ClusterId'],
            [x for x in resp['OperationLocks']['LockReason']], resp['ZoneId'])

    def start_instance(self, instance_id):
        """Start an instance.
        Args:
            instance_id (str): The id of the instance.
        """
        self.get({'Action': 'StartInstance', 'InstanceId': instance_id})

    def stop_instance(self, instance_id, force=False):
        """Stop an instance.
        Args:
            instance_id (str): The id of the instance.
            force (bool): Whether to force stop the instance.
        """
        self.get({
            'Action': 'StopInstance',
            'InstanceId': instance_id,
            'ForceStop': 'true' if force else 'false'
        })

    def reboot_instance(self, instance_id, force=False):
        """Reboot an instance.
        Args:
            instance_id (str): The id of the instance.
            force (bool): Whether to force reboot the instance.
        """
        self.get({
            'Action': 'RebootInstance',
            'InstanceId': instance_id,
            'ForceStop': 'true' if force else 'false'
        })

    def delete_instance(self, instance_id):
        """Delete an instance.
        Args:
            instance_id (str): The id of the instance.
        """
        self.get({'Action': 'DeleteInstance', 'InstanceId': instance_id})

    def modify_instance(self,
                        instance_id,
                        new_instance_name=None,
                        new_password=None,
                        new_hostname=None,
                        new_security_group_id=None,
                        new_description=None):
        """Modify certain attributes of an instance.
        Only attributes that you want to modify should be specified.
        If you want to associated multiple security groups with an instance
        use the join_security_group method.
        Args:
            instance_id (str): The id of the instance.
            new_instance_name (str): The new instance name.
            new_password (str): The new root password for the instance.
                This requires a reboot to take effect.
            new_hostname (str): The new hostname for the instance.
            new_security_group_id (str): A single security group id.
            new_description (str): The new description for the instance.
        """
        params = {
            'Action': 'ModifyInstanceAttribute',
            'InstanceId': instance_id
        }
        if new_instance_name:
            params['InstanceName'] = new_instance_name
        if new_password:
            params['Password'] = new_password
        if new_hostname:
            params['HostName'] = new_hostname
        if new_security_group_id:
            params['SecurityGroupId'] = new_security_group_id
        if new_description:
            params['Description'] = new_description

        self.get(params)

    def modify_instance_spec(self,
                             instance_id,
                             instance_type=None,
                             internet_max_bandwidth_out=None,
                             internet_max_bandwidth_in=None):
        """NOT PUBLICLY AVAILABLE: Modify instance specification
        Modify an existing instance's instance type or in/out bandwidth limits.
        This API Action is restricted, so you may get an error when calling this
        method.
        Args:
            instance_id (str): The id fo the instance.
            instance_type (str): Use describe_instance_types for valid values.
            internet_max_bandwidth_out (int): Outbound bandwdith limit in Mbps.
                                              between 1 and 200, inclusive.
            internet_max_bandwidth_in (int): Inbound bandwdith limit in Mbps.
                                             between 1 and 200, inclusive.
        """
        params = {'Action': 'ModifyInstanceSpec', 'InstanceId': instance_id}

        if instance_type:
            params['InstanceType'] = instance_type
        if internet_max_bandwidth_out:
            params['InternetMaxBandwidthOut'] = internet_max_bandwidth_out
        if internet_max_bandwidth_in:
            params['InternetMaxBandwidthIn'] = internet_max_bandwidth_in

        self.get(params)

    def report_expiring_instance(self, days=7):
        """Report PrePaid instances that are about to expire in <days>.
        Args:
            days (int): Check instances that will expire in <days>.
        """
        expiring_instances = []
        all_instances = self.get_all_instance_ids()
        for ins in all_instances:
            res = self.get_instance(ins)
            if res.instance_charge_type == 'PrePaid':
                """
            tzinfo has to be the same as the one in instance.expired_time
            So we get it first, then provide it to now() as an arg
            """
                tz = res.expired_time.tzinfo
                now = datetime.datetime.now(tz)
                if (res.expired_time - now).days <= days:
                    expiring_instances.append(ins)

        return expiring_instances

    def renew_instance(self, instance_id, period=None):
        """Renew an PrePaid Instance.
        Args:
            instance_id (str): The id of the instance.
            period (int): The period of renewing an Instance, in month. Valid values are,
                                        - 1 - 9
                                    - 12
                                    - 24
                                    - 36
        """
        params = {'Action': 'RenewInstance', 'InstanceId': instance_id}

        if period is None:
            exit('Period Must be supplied. Valid values are [1-9, 12, 24, 36]')
        params['Period'] = period

        self.get(params)

    def replace_system_disk(self, instance_id, image_id):
        """Replace an Instance's system disk to the given Image.
        Args:
            instance_id (str): ID of the Instance to replace.
            image_id (str): ID of the Image to use for the new system disk.
        Returns:
            ID of the new disk.
        """
        return self.get({
            'Action': 'ReplaceSystemDisk',
            'InstanceId': instance_id,
            'ImageId': image_id
        })['DiskId']

    def join_security_group(self, instance_id, security_group_id):
        """Add an instance to a security group.
        Args:
            instance_id (str): The id of the instance.
            security_group_id (str): The id of the security_group.
        """
        self.get({
            'Action': 'JoinSecurityGroup',
            'InstanceId': instance_id,
            'SecurityGroupId': security_group_id
        })

    def leave_security_group(self, instance_id, security_group_id):
        """Remove an instance from a security group.
        Args:
            instance_id (str): The id of the instance.
            security_group_id (str): The id of the security_group.
        """
        self.get({
            'Action': 'LeaveSecurityGroup',
            'InstanceId': instance_id,
            'SecurityGroupId': security_group_id
        })

    def create_disk(self,
                    zone_id,
                    name=None,
                    description=None,
                    size=None,
                    snapshot_id=None):
        """Create a non-durable disk.
        A new disk will be created and can be managed independently of instance.
        Either size or snapshot_id must be specified, but not both. If
        snapshot_id is specified, the size will be taken from the snapshot.
        If the snapshot referenced was created before 15 July, 2013, the API
        will throw an error of InvalidSnapshot.TooOld.
        Args:
            zone_id (str): the Availability Zone to create the disk in. This is
                           required and cannot be changed. E.g. cn-hangzhou-a.
            name (str): A short name for the disk.
            description (str): A longer description of the disk.
            size (int): Size of the disk in GB. Must be in the range [5-2048].
            snapshot_id (str): The snapshot ID to create a disk from.
                               If used, the size will be taken from the snapshot
                               and the given size will be disregarded.
        Returns:
            (str): The ID to reference the created disk.
        """
        if size is not None and snapshot_id is not None:
            raise Error("Use size or snapshot_id. Not both.")

        params = {'Action': 'CreateDisk', 'ZoneId': zone_id}

        if size is not None:
            params['Size'] = size

        if snapshot_id is not None:
            params['SnapshotId'] = snapshot_id

        if name is not None:
            params['DiskName'] = name

        if description is not None:
            params['Description'] = description

        return self.get(params)['DiskId']

    def attach_disk(self,
                    instance_id,
                    disk_id,
                    device=None,
                    delete_with_instance=None):
        """Attach an existing disk to an existing instance.
        The disk and instance must already exist. The instance must be in the
        Stopped state, or the disk will be attached at next reboot.
        The disk will be attached at the next available drive letter (e.g.
        in linux, /dev/xvdb if only /dev/xvda exists). It will be a raw and
        un-formatted block device.
        Args:
            instance_id (str): ID of the instance to add the disk to.
            disk_id (str): ID of the disk to delete.
            device (str): The full device path for the attached device. E.g.
                          /dev/xvdb. Valid values: /dev/xvd[b-z].
            delete_with_instance (bool): Whether to delete the disk when its
                                         associated instance is deleted.
        """

        params = {
            'Action': 'AttachDisk',
            'InstanceId': instance_id,
            'DiskId': disk_id
        }
        if device is not None:
            params['Device'] = device
        if delete_with_instance is not None:
            params['DeleteWithInstance'] = delete_with_instance

        self.get(params)

    def detach_disk(self, instance_id, disk_id):
        """Detach an existing disk from an existing instance.
        Args:
            instance_id (str): ID of the instance to add the disk to.
            disk_id (str): ID of the disk to delete.
        """

        self.get({
            'Action': 'DetachDisk',
            'InstanceId': instance_id,
            'DiskId': disk_id
        })

    def add_disk(self,
                 instance_id,
                 size=None,
                 snapshot_id=None,
                 name=None,
                 description=None,
                 device=None,
                 delete_with_instance=None):
        """Create and attach a non-durable disk to an instance.
        This is convenience method, combining create_disk and attach_disk.
        A new disk will be allocated for the instance and attached as the next
        available disk letter to the OS. The disk is a plain block device with
        no partitions nor filesystems.
        Either size or snapshot_id must be specified, but not both. If
        snapshot_id is specified, the size will be taken from the snapshot.
        If the snapshot referenced was created before 15 July, 2013, the API
        will throw an error of InvalidSnapshot.TooOld.
        Args:
            instance_id (str): ID of the instance to add the disk to.
            size (int): Size of the disk in GB. Must be in the range [5-2048].
            snapshot_id (str): The snapshot ID to create a disk from.
                               If used, the size will be taken from the snapshot
                               and the given size will be disregarded.
            name (str): A short name for the disk.
            description (str): A longer description of the disk.
            device (str): The full device path for the attached device. E.g.
                          /dev/xvdb. Valid values: /dev/xvd[b-z].
            delete_with_instance (bool): Whether to delete the disk when its
        Returns:
            disk_id (str): the ID to reference the created disk.
        Raises:
            Error: if size and snapshot_id are used.
            Error: InvalidSnapshot.TooOld if referenced snapshot is too old.
        """

        zone = self.get_instance(instance_id).zone_id
        disk = self.create_disk(zone, name, description, size, snapshot_id)
        self.attach_disk(instance_id, disk, device, delete_with_instance)

        return disk

    def reset_disk(self, disk_id, snapshot_id):
        """Reset a disk to its snapshot.
        Args:
            disk_id (str): Disk ID to reset.
            snapshot_id (str): ID of snapshot to reset the disk to.
        """
        self.get({
            'Action': 'ResetDisk',
            'DiskId': disk_id,
            'SnapshotId': snapshot_id
        })

    def delete_disk(self, disk_id):
        """Delete a disk from an instance.
        If the instance state is running, the disk will be removed after reboot.
        If the instance state is stopped, the disk will be removed immediately.
        Args:
            instance_id (str): ID of the instance to delete a disk from.
            disk_id (str): ID of the disk to delete.
        """

        self.get({'Action': 'DeleteDisk', 'DiskId': disk_id})

    def create_instance(self,
                        image_id,
                        instance_type,
                        security_group_id,
                        instance_name=None,
                        internet_max_bandwidth_in=None,
                        internet_max_bandwidth_out=None,
                        hostname=None,
                        password=None,
                        system_disk_type=None,
                        internet_charge_type=None,
                        instance_charge_type='PrePaid',
                        period=1,
                        io_optimized=None,
                        data_disks=None,
                        description=None,
                        zone_id=None):
        """Create an instance.
            Args:
                image_id (str): Which image id to use.
                instance_type (str): The type of the instance.
                    To see options use describe_instance_types.
                security_group_id (str): The security group id to associate.
                instance_name (str): The name to use for the instance.
                internet_max_bandwidth_in (int): Max bandwidth in.
                internet_max_bandwidth_out (int): Max bandwidth out.
            instance_charge_type (str): The charge type of the instance, 'PrePaid' or 'PostPaid'.
            period (int): The time period of the 'PrePaid' instances.
            io_optimized (str): Specify if the instance is IO optimized instance
                                - None (default)
                        - optimized
                hostname (str): The hostname to assign.
            password (str): The root password to assign.
            system_disk_type (str): cloud, ephemeral or ephemeral_hio.
                Default: cloud.
            internet_charge_type (str): PayByBandwidth or PayByTraffic.
                Default: PayByBandwidth.
            data_disks (list): List of *args or **kwargs to :class:`DiskMapping`
            description (str): A long description of the instance.
            zone_id (str): An Availability Zone in the region to put the instance in.
                E.g. 'cn-hangzhou-b'
        Returns:
            The id of the instance created.
        The data_disks argument is passed as *args (if not a dict) or **kwargs
        (if it is a dict) to create a new :class:`.model.DiskMapping`. To create
        two fully-specified data disks::
            [{
               'category': 'ephemeral',
               'size': 200,
               'name': 'mydiskname',
               'description': 'my disk description',
               'device': '/dev/xvdb'
            },
            {
               'category': 'ephemeral',
               'snapshot_id': 'snap-1234',
               'name': 'mydiskname',
               'description': 'my disk description',
               'device': '/dev/xvdb'
            }]
        To create two minimally-specified data disks of 2000GB each:::
            [('cloud', 2000), ('cloud', 2000)]
        The API supports up to 4 additional disks, each up to 2000GB, so to get
        the maximum disk space at instance creation, this should do the trick::
            [
                {'category': 'cloud', 'size': 2000},
                {'category': 'cloud', 'size': 2000},
                {'category': 'cloud', 'size': 2000},
                {'category': 'cloud', 'size': 2000}
            ]
        """
        if data_disks is None:
            data_disks = []
        params = {
            'Action': 'CreateInstance',
            'ImageId': image_id,
            'InstanceType': instance_type,
            'SecurityGroupId': security_group_id
        }
        if instance_name:
            params['InstanceName'] = instance_name
        if internet_max_bandwidth_in:
            params['InternetMaxBandwidthIn'] = str(internet_max_bandwidth_in)
        if internet_max_bandwidth_out:
            params['InternetMaxBandwidthOut'] = str(internet_max_bandwidth_out)
        if io_optimized:
            params['IoOptimized'] = io_optimized
        if hostname:
            params['HostName'] = hostname
        if password:
            params['Password'] = password
        if system_disk_type:
            params['SystemDisk.Category'] = system_disk_type
        if internet_charge_type:
            params['InternetChargeType'] = internet_charge_type
        # Instance charge type & period
        if instance_charge_type == 'PostPaid':
            params['InstanceChargeType'] = 'PostPaid'
        elif instance_charge_type == 'PrePaid':
            params['InstanceChargeType'] = 'PrePaid'
            if not period or period not in [
                    1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 24, 36
            ]:
                exit(
                    "ERROR: PrePaid instances Must have a predefined period, in month [ 1-9, 12, 24, 36 ]"
                )
            else:
                params['Period'] = period
        else:
            exit(
                "InstanceChargeType is null. It is either PrePaid, or PostPaid")
        if data_disks:
            for i, disk in enumerate(data_disks):
                if isinstance(disk, dict):
                    ddisk = DiskMapping(**disk)
                else:
                    ddisk = DiskMapping(*disk)

                params.update(ddisk.api_dict(i + 1))

        if description:
            params['Description'] = description
        if zone_id:
            params['ZoneId'] = zone_id

        return self.get(params)['InstanceId']

    def allocate_public_ip(self, instance_id):
        """Allocate and assign a public IP address to an instance.
        Args:
            instance_id (str): instance ID to add a public IP to.
        Returns:
            the public IP allocated to the instance.
        """
        return self.get({
            'Action': 'AllocatePublicIpAddress',
            'InstanceId': instance_id
        })

    def create_and_start_instance(self,
                                  image_id,
                                  instance_type,
                                  initial_security_group_id,
                                  additional_security_group_ids=[],
                                  instance_name=None,
                                  internet_max_bandwidth_in=None,
                                  internet_max_bandwidth_out=None,
                                  hostname=None,
                                  password=None,
                                  system_disk_type=None,
                                  internet_charge_type=None,
                                  instance_charge_type='PrePaid',
                                  period=1,
                                  assign_public_ip=True,
                                  block_till_ready=True,
                                  data_disks=None,
                                  description=None,
                                  zone_id=None):
        """Create and start an instance.
        This is a convenience method that does more than just create_instance.
        You can specify a list of security groups (5 total) and the method also
        starts the instance. It can optionally block for the instance to be
        running - by default it does block.
        Specifying additional data disks is covered in :func:`create_instance`.
        Args:
            image_id (str): Which image id to use.
            instance_type (str): The type of the instance.
                To see options use describe_instance_types.
            initial_security_group_id (str): The security group id on creation.
            additional_security_group_ids (list): Additional security groups to
                use. Note: Max size 4.
            instance_name (str): The name to use for the instance.
            internet_max_bandwidth_in (int): Max bandwidth in.
            internet_max_bandwidth_out (int): Max bandwidth out.
            instance_charge_type (str): The charge type of the instance, 'PrePaid' or 'PostPaid'.
            period (int): The time period of the 'PrePaid' instances.
            hostname (str): The hostname to assign.
            password (str): The root password to assign.
            system_disk_type (str): cloud, ephemeral or ephemeral_hio.
                Default: cloud.
            internet_charge_type (str): PayByBandwidth or PayByTraffic.
                Default: PayByBandwidth.
            assign_public_ip (bool): Whether the instance should get assigned
                a public ip address. Default: True.
            block_till_ready (bool): Whether to block till the instance is
                running. Default: True.
            data_disks (list): List of dictionaries defining additional data
                disk device mappings.
                Minimum example: [{'category': 'cloud', 'size': 1024}]
            description (str): A long description of the instance.
            zone_id (str): An Availability Zone in the region to put the instance in.
                E.g. 'cn-hangzhou-b'
        Returns:
            The id of the instance created.
        Raises:
            Error: if more then 4 additional security group ids specified.
            Error: if timeout while waiting for instance to be running.
        The data_disks device mapping dictionary describes the same Disk
        attributes as :func:`create_disk`::
            [{
               'category': 'ephemeral',
               'size': 200,
               'name': 'mydiskname',
               'description': 'my disk description',
               'device': '/dev/xvdb'
            },
            {
               'category': 'ephemeral',
               'snapshot_id': 'snap-1234',
               'name': 'mydiskname',
               'description': 'my disk description',
               'device': '/dev/xvdb'
            }]
        The API supports up to 4 additional disks, each up to 1TB, so to get the
        maximum disk space at instance creation, this should do the trick::
            [
                {'category': 'cloud', 'size': 1024},
                {'category': 'cloud', 'size': 1024},
                {'category': 'cloud', 'size': 1024},
                {'category': 'cloud', 'size': 1024}
            ]
        """
        if data_disks is None:
            data_disks = []
        # Cannot have more then 5 security groups total.
        if len(additional_security_group_ids) > 4:
            raise Error('Instance can have max 5 security groups')

        # Create the instance.
        log_debug('creating instance')
        instance_id = self.create_instance(
            image_id,
            instance_type,
            initial_security_group_id,
            instance_name=instance_name,
            internet_max_bandwidth_in=internet_max_bandwidth_in,
            internet_max_bandwidth_out=internet_max_bandwidth_out,
            hostname=hostname,
            password=password,
            system_disk_type=system_disk_type,
            internet_charge_type=internet_charge_type,
            instance_charge_type=instance_charge_type,
            data_disks=data_disks,
            description=description,
            zone_id=zone_id)

        # Modify the security groups.
        if additional_security_group_ids:
            log_debug('Adding additional security groups')
            time.sleep(10)
            for sg in additional_security_group_ids:
                self.join_security_group(instance_id, sg)

        # Assign public IP if specified.
        if assign_public_ip:
            self.allocate_public_ip(instance_id)

        # Start the instance.
        log_debug('Starting the instance: %s', instance_id)
        time.sleep(10)
        self.start_instance(instance_id)

        # If specified block till the instance is running.
        if block_till_ready:
            running = False
            total_time = 0
            while total_time <= BLOCK_TILL_RUNNING_SECS:
                log_debug('Waiting 30 secs for instance to be running')
                time.sleep(30)
                total_time += 30
                if self.get_instance(instance_id).status == 'Running':
                    running = True
                    break

            if not running:
                raise Error('Timed out while waiting for instance to run')

        return instance_id

    def describe_auto_snapshot_policy(self):
        '''Describe the Auto-Snapshot policy for both data- and system-disks.
        Returns:
            :class:`.model.AutoSnapshotPolicyResponse`.
        '''

        resp = self.get({'Action': 'DescribeAutoSnapshotPolicy'})
        exc_status = resp['AutoSnapshotExcutionStatus']
        sys_status = exc_status['SystemDiskExcutionStatus']
        data_status = exc_status['DataDiskExcutionStatus']
        status = AutoSnapshotExecutionStatus(sys_status, data_status)
        p = resp['AutoSnapshotPolicy']
        policy = AutoSnapshotPolicy(
            p['SystemDiskPolicyEnabled'] == 'true',
            int(p['SystemDiskPolicyTimePeriod']),
            int(p['SystemDiskPolicyRetentionDays']),
            p['SystemDiskPolicyRetentionLastWeek'] == 'true',
            p['DataDiskPolicyEnabled'] == 'true',
            int(p['DataDiskPolicyTimePeriod']),
            int(p['DataDiskPolicyRetentionDays']),
            p['DataDiskPolicyRetentionLastWeek'] == 'true')
        return AutoSnapshotPolicyStatus(status, policy)

    def modify_auto_snapshot_policy(
            self, system_disk_policy_enabled, system_disk_policy_time_period,
            system_disk_policy_retention_days,
            system_disk_policy_retention_last_week, data_disk_policy_enabled,
            data_disk_policy_time_period, data_disk_policy_retention_days,
            data_disk_policy_retention_last_week):
        '''Modify the account's auto-snapshot policy.
        Args:
            system_disk_policy_enabled (bool): Enable/Disable for system disks.
            system_disk_policy_time_period (int): Time period for system disk
                                                  auto snapshots.
            system_disk_policy_retention_days (int): Number of days to retain.
            system_disk_policy_retention_last_week (bool): Keep/Discard Sunday's
                                                           auto-snapshot.
            data_disk_policy_enabled (bool): Enable/Disable for data disks.
            data_disk_policy_time_period (int): Time period for data disk auto
                                                snapshots.
            data_disk_policy_retention_days (int): Number of days to retain.
            data_disk_policy_retention_last_week (bool): Keep/Discard Sunday's
                                                           auto-snapshot.
        '''

        self.get({
            'Action': 'ModifyAutoSnapshotPolicy',
            'SystemDiskPolicyEnabled': str(system_disk_policy_enabled).lower(),
            'SystemDiskPolicyTimePeriod': system_disk_policy_time_period,
            'SystemDiskPolicyRetentionDays': system_disk_policy_retention_days,
            'SystemDiskPolicyRetentionLastWeek':
            str(system_disk_policy_retention_last_week).lower(),
            'DataDiskPolicyEnabled': str(data_disk_policy_enabled).lower(),
            'DataDiskPolicyTimePeriod': data_disk_policy_time_period,
            'DataDiskPolicyRetentionDays': data_disk_policy_retention_days,
            'DataDiskPolicyRetentionLastWeek':
            str(data_disk_policy_retention_last_week).lower()
        })

    def describe_disks(self,
                       zone_id=None,
                       disk_ids=None,
                       instance_id=None,
                       disk_type=None,
                       category=None,
                       status=None,
                       snapshot_id=None,
                       portable=None,
                       delete_with_instance=None,
                       delete_auto_snapshot=None):
        """List the disks in the region. All arguments are optional to allow
        restricting the disks retrieved.
        Args:
            zone_id (str): Availability Zone of the disks.
            disk_ids (list): List of disk ids to retrieve.
            instance_id (str): ID of instance retrieved disks are attached to.
            disk_type (str): "system", "data", or "all" (default).
            category (str): "cloud", "ephemeral", or "all" (default).
            status (str): Restrict to disks only with this status.
                          "In_use", "Available", "Attaching", "Detaching",
                          "Creating", "ReIniting", or "All" (default).
            snapshot_id (str): Snapshot used to create the disk.
            portable (bool): Whether the disk can be detached and re-attached
                             elsewhere.
            delete_with_instance (bool): Whether the disk will be deleted with
                                         its associated instance.
            delete_auto_snapshot (bool): Whether the AutoSnapshotPolicy will be
                                         deleted with the Disk.
        Returns:
            List of :class:`.model.Disk` objects.
        """
        disks = []
        params = {'Action': 'DescribeDisks'}
        if zone_id:
            params['ZoneId'] = zone_id
        if disk_ids:
            params['DiskIds'] = ','.join(disk_ids)
        if instance_id:
            params['InstanceId'] = instance_id

        for resp in self.get(params, paginated=True):
            for disk in resp['Disks']['Disk']:
                disks.append(
                    Disk(disk['DiskId'], disk['Type'], disk['Category'], disk[
                        'Size'],
                         dateutil.parser.parse(disk['AttachedTime'])
                         if disk['AttachedTime'] != '' else None,
                         dateutil.parser.parse(disk['CreationTime'])
                         if disk['CreationTime'] != '' else None, disk[
                             'DeleteAutoSnapshot'] == 'true'
                         if disk['DeleteAutoSnapshot'] != '' else None, disk[
                             'DeleteWithInstance'] == 'true'
                         if disk['DeleteWithInstance'] != '' else None, disk[
                             'Description']
                         if disk['Description'] != '' else None,
                         dateutil.parser.parse(disk['DetachedTime']) if disk[
                             'DetachedTime'] != '' else None, disk['Device']
                         if disk['Device'] != '' else None, disk['ImageId']
                         if disk['ImageId'] != '' else None, disk['InstanceId']
                         if disk['InstanceId'] != '' else None,
                         disk['OperationLocks']['OperationLock'], disk[
                             'Portable'] == 'true' if disk['Portable'] != ''
                         else None, disk['ProductCode'] if disk['ProductCode']
                         != '' else None, disk['SourceSnapshotId']
                         if disk['SourceSnapshotId'] != '' else None, disk[
                             'Status'] if disk['Status'] != '' else None, disk[
                                 'ZoneId'] if disk['ZoneId'] != '' else None))
        return disks

    def describe_instance_types(self):
        """List the instance types available.
        Returns:
            List of :class:`.model.InstanceType`.
        """
        instance_types = []
        resp = self.get({'Action': 'DescribeInstanceTypes'})
        for instance_type in resp['InstanceTypes']['InstanceType']:
            instance_types.append(
                InstanceType(instance_type['InstanceTypeId'],
                             int(instance_type['CpuCoreCount']),
                             int(instance_type['MemorySize'])))

        return instance_types

    def describe_instance_disks(self, instance_id):
        """List the disks associated with an instance.
        This is now only a helper method which calls describe_disks with an ID.
        Args:
            instance_id (str): The id of the instance.
        Returns:
            List of :class:`.model.Disk`.
        """
        return self.describe_disks(instance_id=instance_id)

    def modify_disk(self,
                    disk_id,
                    name=None,
                    description=None,
                    delete_with_instance=None):
        """Modify information about a disk.
        Args:
            disk_id (str): The Disk to modify/update.
            name (str): The new disk name.
            description (str): The new disk description.
            delete_with_instance (str): Change whether to delete the disk with
                                        its associated instance.
        """
        params = {'Action': 'ModifyDiskAttribute', 'DiskId': disk_id}
        if name is not None:
            params['DiskName'] = name
        if description is not None:
            params['Description'] = description
        if delete_with_instance is not None:
            params['DeleteWithInstance'] = delete_with_instance

        self.get(params)

    def reinit_disk(self, disk_id):
        """Re-initialize a disk to it's original Image.
        Args:
            disk_id (str): ID of the Disk to re-initialize.
        """
        self.get({'Action': 'ReInitDisk', 'DiskId': disk_id})

    def delete_snapshot(self, instance_id, snapshot_id):
        """Delete a snapshot.
        Args:
            instance_id (str): The id of the instance.
            snapshot_id (str): The id of the snapshot.
        """
        self.get({
            'Action': 'DeleteSnapshot',
            'InstanceId': instance_id,
            'SnapshotId': snapshot_id
        })

    def describe_snapshot(self, snapshot_id):
        """Describe a snapshot.
        Args:
            snapshot_id (str): The id of the snapshot.
        Returns:
            :class:`.model.Snapshot`.
        """
        snaps = self.describe_snapshots(snapshot_ids=[snapshot_id])
        if len(snaps) == 1:
            return snaps[0]
        else:
            raise Error("Could not find the snapshot: %s" % snapshot_id)

    def describe_snapshots(self,
                           instance_id=None,
                           disk_id=None,
                           snapshot_ids=None):
        '''Describe snapshots, filtering by ids or originating disk.
        Args:
            instance_id (str): Instance ID.
            disk_id (str): The originating disk ID to get snapshots for.
            snapshot_ids (list): Filter to up to 10 specific snapshot IDs
        Returns:
            A list of :class:`.model.Snapshot`.
        '''

        snapshots = []
        params = {'Action': 'DescribeSnapshots'}
        if instance_id:
            params['InstanceId'] = instance_id
        if disk_id:
            params['DiskId'] = disk_id
        if snapshot_ids:
            params['SnapshotIds'] = json.dumps(snapshot_ids)

        for resp in self.get(params, paginated=True):
            for snapshot in resp['Snapshots']['Snapshot']:
                snapshots.append(
                    Snapshot(snapshot['SnapshotId'],
                             snapshot.get('SnapshotName', None),
                             int(snapshot['Progress'][:-1]),
                             dateutil.parser.parse(snapshot['CreationTime']),
                             snapshot.get('Description', None),
                             snapshot.get('SourceDiskId', None),
                             snapshot.get('SourceDiskType', None),
                             int(snapshot.get('SourceDiskSize', None))))

        return snapshots

    def create_snapshot(self,
                        instance_id,
                        disk_id,
                        snapshot_name=None,
                        timeout_secs=None,
                        description=None):
        """Create a snapshot of a disk.
        The instance has to be in the running or stopped state.
        Args:
            instance_id (str): The id of the instance.
            disk_id (str): The id of the disk.
            snapshot_name (str): The name to assign to the snapshot.
            timeout_secs (int): If you want to block till the snapshot
                is ready you can specify how long to wait for.
            description (str): A description of the snapshot.
        Returns:
            The snapshot id.
        Raises:
            Error: if a timeout is given and the snapshot is not ready by then.
        """
        params = {
            'Action': 'CreateSnapshot',
            'InstanceId': instance_id,
            'DiskId': disk_id,
        }
        if snapshot_name:
            params['SnapshotName'] = snapshot_name

        if description:
            params['Description'] = description

        # Create the snapshot.
        snapshot_id = self.get(params)['SnapshotId']

        # If specified block till the snapshot is ready.
        if timeout_secs:
            total_time = 0
            created = False
            while total_time <= timeout_secs:
                log_debug('Waiting 30 secs for snapshot')
                time.sleep(30)
                total_time += 30
                snapshot = self.describe_snapshot(snapshot_id)
                if snapshot.progress == 100:
                    created = True
                    break

        # If the snapshot wasn't ready in the specified time error out.
        if timeout_secs and not created:
            raise Error('Snapshot %s not ready in %s seconds' % (snapshot_id,
                                                                 timeout_secs))

        return snapshot_id

    def describe_images(self,
                        image_ids=None,
                        owner_alias=None,
                        snapshot_id=None):
        """List images in the region matching params.
        Args:
            image_ids (list): List of image ids to filter on.
            owner_alias (list): List of owner alias to filter on. Can be
                values: system, self, others or marketplace.
            snapshot_id (str): List images only based off of this snapshot.
        Returns:
            List of :class`.model.Image` objects.
        """
        if image_ids is None:
            image_ids = []
        if owner_alias is None:
            owner_alias = []

        images = []

        params = {'Action': 'DescribeImages'}
        if image_ids:
            params['ImageId'] = ','.join(image_ids)
        if owner_alias:
            params['ImageOwnerAlias'] = '+'.join(owner_alias)
        if snapshot_id:
            params['SnapshotId'] = snapshot_id

        for resp in self.get(params, paginated=True):
            for item in resp['Images']['Image']:
                images.append(
                    Image(item['ImageId'], item['ImageVersion']
                          if 'ImageVersion' in item else None, item[
                              'ImageName'], item['Description']
                          if 'Description' in item else None,
                          int(item['Size']) if 'Size' in item else None, item[
                              'Architecture'] if 'Architecture' in item else
                          None, item['ImageOwnerAlias'], item['OSName']
                          if 'OSName' in item else None))

        return images

    def delete_image(self, image_id):
        """Delete an image.
        Args:
            image_id (str): The id of the image.
        """
        self.get({'Action': 'DeleteImage', 'ImageId': image_id})

    def create_image(self,
                     snapshot_id,
                     image_version=None,
                     description=None,
                     os_name=None):
        """Create an image.
        Args:
            snapshot_id (str): The id of the snapshot to create the image from.
            image_version (str): The version of the image.
            description (str): The description of the image.
            os_name (str): The os name.
        Returns:
            The image id.
        """
        params = {'Action': 'CreateImage', 'SnapshotId': snapshot_id}
        if image_version:
            params['ImageVersion'] = image_version
        if description:
            params['Description'] = description
        if os_name:
            params['OSName'] = os_name

        return self.get(params)['ImageId']

    def create_image_from_instance(self,
                                   instance_id,
                                   image_version=None,
                                   description=None,
                                   os_name=None,
                                   timeout_secs=600):
        """Create an image from an instance.
        This is a convenience method that handles creating the snapshot
        from the system disk and then creates the image.
        Args:
            instance_id (str): The id of the instance.
            image_version (str): The version of the image.
            description (str): The description.
            os_name (str): The os name.
            timeout_secs (int): How long to wait for the snapshot to be
                created. Default: 600.
        Returns:
            The (snapshot id, image id) pair.
        Raises:
            Error: if the system disk cannot be found or if the snapshot
                creation process times out.
        """
        # Get the system disk id.
        log_debug('Getting system disk for %s', instance_id)
        disks = self.describe_instance_disks(instance_id)
        system_disk = next((d for d in disks if d.disk_type == 'system'), None)
        if not system_disk:
            raise Error('System disk for %s not found' % instance_id)

        # Create the snapshot.
        log_debug('Creating snapshot for system disk %s' % system_disk.disk_id)
        snapshot_id = self.create_snapshot(
            instance_id, system_disk.disk_id, timeout_secs=timeout_secs)

        # Create the image.
        log_debug('Creating image from snapshot %s', snapshot_id)
        image_id = self.create_image(
            snapshot_id,
            image_version=image_version,
            description=description,
            os_name=os_name)
        time.sleep(30)

        return (snapshot_id, image_id)

    def describe_security_groups(self):
        """List all the security groups in the region.
        Returns:
            List of :class:`.model.SecurityGroupInfo`.
        """
        infos = []
        for resp in self.get({
                'Action': 'DescribeSecurityGroups'
        },
                             paginated=True):
            for item in resp['SecurityGroups']['SecurityGroup']:
                infos.append(
                    SecurityGroupInfo(item['SecurityGroupId'], item[
                        'Description'] if 'Description' in item else None))

        return infos

    def get_security_group_ids(self):
        """List all the security group ids in the region.
        Returns:
            List of security group ids.
        """
        return [x.security_group_id for x in self.describe_security_groups()]

    def create_security_group(self, description):
        """Create a security group.
        Args:
            description (str): The description.
        Returns:
            The security group id.
        """
        return self.get({
            'Action': 'CreateSecurityGroup',
            'Description': description
        })['SecurityGroupId']

    def get_security_group(self, security_group_id):
        """Get a security group.
        Args:
            security_group_id (str): The id of the security group.
        Returns:
            The :class:`.model.SecurityGroup` object.
        """
        outside_resp = self.get({
            'Action': 'DescribeSecurityGroupAttribute',
            'SecurityGroupId': security_group_id,
            'NicType': 'internet'
        })
        inside_resp = self.get({
            'Action': 'DescribeSecurityGroupAttribute',
            'SecurityGroupId': security_group_id,
            'NicType': 'intranet'
        })
        permissions = []
        for p in outside_resp['Permissions']['Permission']:
            permissions.append(
                SecurityGroupPermission(p['IpProtocol'], p['PortRange'], p[
                    'SourceCidrIp'] if 'SourceCidrIp' in p else None, p[
                        'SourceGroupId'] if 'SourceGroupId' in p else None, p[
                            'Policy'], p['NicType']))
        for p in inside_resp['Permissions']['Permission']:
            permissions.append(
                SecurityGroupPermission(p['IpProtocol'], p['PortRange'], p[
                    'SourceCidrIp'] if 'SourceCidrIp' in p else None, p[
                        'SourceGroupId'] if 'SourceGroupId' in p else None, p[
                            'Policy'], p['NicType']))

        return SecurityGroup(outside_resp['RegionId'],
                             outside_resp['SecurityGroupId'],
                             outside_resp['Description'], permissions)

    def delete_security_group(self, security_group_id):
        """Delete a security group.
        Args:
            security_group_id (str): The id of the security group.
        """
        self.get({
            'Action': 'DeleteSecurityGroup',
            'SecurityGroupId': security_group_id
        })

    def add_external_cidr_ip_rule(self,
                                  security_group_id,
                                  ip_protocol,
                                  port_range,
                                  source_cidr_ip,
                                  policy=None):
        """Add a rule for an external CidrIp to a security group.
        Args:
            security_group_id (str): The id of the security group.
            ip_protocol (str): TCP, UDP, ICMP, GRE or ALL
            port_range (str): For tcp/udp range is 1 to 65535. Else -1/-1.
            source_cidr_ip (str): Source IP address range.
            policy (str): Accept, Drop or Reject. Default: Accept.
        """
        self._add_security_rule(
            security_group_id,
            ip_protocol,
            port_range,
            source_cidr_ip=source_cidr_ip,
            policy=policy,
            nic_type='internet')

    def add_internal_cidr_ip_rule(self,
                                  security_group_id,
                                  ip_protocol,
                                  port_range,
                                  source_cidr_ip,
                                  policy=None):
        """Add a rule for an internal CidrIp to a security group.
        Args:
            security_group_id (str): The id of the security group.
            ip_protocol (str): TCP, UDP, ICMP, GRE or ALL
            port_range (str): For tcp/udp range is 1 to 65535. Else -1/-1.
            source_cidr_ip (str): Source IP address range.
            policy (str): Accept, Drop or Reject. Default: Accept.
        """
        self._add_security_rule(
            security_group_id,
            ip_protocol,
            port_range,
            source_cidr_ip=source_cidr_ip,
            policy=policy,
            nic_type='intranet')

    def add_group_rule(self,
                       security_group_id,
                       ip_protocol,
                       port_range,
                       source_group_id,
                       policy=None):
        """Add a rule for one security group to access another security group.
        Args:
            security_group_id (str): The id of the security group.
            ip_protocol (str): TCP, UDP, ICMP, GRE or ALL
            port_range (str): For tcp/udp range is 1 to 65535. Else -1/-1.
            source_group_id (str): Source security group.
            policy (str): Accept, Drop or Reject. Default: Accept.
        """
        self._add_security_rule(
            security_group_id,
            ip_protocol,
            port_range,
            source_group_id=source_group_id,
            policy=policy,
            nic_type='intranet')

    def _add_security_rule(self,
                           security_group_id,
                           ip_protocol,
                           port_range,
                           source_cidr_ip=None,
                           source_group_id=None,
                           policy=None,
                           nic_type=None):
        """Add a rule to a security group.
        Args:
            security_group_id (str): The id of the security group.
            ip_protocol (str): TCP, UDP, ICMP, GRE or ALL
            port_range (str): For tcp/udp range is 1 to 65535. Else -1/-1.
            source_cidr_ip (str): Source IP address range.
            source_group_id (str): Source security group.
            policy (str): Accept, Drop or Reject. Default: Accept.
            nic_type (str): internet or intranet. Default: internet.
        """
        params = {
            'Action': 'AuthorizeSecurityGroup',
            'SecurityGroupId': security_group_id,
            'IpProtocol': ip_protocol,
            'PortRange': port_range
        }
        if source_cidr_ip:
            params['SourceCidrIp'] = source_cidr_ip
        if source_group_id:
            params['SourceGroupId'] = source_group_id
        if policy:
            params['Policy'] = policy
        if nic_type:
            params['NicType'] = nic_type

        self.get(params)

    def remove_external_cidr_ip_rule(self,
                                     security_group_id,
                                     ip_protocol,
                                     port_range,
                                     source_cidr_ip,
                                     policy=None):
        """Remove a rule for an external CidrIp from a security group.
        Args:
            security_group_id (str): The id of the security group.
            ip_protocol (str): TCP, UDP, ICMP, GRE or ALL
            port_range (str): For tcp/udp range is 1 to 65535. Else -1/-1.
            source_cidr_ip (str): Source IP address range.
            policy (str): Accept, Drop or Reject. Default: Accept.
        """
        self._remove_security_rule(
            security_group_id,
            ip_protocol,
            port_range,
            source_cidr_ip=source_cidr_ip,
            policy=policy,
            nic_type='internet')

    def remove_internal_cidr_ip_rule(self,
                                     security_group_id,
                                     ip_protocol,
                                     port_range,
                                     source_cidr_ip,
                                     policy=None):
        """Remove a rule for an internal CidrIp from a security group.
        Args:
            security_group_id (str): The id of the security group.
            ip_protocol (str): TCP, UDP, ICMP, GRE or ALL
            port_range (str): For tcp/udp range is 1 to 65535. Else -1/-1.
            source_cidr_ip (str): Source IP address range.
            policy (str): Accept, Drop or Reject. Default: Accept.
        """
        self._remove_security_rule(
            security_group_id,
            ip_protocol,
            port_range,
            source_cidr_ip=source_cidr_ip,
            policy=policy,
            nic_type='intranet')

    def remove_group_rule(self,
                          security_group_id,
                          ip_protocol,
                          port_range,
                          source_group_id,
                          policy=None):
        """Remove a rule for a security group to access another security group.
        Args:
            security_group_id (str): The id of the security group.
            ip_protocol (str): TCP, UDP, ICMP, GRE or ALL
            port_range (str): For tcp/udp range is 1 to 65535. Else -1/-1.
            source_group_id (str): Source security group.
            policy (str): Accept, Drop or Reject. Default: Accept.
        """
        self._remove_security_rule(
            security_group_id,
            ip_protocol,
            port_range,
            source_group_id=source_group_id,
            policy=policy,
            nic_type='intranet')

    def _remove_security_rule(self,
                              security_group_id,
                              ip_protocol,
                              port_range,
                              source_cidr_ip=None,
                              source_group_id=None,
                              policy=None,
                              nic_type=None):
        """Remove a rule from a security group.
        Args:
            security_group_id (str): The id of the security group.
            ip_protocol (str): TCP, UDP, ICMP, GRE or ALL
            port_range (str): For tcp/udp range is 1 to 65535. Else -1/-1.
            source_cidr_ip (str): Source IP address range.
            source_group_id (str): Source security group.
            policy (str): Accept, Drop or Reject. Default: Accept.
            nic_type (str): internet or intranet. Default: internet.
        """
        params = {
            'Action': 'RevokeSecurityGroup',
            'SecurityGroupId': security_group_id,
            'IpProtocol': ip_protocol,
            'PortRange': port_range
        }
        if source_cidr_ip:
            params['SourceCidrIp'] = source_cidr_ip
        if source_group_id:
            params['SourceGroupId'] = source_group_id
        if policy:
            params['Policy'] = policy
        if nic_type:
            params['NicType'] = nic_type

        self.get(params)


EngineVersion = {
    'MySQL': [5.5, 5.6],
    'SQLServer': ['2008r2'],
    'PostgreSQL': [9.4],
    'PPAS': [9.3]
}


class RDSInstanceStatus(object):
    def __init__(self, instance_id, status):
        """Constructor.
        Args:
            instance_id (str): The id of the RDS instance.
            status (str): The status of the RDS instance.
        """
        self.instance_id = instance_id
        self.status = status

    def __repr__(self):
        return u'<InstanceId %s is %s at %s>' % (self.instance_id, self.status,
                                                 id(self))

    def __eq__(self, other):
        return (self.__class__ == other.__class__ and
                self.__dict__ == other.__dict__)


class RDSInstance(object):
    """An Aliyun RDS instance."""

    def __init__(self, instance_id, region_id, instance_type, description,
                 status, security_ip_list, creation_time, expired_time,
                 instance_charge_type, connection_string, dbinstance_net_type,
                 max_connections, engine, availability_value,
                 account_max_quantity, db_max_quantity, db_instance_memory,
                 max_iops, dbinstance_type, engineversion, dbinstance_storage,
                 port):
        """"Constructor.
        Args:
            instance_id (str): The id of the RDS instance.
            region_id (str): The id of the region in which the RDS instance lies.
            instance_type (str): The spec of the instance.
            description (str): The hostname of the instance.
            status (str): The status of the instance.
            security_ip_list (list): The security group ids for the instance.
            creation_time (datetime): Its creation time.
            expired_time (datetime): The expired time for PrePaid instances.
            instance_charge_type: The charge type of instance, either PrePaid or PostPaid.
            connection_string (str): The connection address.
            dbinstance_net_type (str): The network type of the RDS instance, Internet or Intranet.
            max_connections (int): The maximum concurrent connetions of the RDS instance.
            engine (str): The database type.
            availability_value (str): The availability status of the RDS instance.
            account_max_quantity (int): The maximum account number that can be created.
            db_max_quantity (int): The maximum database number that can be created on the RDS instance.
            db_instance_memory (int): The memory of the RDS instance.
            max_iops (int): The maximum IO number per second.
            dbinstance_type (str): The type of the RDS instance, Primary/ReadOnly/Guard/Temp.
            engineversion (str): The version of the database.
            dbinstance_storage (int): The storage space of the RDS instance, in GB.
            port (int): The LISTENING port of the Database.
        """
        self.instance_id = instance_id
        self.region_id = region_id
        self.instance_type = instance_type
        self.description = description
        self.status = status
        self.security_ip_list = security_ip_list
        self.creation_time = creation_time
        self.expired_time = expired_time
        self.instance_charge_type = instance_charge_type
        self.connection_string = connection_string
        self.dbinstance_net_type = dbinstance_net_type
        self.max_connections = max_connections
        self.engine = engine
        self.availability_value = availability_value
        self.account_max_quantity = account_max_quantity
        self.db_max_quantity = db_max_quantity
        self.db_instance_memory = db_instance_memory
        self.max_iops = max_iops
        self.dbinstance_type = dbinstance_type
        self.engineversion = engineversion
        self.dbinstance_storage = dbinstance_storage
        self.port = port

    def __repr__(self):
        return '<Instance %s at %s>' % (self.instance_id, id(self))

    def __eq__(self, other):
        return (self.__class__ == other.__class__ and
                self.__dict__ == other.__dict__)


class RdsConnection(Connection):
    """A connection to Aliyun RDS service.
    Args:
        region_id (str): The id of the region to connect to.
        access_key_id (str): The access key id.
        secret_access_key (str): The secret access key.
    """

    def __init__(self, region_id, access_key_id=None, secret_access_key=None):
        super(RdsConnection, self).__init__(region_id, 'rds')

    def describe_all_db_instances(self,
                                  region_id='cn-hangzhou',
                                  engine=None,
                                  db_instance_type=None,
                                  instance_network_type=None,
                                  connection_mode=None):
        """
        Get the list of all RDS instances OR the list of RDS instances that are authorized by RAM.
	    Args:
	        region_id (str): The id of the region to connect to.
	        engine (str): Database type, MySQL/SQLServer/PostgreSQL/PPAS
	        db_instance_type (str): Instance type, Primary/Readonly/Guard/Temp
	        instance_network_type (str): Network type, VPC/Classic
	        connection_mode (str): values are in Performance/Safty

	    Returns:
        """
        dbinstance_status = []
        params = {
            'Action': 'DescribeDBInstances',
            'RegionId': self.region_id,
        }
        if engine:
            params['Engine'] = engine
        if db_instance_type:
            params['DBInstanceType'] = db_instance_type
        if instance_network_type:
            params['InstanceNetworkType'] = instance_network_type

        for item in self.get(params)['Items']['DBInstance']:
            dbinstance_status.append(
                RDSInstanceStatus(item['DBInstanceId'], item[
                    'DBInstanceStatus']))
        return dbinstance_status

    def get_all_dbinstance_ids(self, region_id=None):
        """Get all the instance ids in a region.
        Args:
            zone_id (str, optional): The Zone ID to get instance ids from.
        Returns:
            The list of instance ids.
        """
        return [
            x.instance_id for x in self.describe_all_db_instances(region_id)
        ]

    def get_dbinstance(self, instance_id):
        """Get an rdsinstance.
        Args:
            instance_id (str): The id of the instance.
        Returns:
            :class:`.model.RdsInstance` if found.
        Raises:
            Error: if not found.
        """
        resp = self.get({
            'Action': 'DescribeDBInstanceAttribute',
            'DBInstanceId': instance_id
        })['Items']['DBInstanceAttribute'][0]
        return RDSInstance(
            resp['DBInstanceId'], resp['RegionId'], resp['DBInstanceClass'],
            resp['DBInstanceDescription'], resp['DBInstanceStatus'],
            resp['SecurityIPList'], resp['CreationTime'], resp['ExpireTime'],
            resp['PayType'], resp['ConnectionString'],
            resp['DBInstanceNetType'], resp['MaxConnections'], resp['Engine'],
            resp['AvailabilityValue'], resp['AccountMaxQuantity'],
            resp['DBMaxQuantity'], resp['DBInstanceMemory'], resp['MaxIOPS'],
            resp['DBInstanceType'], resp['EngineVersion'],
            resp['DBInstanceStorage'], resp['Port'])

    def report_expiring_dbinstance(self, days=7):
        """Report PrePaid RDS instances that are about to expire in <days>.
        Args:
        days (int): Check instances that will expire in <days>.
        """
        expiring_instances = []
        all_instances = self.get_all_dbinstance_ids()
        for ins in all_instances:
            res = self.get_dbinstance(ins)
            if res.instance_charge_type == 'Prepaid':
                expire_time = datetime.datetime.strptime(res.expired_time,
                                                         "%Y-%m-%dT%H:%M:%SZ")
                now = datetime.datetime.now()
                if (expire_time - now).days <= days:
                    expiring_instances.append(ins)
        return expiring_instances


class LoadBalancerStatus(object):
    """Simple status of SLB
    Args:
        load_balancer_id (str): LoadBalancerId unique identifier of the SLB.
        load_balancer_name (str): name of the SLB.
        status (str): SLB status.
    """

    def __init__(self, load_balancer_id, load_balancer_name, status):
        self.load_balancer_id = load_balancer_id
        self.status = status

    def __repr__(self):
        return ('<LoadBalancerStatus %s is %s at %s>' %
                (self.load_balancer_id, self.status, id(self)))

    def __eq__(self, other):
        return (self.__class__ == other.__class__ and
                self.__dict__ == other.__dict__)


class LoadBalancer(object):
    """An Aliyun Server Load Balancer (SLB) instance. Modeled after the
    DescribeLoadBalancerAttribute SLB API.
    Args:
        load_balancer_id (str): unique identifier of the SLB.
        region_id (str): region id for the SLB.
        load_balancer_name (str): description of the SLB.
        load_balancer_status (str): status of the SLB. 'inactive' or 'active'
        address (str): IP address of the SLB.
        address_type (str): internet vs intranet
        listener_ports (list int): Ports which have listeners
        backend_servers (list of BackendServer, optional): BackendServers to
                        put into the load balancer
    """

    def __init__(self,
                 load_balancer_id,
                 region_id,
                 load_balancer_name,
                 load_balancer_status,
                 address,
                 address_type,
                 listener_ports,
                 backend_servers=None):
        if backend_servers is None:
            backend_servers = []

        if load_balancer_id is None:
            raise Error(
                'LoadBalancer requires load_balancer_id to be not None')

        self.load_balancer_id = load_balancer_id
        self.region_id = region_id
        self.load_balancer_name = load_balancer_name
        self.load_balancer_status = load_balancer_status
        self.address = address
        self.address_type = address_type
        self.listener_ports = listener_ports
        self.backend_servers = backend_servers

    def __repr__(self):
        return ('<LoadBalancer %s (%s) at %s>' %
                (self.load_balancer_id, self.load_balancer_name, id(self)))

    def __eq__(self, other):
        return (self.__class__ == other.__class__ and
                self.__dict__ == other.__dict__)


class ListenerStatus(object):
    """Status for listener port and backend server list pairings.
    Args:
        listener_port (int): Number between 1 and 65535.
        backend_servers (list of BackendServerStatus)
    """

    def __init__(self, listener_port, backend_servers=None):
        if backend_servers is None:
            backend_servers = []
        self.listener_port = listener_port
        self.backend_servers = backend_servers

    def __repr__(self):
        return u'<ListenerStatus %s at %s>' % (self.listener_port, id(self))

    def __eq__(self, other):
        return (self.__class__ == other.__class__ and
                self.__dict__ == other.__dict__)


class Listener(object):
    """(Abstract by use) base class for LoadBalancerListeners
    Args:
        load_balancer_id (int, required): ID of the SLB instance
        listener_port (int, required): port the Load Balancer listens on
        backend_server_port (int, required): port number to connect to servers
        listener_status (str): 'active' (default) or 'stopped'.
        scheduler (str): wrr or wlc. Round Robin (default) or
            Least Connections.
        health_check (bool): True for 'on' and False for 'off' (default)
        healthy_threshold (int): number of health check successes to become
            healthy
        unhealthy_threshold (int): number of health check failures to become
            unhealthy
        connect_timeout (int): number of seconds to timeout and fail a health
            check
        interval (int): number of seconds between health checks
    """

    def __init__(self,
                 load_balancer_id,
                 listener_port,
                 backend_server_port,
                 listener_status=None,
                 scheduler='wrr',
                 health_check=False,
                 connect_timeout=5,
                 interval=2):

        self.load_balancer_id = load_balancer_id
        self.listener_port = listener_port
        self.backend_server_port = backend_server_port
        self.listener_status = listener_status
        self.scheduler = scheduler
        self.health_check = health_check
        self.connect_timeout = connect_timeout

    def __eq__(self, other):
        return (self.__class__ == other.__class__ and
                self.__dict__ == other.__dict__)


class TCPListener(Listener):
    """TCP Load Balancer Listener
    Args:
        load_balancer_id (str): LoadBalancerId unique identifier of the SLB.
        listener_port (int, required): port the Load Balancer listens on
        backend_server_port (int, required): port number to connect to servers
        listener_status (str): 'active' (default) or 'stopped'.
        scheduler (str): wrr or wlc. Round Robin (default) or
            Least Connections.
        health_check (bool): True for 'on' and False for 'off' (default)
        connect_timeout (int): number of seconds to timeout and fail a health
            check
        interval (int): number of seconds between health checks
        connect_port (int): defaults to backend_server_port
        persistence_timeout (int): number of seconds to hold TCP connection
            open
    """

    def __init__(self,
                 load_balancer_id,
                 listener_port,
                 backend_server_port,
                 listener_status='active',
                 scheduler='wrr',
                 health_check=False,
                 connect_timeout=5,
                 interval=2,
                 connect_port=None,
                 persistence_timeout=0):

        self.load_balancer_id = load_balancer_id
        self.listener_port = listener_port
        self.backend_server_port = backend_server_port
        self.listener_status = listener_status
        self.scheduler = scheduler
        self.health_check = health_check
        self.connect_timeout = connect_timeout

        if connect_port is None:
            connect_port = backend_server_port

        self.connect_port = connect_port
        self.persistence_timeout = persistence_timeout

        super(TCPListener, self).__init__(load_balancer_id, listener_port,
                                          backend_server_port, listener_status,
                                          scheduler, health_check,
                                          connect_timeout, interval)

    def __repr__(self):
        return u'<TCPListener on %s for %s at %s>' % (
            self.listener_port, self.load_balancer_id, id(self))


class HTTPListener(Listener):
    """HTTP Load Balancer Listener
    Args:
        load_balancer_id (str): LoadBalancerId unique identifier of the SLB.
        listener_port (int, required): port the Load Balancer listens on
        backend_server_port (int, required): port number to connect to servers
        listener_status (str): 'active' (default) or 'stopped'
        scheduler (str): wrr or wlc. Round Robin (default) or
            Least Connections.
        health_check (bool): True for 'on' and False for 'off' (default)
        connect_timeout (int): number of seconds to timeout and fail a health
            check
        interval (int): number of seconds between health checks
        x_forwarded_for (bool): Wether or not to append IPs to
            X-Fordwarded-For HTTP header
        sticky_session (bool): Use SLB Sticky Sessions. Default False.
        sticky_session_type (str):
            'insert' to have the SLB add a cookie to requests
            'server' to have the SLB look for a server-injected cookie
            sticky_session must be 'on'
        cookie_timeout (int [0-86400]):
            Lifetime of cookie in seconds. Max 1 day.
            sticky_session must be True.
        cookie (str):
            The Cookie key to use as sticky_session indicator.
            sticky_session_type must be 'server'
        domain (str): the Host header to use for the health check
        uri (str): URL path for healthcheck. E.g. /health
    """

    def __init__(self,
                 load_balancer_id,
                 listener_port,
                 backend_server_port,
                 listener_status='active',
                 scheduler='wrr',
                 health_check=False,
                 connect_timeout=5,
                 interval=2,
                 x_forwarded_for=False,
                 sticky_session=False,
                 sticky_session_type=None,
                 cookie_timeout=None,
                 cookie=None,
                 domain=None,
                 uri=''):

        self.load_balancer_id = load_balancer_id
        self.listener_port = listener_port
        self.backend_server_port = backend_server_port
        self.listener_status = listener_status
        self.scheduler = scheduler
        self.health_check = health_check
        self.connect_timeout = connect_timeout

        super(HTTPListener, self).__init__(
            load_balancer_id, listener_port, backend_server_port,
            listener_status, scheduler, health_check, connect_timeout,
            interval)

        if sticky_session == True and sticky_session_type is None:
            raise Error('sticky_session_type must be specified when using '
                        'sticky_session=True')
        if sticky_session_type == 'server' and cookie is None:
            raise Error('cookie must be specified when using '
                        'sticky_session_type=server')

        self.x_forwarded_for = x_forwarded_for
        self.sticky_session = sticky_session
        self.sticky_session_type = sticky_session_type
        self.cookie_timeout = cookie_timeout
        self.cookie = cookie
        self.domain = domain
        self.uri = uri

    def __repr__(self):
        return u'<HTTPListener on %s at %s>' % (self.listener_port, id(self))


class BackendServerStatus(object):
    def __init__(self, server_id, status):
        self.server_id = server_id
        self.status = status

    def __repr__(self):
        return (u'<BackendServerStatus %s is %s at %s>' %
                (self.server_id, self.status, id(self)))

    def __eq__(self, other):
        return (self.__class__ == other.__class__ and
                self.__dict__ == other.__dict__)


class BackendServer(object):
    """BackendServer describing ECS instances attached to an SLB
    Args:
        instance_id (str): ECS InstanceId (also SLB ServerId) attached
        weight (int): SLB weight. Between 1 and 1000. Default 100.
    Properties:
        status (str): (read-only) SLB ServerHealthStatus either 'normal' or
        'abnormal' """

    def __init__(self, instance_id, weight):
        self.instance_id = instance_id
        self.weight = weight

    def __repr__(self):
        return u'<BackendServer %s at %s>' % (self.instance_id, id(self))

    def __eq__(self, other):
        return (self.__class__ == other.__class__ and
                self.__dict__ == other.__dict__)


class SlbConnection(Connection):
    """A connection to Aliyun SLB service."""

    def __init__(self, region_id, access_key_id=None, secret_access_key=None):
        """Constructor.
        If the access and secret key are not provided the credentials are
        looked for in $HOME/.aliyun.cfg or /etc/aliyun.cfg.
        Args:
            region_id (str): The id of the region to connect to.
            access_key_id (str): The access key id.
            secret_access_key (str): The secret access key.
        """
        super(SlbConnection, self).__init__(region_id, 'slb')

    def get_all_regions(self):
        """Get all regions.
        Return: list[slb.Region]
        """
        resp = self.get({'Action': 'DescribeRegions'})
        regions = []
        for region in resp['Regions']['Region']:
            regions.append(Region(region['RegionId']))
        return regions

    def get_all_region_ids(self):
        return [r.region_id for r in self.get_all_regions()]

    def get_all_load_balancer_status(self, instance_id=None):
        """Get all LoadBalancerStatus in the region.
        Args:
            instance_id (str, optional): Restrict results to LBs with this
                instance.
        Return:
            List of LoadBalancerStatus.
        """
        lb_status = []
        params = {'Action': 'DescribeLoadBalancers'}

        if instance_id:
            params['ServerId'] = instance_id

        resp = self.get(params)
        for lb in resp['LoadBalancers']['LoadBalancer']:
            new_lb_status = LoadBalancerStatus(lb['LoadBalancerId'],
                                               lb['LoadBalancerName'],
                                               lb['LoadBalancerStatus'])
            lb_status.append(new_lb_status)

        return lb_status

    def get_all_load_balancer_ids(self):
        """Get all the load balancer IDs in the region."""
        return (
            [x.load_balancer_id for x in self.get_all_load_balancer_status()])

    def delete_load_balancer(self, load_balancer_id):
        """Delete a LoadBalancer by ID
        Args:
            load_balancer_id (str): Aliyun SLB LoadBalancerId to delete.
        """
        params = {
            'Action': 'DeleteLoadBalancer',
            'LoadBalancerId': load_balancer_id
        }

        return self.get(params)

    def get_load_balancer(self, load_balancer_id):
        """Get a LoadBalancer by ID.
        Args:
            load_balancer_id (str): Aliyun SLB LoadBalancerId to retrieve.
        Returns:
            LoadBalancer with given ID.
        """
        resp = self.get({
            'Action': 'DescribeLoadBalancerAttribute',
            'LoadBalancerId': load_balancer_id
        })

        backend_servers = []
        for bs in resp['BackendServers']['BackendServer']:
            backend_servers.append(BackendServer(bs['ServerId'], bs['Weight']))

        return LoadBalancer(
            resp['LoadBalancerId'], resp['RegionId'], resp['LoadBalancerName'],
            resp['LoadBalancerStatus'], resp['Address'], resp['AddressType'],
            [port for port in resp['ListenerPorts']['ListenerPort']],
            backend_servers)

    def create_load_balancer(self,
                             region_id,
                             address_type=None,
                             internet_charge_type=None,
                             bandwidth=None,
                             load_balancer_name=None):
        """Create a load balancer. This does not configure listeners nor
        backend servers.
        Args:
            region_id (str): An id from get_all_region_ids()
            addres_type (str): IP the SLB on the public network ('internet',
                               default) or the private network ('intranet')
            internet_charge_type (str): 'paybytraffic' (default) vs
                                        'paybybandwidth'
            bandwidth (int): peak burst speed of 'paybybandwidth' type slbs.
                             Listener must be set first before this will take
                             effect. default: 1 (unit Mbps)
            load_balancer_name (str): Name of the SLB. 80 char max. Optional.
        Returns:
            load_balancer_id of the created LB. Address and Name are not given.
        """
        params = {'Action': 'CreateLoadBalancer', 'RegionId': region_id}

        if load_balancer_name is not None:
            params['LoadBalancerName'] = load_balancer_name

        if address_type is not None:
            params['AddressType'] = address_type.lower()

        if internet_charge_type is not None:
            params['InternetChargeType'] = internet_charge_type.lower()

        if bandwidth is not None:
            params['Bandwidth'] = bandwidth

        resp = self.get(params)
        log_debug(
            "Created a load balancer: %(LoadBalancerId)s named %(LoadBalancerName)s at %(Address)s",
            resp)
        return resp['LoadBalancerId']

    def set_load_balancer_status(self, load_balancer_id, status):
        """Set the Status of an SLB
        Args:
            load_balancer_id (str): SLB ID
            status (str): One of 'inactive' or 'active'
        """
        params = {
            'Action': 'SetLoadBalancerStatus',
            'LoadBalancerId': load_balancer_id,
            'LoadBalancerStatus': status
        }
        return self.get(params)

    def set_load_balancer_name(self, load_balancer_id, name):
        """Set the Name of an SLB
        Args:
            load_balancer_id (str): SLB ID
            name (str): Alias for the SLB. Up to 64 characters.
        """
        params = {
            'Action': 'SetLoadBalancerName',
            'LoadBalancerId': load_balancer_id,
            'LoadBalancerName': name
        }
        return self.get(params)

    def delete_listener(self, load_balancer_id, listener_port):
        """Delete the SLB Listner on specified port
        Args:
            load_balancer_id (str): SLB ID
            listener_port (int): SLB Listener port. Between 1 and 65535.
        """
        params = {
            'Action': 'DeleteLoadBalancerListener',
            'LoadBalancerId': load_balancer_id,
            'ListenerPort': listener_port
        }
        return self.get(params)

    def set_listener_status(self, load_balancer_id, listener_port, status):
        """Set the status of an SLB Listener. Turn them on or off.
        Args:
            load_balancer_id (str): SLB ID
            listener_port (int): SLB Listener port. Between 1 and 65535.
            status (str): 'inactive' for off and 'active' for on.
        """
        params = {
            'Action': 'SetLoadBalancerListenerStatus',
            'LoadBalancerId': load_balancer_id,
            'ListenerPort': listener_port,
            'ListenerStatus': status
        }
        return self.get(params)

    def get_tcp_listener(self, load_balancer_id, listener_port):
        """Get the TCP Listener from an SLB ID and port
        Args:
            load_balancer_id (str): SLB ID
            listener_port (int): SLB Listener port. Between 1 and 65535.
        Returns:
            TCPListener
        """
        params = {
            'Action': 'DescribeLoadBalancerTCPListenerAttribute',
            'LoadBalancerId': load_balancer_id,
            'ListenerPort': listener_port
        }
        resp = self.get(params)

        if 'ConnectPort' not in resp:
            resp['ConnectPort'] = resp['BackendServerPort']

        return TCPListener(
            load_balancer_id,
            int(resp['ListenerPort']),
            int(resp['BackendServerPort']),
            listener_status=resp['Status'],
            scheduler=resp['Scheduler'] or None,
            health_check=resp['HealthCheck'] == 'on',
            connect_port=int(resp['ConnectPort']) or None,
            persistence_timeout=int(resp['PersistenceTimeout']))

    def get_http_listener(self, load_balancer_id, listener_port):
        """Get the HTTP Listener from an SLB ID and port
        Args:
            load_balancer_id (str): SLB ID
            listener_port (int): SLB Listener port. Between 1 and 65535.
        Returns:
            HTTPListener
        """
        params = {
            'Action': 'DescribeLoadBalancerHTTPListenerAttribute',
            'LoadBalancerId': load_balancer_id,
            'ListenerPort': listener_port
        }
        resp = self.get(params)

        return HTTPListener(
            load_balancer_id,
            int(resp['ListenerPort']),
            int(resp['BackendServerPort']),
            listener_status=resp['Status'] or None,
            scheduler=resp['Scheduler'] or None,
            health_check=resp['HealthCheck'] == 'on',
            x_forwarded_for=resp['XForwardedFor'] == 'on',
            sticky_session=resp['StickySession'] == 'on',
            sticky_session_type=resp['StickySessionapiType'] or None,
            cookie=resp['Cookie'] or None,
            domain=resp['Domain'] or None,
            uri=resp['URI'])

    def create_tcp_listener(self,
                            load_balancer_id,
                            listener_port,
                            backend_server_port,
                            healthy_threshold=3,
                            unhealthy_threshold=3,
                            listener_status=None,
                            scheduler=None,
                            health_check=None,
                            connect_timeout=None,
                            interval=None,
                            connect_port=None,
                            persistence_timeout=None):
        """Create a TCP SLB Listener
        Args:
            load_balancer_id (str): LoadBalancerId unique identifier of the
                SLB.
            listener_port (int): Port for the SLB to listen on
            backend_server_port (int): Port to send traffic to on the back-end
            healthy_threshold (int): Number of successful healthchecks before
                considering the listener healthy. Default 3.
            unhealthy_threshold (int): Number of failed healthchecks before
                considering the listener unhealthy.
                Default 3.
            TCPListener arguments:
            listener_status (str): 'active' (default) or 'stopped'.
            scheduler (str): wrr or wlc. Round Robin (default) or
                Least Connections.
            health_check (bool): True for 'on' and False for 'off' (default)
            connect_timeout (int): number of seconds to timeout and fail a
                health check
            interval (int): number of seconds between health checks
            connect_port (int): defaults to backend_server_port
            persistence_timeout (int): number of seconds to hold TCP
                connection open
        """
        params = {
            'Action': 'CreateLoadBalancerTCPListener',
            'LoadBalancerId': load_balancer_id,
            'ListenerPort': int(listener_port),
            'BackendServerPort': int(backend_server_port),
        }

        if healthy_threshold is not None:
            params['HealthyThreshold'] = healthy_threshold
        if unhealthy_threshold is not None:
            params['UnhealthyThreshold'] = unhealthy_threshold
        if listener_status:
            params['ListenerStatus'] = listener_status
        if scheduler:
            params['Scheduler'] = scheduler
        if health_check is not None:
            params['HealthCheck'] = 'on' if health_check else 'off'
        if connect_timeout is not None:
            params['ConnectTimeout'] = connect_timeout
        if interval is not None:
            params['Interval'] = interval
        if connect_port is not None:
            params['ConnectPort'] = connect_port
        if persistence_timeout is not None:
            params['PersistenceTimeout'] = int(persistence_timeout)

        self.get(params)

    def create_http_listener(self,
                             load_balancer_id,
                             listener_port,
                             backend_server_port,
                             bandwidth,
                             sticky_session,
                             health_check,
                             healthy_threshold=3,
                             unhealthy_threshold=3,
                             scheduler=None,
                             connect_timeout=None,
                             interval=None,
                             x_forwarded_for=None,
                             sticky_session_type=None,
                             cookie_timeout=None,
                             cookie=None,
                             domain=None,
                             uri=None):
        """Create an HTTP SLB Listener
        Args:
            load_balancer_id (str): LoadBalancerId unique identifier of the
                SLB.
            listener_port (int): Port for the SLB to listen on
            backend_server_port (int): Port to send traffic to on the back-end
            bandwidth (int): The peak burst speed of the network.
                Optional values: - 1|1 - 1000Mbps
                For the paybybandwidth intances, the peak
                burst speed of all Listeners should not exceed
                the Bandwidth value in SLB instance creation,
                and the Bandwidth value must not be set to - 1.
                For paybytraffic instances, this value can be set
                to - 1, meaning there is no restriction on
                bandwidth peak speed.
            sticky_session (str): on or off
            healthy_threshold (int): Number of successful healthchecks before
                considering the listener healthy. Default 3.
            unhealthy_threshold (int): Number of failed healthchecks before
                considering the listener unhealthy. Default 3.
            health_check (str): 'on' and 'off' (default)
        HTTPListener arguments:
            scheduler (str): wrr or wlc. Round Robin (default) or
                Least Connections.
            connect_timeout (int): number of seconds to timeout and fail a
                health check
            interval (int): number of seconds between health checks
            x_forwarded_for (bool): wether or not to append ips to
                x-fordwarded-for http header
            sticky_session_type (str):
                'insert' to have the SLB add a cookie to requests
                'server' to have the SLB look for a server-injected cookie
                sticky_session must be 'on'
            cookie_timeout (int [0-86400]):
                Lifetime of cookie in seconds. Max 1 day.
                sticky_session must be 'on'
            cookie (str):
                The Cookie key to use as sticky_session indicator.
                sticky_session_type must be 'server'
            domain (str): the Host header to use for the health check
            uri (str): URL path for healthcheck. E.g. /health
        """
        params = {
            'Action': 'CreateLoadBalancerHTTPListener',
            'LoadBalancerId': load_balancer_id,
            'ListenerPort': int(listener_port),
            'BackendServerPort': int(backend_server_port),
            'Bandwidth': int(bandwidth),
            'StickySession': sticky_session,
            'HealthCheck': health_check,
        }
        if healthy_threshold is not None:
            params['HealthyThreshold'] = healthy_threshold
        if unhealthy_threshold is not None:
            params['UnhealthyThreshold'] = unhealthy_threshold
        if scheduler:
            params['Scheduler'] = scheduler
        if connect_timeout is not None:
            params['ConnectTimeout'] = connect_timeout
        if interval is not None:
            params['Interval'] = interval
        if x_forwarded_for is not None:
            params['XForwardedFor'] = 'on' if x_forwarded_for else 'off'
        if sticky_session_type is not None:
            params['StickySessionapiType'] = sticky_session_type
        if cookie_timeout is not None:
            params['CookieTimeout'] = cookie_timeout
        if cookie is not None:
            params['Cookie'] = cookie
        if domain is not None:
            params['Domain'] = domain
        if uri is not None:
            params['URI'] = uri

        self.get(params)

    def update_tcp_listener(self,
                            load_balancer_id,
                            listener_port,
                            healthy_threshold=None,
                            unhealthy_threshold=None,
                            scheduler=None,
                            health_check=None,
                            connect_timeout=None,
                            interval=None,
                            connect_port=None,
                            persistence_timeout=None):
        """Update an existing TCP SLB Listener
        Args:
            load_balancer_id (str): LoadBalancerId unique identifier of the
                SLB.
            listener_port (int): Port for the SLB to listen on
            healthy_threshold (int): Number of successful healthchecks before
                considering the listener healthy. Default 3.
            unhealthy_threshold (int): Number of failed healthchecks before
                considering the listener unhealthy.
                Default 3.
            scheduler (str): wrr or wlc. Round Robin (default) or
                Least Connections.
            health_check (bool): True for 'on' and False for 'off' (default)
            connect_timeout (int): number of seconds to timeout and fail a
                health check
            interval (int): number of seconds between health checks
            connect_port (int): defaults to backend_server_port
            persistence_timeout (int): number of seconds to hold TCP
                connection open
        """
        params = {
            'Action': 'SetLoadBalancerTCPListenerAttribute',
            'LoadBalancerId': load_balancer_id,
            'ListenerPort': listener_port
        }
        if healthy_threshold is not None:
            params['HealthyThreshold'] = healthy_threshold
        if unhealthy_threshold is not None:
            params['UnhealthyThreshold'] = unhealthy_threshold
        if scheduler is not None:
            params['Scheduler'] = scheduler
        if health_check is not None:
            params['HealthCheck'] = 'on' if health_check else 'off'
        if connect_timeout is not None:
            params['ConnectTimeout'] = connect_timeout
        if interval is not None:
            params['Interval'] = interval
        if connect_port is not None:
            params['ConnectPort'] = connect_port
        if persistence_timeout is not None:
            params['PersistenceTimeout'] = persistence_timeout

        self.get(params)

    def update_http_listener(self,
                             load_balancer_id,
                             listener_port,
                             healthy_threshold=None,
                             unhealthy_threshold=None,
                             scheduler=None,
                             health_check=None,
                             health_check_timeout=None,
                             interval=None,
                             x_forwarded_for=None,
                             sticky_session=None,
                             sticky_session_type=None,
                             cookie_timeout=None,
                             cookie=None,
                             domain=None,
                             uri=None):
        """Update an existing HTTP SLB Listener
        Args:
            load_balancer_id (str): LoadBalancerId unique identifier of the
                SLB.
            listener_port (int): Port for the SLB to listen on
            healthy_threshold (int): Number of successful healthchecks before
                considering the listener healthy. Default 3.
            unhealthy_threshold (int): Number of failed healthchecks before
                considering the listener unhealthy. Default 3.
            scheduler (str): wrr or wlc. Round Robin (default) or
                Least Connections.
            health_check (bool): True for 'on' and False for 'off' (default)
            health_check_timeout (int): number of seconds to timeout and fail a
                health check
            interval (int): number of seconds between health checks
            x_forwarded_for (bool): wether or not to append ips to
                x-fordwarded-for http header
            sticky_session (bool): use slb sticky sessions. default false.
            sticky_session_type (str):
                'insert' to have the SLB add a cookie to requests
                'server' to have the SLB look for a server-injected cookie
                sticky_session must be 'on'
            cookie_timeout (int [0-86400]):
                Lifetime of cookie in seconds. Max 1 day.
                sticky_session must be 'on'
            cookie (str):
                The Cookie key to use as sticky_session indicator.
                sticky_session_type must be 'server'
            domain (str): the Host header to use for the health check
            uri (str): URL path for healthcheck. E.g. /health
        """

        params = {
            'Action': 'SetLoadBalancerHTTPListenerAttribute',
            'LoadBalancerId': load_balancer_id,
            'ListenerPort': int(listener_port),
        }

        if healthy_threshold is not None:
            params['HealthyThreshold'] = healthy_threshold
        if unhealthy_threshold is not None:
            params['UnhealthyThreshold'] = unhealthy_threshold
        if scheduler:
            params['Scheduler'] = scheduler
        if health_check is not None:
            params['HealthCheck'] = 'on' if health_check else 'off'
        if health_check_timeout is not None:
            params['HealthCheckTimeout'] = health_check_timeout
        if interval is not None:
            params['Interval'] = interval
        if x_forwarded_for is not None:
            params['XForwardedFor'] = 'on' if x_forwarded_for else 'off'
        if sticky_session is not None:
            params['StickySession'] = 'on' if sticky_session else 'off'
        if sticky_session_type is not None:
            params['StickySessionapiType'] = sticky_session_type
        if cookie_timeout is not None:
            params['CookieTimeout'] = cookie_timeout
        if cookie is not None:
            params['Cookie'] = cookie
        if domain is not None:
            params['Domain'] = domain
        if uri is not None:
            params['URI'] = uri

        self.get(params)

    def start_load_balancer_listener(self, load_balancer_id, listener_port):
        """Start a listener
        Args:
            load_balancer_id (str): Aliyun SLB LoadBalancerId
            listener_port (int): The listener port to activate
        """
        params = {
            'Action': 'StartLoadBalancerListener',
            'LoadBalancerId': str(load_balancer_id),
            'ListenerPort': int(listener_port)
        }

        self.get(params)

    def stop_load_balancer_listener(self, load_balancer_id, listener_port):
        """Stop a listener
        Args:
            load_balancer_id (str): Aliyun SLB LoadBalancerId
            listener_port (int): The listener port to activate
        """
        params = {
            'Action': 'StopLoadBalancerListener',
            'LoadBalancerId': str(load_balancer_id),
            'ListenerPort': int(listener_port)
        }

        self.get(params)

    def get_backend_servers(self, load_balancer_id, listener_port=None):
        """Get backend servers for a given load balancer and its listener port.
        If listener_port is not specified, all listeners are listed separately.
        Args:
            load_balancer_id (str): Aliyun SLB LoadBalancerId to retrieve.
            listener_port (int, optional): the port to get backend server
                statuses for
        Returns:
            List of ListenerStatus
        """
        params = {
            'Action': 'DescribeBackendServers',
            'LoadBalancerId': load_balancer_id,
        }
        if listener_port is not None:
            params['ListenerPort'] = listener_port

        listeners = []
        resp = self.get(params)
        for listener in resp['Listeners']['Listener']:
            backends = []
            for bs in listener['BackendServers']['BackendServer']:
                backends.append(
                    BackendServerStatus(bs['ServerId'], bs[
                        'ServerHealthStatus']))
            listeners.append(
                ListenerStatus(listener['ListenerPort'], backends))

        return listeners

    def get_backend_server_ids(self, load_balancer_id, listener_port=None):
        backends = []
        statuses = self.get_backend_servers(load_balancer_id, listener_port)
        for status in statuses:
            backends.extend([bs.server_id for bs in status.backend_servers])

        return list(set(backends))

    def remove_backend_servers(self, load_balancer_id, backend_servers):
        """Remove backend servers from a load balancer
           Note: the SLB API ignores Weight when Removing Backend Servers. So
           you're probably better off using remove_backend_server_id anyway.
        Args:
            load_balancer_id (str): Aliyun SLB LoadBalancerId to retrieve.
            backend_servers (list of BackendServer): the backend servers to
                remove
        """
        params = {
            'Action': 'RemoveBackendServers',
            'LoadBalancerId': load_balancer_id
        }

        backends = []
        for bs in backend_servers:
            backends.append({'ServerId': bs.instance_id})

        params['BackendServers'] = backends

        return self.get(params)

    def remove_backend_server_ids(self, load_balancer_id, backend_server_ids):
        """Helper wrapper to remove backend server IDs specified from the SLB
           specified.
        Args:
            load_balancer_id (str): Aliyun SLB LoadBalancerId to retrieve.
            backend_server_ids (list of str): the backend server ids to remove
        """
        backends = [BackendServer(bsid, None) for bsid in backend_server_ids]
        return self.remove_backend_servers(load_balancer_id, backends)

    def add_backend_servers(self, load_balancer_id, backend_servers):
        """Add backend servers to a load balancer
        Args:
            load_balancer_id (str): Aliyun SLB LoadBalancerId to retrieve.
            backend_servers (list of BackendServer): the backend servers to add
        """
        params = {
            'Action': 'AddBackendServers',
            'LoadBalancerId': load_balancer_id
        }

        backends = []
        for bs in backend_servers:
            if bs.weight is not None:
                backends.append({
                    'ServerId': bs.instance_id,
                    'Weight': bs.weight
                })
            else:
                backends.append({'ServerId': bs.instance_id})

        params['BackendServers'] = backends

        return self.get(params)

    def add_backend_server_ids(self, load_balancer_id, backend_server_ids):
        """Helper wrapper to add backend server IDs specified to the SLB
           specified.
        Args:
            load_balancer_id (str): Aliyun SLB LoadBalancerId to retrieve.
            backend_server_ids (list of str): the backend server ids to add
        """
        backends = [BackendServer(bsid, None) for bsid in backend_server_ids]
        return self.add_backend_servers(load_balancer_id, backends)

    def deregister_backend_server_ids(self, server_ids):
        """Helper wrapper to get load balancers with the server id in them and
        remove the server from each load balancer.
        Args:
            server_id (List of str): List of Aliyun ECS Instance IDs
        Returns:
            List of SLB IDs that were modified.
        """
        lbs = collections.defaultdict(list)
        for instance_id in server_ids:
            for lb_status in self.get_all_load_balancer_status(instance_id):
                lbs[lb_status.load_balancer_id].append(instance_id)
        for lb_id, bs_ids in lbs.iteritems():
            self.remove_backend_server_ids(lb_id, list(set(bs_ids)))

        return lbs.keys()

    def deregister_backend_servers(self, backend_servers):
        return (self.deregister_backend_server_ids(
            [bs.instance_id for bs in backend_servers]))


class VpcConnection(Connection):
    """A connection to Aliyun DNS service.
    Args:
        region_id (str): NOT IN USE FOR DNS
                         But needed for backward comptibility
                         The id of the region to connect to.
        access_key_id (str): The access key id.
        secret_access_key (str): The secret access key.
    """

    def __init__(self,
                 region_id='cn-hangzhou',
                 access_key_id=None,
                 secret_access_key=None):
        super(VpcConnection, self).__init__(region_id, 'vpc')

    def create_vpc(self,
                   cidr_block=None,
                   usercidr=None,
                   vpcname=None,
                   description=None):
        params = {'Action': 'CreateVpc'}
        if cidr_block:
            params['CidrBlock'] = cidr_block
        if usercidr:
            params['UserCidr'] = usercidr
        if vpcname:
            params['VpcName'] = vpcname
        if description:
            params['Description'] = description
        return self.get(params)

    def delete_vpc(self, vpcid):
        params = {'Action': 'DeleteVpc', 'VpcId': vpcid}
        return self.get(params)

    def describe_vpcs(self):
        params = {'Action': 'DescribeVpcs'}
        return self.get(params)

    def modify_vpc(self, vpcid, usercidr=None, vpcname=None, description=None):
        params = {'Action': 'ModifyVpcAttribute', 'VpcId': vpcid}
        if usercidr:
            params['UserCidr'] = usercidr
        if vpcname:
            params['VpcName'] = vpcname
        if description:
            params['Description'] = description
        return self.get(params)

    def describe_vrouters(self):
        params = {'Action': 'DescribeVRouters'}
        return self.get(params)

    def modify_vrouter(self, vrouter_id, vroutername=None, description=None):
        params = {'Action': 'ModifyVRouterAttribute', 'VRouterId': vrouter_id}
        if vroutername:
            params['VRouterName'] = vroutername
        if description:
            params['Description'] = description
        return self.get(params)

    def create_vswitch(self,
                       zone_id,
                       cidr_block,
                       vpc_id,
                       vswitchname=None,
                       description=None):
        params = {
            'Action': 'CreateVSwitch',
            'ZoneId': zone_id,
            'CidrBlock': cidr_block,
            'VpcId': vpc_id,
        }
        if vswitchname:
            params['VSwitchName'] = vswitchname
        if description:
            params['Description'] = description
        return self.get(params)

    def delete_vswitch(self, vswitch_id):
        params = {'Action': 'DeleteVSwitch', 'VSwitchId': vswitch_id}
        return self.get(params)

    def describe_vswitches(self,
                           vpc_id,
                           zone_id=None,
                           vswitch_id=None,
                           is_default=None):
        params = {'Action': 'DescribeVSwitches', 'VpcId': vpc_id}
        if vswitch_id:
            params['VSwitchId'] = vswitch_id
        if zone_id:
            params['ZoneId'] = zone_id
        if is_default:
            params['IsDefault'] = is_default
        return self.get(params)

    def modify_vswitch(self, vswitch_id, vswitchname=None, description=None):
        params = {'Action': 'ModifyVSwitchAttribute', 'VSwitchId': vswitch_id}
        if vswitchname:
            params['VSwitchName'] = vswitchname
        if description:
            params['Description'] = description
        return self.get(params)

    def create_route_entry(self,
                           routetable_id,
                           destination_cidr_block,
                           nexthop_type=None,
                           nexthop_id=None,
                           nexthop_list=None):
        params = {
            'Action': 'CreateRouteEntry',
            'RouteTableId': routetable_id,
            'DestinationCidrBlock': destination_cidr_block
        }
        if nexthop_type:
            params['NextHopType'] = nexthop_type
        if nexthop_id:
            params['NextHopId'] = nexthop_id
        if nexthop_list:
            params['NextHopList'] = nexthop_list
        return self.get(params)

    def delete_route_entry(self,
                           routetable_id,
                           nexthop_type=None,
                           nexthop_id=None,
                           nexthop_list=None):
        params = {'Action': 'DeleteRouteEntry', 'RouteTableId': routetable_id}
        if nexthop_type:
            params['NextHopType'] = nexthop_type
        if nexthop_id:
            params['NextHopId'] = nexthop_id
        if nexthop_list:
            params['NextHopList'] = nexthop_list
        return self.get(params)

    def describe_route_table(self):
        params = {'Action': 'DescribeRouteTables'}
        return self.get(params)

    def allocate_eip_dddress(self, bandwidth=None, internet_charge_type=None):
        params = {'Action': 'AllocateEipAddress'}
        if bandwidth:
            params['Bandwidth'] = bandwidth
        if internet_charge_type:
            params['InternetChargeType'] = internet_charge_type
        return self.get(params)

    def associate_eip_dddress(self,
                              allocation_id,
                              instance_id,
                              instance_type=None):
        params = {
            'Action': 'AllocateEipAddress',
            'AllocationId': allocation_id,
            'InstanceId': instance_id
        }
        if instance_type:
            params['InstanceType'] = instance_type
        return self.get(params)

    def unassociate_eip_dddress(self,
                                allocation_id,
                                instance_id,
                                instance_type=None):
        params = {
            'Action': 'UnassociateEipAddress',
            'AllocationId': allocation_id,
            'InstanceId': instance_id
        }
        if instance_type:
            params['InstanceType'] = instance_type
        return self.get(params)

    def describe_eip_dddress(self):
        params = {'Action': 'DescribeEipAddresses'}
        return self.get(params)

    def modify_eip_dddress(self, allocation_id, bandwidth=None):
        params = {
            'Action': 'ModifyEipAddressAttribute',
            'AllocationId': allocation_id
        }
        if bandwidth:
            params['Bandwidth'] = bandwidth
        return self.get(params)

    def release_eip_dddress(self, allocation_id):
        params = {'Action': 'ReleaseEipAddress', 'AllocationId': allocation_id}
        return self.get(params)

    def create_virtual_border_router(self, physical_connection_id, vlan_id):
        params = {
            'Action': 'CreateVirtualBorderRouter',
            'PhysicalConnectionId': physical_connection_id,
            'VlanId': vlan_id
        }
        return self.get(params)
