#!/usr/bin/env python
# -*- coding:utf8 -*-

from library.aliyun import Connection, DnsConnection, EssConnection, RdsConnection, EcsConnection, SlbConnection, VpcConnection


class Aliyun:
    def help(self, req, resp):
        h = '''
                        aliyun ecs rds ess slb dns

        '''
        return h

    def add_record(self, req, resp):
        rr = req.get_param(name='rr')
        if rr is None:
            return '--rr(rr) is need'
        rrtype = req.get_param(name='rr') or 'A'
        value = req.get_param(name='value')
        if value is None:
            return '--value(value) is need'
        domainname = req.get_param(name='domainname')
        if domainname is None:
            return '--domainname(domainname) is need'
        return DnsConnection.add_record(
            rr=rr, rrtype=rrtype, value=value, domainname=domainname)

    def get_all_records(self, req, resp):
        domainname = req.get_param(name='domainname')
        if domainname is None:
            return '--domainname(domainname) is need'
        return DnsConnection.get_all_records(domainname=domainname)

    def get_record_id(self, req, resp):
        rr = req.get_param(name='rr')
        if rr is None:
            return '--rr(rr) is need'
        rrtype = req.get_param(name='rr') or 'A'
        value = req.get_param(name='value')
        if value is None:
            return '--value(value) is need'
        domainname = req.get_param(name='domainname')
        if domainname is None:
            return '--domainname(domainname) is need'
        return DnsConnection.get_record_id(
            rr=rr, rrtype=rrtype, value=value, domainname=domainname)

    def delete_record(self, req, resp):
        rr = req.get_param(name='rr')
        if rr is None:
            return '--rr(rr) is need'
        rrtype = req.get_param(name='rr') or 'A'
        value = req.get_param(name='value')
        if value is None:
            return '--value(value) is need'
        domainname = req.get_param(name='domainname')
        if domainname is None:
            return '--domainname(domainname) is need'
        return DnsConnection.delete_record(
            rr=rr, rrtype=rrtype, value=value, domainname=domainname)

    def create_scaling_group(self, req, resp):
        max_size = req.get_param(name='max_size')
        if max_size is None:
            return '--max_size(max_size) is need'
        min_size = req.get_param(name='min_size')
        if min_size is None:
            return '--min_size(min_size) is need'

        scaling_group_name = req.get_param(name='scaling_group_name')
        default_cooldown = req.get_param(name='default_cooldown')
        removal_policies = req.get_param(name='removal_policies')
        load_balancer_id = req.get_param(name='load_balancer_id')
        db_instance_ids = req.get_param(name='db_instance_ids')
        return EssConnection.create_scaling_group(
            max_size=max_size,
            min_size=min_size,
            scaling_group_name=scaling_group_name,
            default_cooldown=default_cooldown,
            removal_policies=removal_policies,
            load_balancer_id=load_balancer_id,
            db_instance_ids=db_instance_ids)

    def modify_scaling_group(self, req, resp):
        max_size = req.get_param(name='max_size')
        min_size = req.get_param(name='min_size')
        scaling_group_id = req.get_param(name='scaling_group_id')
        if scaling_group_id is None:
            return '--scaling_group_id(scaling_group_id) is need'

        scaling_group_name = req.get_param(name='scaling_group_name')
        default_cooldown = req.get_param(name='default_cooldown')
        removal_policies = req.get_param(name='removal_policies')
        active_scaling_configuration_id = req.get_param(
            name='active_scaling_configuration_id')
        return EssConnection.modify_scaling_group(
            scaling_group_id=scaling_group_id,
            scaling_group_name=scaling_group_name,
            active_scaling_configuration_id=active_scaling_configuration_id,
            min_size=min_size,
            max_size=max_size,
            default_cooldown=default_cooldown,
            removal_policies=removal_policies)

    def describe_scaling_groups(self, req, resp):
        scaling_group_ids = req.get_param(name='scaling_group_ids')
        scaling_group_names = req.get_param(name='scaling_group_names')
        return EssConnection.describe_scaling_groups(
            scaling_group_ids=scaling_group_ids,
            scaling_group_names=scaling_group_names)

    def get_all_regions(self, req, resp):
        return EcsConnection.get_all_regions()

    def get_all_zones(self, req, resp):
        return EcsConnection.get_all_zones()

    def get_all_clusters(self, req, resp):
        return EcsConnection.get_all_clusters()

    def get_all_instance_status(self, req, resp):
        zone_id = req.get_param(name='zone_id')
        if zone_id is None:
            return '--zone_id(zone_id) is need'
        return EcsConnection.get_all_instance_status(zone_id=zone_id)

    def get_instance(self, req, resp):
        instance_id = req.get_param(name='instance_id')
        if instance_id is None:
            return '--instance_id(instance_id) is need'
        return EcsConnection.get_instance(instance_id=instance_id)

    def start_instance(self, req, resp):
        instance_id = req.get_param(name='instance_id')
        if instance_id is None:
            return '--instance_id(instance_id) is need'
        return EcsConnection.start_instance(instance_id=instance_id)

    def stop_instance(self, req, resp):
        instance_id = req.get_param(name='instance_id')
        if instance_id is None:
            return '--instance_id(instance_id) is need'
        force = req.get_param(name='force') or False
        return EcsConnection.stop_instance(
            instance_id=instance_id, force=force)

    def reboot_instance(self, req, resp):
        instance_id = req.get_param(name='instance_id')
        if instance_id is None:
            return '--instance_id(instance_id) is need'
        force = req.get_param(name='force') or False
        return EcsConnection.reboot_instance(
            instance_id=instance_id, force=force)

    def delete_instance(self, req, resp):
        instance_id = req.get_param(name='instance_id')
        if instance_id is None:
            return '--instance_id(instance_id) is need'
        return EcsConnection.delete_instance(instance_id=instance_id)

    def modify_instance(self, req, resp):
        instance_id = req.get_param(name='instance_id')
        if instance_id is None:
            return '--instance_id(instance_id) is need'
        new_instance_name = req.get_param(name='new_instance_name')
        new_password = req.get_param(name='new_password')
        new_hostname = req.get_param(name='new_hostname')
        new_security_group_id = req.get_param(name='new_security_group_id')
        new_description = req.get_param(name='new_description')
        return EcsConnection.modify_instance(
            instance_id=instance_id,
            new_instance_name=new_instance_name,
            new_password=new_password,
            new_hostname=new_hostname,
            new_security_group_id=new_security_group_id,
            new_description=new_description)

    def modify_instance_spec(self, req, resp):
        instance_id = req.get_param(name='instance_id')
        if instance_id is None:
            return '--instance_id(instance_id) is need'
        instance_type = req.get_param(name='instance_type')
        internet_max_bandwidth_out = req.get_param(
            name='internet_max_bandwidth_out')
        internet_max_bandwidth_in = req.get_param(
            name='internet_max_bandwidth_in')
        return EcsConnection.modify_instance_spec(
            instance_id=instance_id,
            instance_type=instance_type,
            internet_max_bandwidth_out=internet_max_bandwidth_out,
            internet_max_bandwidth_in=internet_max_bandwidth_in)

    def renew_instance(self, req, resp):
        instance_id = req.get_param(name='instance_id')
        if instance_id is None:
            return '--instance_id(instance_id) is need'
        period = req.get_param(name='period')
        return EcsConnection.renew_instance(
            instance_id=instance_id, period=period)

    def report_expiring_instance(self, req, resp):
        days = req.get_param(name='days') or 7
        return EcsConnection.report_expiring_instance(days=days)

    def replace_system_disk(self, req, resp):
        instance_id = req.get_param(name='instance_id')
        if instance_id is None:
            return '--instance_id(instance_id) is need'
        image_id = req.get_param(name='image_id')
        if image_id is None:
            return '--image_id(image_id) is need'
        return EcsConnection.replace_system_disk(
            instance_id=instance_id, image_id=image_id)

    def join_security_group(self, req, resp):
        instance_id = req.get_param(name='instance_id')
        if instance_id is None:
            return '--instance_id(instance_id) is need'
        security_group_id = req.get_param(name='security_group_id')
        if security_group_id is None:
            return '--security_group_id(security_group_id) is need'
        return EcsConnection.join_security_group(
            instance_id=instance_id, security_group_id=security_group_id)

    def leave_security_group(self, req, resp):
        instance_id = req.get_param(name='instance_id')
        if instance_id is None:
            return '--instance_id(instance_id) is need'
        security_group_id = req.get_param(name='security_group_id')
        if security_group_id is None:
            return '--security_group_id(security_group_id) is need'
        return EcsConnection.leave_security_group(
            instance_id=instance_id, security_group_id=security_group_id)

    def create_disk(self, req, resp):
        zone_id = req.get_param(name='zone_id')
        if zone_id is None:
            return '--zone_id(zone_id) is need'
        name = req.get_param(name='name')
        description = req.get_param(name='description')
        size = req.get_param(name='size')
        snapshot_id = req.get_param(name='snapshot_id')
        return EcsConnection.create_disk(
            zone_id=zone_id,
            name=name,
            description=description,
            size=size,
            snapshot_id=snapshot_id)

    def attach_disk(self, req, resp):
        instance_id = req.get_param(name='instance_id')
        if instance_id is None:
            return '--instance_id(instance_id) is need'
        disk_id = req.get_param(name='disk_id')
        if instance_id is None:
            return '--instance_id(instance_id) is need'
        device = req.get_param(name='device')
        delete_with_instance = req.get_param(name='delete_with_instance')
        return EcsConnection.attach_disk(
            instance_id=instance_id,
            disk_id=disk_id,
            device=device,
            delete_with_instance=delete_with_instance)

    def detach_disk(self, req, resp):
        instance_id = req.get_param(name='instance_id')
        if instance_id is None:
            return '--instance_id(instance_id) is need'
        disk_id = req.get_param(name='disk_id')
        if instance_id is None:
            return '--instance_id(instance_id) is need'
        return EcsConnection.detach_disk(
            instance_id=instance_id, disk_id=disk_id)

    def add_disk(self, req, resp):
        instance_id = req.get_param(name='instance_id')
        if instance_id is None:
            return '--instance_id(instance_id) is need'
        size = req.get_param(name='size')
        snapshot_id = req.get_param(name='snapshot_id')
        name = req.get_param(name='name')
        description = req.get_param(name='description')
        device = req.get_param(name='device')
        delete_with_instance = req.get_param(name='delete_with_instance')
        return EcsConnection.add_disk(
            instance_id=instance_id,
            size=size,
            snapshot_id=snapshot_id,
            name=name,
            description=description,
            device=device,
            delete_with_instance=delete_with_instance)

    def reset_disk(self, req, resp):
        snapshot_id = req.get_param(name='snapshot_id')
        if snapshot_id is None:
            return '--snapshot_id(snapshot_id) is need'
        disk_id = req.get_param(name='disk_id')
        if disk_id is None:
            return '--instance_id(instance_id) is need'
        return EcsConnection.reset_disk(
            disk_id=disk_id, snapshot_id=snapshot_id)

    def delete_disk(self, req, resp):
        disk_id = req.get_param(name='disk_id')
        if disk_id is None:
            return '--disk_id(disk_id) is need'
        return EcsConnection.delete_disk(disk_id=disk_id)

    def create_instance(self, req, resp):
        image_id = req.get_param(name='image_id')
        if image_id is None:
            return '--image_id(image_id) is need'
        instance_type = req.get_param(name='instance_type')
        if instance_type is None:
            return '--instance_type(instance_type) is need'
        security_group_id = req.get_param(name='security_group_id')
        if security_group_id is None:
            return '--security_group_id(security_group_id) is need'
        instance_name = req.get_param(name='instance_name')
        internet_max_bandwidth_in = req.get_param(
            name='internet_max_bandwidth_in')
        internet_max_bandwidth_out = req.get_param(
            name='internet_max_bandwidth_out')
        hostname = req.get_param(name='hostname')
        password = req.get_param(name='password')
        system_disk_type = req.get_param(name='system_disk_type')
        internet_charge_type = req.get_param(name='internet_charge_type')
        io_optimized = req.get_param(name='io_optimized')
        data_disks = req.get_param(name='data_disks')
        description = req.get_param(name='description')
        zone_id = req.get_param(name='zone_id')
        instance_charge_type = req.get_param(
            name='instance_charge_type') or 'PrePaid'
        period = req.get_param(name='period') or 1

        return EcsConnection.create_instance(
            image_id=image_id,
            instance_type=instance_type,
            security_group_id=security_group_id,
            instance_name=instance_name,
            internet_max_bandwidth_in=internet_max_bandwidth_in,
            internet_max_bandwidth_out=internet_max_bandwidth_out,
            hostname=hostname,
            password=password,
            system_disk_type=system_disk_type,
            internet_charge_type=internet_charge_type,
            instance_charge_type=instance_charge_type,
            io_optimized=io_optimized,
            data_disks=data_disks,
            description=description,
            zone_id=zone_id,
            period=period)

    def allocate_public_ip(self, req, resp):
        instance_id = req.get_param(name='instance_id')
        if instance_id is None:
            return '--instance_id(instance_id) is need'
        return EcsConnection.allocate_public_ip(instance_id=instance_id)

    def create_and_start_instance(self, req, resp):
        image_id = req.get_param(name='image_id')
        if image_id is None:
            return '--image_id(image_id) is need'
        instance_type = req.get_param(name='instance_type')
        if instance_type is None:
            return '--instance_type(instance_type) is need'
        initial_security_group_id = req.get_param(
            name='initial_security_group_id')
        if initial_security_group_id is None:
            return '--initial_security_group_id(initial_security_group_id) is need'
        additional_security_group_ids = req.get_param(
            name='additional_security_group_ids') or []
        instance_name = req.get_param(name='instance_name')
        internet_max_bandwidth_in = req.get_param(
            name='internet_max_bandwidth_in')
        internet_max_bandwidth_out = req.get_param(
            name='internet_max_bandwidth_out')
        hostname = req.get_param(name='hostname')
        password = req.get_param(name='password')
        system_disk_type = req.get_param(name='system_disk_type')
        internet_charge_type = req.get_param(name='internet_charge_type')
        block_till_ready = req.get_param(name='block_till_ready')
        data_disks = req.get_param(name='data_disks')
        description = req.get_param(name='description')
        zone_id = req.get_param(name='zone_id')
        instance_charge_type = req.get_param(
            name='instance_charge_type') or 'PrePaid'
        assign_public_ip = req.get_param(name='assign_public_ip')
        return EcsConnection.create_and_start_instance(
            image_id=image_id,
            instance_type=instance_type,
            initial_security_group_id=initial_security_group_id,
            additional_security_group_ids=additional_security_group_ids,
            instance_name=instance_name,
            internet_max_bandwidth_in=internet_max_bandwidth_in,
            internet_max_bandwidth_out=internet_max_bandwidth_out,
            hostname=hostname,
            password=password,
            system_disk_type=system_disk_type,
            internet_charge_type=internet_charge_type,
            instance_charge_type=instance_charge_type,
            assign_public_ip=assign_public_ip,
            block_till_ready=block_till_ready,
            data_disks=data_disks,
            description=description,
            zone_id=zone_id)

    def describe_auto_snapshot_policy(self, req, resp):
        return EcsConnection.describe_auto_snapshot_policy()

    def modify_auto_snapshot_policy(self, req, resp):
        system_disk_policy_enabled = req.get_param(
            name='system_disk_policy_enabled')
        if system_disk_policy_enabled is None:
            return '--system_disk_policy_enabled(system_disk_policy_enabled) is need'
        system_disk_policy_time_period = req.get_param(
            name='system_disk_policy_time_period')
        if system_disk_policy_time_period is None:
            return '--system_disk_policy_time_period(system_disk_policy_time_period) is need'
        system_disk_policy_time_period = req.get_param(
            name='system_disk_policy_time_period')
        if system_disk_policy_time_period is None:
            return '--system_disk_policy_time_period(system_disk_policy_time_period) is need'
        system_disk_policy_retention_days = req.get_param(
            name='system_disk_policy_retention_days')
        if system_disk_policy_retention_days is None:
            return '--system_disk_policy_retention_days(system_disk_policy_retention_days) is need'
        system_disk_policy_retention_last_week = req.get_param(
            name='system_disk_policy_retention_last_week')
        if system_disk_policy_retention_last_week is None:
            return '--system_disk_policy_retention_last_week(system_disk_policy_retention_last_week) is need'
        data_disk_policy_enabled = req.get_param(
            name='data_disk_policy_enabled')
        if data_disk_policy_enabled is None:
            return '--data_disk_policy_enabled(data_disk_policy_enabled) is need'
        data_disk_policy_time_period = req.get_param(
            name='data_disk_policy_time_period')
        if data_disk_policy_time_period is None:
            return '--data_disk_policy_time_period(data_disk_policy_retention_days) is need'
        data_disk_policy_retention_days = req.get_param(
            name='data_disk_policy_retention_days')
        if data_disk_policy_retention_days is None:
            return '--data_disk_policy_retention_days(data_disk_policy_retention_days) is need'
        data_disk_policy_retention_last_week = req.get_param(
            name='data_disk_policy_retention_last_week')
        if data_disk_policy_retention_last_week is None:
            return '--data_disk_policy_retention_last_week(data_disk_policy_retention_last_week) is need'
        return EcsConnection.modify_auto_snapshot_policy(
            system_disk_policy_enabled=system_disk_policy_enabled,
            system_disk_policy_time_period=system_disk_policy_time_period,
            system_disk_policy_retention_days=system_disk_policy_retention_days,
            system_disk_policy_retention_last_week=system_disk_policy_retention_last_week,
            data_disk_policy_enabled=data_disk_policy_enabled,
            data_disk_policy_time_period=data_disk_policy_time_period,
            data_disk_policy_retention_days=data_disk_policy_retention_days,
            data_disk_policy_retention_last_week=data_disk_policy_retention_last_week
        )

    def describe_disks(self, req, resp):
        zone_id = req.get_param(name='zone_id')
        disk_ids = req.get_param(name='disk_ids')
        instance_id = req.get_param(name='instance_id')
        return EcsConnection.describe_disks(
            zone_id=zone_id, disk_ids=disk_ids, instance_id=instance_id)

    def describe_instance_types(self, req, resp):
        return EcsConnection.describe_instance_types()

    def describe_instance_disks(self, req, resp):
        instance_id = req.get_param(name='instance_id')
        if instance_id is None:
            return '--instance_id(instance_id) is need'
        return EcsConnection.describe_instance_disks(instance_id=instance_id)

    def modify_disk(self, req, resp):
        disk_id = req.get_param(name='disk_id')
        if disk_id is None:
            return '--disk_id(disk_id) is need'
        name = req.get_param(name='name')
        description = req.get_param(name='description')
        delete_with_instance = req.get_param(name='delete_with_instance')
        return EcsConnection.modify_disk(
            disk_id=disk_id,
            name=name,
            description=description,
            delete_with_instance=delete_with_instance)

    def reinit_disk(self, req, resp):
        disk_id = req.get_param(name='disk_id')
        if disk_id is None:
            return '--disk_id(disk_id) is need'
        return EcsConnection.reinit_disk(disk_id=disk_id)

    def delete_snapshot(self, req, resp):
        instance_id = req.get_param(name='instance_id')
        if instance_id is None:
            return '--instance_id(instance_id) is need'
        instance_id = req.get_param(name='instance_id')
        if instance_id is None:
            return '--instance_id(instance_id) is need'
        return EcsConnection.delete_snapshot(
            instance_id=instance_id, snapshot_id=instance_id)

    def describe_snapshot(self, req, resp):
        instance_id = req.get_param(name='instance_id')
        if instance_id is None:
            return '--instance_id(instance_id) is need'
        return EcsConnection.describe_snapshot(snapshot_id=instance_id)

    def describe_snapshots(self, req, resp):
        instance_id = req.get_param(name='instance_id')
        disk_id = req.get_param(name='disk_id')
        snapshot_ids = req.get_param(name='snapshot_ids')
        return EcsConnection.describe_snapshots(
            instance_id=instance_id,
            disk_id=disk_id,
            snapshot_ids=snapshot_ids)

    def create_snapshot(self, req, resp):
        instance_id = req.get_param(name='instance_id')
        disk_id = req.get_param(name='disk_id')
        if instance_id is None:
            return '--instance_id(instance_id) is need'
        disk_id = req.get_param(name='disk_id')
        if disk_id is None:
            return '--disk_id(disk_id) is need'
        snapshot_name = req.get_param(name='snapshot_name')
        timeout_secs = req.get_param(name='timeout_secs')
        description = req.get_param(name='description')
        return EcsConnection.create_snapshot(
            instance_id=instance_id,
            disk_id=disk_id,
            snapshot_name=snapshot_name,
            timeout_secs=timeout_secs,
            description=description)

    def describe_images(self, req, resp):
        image_ids = req.get_param(name='image_ids')
        owner_alias = req.get_param(name='owner_alias')
        snapshot_id = req.get_param(name='snapshot_id')
        return EcsConnection.describe_images(
            image_ids=image_ids,
            owner_alias=owner_alias,
            snapshot_id=snapshot_id)

    def delete_image(self, req, resp):
        image_id = req.get_param(name='image_id')
        if image_id is None:
            return '--image_id(image_id) is need'
        return EcsConnection.delete_image(image_id=image_id)

    def create_image(self, req, resp):
        snapshot_id = req.get_param(name='snapshot_id')
        if snapshot_id is None:
            return '--snapshot_id(snapshot_id) is need'
        image_version = req.get_param(name='image_version')
        description = req.get_param(name='description')
        os_name = req.get_param(name='os_name')
        return EcsConnection.create_image(
            snapshot_id=snapshot_id,
            image_version=image_version,
            description=description,
            os_name=os_name)

    def create_image_from_instance(self, req, resp):
        instance_id = req.get_param(name='instance_id')
        if instance_id is None:
            return '--instance_id(instance_id) is need'
        image_version = req.get_param(name='image_version')
        description = req.get_param(name='description')
        os_name = req.get_param(name='os_name')
        timeout_secs = req.get_param(name='timeout_secs')
        return EcsConnection.create_image_from_instance(
            instance_id=instance_id,
            image_version=image_version,
            description=description,
            os_name=os_name,
            timeout_secs=timeout_secs)

    def describe_security_groups(self, req, resp):
        return EcsConnection.describe_security_groups()

    def create_security_group(self, req, resp):
        description = req.get_param(name='description')
        if description is None:
            return '--description(description) is need'
        return EcsConnection.create_security_group(description=description)

    def get_security_group(self, req, resp):
        security_group_id = req.get_param(name='security_group_id')
        if security_group_id is None:
            return '--security_group_id(security_group_id) is need'
        return EcsConnection.get_security_group(
            security_group_id=security_group_id)

    def delete_security_group(self, req, resp):
        security_group_id = req.get_param(name='security_group_id')
        if security_group_id is None:
            return '--security_group_id(security_group_id) is need'
        return EcsConnection.delete_security_group(
            security_group_id=security_group_id)

    def add_external_cidr_ip_rule(self, req, resp):
        security_group_id = req.get_param(name='security_group_id')
        if security_group_id is None:
            return '--security_group_id(security_group_id) is need'
        ip_protocol = req.get_param(name='ip_protocol')
        if ip_protocol is None:
            return '--ip_protocol(ip_protocol) is need'
        port_range = req.get_param(name='port_range')
        if port_range is None:
            return '--port_range(port_range) is need'
        source_cidr_ip = req.get_param(name='source_cidr_ip')
        if source_cidr_ip is None:
            return '--source_cidr_ip(source_cidr_ip) is need'
        policy = req.get_param(name='policy')
        return EcsConnection.add_external_cidr_ip_rule(
            security_group_id=security_group_id,
            ip_protocol=ip_protocol,
            port_range=port_range,
            source_cidr_ip=source_cidr_ip,
            policy=policy)

    def add_group_rule(self, req, resp):
        security_group_id = req.get_param(name='security_group_id')
        if security_group_id is None:
            return '--security_group_id(security_group_id) is need'
        ip_protocol = req.get_param(name='ip_protocol')
        if ip_protocol is None:
            return '--ip_protocol(ip_protocol) is need'
        port_range = req.get_param(name='port_range')
        if port_range is None:
            return '--port_range(port_range) is need'
        source_group_id = req.get_param(name='source_group_id')
        if source_group_id is None:
            return '--source_group_id(source_group_id) is need'
        policy = req.get_param(name='policy')
        return EcsConnection.add_group_rule(
            security_group_id=security_group_id,
            ip_protocol=ip_protocol,
            port_range=port_range,
            source_group_id=source_group_id,
            policy=policy)

    def remove_external_cidr_ip_rule(self, req, resp):
        security_group_id = req.get_param(name='security_group_id')
        if security_group_id is None:
            return '--security_group_id(security_group_id) is need'
        ip_protocol = req.get_param(name='ip_protocol')
        if ip_protocol is None:
            return '--ip_protocol(ip_protocol) is need'
        port_range = req.get_param(name='port_range')
        if port_range is None:
            return '--port_range(port_range) is need'
        source_cidr_ip = req.get_param(name='source_cidr_ip')
        if source_cidr_ip is None:
            return '--source_cidr_ip(source_cidr_ip) is need'
        policy = req.get_param(name='policy')
        return EcsConnection.remove_external_cidr_ip_rule(
            security_group_id=security_group_id,
            ip_protocol=ip_protocol,
            port_range=port_range,
            source_cidr_ip=source_cidr_ip,
            policy=policy)

    def remove_internal_cidr_ip_rule(self, req, resp):
        security_group_id = req.get_param(name='security_group_id')
        if security_group_id is None:
            return '--security_group_id(security_group_id) is need'
        ip_protocol = req.get_param(name='ip_protocol')
        if ip_protocol is None:
            return '--ip_protocol(ip_protocol) is need'
        port_range = req.get_param(name='port_range')
        if port_range is None:
            return '--port_range(port_range) is need'
        source_cidr_ip = req.get_param(name='source_cidr_ip')
        if source_cidr_ip is None:
            return '--source_cidr_ip(source_cidr_ip) is need'
        policy = req.get_param(name='policy')
        return EcsConnection.remove_internal_cidr_ip_rule(
            security_group_id=security_group_id,
            ip_protocol=ip_protocol,
            port_range=port_range,
            source_cidr_ip=source_cidr_ip,
            policy=policy)

    def remove_group_rule(self, req, resp):
        security_group_id = req.get_param(name='security_group_id')
        if security_group_id is None:
            return '--security_group_id(security_group_id) is need'
        ip_protocol = req.get_param(name='ip_protocol')
        if ip_protocol is None:
            return '--ip_protocol(ip_protocol) is need'
        port_range = req.get_param(name='port_range')
        if port_range is None:
            return '--port_range(port_range) is need'
        source_cidr_ip = req.get_param(name='source_cidr_ip')
        if source_cidr_ip is None:
            return '--source_cidr_ip(source_cidr_ip) is need'
        policy = req.get_param(name='policy')
        return EcsConnection.remove_group_rule(
            security_group_id=security_group_id,
            ip_protocol=ip_protocol,
            port_range=port_range,
            source_cidr_ip=source_cidr_ip,
            policy=policy)

    def get_dbinstance(self, req, resp):
        instance_id = req.get_param(name='instance_id')
        if instance_id is None:
            return '--instance_id(instance_id) is need'
        return RdsConnection.get_dbinstance(instance_id=instance_id)

    def describe_all_db_instances(self, req, resp):
        region_id = req.get_param(name='region_id') or 'cn-hangzhou'
        engine = req.get_param(name='engine')
        db_instance_type = req.get_param(name='db_instance_type')
        instance_network_type = req.get_param(name='instance_network_type')
        connection_mode = req.get_param(name='connection_mode')
        return RdsConnection.describe_all_db_instances(
            region_id=region_id,
            engine=engine,
            db_instance_type=db_instance_type,
            instance_network_type=instance_network_type,
            connection_mode=connection_mode)

    def report_expiring_dbinstance(self, req, resp):
        days = req.get_param(name='days') or 7
        return RdsConnection.report_expiring_dbinstance(days=days)

    def get_all_load_balancer_status(self, req, resp):
        instance_id = req.get_param(name='instance_id')
        if instance_id is None:
            return '--instance_id(instance_id) is need'
        return SlbConnection.get_all_load_balancer_status(
            instance_id=instance_id)

    def delete_load_balancer(self, req, resp):
        load_balancer_id = req.get_param(name='load_balancer_id')
        if load_balancer_id is None:
            return '--load_balancer_id(load_balancer_id) is need'
        return SlbConnection.delete_load_balancer(
            load_balancer_id=load_balancer_id)

    def get_load_balancer(self, req, resp):
        load_balancer_id = req.get_param(name='load_balancer_id')
        if load_balancer_id is None:
            return '--load_balancer_id(load_balancer_id) is need'
        return SlbConnection.get_load_balancer(
            load_balancer_id=load_balancer_id)

    def create_load_balancer(self, req, resp):
        region_id = req.get_param(name='region_id')
        if region_id is None:
            return '--region_id(region_id) is need'
        address_type = req.get_param(name='address_type')
        internet_charge_type = req.get_param(name='internet_charge_type')
        bandwidth = req.get_param(name='bandwidth')
        load_balancer_name = req.get_param(name='load_balancer_name')
        return SlbConnection.create_load_balancer(
            region_id=region_id,
            address_type=address_type,
            internet_charge_type=internet_charge_type,
            bandwidth=bandwidth,
            load_balancer_name=load_balancer_name)

    def set_load_balancer_status(self, req, resp):
        load_balancer_id = req.get_param(name='load_balancer_id')
        if load_balancer_id is None:
            return '--load_balancer_id(load_balancer_id) is need'
        status = req.get_param(name='status')
        if status is None:
            return '--status(status) is need'
        return SlbConnection.set_load_balancer_status(
            load_balancer_id=load_balancer_id, status=status)

    def set_load_balancer_name(self, req, resp):
        load_balancer_id = req.get_param(name='load_balancer_id')
        if load_balancer_id is None:
            return '--load_balancer_id(load_balancer_id) is need'
        name = req.get_param(name='name')
        if name is None:
            return '--name(name) is need'
        return SlbConnection.set_load_balancer_name(
            load_balancer_id=load_balancer_id, name=name)

    def delete_listener(self, req, resp):
        load_balancer_id = req.get_param(name='load_balancer_id')
        if load_balancer_id is None:
            return '--load_balancer_id(load_balancer_id) is need'
        listener_port = req.get_param(name='listener_port')
        if listener_port is None:
            return '--listener_port(listener_port) is need'
        return SlbConnection.delete_listener(
            load_balancer_id=load_balancer_id, listener_port=listener_port)

    def set_listener_status(self, req, resp):
        load_balancer_id = req.get_param(name='load_balancer_id')
        if load_balancer_id is None:
            return '--load_balancer_id(load_balancer_id) is need'
        status = req.get_param(name='status')
        if status is None:
            return '--status(status) is need'
        return SlbConnection.set_load_balancer_status(
            load_balancer_id=load_balancer_id, status=status)

    def get_tcp_listener(self, req, resp):
        load_balancer_id = req.get_param(name='load_balancer_id')
        if load_balancer_id is None:
            return '--load_balancer_id(load_balancer_id) is need'
        listener_port = req.get_param(name='listener_port')
        if listener_port is None:
            return '--listener_port(listener_port) is need'
        return SlbConnection.get_tcp_listener(
            load_balancer_id=load_balancer_id, listener_port=listener_port)

    def get_http_listener(self, req, resp):
        load_balancer_id = req.get_param(name='load_balancer_id')
        if load_balancer_id is None:
            return '--load_balancer_id(load_balancer_id) is need'
        listener_port = req.get_param(name='listener_port')
        if listener_port is None:
            return '--listener_port(listener_port) is need'
        return SlbConnection.get_http_listener(
            load_balancer_id=load_balancer_id, listener_port=listener_port)

    def create_tcp_listener(self, req, resp):
        load_balancer_id = req.get_param(name='load_balancer_id')
        if load_balancer_id is None:
            return '--load_balancer_id(load_balancer_id) is need'
        listener_port = req.get_param(name='listener_port')
        if listener_port is None:
            return '--listener_port(listener_port) is need'
        backend_server_port = req.get_param(name='backend_server_port')
        if backend_server_port is None:
            return '--backend_server_port(backend_server_port) is need'
        healthy_threshold = req.get_param(name='healthy_threshold') or 3
        unhealthy_threshold = req.get_param(name='unhealthy_threshold') or 3
        listener_status = req.get_param(name='listener_status')
        scheduler = req.get_param(name='scheduler')
        health_check = req.get_param(name='health_check')
        connect_timeout = req.get_param(name='connect_timeout')
        interval = req.get_param(name='interval')
        connect_port = req.get_param(name='connect_port')
        persistence_timeout = req.get_param(name='persistence_timeout')
        return SlbConnection.create_tcp_listener(
            load_balancer_id=load_balancer_id,
            listener_port=listener_port,
            backend_server_port=backend_server_port,
            healthy_threshold=healthy_threshold,
            unhealthy_threshold=unhealthy_threshold,
            listener_status=listener_status,
            scheduler=scheduler,
            health_check=health_check,
            connect_timeout=connect_timeout,
            interval=interval,
            connect_port=connect_port,
            persistence_timeout=persistence_timeout)

    def create_http_listener(self, req, resp):
        load_balancer_id = req.get_param(name='load_balancer_id')
        if load_balancer_id is None:
            return '--load_balancer_id(load_balancer_id) is need'
        listener_port = req.get_param(name='listener_port')
        if listener_port is None:
            return '--listener_port(listener_port) is need'
        backend_server_port = req.get_param(name='backend_server_port')
        if backend_server_port is None:
            return '--backend_server_port(backend_server_port) is need'
        healthy_threshold = req.get_param(name='healthy_threshold') or 3
        unhealthy_threshold = req.get_param(name='unhealthy_threshold') or 3
        bandwidth = req.get_param(name='bandwidth')
        scheduler = req.get_param(name='scheduler')
        health_check = req.get_param(name='health_check')
        connect_timeout = req.get_param(name='connect_timeout')
        interval = req.get_param(name='interval')
        sticky_session = req.get_param(name='sticky_session')
        x_forwarded_for = req.get_param(name='x_forwarded_for')
        sticky_session_type = req.get_param(name='sticky_session_type')
        cookie_timeout = req.get_param(name='cookie_timeout')
        cookie = req.get_param(name='cookie')
        domain = req.get_param(name='domain')
        uri = req.get_param(name='uri')
        if bandwidth is None:
            return '--bandwidth(bandwidth) is need'
        if sticky_session is None:
            return '--sticky_session(sticky_session) is need'
        if health_check is None:
            return '--health_check(health_check) is need'
        return SlbConnection.create_http_listener(
            load_balancer_id=load_balancer_id,
            listener_port=listener_port,
            backend_server_port=backend_server_port,
            bandwidth=bandwidth,
            sticky_session=sticky_session,
            health_check=health_check,
            healthy_threshold=healthy_threshold,
            unhealthy_threshold=unhealthy_threshold,
            scheduler=scheduler,
            connect_timeout=connect_timeout,
            interval=interval,
            x_forwarded_for=x_forwarded_for,
            sticky_session_type=sticky_session_type,
            cookie_timeout=cookie_timeout,
            cookie=cookie,
            domain=domain,
            uri=uri)

    def update_tcp_listener(self, req, resp):
        load_balancer_id = req.get_param(name='load_balancer_id')
        if load_balancer_id is None:
            return '--load_balancer_id(load_balancer_id) is need'
        listener_port = req.get_param(name='listener_port')
        if listener_port is None:
            return '--listener_port(listener_port) is need'
        healthy_threshold = req.get_param(name='healthy_threshold') or 3
        unhealthy_threshold = req.get_param(name='unhealthy_threshold') or 3
        scheduler = req.get_param(name='scheduler')
        health_check = req.get_param(name='health_check')
        connect_timeout = req.get_param(name='connect_timeout')
        interval = req.get_param(name='interval')
        connect_port = req.get_param(name='connect_port')
        persistence_timeout = req.get_param(name='persistence_timeout')
        return SlbConnection.update_tcp_listener(
            load_balancer_id=load_balancer_id,
            listener_port=listener_port,
            healthy_threshold=healthy_threshold,
            unhealthy_threshold=unhealthy_threshold,
            scheduler=scheduler,
            health_check=health_check,
            connect_timeout=connect_timeout,
            interval=interval,
            connect_port=connect_port,
            persistence_timeout=persistence_timeout)

    def update_http_listener(self, req, resp):
        load_balancer_id = req.get_param(name='load_balancer_id')
        if load_balancer_id is None:
            return '--load_balancer_id(load_balancer_id) is need'
        listener_port = req.get_param(name='listener_port')
        if listener_port is None:
            return '--listener_port(listener_port) is need'
        healthy_threshold = req.get_param(name='healthy_threshold') or 3
        unhealthy_threshold = req.get_param(name='unhealthy_threshold') or 3
        scheduler = req.get_param(name='scheduler')
        health_check = req.get_param(name='health_check')
        health_check_timeout = req.get_param(name='health_check_timeout')
        interval = req.get_param(name='interval')
        sticky_session = req.get_param(name='sticky_session')
        x_forwarded_for = req.get_param(name='x_forwarded_for')
        sticky_session_type = req.get_param(name='sticky_session_type')
        cookie_timeout = req.get_param(name='cookie_timeout')
        cookie = req.get_param(name='cookie')
        domain = req.get_param(name='domain')
        uri = req.get_param(name='uri')
        return SlbConnection.update_http_listener(
            load_balancer_id=load_balancer_id,
            listener_port=listener_port,
            healthy_threshold=healthy_threshold,
            unhealthy_threshold=unhealthy_threshold,
            scheduler=scheduler,
            health_check=health_check,
            health_check_timeout=health_check_timeout,
            interval=interval,
            x_forwarded_for=x_forwarded_for,
            sticky_session=sticky_session,
            sticky_session_type=sticky_session_type,
            cookie_timeout=cookie_timeout,
            cookie=cookie,
            domain=domain,
            uri=uri)

    def start_load_balancer_listener(self, req, resp):
        load_balancer_id = req.get_param(name='load_balancer_id')
        if load_balancer_id is None:
            return '--load_balancer_id(load_balancer_id) is need'
        listener_port = req.get_param(name='listener_port')
        if listener_port is None:
            return '--listener_port(listener_port) is need'
        return SlbConnection.start_load_balancer_listener(
            load_balancer_id=load_balancer_id, listener_port=listener_port)

    def stop_load_balancer_listener(self, req, resp):
        load_balancer_id = req.get_param(name='load_balancer_id')
        if load_balancer_id is None:
            return '--load_balancer_id(load_balancer_id) is need'
        listener_port = req.get_param(name='listener_port')
        if listener_port is None:
            return '--listener_port(listener_port) is need'
        return SlbConnection.stop_load_balancer_listener(
            load_balancer_id=load_balancer_id, listener_port=listener_port)

    def get_backend_servers(self, req, resp):
        load_balancer_id = req.get_param(name='load_balancer_id')
        if load_balancer_id is None:
            return '--load_balancer_id(load_balancer_id) is need'
        listener_port = req.get_param(name='listener_port')
        if listener_port is None:
            return '--listener_port(listener_port) is need'
        return SlbConnection.get_backend_servers(
            load_balancer_id=load_balancer_id, listener_port=listener_port)

    def remove_backend_servers(self, req, resp):
        load_balancer_id = req.get_param(name='load_balancer_id')
        if load_balancer_id is None:
            return '--load_balancer_id(load_balancer_id) is need'
        backend_servers = req.get_param(name='backend_servers')
        if backend_servers is None:
            return '--backend_servers(backend_servers) is need'
        return SlbConnection.remove_backend_servers(
            load_balancer_id=load_balancer_id, backend_servers=backend_servers)

    def add_backend_servers(self, req, resp):
        load_balancer_id = req.get_param(name='load_balancer_id')
        if load_balancer_id is None:
            return '--load_balancer_id(load_balancer_id) is need'
        backend_servers = req.get_param(name='backend_servers')
        if backend_servers is None:
            return '--backend_servers(backend_servers) is need'
        return SlbConnection.add_backend_servers(
            load_balancer_id=load_balancer_id, backend_servers=backend_servers)

    def deregister_backend_servers(self, req, resp):
        backend_servers = req.get_param(name='backend_servers')
        if backend_servers is None:
            return '--backend_servers(backend_servers) is need'
        return SlbConnection.deregister_backend_servers(backend_servers)

    def create_vpc(self, req, resp):
        cidr_block = req.get_param(name='cidr_block')
        usercidr = req.get_param(name='usercidr')
        vpcname = req.get_param(name='vpcname')
        description = req.get_param(name='description')
        return VpcConnection.create_vpc(
            cidr_block=cidr_block,
            usercidr=usercidr,
            vpcname=vpcname,
            description=description)

    def delete_vpc(self, req, resp):
        vpcid = req.get_param(name='vpcid')
        if vpcid is None:
            return '--vpcid(vpcid) is need'
        return VpcConnection.delete_vpc(vpcid=vpcid)

    def describe_vpcs(self, req, resp):
        return VpcConnection.describe_vpcs()

    def modify_vpc(self, req, resp):
        cidr_block = req.get_param(name='cidr_block')
        usercidr = req.get_param(name='usercidr')
        vpcname = req.get_param(name='vpcname')
        description = req.get_param(name='description')
        return VpcConnection.modify_vpc(
            cidr_block=cidr_block,
            usercidr=usercidr,
            vpcname=vpcname,
            description=description)

    def describe_vrouters(self, req, resp):
        return VpcConnection.describe_vrouters()

    def modify_vrouter(self, req, resp):
        vrouter_id = req.get_param(name='vrouter_id')
        if vrouter_id is None:
            return '--vrouter_id is need'
        vroutername = req.get_param(name='vroutername')
        description = req.get_param(name='description')
        return VpcConnection.modify_vrouter(
            vrouter_id=vrouter_id,
            vroutername=vroutername,
            description=description)

    def create_vswitch(self, req, resp):
        zone_id = req.get_param(name='zone_id')
        if zone_id is None:
            return '--zone_id is need'
        cidr_block = req.get_param(name='cidr_block')
        if cidr_block is None:
            return '--cidr_block is need'
        vpc_id = req.get_param(name='vpc_id')
        if vpc_id is None:
            return '--vpc_id is need'
        vswitchname = req.get_param(name='vswitchname')
        description = req.get_param(name='description')
        return VpcConnection.create_vswitch(
            zone_id=zone_id,
            cidr_block=cidr_block,
            vpc_id=vpc_id,
            vswitchname=vswitchname,
            description=description)

    def describe_vswitches(self, req, resp):
        vpc_id = req.get_param(name='vpc_id')
        zone_id = req.get_param(name='zone_id')
        vswitch_id = req.get_param(name='vswitch_id')
        is_default = req.get_param(name='is_default')
        if vpc_id is None:
            return '--vpc_id is need'
        return VpcConnection.describe_vswitches(
            vpc_id=vpc_id,
            zone_id=zone_id,
            vswitch_id=vswitch_id,
            is_default=is_default)

    def delete_vswitch(self, req, resp):
        vswitch_id = req.get_param(name='vswitch_id')
        if vswitch_id is None:
            return '--vswitch_id is need'
        return VpcConnection.delete_vswitch(vswitch_id=vswitch_id)

    def modify_vswitch(self, req, resp):
        vswitch_id = req.get_param(name='vswitch_id')
        if vswitch_id is None:
            return '--vswitch_id is need'
        vswitchname = req.get_param(name='vswitchname')
        description = req.get_param(name='description')
        return VpcConnection.modify_vswitch(
            vswitch_id=vswitch_id,
            vswitchname=vswitchname,
            description=description)

    def create_route_entry(self, req, resp):
        routetable_id = req.get_param(name='routetable_id')
        if routetable_id is None:
            return '--routetable_id is need'
        destination_cidr_block = req.get_param(name='destination_cidr_block')
        if destination_cidr_block is None:
            return '--destination_cidr_block is need'
        nexthop_type = req.get_param(name='nexthop_type')
        nexthop_id = req.get_param(name='nexthop_id')
        nexthop_list = req.get_param(name='nexthop_list')
        return VpcConnection.create_route_entry(
            routetable_id=routetable_id,
            destination_cidr_block=destination_cidr_block,
            nexthop_type=nexthop_type,
            nexthop_id=nexthop_id,
            nexthop_list=nexthop_list)

    def delete_route_entry(self, req, resp):
        routetable_id = req.get_param(name='routetable_id')
        if routetable_id is None:
            return '--routetable_id is need'
        nexthop_type = req.get_param(name='nexthop_type')
        nexthop_id = req.get_param(name='nexthop_id')
        nexthop_list = req.get_param(name='nexthop_list')
        return VpcConnection.delete_route_entry(
            routetable_id=routetable_id,
            nexthop_type=nexthop_type,
            nexthop_id=nexthop_id,
            nexthop_list=nexthop_list)

    def describe_route_table(self, req, resp):
        return VpcConnection.describe_route_table()

    def allocate_eip_dddress(self, req, resp):
        bandwidth = req.get_param(name='bandwidth')
        internet_charge_type = req.get_param(name='internet_charge_type')
        return VpcConnection.allocate_eip_dddress(
            bandwidth=bandwidth, internet_charge_type=internet_charge_type)

    def associate_eip_dddress(self, req, resp):
        allocation_id = req.get_param(name='allocation_id')
        if allocation_id is None:
            return '--allocation_id is need'
        instance_id = req.get_param(name='instance_id')
        if instance_id is None:
            return '--instance_id is need'
        instance_type = req.get_param(name='instance_type')
        return VpcConnection.associate_eip_dddress(
            allocation_id=allocation_id,
            instance_id=instance_id,
            instance_type=instance_type)

    def unassociate_eip_dddress(self, req, resp):
        allocation_id = req.get_param(name='allocation_id')
        if allocation_id is None:
            return '--allocation_id is need'
        instance_id = req.get_param(name='instance_id')
        if instance_id is None:
            return '--instance_id is need'
        instance_type = req.get_param(name='instance_type')
        return VpcConnection.unassociate_eip_dddress(
            allocation_id=allocation_id,
            instance_id=instance_id,
            instance_type=instance_type)

    def describe_eip_dddress(self, req, resp):
        return VpcConnection.describe_eip_dddress()

    def modify_eip_dddress(self, req, resp):
        allocation_id = req.get_param(name='allocation_id')
        if allocation_id is None:
            return '--allocation_id is need'
        bandwidth = req.get_param(name='bandwidth')
        return VpcConnection.modify_eip_dddress(
            allocation_id=allocation_id, bandwidth=bandwidth)

    def release_eip_dddress(self, req, resp):
        allocation_id = req.get_param(name='allocation_id')
        if allocation_id is None:
            return '--allocation_id is need'
        return VpcConnection.release_eip_dddress(allocation_id=allocation_id)

    def create_virtual_border_router(self, req, resp):
        physical_connection_id = req.get_param(name='physical_connection_id')
        if physical_connection_id is None:
            return '--physical_connection_id is need'
        vlan_id = req.get_param(name='vlan_id')
        if vlan_id is None:
            return '--vlan_id is need'
        return VpcConnection.create_virtual_border_router(
            physical_connection_id=physical_connection_id, vlan_id=vlan_id)
