#!/usr/bin/env python
# -*- coding:utf8 -*-

from models.cmdb import *
from library.IPy import IP
import simplejson as json
from configs import cmdb_config
from helpers.cmdb import server_tag_ip


class cmdb:
    def help(self, req, resp):
        h = '''
            ops cmdb listip -t cop.meizu_loc.bj_owt.test 根据tag获取ip列表
                             ------------------------------------------------
                            给机器打标签  参考小米tag模型
                            强烈建议事先规范好 取名尽量通俗易懂
                            因为这个标签是其它系统比如发布,监控,虚拟化等自动化的基础
                             ------------------------------------------------
            ops cmdb addtag -t cop=meizu,loc=bj,owt=test -h 10.3.133.18 对10.3.133.18打上key=value的标签
            ops cmdb edittag -t cop=meizu,loc=bj,owt=test -h 10.3.133.18 修改10.3.133.18打上key=value的标签
            ops cmdb deltag -k owt -h 10.3.133.18 删除10.3.133.18的名为key的标签
            ops cmdb listhosttag -h 10.3.133.18 查看10.3.133.18的标签
            ops cmdb listkey 查看可以使用的标签key

            ops cmdb hostinfo -h 10.3.133.18 查看机器信息
            ops cmdb listhosts 获取所有机器列表

                             ------------------------------------------------
                                    添加机器 以下除了ip是必须
                              其它的建议填准确 以便后面的业务智能调度,方便运维管理
                             ------------------------------------------------
            ops cmdb addhost --room BJ --rack C18 --seat 20 --ip 10.3.133.18 添加服务器
                备注:
                    room:机房简写 用英文字母或拼音简写
                    rack:放在哪个机架 机架编号(一般是上架的时候有idc提供)
                    seat:放的位置
                    ip:机器的ip
                    type:机器类型 server,switch,router,firewall,virtual_machine (服务器,交换机,路由器,防火墙,虚拟机)
                    logicarea:网络的分区 virt,lvs,db,manage,big_data,external (虚拟化区,lvs区,db区,管理网区,大数据区,外网区)
                    remarks:备注

            ops cmdb importhost -f cmdb_example.json 导入数据 通过ops download cmdb_example.json 获取示例

                             ------------------------------------------------
                                                    网段管理
                             ------------------------------------------------
            ops cmdb addsegment --cidr 10.3.133.0/24 --gateway 10.3.133.1 --room Bj 添加网段
                    备注:
                        cidr 网段
                        gateway 网关
                        room 机房
                        vlan_id vlan号
                        ip_type ip类型支持 internal,external,vip (内网,外网,vip)
                        carriers 运营商 internal,telecom,china_unicorm,edu_net,china_mobile,other(内网,电信,联通,教育,移动,其它)
                        remarks 备注 一般填写此网段的用途
            ops cmdb delsegment --cidr 10.3.133.0/24 删除网段
            ops cmdb listsegment 获取网段列表

        '''
        return h

    def listip(self, req, resp):
        tag = req.get_param(name='t')
        if tag is None:
            return '-t(tag) is need'
        return server_tag_ip(tag=tag)

    def _get_asset_id(self, host):
        assets = Ip.select().where(Ip.ip == host)
        if len(assets) < 1:
            return None
        return assets[0].assets

    def addtag(self, req, resp):
        host = req.get_param(name='h') or req.get_header(name='SERVER-IP')
        if host is None:
            return '-h(host) is need'
        tag = req.get_param(name='t')
        if tag is None:
            return '-t(tag) is need'
        asset_id = self._get_asset_id(host=host)
        if asset_id is None:
            return {
                'status': 'fail',
                'msg': 'not such host,please addhost first'
            }
        taglist = tag.split(',')
        unsuport_key = []
        for item in taglist:
            tmp = item.split('=')
            key, value = tmp[0], tmp[1]
            key_can_use_list = cmdb_config.get('key_can_use_list')
            if key not in key_can_use_list:
                unsuport_key.append(key)
                continue
            servertag, created = ServerTag.get_or_create(
                assets=asset_id, server_tag_value=value, server_tag_key=key)
        if len(unsuport_key) > 0:
            return {
                'status': 'fail',
                'unsuport_key': unsuport_key,
                'msg': 'have some un support key'
            }
        return {'status': 'ok'}

    def edittag(self, req, resp):
        host = req.get_param(name='h') or req.get_header(name='SERVER-IP')
        if host is None:
            return '-h(host) is need'
        tag = req.get_param(name='t')
        if tag is None:
            return '-t(tag) is need'
        asset_id = self._get_asset_id(host=host)
        if asset_id is None:
            return {
                'status': 'fail',
                'msg': 'not such host,please addhost first'
            }
        taglist = tag.split(',')
        unsuport_key = []
        for item in taglist:
            tmp = item.split('=')
            key, value = tmp[0], tmp[1]
            key_can_use_list = cmdb_config.get('key_can_use_list')
            if key not in key_can_use_list:
                unsuport_key.append(key)
                continue
            ServerTag.update(server_tag_value=value)\
                .where((ServerTag.server_tag_key == key) & (ServerTag.assets == asset_id)).execute()
        if len(unsuport_key) > 0:
            return {
                'status': 'fail',
                'unsuport_key': unsuport_key,
                'msg': 'have some un support key'
            }
        return {'status': 'ok'}

    def deltag(self, req, resp):
        host = req.get_param(name='h') or req.get_header(name='SERVER-IP')
        if host is None:
            return '-h(host) is need'
        tag = req.get_param(name='t')
        if tag is None:
            return '-t(tag) is need'
        taglist = tag.split(',')
        for item in taglist:
            tmp = item.split('=')
            key, value = tmp[0], tmp[1]
            ServerTag.delete().where((ServerTag.server_tag_key == key) & (
                ServerTag.server_tag_value == value)).execute()
        return {'status': 'ok'}

    def listhosttag(self, req, resp):
        host = req.get_param(name='h') or req.get_header(name='SERVER-IP')
        if host is None:
            return '-h(host) is need'
        result = []
        taglist = ServerTag.select().join(Ip,on=(ServerTag.assets==Ip.assets))\
            .where(Ip.ip==host)
        for item in taglist:
            result.append(item.server_tag_key + '.' + item.server_tag_value)
        return result

    def listkey(self, req, resp):
        result = cmdb_config.get('key_can_use_list')
        return result

    def hostinfo(self, req, resp):
        host = req.get_param(name='h') or req.get_header(name='SERVER-IP')
        if host is None:
            return '-h(host) is need'
        result = {}
        taglist = ServerTag.select().join(Ip,on=(ServerTag.assets==Ip.assets)) \
            .where(Ip.ip==host)
        tag = []
        for item in taglist:
            tag.append(item.server_tag_key + '.' + item.server_tag_value)
        result['tag'] = tag
        asset_id = self._get_asset_id(host=host)
        if asset_id is None:
            return 'not such host,please addhost first'

        device = Device.select().where(Device.assets == asset_id)
        for item in device:
            result['status'] = item.device_status
            result['environment'] = item.environment
            result['logic_area'] = item.logic_area
            result['seat'] = item.seat
            result['tier'] = item.tier
        template = DeviceTemplate.select().join(Device,on=(DeviceTemplate.template == Device.template))\
                   .where(Device.assets == asset_id)
        for item in template:
            result['cpu'] = item.cpu
            result['disk'] = item.disk
            result['memory'] = item.memory
            result['server_type'] = item.server_type
            result['kernel'] = item.kernel

        return result

    def listhosts(self, req, resp):
        result = []
        res = Ip.select().group_by(Ip.ip)
        for server in res:
            result.append(server.ip)
        return result

    def addhost(self, req, resp):
        type = req.get_param(name='type') or 'server'
        logicarea = req.get_param(name='logicarea') or 'virt'
        remarks = req.get_param(name='remarks')
        ip = req.get_param(name='ip')
        room = req.get_param(name='room')

        rack = req.get_param(name='rack')
        seat = req.get_param(name='seat')

        return self._addhost(
            type=type,
            ip=ip,
            room=room,
            rack=rack,
            seat=seat,
            logicarea=logicarea,
            remarks=remarks)

    def addsegment(self, req, resp):
        vlan_id = req.get_param(name='vlan_id') or 0
        ip_type = req.get_param(name='ip_type') or 'internal'
        carriers = req.get_param(name='carriers') or 'internal'
        remarks = req.get_param(name='remarks')
        room = req.get_param(name='room')
        cidr = req.get_param(name='cidr')
        gateway = req.get_param(name='gateway')
        if room is None:
            return '--room(room) is need'
        if cidr is None:
            return '--cidr(cidr) is need'
        if gateway is None:
            return '--gateway(gateway) is need'
        segment_ip = cidr.split('/')[0]
        ips = IP(cidr)
        netmask = ips.netmask()

        room_res, created = Room.get_or_create(
            room_name_en=room, room_name=room)
        room_id = room_res.room

        segment, created = Segment.get_or_create(
            gateway=gateway,
            ip_type=ip_type,
            carriers=carriers,
            remarks=remarks,
            segment_ip=segment_ip,
            netmask=netmask,
            total=len(ips),
            vlan=vlan_id,
            room=room_id)
        if created:
            insert = []
            for ip in ips:
                insert.append({'segment': segment.segment, 'ip': ip})
            SegmentIpPool.insert_many(insert).execute()

        return 'ok'

    def delsegment(self, req, resp):
        cidr = req.get_param(name='cidr')
        if cidr is None:
            return '--cidr(cidr) is need'
        segment_ip = cidr.split('/')[0]
        ips = IP(cidr)
        netmask = ips.netmask()
        for ip in ips:
            SegmentIpPool.delete().where(SegmentIpPool.ip == ip).execute()
        Segment.delete().where((Segment.segment_ip == segment_ip) & (
            Segment.netmask == netmask)).execute()
        return 'ok'

    def listsegment(self, req, resp):
        result = []
        res = Segment.select()
        for item in res:
            result.append({
                'vlan': item.vlan,
                'total': item.total,
                'ip_type': item.ip_type,
                'status': item.status,
                'remarks': item.remarks,
                'netmask': item.netmask,
                'gateway': item.gateway,
                'segment_ip': item.segment_ip,
                'carriers': item.carriers,
                'logic_area': item.logic_area,
                'assigned': item.assigned
            })

        return result

    def importhost(self, req, resp):
        filename = req.get_param('f')
        if filename is None:
            return '-f(file) need'
        json_txt = filename.file.read()

        raw = json.loads(json_txt)
        for row in raw:
            type = row.get('type')
            ip = row.get('ip')
            room = row.get('room')
            rack = row.get('rack')
            seat = row.get('seat')
            logicarea = row.get('logicarea')
            remarks = row.get('remarks')
            self._addhost(
                type=type,
                ip=ip,
                room=room,
                rack=rack,
                seat=seat,
                logicarea=logicarea,
                remarks=remarks)
        return 'ok'

    def _addhost(self, type, ip, room, rack, seat, logicarea, remarks=None):
        #check ip exist
        exist = SegmentIpPool.select().where(SegmentIpPool.ip == ip)
        if not exist:
            return 'please add segment first'

        room_res, created = Room.get_or_create(
            room_name_en=room, room_name=room)
        room_id = room_res.room

        rack_res, created = Rack.get_or_create(room=room_id, rack=rack)
        rack_id = rack_res.rack_id
        Seat.get_or_create(seat=seat, rack=rack_id, room=room_id)
        template, created = DeviceTemplate.get_or_create(server_type=type, )
        template_id = template.template

        device, created = Device.get_or_create(
            logic_area=logicarea,
            remarks=remarks,
            room=room_id,
            rack=rack_id,
            seat=seat,
            template=template_id)
        asset_id = device.assets

        SegmentIpPool.update(assigned='enable').where(
            SegmentIpPool.ip == ip).execute()
        segment_id = exist[0].segment
        segment = Segment.select().where(Segment.segment == segment_id)
        Segment.update(assigned=segment[0].assigned + 1).execute()
        Ip.get_or_create(
            assets=asset_id,
            ip=ip,
            carriers=segment[0].carriers,
            gateway=segment[0].gateway,
            netmask=segment[0].netmask,
            segment_ip=segment[0].segment_ip)

        return 'ok'
