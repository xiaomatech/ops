#!/usr/bin/env python
# -*- coding:utf8 -*-
from helpers.common import *
from models.deploy import *
from configs import deploy_config
import time
from helpers.cmdb import server_tag_ip, server_tag_group
from helpers.logger import log_debug, log_error


class Deploy:
    def __init__(self):
        self.support_types = ['copy', 'rsync', 'git', 'download', 's3']
        self.ansistrano_deploy_to = deploy_config.get('deploy_to_dir')
        self.ansistrano_version_dir = deploy_config.get('version_dir')
        self.ansistrano_current_dir = deploy_config.get('current_dir')
        self.ansistrano_rsync_extra_params = deploy_config.get(
            'rsync_extra_params')
        self.ansistrano_git_branch = deploy_config.get('git_branch')
        self.ansistrano_get_url_base = deploy_config.get('get_url_base')

    def help(self, req, resp):
        h = '''
                                发布
                前提条件:
                    1,初始化ansible 并配置好/etc/ansible/hosts文件(主要是ip列表和ssh账号密码(或者配置成免登陆))
                    2,确保 ansible-playbook/deploy 存在
                    3,确保已上传发布用的步骤文件
                            deploy_check.sh 检测业务是否启动正常的 参考 ops download deploy/deploy_check.sh
                            deploy_offline.sh 业务的下线操作 参考 ops download deploy/deploy_offline.sh
                            deploy_online.sh 业务的上线操作 参考 ops download deploy/deploy_online.sh
                    4,配置好需要发布的业务的组信息(按组发布),每个业务一个配置
                        示例 ops download business_group.json|python -m json.tool
                        检查编写的是否正确 ops check_group business_group.json
                    5,回滚就是再发布一次上一个版本
                    6,按组发布 如果有一组不成功即停止 人工确认情况后继续发

                        使用

            ops deploy list_type 查看支持的发布方式

            ops deploy create -f business_group.json -t download -uri http://jenkins.example.com/test/1.0/test-1.0.zip 创建一个发布

            ops deploy info -j 20160713321 查看发布id为 20160713321(创建的时候返回的) 发布情况

            ops deploy retry -j 20160713321 继续未完成的发布

            ops deploy list_deploy -t test -l 10 查看业务为test的最新10条发布历史

        '''
        return h

    def list_template(self, req, resp):
        result = []
        res = DeployTemplate.select()
        for item in res:
            result.append({
                'server_tag': item.server_tag,
                'package_uri': item.package_uri,
                'package_type': item.package_type
            })
        return result

    def add_template(self, req, resp):
        server_tag = req.get_param('server_tag')
        package_uri = req.get_param('package_uri')
        package_type = req.get_param('package_type')
        if server_tag is None:
            return '--server_tag need'
        if package_uri is None:
            return '--package_uri need'
        if package_type is None:
            return '--package_type need'

        template, created = DeployTemplate.get_or_create(
            server_tag=server_tag,
            package_uri=package_uri,
            package_type=package_type)
        return template.template

    def edit_template(self, req, resp):
        server_tag = req.get_param('server_tag')
        package_uri = req.get_param('package_uri')
        package_type = req.get_param('package_type')
        if server_tag is None:
            return '--server_tag need'
        if package_uri is None:
            return '--package_uri need'
        if package_type is None:
            return '--package_type need'

        return DeployTemplate.update(
            package_uri=package_uri, package_type=package_type).where(
                DeployTemplate.server_tag == server_tag).execute()

    def del_template(self, req, resp):
        server_tag = req.get_param('server_tag')
        if server_tag is None:
            return '--server_tag need'
        return DeployTemplate.delete().where(
            DeployTemplate.server_tag == server_tag)

    def list_type(self, req, resp):
        return self.support_types

    def _job_id(self, uid):
        now_time = time.time()
        request_id = str(now_time).replace('.', '')[-8:] + str(uid)[-4:]
        return request_id.replace('.', '')

    @staticmethod
    @async_task(callback=ansible_callback)
    def _do_job(job_id=None, is_retry=False):
        if job_id is None:
            return
        server_group = {}
        if is_retry:
            res = Tasks.select().where((Tasks.job == job_id) & ((
                Tasks.result_status == 2) | (Tasks.result_status == 0)))
        else:
            res = Tasks.select().where((Tasks.job == job_id) & (
                Tasks.result_status == 2))
        for item in res:
            if not item.group in server_group.keys():
                server_group[item.group] = []
            server_group[item.group].append(item.server_ip)
        for key, item in enumerate(server_group):
            lb_ip = item
            app_ip_list = server_group.get(lb_ip)
            for app_ip in app_ip_list:
                log_debug(app_ip)

    def create(self, req, resp):
        uid = req.get_header(name='LOGIN-UID') or req.get_param(name='uid')
        operator = req.get_header(name='LOGIN-USER')
        if uid is None:
            return 'uid need'
        job_id = req.get_header(name='REQUEST-ID') or self._job_id(uid=uid)
        group_file = req.get_param(name='f')
        if group_file is not None:
            json_txt = group_file.file.read()
            server_group = json.loads(json_txt)
        else:
            server_tag = req.get_param(name='server_tag')
            if server_tag is None:
                return '--server_tag need'
            server_group = server_tag_ip(tag=server_tag)
        template_id = req.get_param(name='t')
        version = req.get_param(name='version')

        #create job
        Jobs.insert(
            group_list=server_group,
            job=job_id,
            operator=operator,
            template=template_id,
            release_version=version).execute()
        #create task
        for key, item in enumerate(server_group):
            lb_ip = item
            app_ip_list = server_group.get(lb_ip)
            for app_ip in app_ip_list:
                Tasks.insert(
                    job=job_id, group=lb_ip, server_ip=app_ip).execute()
        #threadpool task for every group
        self._do_job(job_id=job_id)

        return {'job_id': str(job_id)}

    def info(self, req, resp):
        job_id = req.get_param(name='j')
        if job_id is None:
            return '-j(job_id) need'
        result = {}
        res = Jobs.select().join(
            DeployTemplate,
            on=(Jobs.template == DeployTemplate.template)).where(
                Jobs.job == job_id)
        for item in res:
            result = {
                'job_id': job_id,
                'group': item.group_list,
                'operator': item.operator,
                'release_version': item.release_version,
                'server_tag': item.template.server_tag,
                'package_uri': item.template.package_uri,
                'package_type': item.template.package_type,
            }
        return result

    def retry(self, req, resp):
        job_id = req.get_param(name='j')
        if job_id is None:
            return '-j(job_id) need'
        #threadpool task for every group
        self._do_job(job_id=job_id, is_retry=True)

        return 'retrying'

    def list_deploy(self, req, resp):
        tag = req.get_param(name='t')
        if tag is None:
            return '-t(tag) need'
        limit = req.get_param(name='l')
        if limit is None:
            return '-l(limit) need'
        result = []
        res = Jobs.select().join(DeployTemplate,on=(Jobs.template==DeployTemplate.template))\
            .where(DeployTemplate.server_tag==tag).limit(int(limit))
        for item in res:
            result.append({
                'job_id': item.job,
                'group': item.group_list,
                'operator': item.operator,
                'release_version': item.release_version,
                'server_tag': item.template.server_tag,
                'package_uri': item.template.package_uri,
                'package_type': item.template.package_type,
            })
        return result
