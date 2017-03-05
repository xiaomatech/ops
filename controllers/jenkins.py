#!/usr/bin/env python
# -*- coding:utf8 -*-
from autojenkins import Jenkins
from configs import jenkins_config
from helpers.logger import log_error


class jenkins:
    def __init__(self):
        self.jenkins_url = jenkins_config.get('url')
        self.user = jenkins_config.get('user')
        self.password = jenkins_config.get('password')
        if self.jenkins_url is not None:
            try:
                self.jenkins = Jenkins(
                    self.jenkins_url, auth=(self.user, self.password))
            except Exception as e:
                log_error(e)

    def help(self, req, resp):
        h = '''
                                jenkins CI

                    ops jenkins create_copy -j job -t template -r repo -b branch -p package

                    ops jenkins result -j job
                    ops jenkins info -t template
                    ops jenkins build -j job

                    ops jenkins enable -j job
                    ops jenkins disable -j job
                    ops jenkins delete -j job
        '''
        return h

    def result(self, req, resp):
        job = req.get_param(name='j')
        if job is None:
            return '-j(job) need'
        return self.jenkins.last_result(job)['result']

    def info(self, req, resp):
        template = req.get_param(name='t')
        if template is None:
            return '-t(template) need'
        return self.jenkins.get_config_xml(template)

    def create_copy(self, req, resp):
        job = req.get_param(name='j')
        template = req.get_param(name='t')
        repo = req.get_param(name='r')
        branch = req.get_param(name='b')
        package = req.get_param(name='p')
        if job is None:
            return '-j(job) need'
        if template is None:
            return '-t(template) need'
        if repo is None:
            return '-r(repo) need'
        if branch is None:
            return '-b(branch) need'
        if package is None:
            return '-p(package) need'
        return self.jenkins.create_copy(
            job, template, repo=repo, branch=branch, package=package)

    def build(self, req, resp):
        job = req.get_param(name='j')
        if job is None:
            return '-j(job) need'
        return self.jenkins.build(job)

    def enable(self, req, resp):
        job = req.get_param(name='j')
        if job is None:
            return '-j(job) need'
        return self.jenkins.enable(job)

    def disable(self, req, resp):
        job = req.get_param(name='j')
        if job is None:
            return '-j(job) need'
        return self.jenkins.disable(job)

    def delete(self, req, resp):
        job = req.get_param(name='j')
        if job is None:
            return '-j(job) need'
        return self.jenkins.delete(job)
