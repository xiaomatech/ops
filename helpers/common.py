#!/usr/bin/env python
# -*- coding:utf8 -*-
import functools
from gevent.threadpool import ThreadPool
from gevent.pool import Pool
#from multiprocessing.dummy import Pool as ThreadPool
#from multiprocessing import Pool
from logger import log_error, log_debug
from configs import ssh_config
import subprocess
from subprocess import Popen, PIPE
import simplejson as json
import multiprocessing
import requests
import hashlib


def ansible_run(**post_data):
    playbook = post_data.get('playbook')
    extra_vars = post_data.get('extra_vars')
    hosts = post_data.get('hosts')
    if playbook is None or extra_vars is None or hosts is None:
        raise Exception('params missing')
    thread_pool.apply_async(
        do_task, kwds=json.loads(post_data), callback=ansible_callback)


def do_task(**post_data):
    callback = post_data.get('callback_url')
    acceptkey = post_data.get('accept_key')
    task_id = post_data.get('task_id')
    playbook = post_data.get('playbook')
    extra_vars = post_data.get('extra_vars')
    hosts = post_data.get('hosts')
    p = Popen(
        "/usr/bin/ansible-playbook -i %s  %s --extra-vars='%s' -s" %
        (hosts, playbook, extra_vars),
        shell=True,
        stdout=PIPE,
        stderr=PIPE)
    try:
        stdout, stderr = p.communicate()
    finally:
        subprocess._cleanup()
        p.stdout.close()
        p.stderr.close()
    rc = p.returncode

    log_debug(
        'task id  %d in hosts %s playbook %s return stdout %s ,stderr %s!' %
        (task_id, hosts, playbook, stdout, stderr))
    return {
        'task_id': task_id,
        'callback_url': callback,
        'accept_key': acceptkey,
        'hosts': hosts,
        'playbook': playbook,
        'stdout': stdout,
        'stderr': stderr,
        'returncode': rc
    }


def callback_post(**result):
    callback_url = result.get('callback_url')
    if not callback_url:
        return
    headers = {'content-type': 'application/json'}
    m1 = hashlib.md5()
    accept_key = result.get('accept_key')
    m1.update(accept_key + str(result['task_id']))
    result['access_token'] = m1.hexdigest()
    r = requests.post(callback_url, data=json.dumps(result), headers=headers)
    log_debug("callback %s  data %s return %s" %
              (callback_url, json.dumps(result), r.text))
    r.close()


def ansible_callback(callback_result):
    callback_pool.apply_async(callback_post, kwds=callback_result)


def ssh_remote_execute(host, cmd):
    try:
        import paramiko
        if not cmd:
            log_error("cmd is None! Failed!")
            return None

        try:
            client = paramiko.SSHClient()
            private_key_file = ssh_config.get('private_key_file')
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            if private_key_file is not None and private_key_file != '':
                k = paramiko.RSAKey.from_private_key_file(
                    filename=ssh_config.get('private_key_file'))
                client.connect(
                    host,
                    username=ssh_config.get('user'),
                    port=ssh_config.get('port'),
                    timeout=ssh_config.get('timeout'),
                    pkey=k)
            else:
                client.connect(
                    host,
                    username=ssh_config.get('user'),
                    password=ssh_config.get('password'),
                    port=ssh_config.get('port'),
                    timeout=ssh_config.get('timeout'))
            stdin, stdout, stderr = client.exec_command(cmd, timeout=300)
            result = stdout.readlines()
            log_debug(result)
            return result

        except Exception as exc:
            log_error("failed: %s" % cmd)
            log_error(exc)
            return None

        finally:
            try:
                stdin.close()
                stdout.close()
                stderr.close()
                client.close()
            except:
                pass

    except ImportError as exc:
        log_error("load module 'paramiko', donnot exist!")
        log_error(exc)
        return None


thread_pool = ThreadPool(multiprocessing.cpu_count() - 1)
callback_pool = ThreadPool(multiprocessing.cpu_count() - 1)

processe_pool = Pool(multiprocessing.cpu_count())
async_processe_pool = Pool(multiprocessing.cpu_count())


#高io 线程池同步处理
def thread_task():
    def handle_func(func):
        @functools.wraps(func)
        def handle_args(**kwargs):
            return thread_pool.apply(func, kwds=kwargs)

        return handle_args

    return handle_func


#高io 线程池异步处理
def async_task(callback):
    def handle_func(func):
        @functools.wraps(func)
        def handle_args(*args, **kwargs):
            async_pool = callback_pool.apply_async(
                func, kwds=kwargs, callback=callback)
            async_pool.join()

        return handle_args

    return handle_func


#高cpu同步进程池
def process_task():
    def handle_func(func):
        @functools.wraps(func)
        def handle_args(*args, **kwargs):
            result = processe_pool.map(func=func, iterable=args)
            processe_pool.join()
            return result

        return handle_args

    return handle_func


#高cpu异步进程池
def async_process_task(callback):
    def handle_func(func):
        @functools.wraps(func)
        def handle_args(*args, **kwargs):
            result = async_processe_pool.map_async(
                func=func, iterable=args, callback=callback)
            async_processe_pool.join()
            return result

        return handle_args

    return handle_func
