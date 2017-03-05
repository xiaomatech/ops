#!/usr/bin/env python
# coding: utf-8
BASE_DIR = '/data/jumpserver'
SSH_PORT = 22
db_config = {
    'host': "1.1.1.1",
    'database': 'db_test',
    'user': 'test',
    'password': 'test'
}
is_log2db = False
get_user_host_list_url = 'http://example.com/v1/get_user_host_list_url'

import sys
sys.setdefaultencoding('utf-8')
import os
import re
import time
import datetime
import textwrap
import paramiko
import errno
import pyte
import operator
import struct, fcntl, socket, select
import uuid
import subprocess

import urllib2
import simplejson as json

import os.path

from ansible.inventory.group import Group
from ansible.inventory.host import Host
from ansible.inventory import Inventory
from ansible.runner import Runner
from ansible.playbook import PlayBook
from ansible import callbacks
from ansible import utils
import ansible.constants as C
import logging
import torndb
import MySQLdb

import signal

#去除ctl+c键盘事件
signal.signal(signal.SIGINT, signal.SIG_IGN)
signal.signal(signal.SIGTSTP, signal.SIG_IGN)

LOG_DIR = os.path.join(BASE_DIR, 'logs')
user = os.popen('whoami').read().strip()
homedir = '/home/' + user

user_log_path = BASE_DIR + '/logs/' + user
if not os.path.isdir(user_log_path):
    os.mkdir(user_log_path, 0777)

uid = os.getuid()

if is_log2db:
    #日志记录到db
    db = torndb.Connection(**db_config)

date = datetime.datetime.now().strftime('%Y%m%d')
if not os.path.isdir(os.path.join(LOG_DIR, 'tty', date)):
    os.makedirs(os.path.join(LOG_DIR, 'tty', date), 0777)


#获取用户机器列表
def get_user_server_list():
    req = urllib2.Request(get_user_host_list_url + '/' + user)
    response_stream = urllib2.urlopen(req)
    res = response_stream.read()
    if not res:
        return []
    res = json.loads(res)
    user_server_list = res
    hostfile = homedir + '/hosts'
    output = open(hostfile, 'w')
    try:
        result = {}
        for item in res:
            key = item['datacenter'] + '->' + item['business'] + '->' + item[
                'container'] + '->' + item['module']
            if not key in result.keys():
                result[key] = []
            result[key].append(item['ip'])
        for i in result:
            output.write('[' + i + ']\n')
            output.write('\n'.join(result[i]))
            output.write('\n\n')
    except Exception as e:
        print e
    finally:
        output.close()

    return user_server_list


user_server_list = get_user_server_list()


def get_tmp_dir():
    seed = uuid.uuid4().hex[:4]
    dir_name = os.path.join('/tmp', '%s-%s' % (
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S'), seed))
    os.mkdir(dir_name, 0777)
    return dir_name


log_id = 0


class Log():
    def __init__(
            self,
            host,
            remote_ip,
            login_type,
            log_path,
            start_time,
            pid,
            is_finished=0,
            end_time=datetime.datetime.now() - datetime.timedelta(hours=8),
            filename=''):
        self.host = host
        self.remote_ip = remote_ip
        self.login_type = login_type
        self.log_path = log_path
        self.start_time = start_time
        self.pid = pid
        self.is_finished = is_finished
        self.end_time = end_time
        self.filename = filename
        self.msg = host + '\r\r' + remote_ip + '\r\r' + login_type + '\r\r' + str(start_time) + '\r\r' + str(pid) + '\r\r' \
                   + log_path + '\r\n\r\n\r\n'
        if is_log2db:
            try:
                db._ensure_connected()
                self.insert_id = db.insert(
                    "INSERT INTO log (`user`,`host`,`remote_ip`,`login_type`,`log_path`,`start_time`,`pid`,`is_finished`) VALUES ('%s','%s','%s','%s','%s','%s',%d,'%d')"
                    % (user, host, remote_ip, login_type, log_path,
                       str(start_time), pid, is_finished))
                global log_id
                log_id = self.insert_id
            except Exception as err:
                pass

    def save(self):
        if is_log2db:
            db._ensure_connected()
            db.update(
                "update log set is_finished='%d', end_time ='%s',filename='%s' where id=%d"
                % (self.is_finished, self.end_time, self.filename,
                   self.insert_id))
        f = file(user_log_path + '/default', 'a')
        write_log(f, self.msg)
        f.close()


class Alert():
    def __init__(self, msg, time, is_finished):
        self.msg = msg + '\r\r' + time + '\r\r' + is_finished + '\r\n\r\n\r\n'
        if is_log2db:
            try:
                db._ensure_connected()
                db.insert(
                    "INSERT INTO alert (`msg`,`time`,`is_finished`) VALUES ('%s','%s','%s')"
                    % (msg, time, is_finished))
            except Exception as err:
                pass

    def save(self):
        f = file(user_log_path + '/alert', 'a')
        write_log(f, self.msg)
        f.close()


class TtyLog():
    def __init__(self, datetime, cmd):
        self.msg = str(datetime) + '\r\r' + cmd + '\r\n\r\n\r\n'
        if is_log2db:
            try:
                global log_id
                db._ensure_connected()
                db.insert(
                    "INSERT INTO ttylog (`datetime`,`cmd`,`log_id`) VALUES ('%s','%s','%d')"
                    % (str(datetime), MySQLdb.escape_string(cmd), log_id))
            except Exception as err:
                pass

    def save(self):
        f = file(user_log_path + '/ttylog', 'a')
        write_log(f, self.msg)
        f.close()


class ExecLog():
    def __init__(self, host, cmd, remote_ip, result):
        self.msg = str(
            host) + '\r\r' + cmd + '\r\r' + remote_ip + '\r\r' + str(result)
        sql = "INSERT INTO execlog (`user`,`host`,`cmd`,`remote_ip`,`result`) VALUES (%s,%s,%s,%s,%s)"
        if is_log2db:
            try:
                db._ensure_connected()
                db.insert(sql, user, host,
                          MySQLdb.escape_string(cmd), remote_ip,
                          MySQLdb.escape_string(str(result)))
            except Exception as err:
                pass

    def save(self):
        f = file(user_log_path + '/execlog', 'a')
        write_log(f, self.msg)
        f.close()


class FileLog():
    def __init__(self, host, filename, type, remote_ip, result):
        self.msg = str(
            host
        ) + '\r\r' + filename + '\r\r' + type + '\r\r' + remote_ip + '\r\r' + str(
            result) + '\r\n\r\n\r\n'
        if is_log2db:
            try:
                db._ensure_connected()
                db.insert(
                    "INSERT INTO filelog (`user`,`host`,`filename`,`type`,`remote_ip`,`result`) VALUES ('%s','%s','%s','%s','%s','%s')"
                    % (user, host, filename, type, remote_ip,
                       MySQLdb.escape_string(str(result))))
            except Exception as err:
                pass

    def save(self):
        f = file(user_log_path + '/filelog', 'a')
        write_log(f, self.msg)
        f.close()


class TermLog():
    def __init__(self, logPath, logPWD, filename, history, timestamp, log):
        self.msg = logPath + '\r\r' + filename + '\r\r' + logPWD +  '\r\r' + history \
                   + '\r\r' + str(log) + '\r\n\r\n\r\n'
        if is_log2db:
            try:
                db._ensure_connected()
                sql = 'INSERT INTO termlog (`logPath`,`logPWD`,`filename`,`timestamp`,`log_id`,`history`,`log`) VALUES (%s,"%s","%s",%s, %s,"%s","%s")'
                global log_id
                termlog_id = db.insert(sql, logPath, logPWD, filename,
                                       str(timestamp), log_id, history, log)

                db.insert(
                    "INSERT INTO termlog_user (`termlog_id`,`user_id`) VALUES ('%d','%d')"
                    % (termlog_id, os.getuid()))
            except Exception as err:
                pass

    def save(self):
        f = file(user_log_path + '/termlog', 'a')
        write_log(f, self.msg)
        f.close()


def set_log(level, filename='shell.log'):
    """
    return a log file object
    根据提示设置log打印
    """
    log_file = os.path.join(LOG_DIR, filename)
    log_level_total = {
        'debug': logging.DEBUG,
        'info': logging.INFO,
        'warning': logging.WARN,
        'error': logging.ERROR,
        'critical': logging.CRITICAL
    }
    logger_f = logging.getLogger('jumpserver')
    logger_f.setLevel(logging.DEBUG)
    fh = logging.FileHandler(log_file)
    fh.setLevel(log_level_total.get(level, logging.DEBUG))
    formatter = logging.Formatter(
        '%(asctime)s - %(filename)s - %(levelname)s - %(message)s')
    fh.setFormatter(formatter)
    logger_f.addHandler(fh)
    return logger_f


def get_private_key_file():
    return homedir + "/.ssh/id_rsa"


hostfile = homedir + '/hosts'
my_inventory = hostfile
private_key_file = get_private_key_file()

logger = set_log('debug')

API_DIR = os.path.dirname(os.path.abspath(__file__))
ANSIBLE_DIR = os.path.join(API_DIR, 'playbooks')
C.HOST_KEY_CHECKING = False

import zipfile


class TermLogRecorder(object):
    """
    TermLogRecorder
    ---
    This class is use for record the terminal output log.
        self.commands is pure commands list, it will have empty item '' because in vi/vim model , I made it log noting.
        self.CMD is the command with timestamp, like this {'1458723794.88': u'ls', '1458723799.82': u'tree'}.
        self.log is the all output with delta time log.
        self.vim_pattern is the regexp for check vi/vim/fg model.
    Usage:
        recorder = TermLogRecorder(user=UserObject) # or recorder = TermLogRecorder(uid=UserID)
        recoder.write(messages)
        recoder.save() # save all log into database
        # The following methods all have `user`,`uid`,args. Same as __init__
        list = recoder.list() # will give a object about this user's all log info
        recoder.load_full_log(filemane) # will get full log
        recoder.load_history(filename) # will only get the command history list
        recoder.share_to(filename,user=UserObject) # or recoder.share_to(filename,uid=UserID). will share this commands to someone
        recoder.unshare_to(filename,user=UserObject) # or recoder.unshare_to(filename,uid=UserID). will unshare this commands to someone
        recoder.setid(id) # registered this term with an id, for monitor
    """
    loglist = dict()

    def __init__(self, user=None, uid=None):
        self.log = {}
        self.id = uid
        self.user = user
        self.recoderStartTime = time.time()
        self.__init_screen_stream()
        self.recoder = False
        self.commands = []
        self._lists = None
        self.file = None
        self.filename = None
        self._data = None
        self.vim_pattern = re.compile(r'\W?vi[m]?\s.* | \W?fg\s.*', re.X)
        self._in_vim = False
        self.CMD = {}

    def __init_screen_stream(self):
        """
        Initializing the virtual screen and the character stream
        """
        self._stream = pyte.ByteStream()
        self._screen = pyte.Screen(100, 35)
        self._stream.attach(self._screen)

    def _command(self):
        for i in self._screen.display:
            if i.strip().__len__() > 0:
                self.commands.append(i.strip())
                if not i.strip() == '':
                    self.CMD[str(time.time())] = self.commands[-1]
        self._screen.reset()

    def setid(self, id):
        self.id = id
        TermLogRecorder.loglist[str(id)] = [self]

    def write(self, msg):
        try:
            self.write_message(msg)
        except:
            pass
        self.log[str(time.time() - self.recoderStartTime)] = msg.decode(
            'utf-8', 'replace')

    def save(self, path=LOG_DIR):
        date = datetime.datetime.now().strftime('%Y%m%d')
        filename = str(uuid.uuid4())
        self.filename = filename
        filepath = os.path.join(path, 'tty', date, filename + '.zip')

        if not os.path.isdir(os.path.join(path, 'tty', date)):
            os.makedirs(os.path.join(path, 'tty', date), 0777)
            os.chmod(os.path.join(LOG_DIR, 'tty', date), 0777)
        while os.path.isfile(filepath):
            filename = str(uuid.uuid4())
            filepath = os.path.join(path, 'tty', date, filename + '.zip')
        password = str(uuid.uuid4())
        try:
            record = TermLog(
                logPath=filepath,
                logPWD=password,
                filename=filename,
                history=json.dumps(self.CMD),
                timestamp=int(self.recoderStartTime)).save()
        except:
            record = TermLog(
                logPath='locale',
                logPWD=password,
                log=json.dumps(self.log),
                filename=filename,
                history=json.dumps(self.CMD),
                timestamp=int(self.recoderStartTime)).save()
        try:
            del TermLogRecorder.loglist[str(self.id)]
        except KeyError:
            pass


class AnsibleError(StandardError):
    """
    the base AnsibleError which contains error(required),
    data(optional) and message(optional).
    存储所有Ansible 异常对象
    """

    def __init__(self, error, data='', message=''):
        super(AnsibleError, self).__init__(message)
        self.error = error
        self.data = data
        self.message = message


class CommandValueError(AnsibleError):
    """
    indicate the input value has error or invalid.
    the data specifies the error field of input form.
    输入不合法 异常对象
    """

    def __init__(self, field, message=''):
        super(CommandValueError, self).__init__('value:invalid', field,
                                                message)


class MyInventory(Inventory):
    """
    this is my ansible inventory object.
    """

    def __init__(self):
        self.inventory = Inventory(my_inventory)
        #self.gen_inventory()

    def my_add_group(self, hosts, groupname, groupvars=None):
        """
        add hosts to a group
        """
        my_group = Group(name=groupname)

        # if group variables exists, add them to group
        if groupvars:
            for key, value in groupvars.iteritems():
                my_group.set_variable(key, value)

        # add hosts to group
        for host in hosts:
            # set connection variables
            hostname = host.get("hostname")
            hostip = host.get('ip', hostname)
            hostport = host.get("port")
            username = host.get("username")
            password = host.get("password")
            ssh_key = host.get("ssh_key")
            my_host = Host(name=hostname, port=hostport)
            my_host.set_variable('ansible_ssh_host', hostip)
            my_host.set_variable('ansible_ssh_port', hostport)
            my_host.set_variable('ansible_ssh_user', username)
            my_host.set_variable('ansible_ssh_pass', password)
            my_host.set_variable('ansible_ssh_private_key_file', ssh_key)

            # set other variables
            for key, value in host.iteritems():
                if key not in ["hostname", "port", "username", "password"]:
                    my_host.set_variable(key, value)
            # add to group
            my_group.add_host(my_host)

        self.inventory.add_group(my_group)

    def gen_inventory(self):
        """
        add hosts to inventory.
        """
        if isinstance(self.resource, list):
            self.my_add_group(self.resource, 'default_group')
        elif isinstance(self.resource, dict):
            for groupname, hosts_and_vars in self.resource.iteritems():
                self.my_add_group(
                    hosts_and_vars.get("hosts"), groupname,
                    hosts_and_vars.get("vars"))


class MyRunner(MyInventory):
    """
    This is a General object for parallel execute modules.
    """

    def __init__(self, *args, **kwargs):
        super(MyRunner, self).__init__(*args, **kwargs)
        self.results_raw = {}

    def run(self,
            module_name='shell',
            module_args='',
            timeout=10,
            forks=10,
            pattern='*',
            become=False,
            become_method='sudo',
            become_user='root',
            become_pass='',
            transport='paramiko'):
        """
        run module from andible ad-hoc.
        module_name: ansible module_name
        module_args: ansible module args
        """
        hoc = Runner(
            module_name=module_name,
            module_args=module_args,
            timeout=timeout,
            inventory=self.inventory,
            private_key_file=private_key_file,
            pattern=pattern,
            forks=forks,
            become=become,
            become_method=become_method,
            become_user=become_user,
            become_pass=become_pass,
            transport=transport)
        self.results_raw = hoc.run()
        logger.debug(self.results_raw)
        return self.results_raw

    @property
    def results(self):
        """
        {'failed': {'localhost': ''}, 'ok': {'jumpserver': ''}}
        """
        result = {'failed': {}, 'ok': {}}
        dark = self.results_raw.get('dark')
        contacted = self.results_raw.get('contacted')
        if dark:
            for host, info in dark.items():
                result['failed'][host] = info.get('msg')

        if contacted:
            for host, info in contacted.items():
                if info.get('invocation').get('module_name') in [
                        'raw', 'shell', 'command', 'script'
                ]:
                    if info.get('rc') == 0:
                        result['ok'][host] = info.get('stdout') + info.get(
                            'stderr')
                    else:
                        result['failed'][host] = info.get('stdout') + info.get(
                            'stderr')
                else:
                    if info.get('failed'):
                        result['failed'][host] = info.get('msg')
                    else:
                        result['ok'][host] = info.get('changed')
        return result


class Command(MyInventory):
    """
    this is a command object for parallel execute command.
    """

    def __init__(self, *args, **kwargs):
        super(Command, self).__init__(*args, **kwargs)
        self.results_raw = {}

    def run(self,
            command,
            module_name="command",
            timeout=10,
            forks=10,
            pattern=''):
        """
        run command from andible ad-hoc.
        command  : 必须是一个需要执行的命令字符串， 比如
                 'uname -a'
        """
        data = {}

        if module_name not in ["raw", "command", "shell"]:
            raise CommandValueError(
                "module_name",
                "module_name must be of the 'raw, command, shell'")
        hoc = Runner(
            module_name=module_name,
            module_args=command,
            timeout=timeout,
            inventory=self.inventory,
            pattern=pattern,
            forks=forks, )
        self.results_raw = hoc.run()

    @property
    def result(self):
        result = {}
        for k, v in self.results_raw.items():
            if k == 'dark':
                for host, info in v.items():
                    result[host] = {'dark': info.get('msg')}
            elif k == 'contacted':
                for host, info in v.items():
                    result[host] = {}
                    if info.get('stdout'):
                        result[host]['stdout'] = info.get('stdout')
                    elif info.get('stderr'):
                        result[host]['stderr'] = info.get('stderr')
        return result

    @property
    def state(self):
        result = {}
        if self.stdout:
            result['ok'] = self.stdout
        if self.stderr:
            result['err'] = self.stderr
        if self.dark:
            result['dark'] = self.dark
        return result

    @property
    def exec_time(self):
        """
        get the command execute time.
        """
        result = {}
        all = self.results_raw.get("contacted")
        for key, value in all.iteritems():
            result[key] = {
                "start": value.get("start"),
                "end": value.get("end"),
                "delta": value.get("delta"),
            }
        return result

    @property
    def stdout(self):
        """
        get the comamnd standard output.
        """
        result = {}
        all = self.results_raw.get("contacted")
        for key, value in all.iteritems():
            result[key] = value.get("stdout")
        return result

    @property
    def stderr(self):
        """
        get the command standard error.
        """
        result = {}
        all = self.results_raw.get("contacted")
        for key, value in all.iteritems():
            if value.get("stderr") or value.get("warnings"):
                result[key] = {
                    "stderr": value.get("stderr"),
                    "warnings": value.get("warnings"),
                }
        return result

    @property
    def dark(self):
        """
        get the dark results.
        """
        return self.results_raw.get("dark")


class CustomAggregateStats(callbacks.AggregateStats):
    """
    Holds stats about per-host activity during playbook runs.
    """

    def __init__(self):
        super(CustomAggregateStats, self).__init__()
        self.results = []

    def compute(self,
                runner_results,
                setup=False,
                poll=False,
                ignore_errors=False):
        """
        Walk through all results and increment stats.
        """
        super(CustomAggregateStats, self).compute(runner_results, setup, poll,
                                                  ignore_errors)

        self.results.append(runner_results)

    def summarize(self, host):
        """
        Return information about a particular host
        """
        summarized_info = super(CustomAggregateStats, self).summarize(host)

        # Adding the info I need
        summarized_info['result'] = self.results

        return summarized_info


class MyPlaybook(MyInventory):
    """
    this is my playbook object for execute playbook.
    """

    def __init__(self, *args, **kwargs):
        super(MyPlaybook, self).__init__(*args, **kwargs)

    def run(self, playbook_relational_path, extra_vars=None):
        """
        run ansible playbook,
        only surport relational path.
        """
        stats = callbacks.AggregateStats()
        playbook_cb = callbacks.PlaybookCallbacks(verbose=utils.VERBOSITY)
        runner_cb = callbacks.PlaybookRunnerCallbacks(
            stats, verbose=utils.VERBOSITY)
        playbook_path = os.path.join(ANSIBLE_DIR, playbook_relational_path)

        pb = PlayBook(
            playbook=playbook_path,
            stats=stats,
            callbacks=playbook_cb,
            runner_callbacks=runner_cb,
            inventory=self.inventory,
            extra_vars=extra_vars,
            check=False)

        self.results = pb.run()

    @property
    def raw_results(self):
        """
        get the raw results after playbook run.
        """
        return self.results


class App(MyPlaybook):
    """
    this is a app object for inclue the common playbook.
    """

    def __init__(self, *args, **kwargs):
        super(App, self).__init__(*args, **kwargs)


#---------------------------------------------------------------------
# 开始
#---------------------------------------------------------------------

login_user = user
try:
    remote_ip = os.environ.get('SSH_CLIENT').split()[0]
except (IndexError, AttributeError):
    remote_ip = os.popen("who -m | awk '{ print $NF }'").read().strip('()\n')

try:
    import termios
    import tty
except ImportError:
    print '\033[1;31m仅支持类Unix系统 Only unix like supported.\033[0m'
    time.sleep(3)
    if is_log2db:
        db.close()
    sys.exit()


def color_print(msg, color='red', exits=False):
    """
    Print colorful string.
    颜色打印字符或者退出
    """
    color_msg = {
        'blue': '\033[1;36m%s\033[0m',
        'green': '\033[1;32m%s\033[0m',
        'yellow': '\033[1;33m%s\033[0m',
        'red': '\033[1;31m%s\033[0m',
        'title': '\033[30;42m%s\033[0m',
        'info': '\033[32m%s\033[0m'
    }
    msg = color_msg.get(color, 'red') % msg
    print msg
    if exits:
        time.sleep(2)
        if is_log2db:
            db.close()
        sys.exit()
    return msg


def write_log(f, msg):
    msg = re.sub(r'[\r\n]', '\r\n', msg)
    f.write(msg)
    f.flush()


class Tty(object):
    """
    A virtual tty class
    一个虚拟终端类，实现连接ssh和记录日志，基类
    """

    def __init__(self, user, ip, login_type='ssh'):
        self.username = user
        self.ip = ip
        self.port = SSH_PORT
        self.ssh = None
        self.channel = None
        self.asset = ip
        self.user = user
        self.remote_ip = ''
        self.login_type = login_type
        self.vim_flag = False
        self.vim_end_pattern = re.compile(r'\x1b\[\?1049', re.X)
        self.vim_data = ''
        self.stream = None
        self.screen = None
        self.__init_screen_stream()

    def __init_screen_stream(self):
        """
        初始化虚拟屏幕和字符流
        """
        self.stream = pyte.ByteStream()
        self.screen = pyte.Screen(80, 24)
        self.stream.attach(self.screen)

    @staticmethod
    def is_output(strings):
        newline_char = ['\n', '\r', '\r\n']
        for char in newline_char:
            if char in strings:
                return True
        return False

    @staticmethod
    def command_parser(command):
        """
        处理命令中如果有ps1或者mysql的特殊情况,极端情况下会有ps1和mysql
        :param command:要处理的字符传
        :return:返回去除PS1或者mysql字符串的结果
        """
        result = None
        match = re.compile('\[?.*@.*\]?[\$#]\s').split(command)
        if match:
            # 只需要最后的一个PS1后面的字符串
            result = match[-1].strip()
        else:
            # PS1没找到,查找mysql
            match = re.split('mysql>\s', command)
            if match:
                # 只需要最后一个mysql后面的字符串
                result = match[-1].strip()
        return result

    def deal_command(self, data):
        """
        处理截获的命令
        :param data: 要处理的命令
        :return:返回最后的处理结果
        """
        command = ''
        try:
            self.stream.feed(data)
            # 从虚拟屏幕中获取处理后的数据
            for line in reversed(self.screen.buffer):
                line_data = "".join(map(operator.attrgetter("data"),
                                        line)).strip()
                if len(line_data) > 0:
                    parser_result = self.command_parser(line_data)
                    if parser_result is not None:
                        # 2个条件写一起会有错误的数据
                        if len(parser_result) > 0:
                            command = parser_result
                    else:
                        command = line_data
                    break
        except Exception:
            pass
        # 虚拟屏幕清空
        self.screen.reset()
        return command

    def get_log(self):
        """
        Logging user command and output.
        记录用户的日志
        """
        tty_log_dir = os.path.join(LOG_DIR, 'tty')
        date_today = datetime.datetime.now()
        date_start = date_today.strftime('%Y%m%d')
        time_start = date_today.strftime('%H%M%S')
        today_connect_log_dir = os.path.join(tty_log_dir, date_start)
        log_file_path = os.path.join(today_connect_log_dir, '%s_%s_%s' %
                                     (self.username, self.ip, time_start))

        try:
            if not os.path.isdir(today_connect_log_dir):
                os.mkdir(os.path.dirname(today_connect_log_dir), 0777)
            if not os.path.isdir(tty_log_dir):
                os.mkdir(tty_log_dir, 0777)
        except OSError:
            logger.debug('创建目录 %s 失败，请修改%s目录权限' %
                         (today_connect_log_dir, tty_log_dir))
            raise Exception('创建目录 %s 失败，请修改%s目录权限' %
                            (today_connect_log_dir, tty_log_dir))

        try:
            log_file_f = open(log_file_path + '.log', 'a')
            log_time_f = open(log_file_path + '.time', 'a')
        except IOError:
            logger.debug('创建tty日志文件失败, 请修改目录%s权限' % today_connect_log_dir)
            raise Exception('创建tty日志文件失败, 请修改目录%s权限' % today_connect_log_dir)

        if self.login_type == 'ssh':  # 如果是ssh连接过来，记录connect.py的pid，web terminal记录为日志的id
            pid = os.getpid()
            self.remote_ip = remote_ip  # 获取远端IP
        else:
            pid = 0

        log = Log(host=self.ip,
                  remote_ip=self.remote_ip,
                  login_type=self.login_type,
                  log_path=log_file_path,
                  start_time=date_today,
                  pid=pid)
        log.save()

        log_file_f.write('Start at %s\r\n' % datetime.datetime.now())
        return log_file_f, log_time_f, log

    def get_connection(self):
        """
        获取连接成功后的ssh
        """
        # 发起ssh连接请求 Make a ssh connection
        ssh = paramiko.SSHClient()
        # ssh.load_system_host_keys()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        key_filename = get_private_key_file()
        paramiko.util.log_to_file(LOG_DIR + '/' + self.user + "/ssh.log")
        try:
            try:
                ssh.connect(
                    self.ip,
                    port=SSH_PORT,
                    username=self.user,
                    key_filename=key_filename,
                    look_for_keys=False)
                return ssh
            except (paramiko.ssh_exception.AuthenticationException,
                    paramiko.ssh_exception.SSHException):
                logger.warning(u'使用ssh key %s 失败' % key_filename)
                pass
        except paramiko.ssh_exception.AuthenticationException, paramiko.ssh_exception.SSHException:
            raise Exception('认证失败 Authentication Error.')
        except Exception as e:
            raise Exception(
                '端口可能不对 Connect SSH Socket Port Error, Please Correct it.')
        else:
            self.ssh = ssh
            return ssh


class SshTty(Tty):
    """
    A virtual tty class
    一个虚拟终端类，实现连接ssh和记录日志
    """

    @staticmethod
    def get_win_size():
        """
        This function use to get the size of the windows!
        获得terminal窗口大小
        """
        if 'TIOCGWINSZ' in dir(termios):
            TIOCGWINSZ = termios.TIOCGWINSZ
        else:
            TIOCGWINSZ = 1074295912L
        s = struct.pack('HHHH', 0, 0, 0, 0)
        x = fcntl.ioctl(sys.stdout.fileno(), TIOCGWINSZ, s)
        return struct.unpack('HHHH', x)[0:2]

    def set_win_size(self, sig, data):
        """
        This function use to set the window size of the terminal!
        设置terminal窗口大小
        """
        try:
            win_size = self.get_win_size()
            self.channel.resize_pty(height=win_size[0], width=win_size[1])
        except Exception:
            pass

    def posix_shell(self):
        """
        Use paramiko channel connect server interactive.
        使用paramiko模块的channel，连接后端，进入交互式
        """
        log_file_f, log_time_f, log = self.get_log()
        termlog = TermLogRecorder(user=user, uid=uid)
        termlog.setid(os.getpid())
        old_tty = termios.tcgetattr(sys.stdin)
        pre_timestamp = time.time()
        data = ''
        input_mode = False
        try:
            tty.setraw(sys.stdin.fileno())
            tty.setcbreak(sys.stdin.fileno())
            self.channel.settimeout(0.0)
            while True:
                try:
                    r, w, e = select.select([self.channel, sys.stdin], [], [])
                    flag = fcntl.fcntl(sys.stdin, fcntl.F_GETFL, 0)
                    fcntl.fcntl(sys.stdin.fileno(), fcntl.F_SETFL, flag |
                                os.O_NONBLOCK)
                except Exception:
                    pass

                if self.channel in r:
                    try:
                        x = self.channel.recv(10240)
                        if len(x) == 0:
                            break

                        index = 0
                        len_x = len(x)
                        while index < len_x:
                            try:
                                n = os.write(sys.stdout.fileno(), x[index:])
                                sys.stdout.flush()
                                index += n
                            except OSError as msg:
                                if msg.errno == errno.EAGAIN:
                                    continue
                        now_timestamp = time.time()
                        termlog.write(x)
                        termlog.recoder = False
                        log_time_f.write('%s %s\n' % (round(
                            now_timestamp - pre_timestamp, 4), len(x)))
                        log_time_f.flush()
                        log_file_f.write(x)
                        log_file_f.flush()
                        pre_timestamp = now_timestamp
                        log_file_f.flush()

                        self.vim_data += x
                        if input_mode:
                            data += x

                    except socket.timeout:
                        pass

                if sys.stdin in r:
                    try:
                        x = os.read(sys.stdin.fileno(), 4096)
                    except OSError:
                        pass
                    termlog.recoder = True
                    input_mode = True
                    if self.is_output(str(x)):
                        # 如果len(str(x)) > 1 说明是复制输入的
                        if len(str(x)) > 1:
                            data = x
                        match = self.vim_end_pattern.findall(self.vim_data)
                        if match:
                            if self.vim_flag or len(match) == 2:
                                self.vim_flag = False
                            else:
                                self.vim_flag = True
                        elif not self.vim_flag:
                            self.vim_flag = False
                            data = self.deal_command(data)[0:200]
                            if data is not None:
                                TtyLog(
                                    datetime=datetime.datetime.now() -
                                    datetime.timedelta(hours=8),
                                    cmd=data).save()
                        data = ''
                        self.vim_data = ''
                        input_mode = False
                    if len(x) == 0:
                        break
                    self.channel.send(x)

        finally:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_tty)
            log_file_f.write('End time is %s' % datetime.datetime.now())
            log_file_f.close()
            log_time_f.close()
            termlog.save()
            log.filename = termlog.filename
            log.is_finished = True
            log.end_time = datetime.datetime.now() - datetime.timedelta(
                hours=8)
            log.save()

    def connect(self):
        """
        Connect server.
        连接服务器
        """
        # 发起ssh连接请求 Make a ssh connection
        ssh = self.get_connection()

        transport = ssh.get_transport()
        transport.set_keepalive(30)
        transport.use_compression(True)
        # 获取连接的隧道并设置窗口大小 Make a channel and set windows size
        global channel
        win_size = self.get_win_size()
        # self.channel = channel = ssh.invoke_shell(height=win_size[0], width=win_size[1], term='xterm')
        self.channel = channel = transport.open_session()
        self.channel.settimeout(1)
        channel.get_pty(term='xterm', height=win_size[0], width=win_size[1])
        channel.invoke_shell()
        try:
            signal.signal(signal.SIGWINCH, self.set_win_size)
        except:
            pass
        self.posix_shell()
        # Shutdown channel socket
        channel.close()
        ssh.close()


class Nav(object):
    """
    导航提示类
    """

    def __init__(self, user):
        self.user = user
        self.search_result = user_server_list

    @staticmethod
    def print_nav():
        """
        Print prompt
        打印提示导航
        """
        msg = """\n\033[1;32m###    欢迎使用 跳板机   ### \033[0m

        1) 输入 \033[32mID\033[0m 直接登录.
        2) 输入 \033[32mG/g\033[0m 显示您有权限的主机组.
        4) 输入 \033[32mE/e\033[0m 批量执行命令.
        5) 输入 \033[32mU/u\033[0m 批量上传文件.
        6) 输入 \033[32mD/d\033[0m 批量下载文件.
        7) 输入 \033[32mH/h\033[0m 帮助.
        0) 输入 \033[32mQ/q\033[0m 退出.
        """
        print textwrap.dedent(msg)

    def get_asset_group_member(self, str_r):
        gid_pattern = re.compile(r'^g\d+$')

        if gid_pattern.match(str_r):
            gid = int(str_r.lstrip('g'))
            if gid:
                self.search_result = list(user_server_list[gid])
            else:
                color_print('没有该资产组或没有权限')
                return

    def search(self, str_r=''):
        # 搜索结果保存
        if str_r:
            try:
                id_ = int(str_r)
                if id_ < len(self.search_result):
                    self.search_result = [self.search_result[id_]]
                    return
                else:
                    raise ValueError

            except (ValueError, TypeError):
                # 匹配 ip, hostname, 备注
                str_r = str_r.lower()
                self.search_result = [asset for asset in user_server_list if str_r == str(asset.get('ip')).lower()] or \
                                     [asset for asset in user_server_list if str_r in str(asset.get('ip')).lower() \
                                      or str_r in str(asset.get('datacenter')).lower() \
                                      or str_r in str(asset.get('business')).lower() \
                                      or str_r in str(asset.get('container')).lower() \
                                      or str_r in str(asset.get('model')).lower() \
                                      or str_r in str(asset.get('remarks')).lower()]
        else:
            # 如果没有输入就展现所有
            self.search_result = user_server_list

    @staticmethod
    def truncate_str(str_, length=30):
        str_ = str_.decode('utf-8')
        if len(str_) > length:
            return str_[:14] + '..' + str_[-14:]
        else:
            return str_

    def print_search_result(self):
        line = '[%-4s] 			%s		%s 		%s 		%s 		%s '
        color_print(line % ('id', '机器IP', '机房', '业务', '容器', '模块'), 'title')
        if hasattr(self.search_result, '__iter__'):
            for index, asset in enumerate(self.search_result):
                # 格式化资产信息
                print line % (index, asset.get('ip'),
                              asset.get('datacenter').encode('utf-8'),
                              asset.get('business').encode('utf-8'),
                              asset.get('container').encode('utf-8'),
                              asset.get('model').encode('utf-8'))
        print

    def try_connect(self):
        try:
            asset = self.search_result[0]

            print('Connecting %s ...' % asset.get('ip'))
            ssh_tty = SshTty(user, asset.get('ip'))
            ssh_tty.connect()
        except (KeyError, ValueError):
            color_print('请输入正确ID', 'red')
        except Exception, e:
            color_print(e, 'red')

    def print_asset_group(self):
        """
        打印用户授权的资产组
        """
        line = '[%-4s]		%s		%s		%s 		%s 		%s 	'
        color_print(line % ('id', '机器IP', '机房', '业务', '容器', '模块'), 'title')
        if hasattr(user_server_list, '__iter__'):
            for index, asset in enumerate(user_server_list):
                # 格式化资产信息
                print line % (index, asset.get('ip'),
                              asset.get('datacenter').encode('utf-8'),
                              asset.get('business').encode('utf-8'),
                              asset.get('container').encode('utf-8'),
                              asset.get('model').encode('utf-8'))
        print

    def exec_cmd(self):
        """
        批量执行命令
        """
        while True:
            assets = user_server_list
            print "授权包含该系统用户的所有主机"
            for asset in assets:
                print ' %s' % asset.get('ip')
            print
            print "请输入IP或ip正则如(10.3.*), 多个主机:分隔,q退出"
            pattern = raw_input("\033[1;32mIP正则选中一组机器>:\033[0m ").strip()
            if pattern == 'q':
                break
            else:
                runner = MyRunner()
                asset_name_str = ''
                print "匹配的主机:"
                for inv in runner.inventory.get_hosts(pattern=pattern):
                    print ' %s' % inv.name
                    asset_name_str += '%s ' % inv.name
                print

                while True:
                    print "请输入执行的命令， 按q退出"
                    command = raw_input("\033[1;32m执行命令>:\033[0m ").strip()
                    if command == 'q':
                        break
                    elif not command:
                        color_print('命令不能为空...')
                        continue
                    runner.run('shell', command, pattern=pattern)
                    ExecLog(
                        host=asset_name_str,
                        cmd=command,
                        remote_ip=remote_ip,
                        result=runner.results).save()
                    for k, v in runner.results.items():
                        if k == 'ok':
                            for host, output in v.items():
                                color_print("%s => %s" % (host, 'Ok'), 'green')
                                print output
                                print
                        else:
                            for host, output in v.items():
                                color_print("%s => %s" % (host, k), 'red')
                                color_print(output, 'red')
                                print
                    print "~o~ Task finished ~o~"
                    print

    def upload(self):
        while True:
            try:
                print "进入批量上传模式"
                print "请输入IP或ip正则如(10.3.*), 多个主机:分隔,q退出"
                pattern = raw_input("\033[1;32mIP正则选中一组机器>:\033[0m ").strip()
                if pattern == 'q':
                    break
                else:
                    runner = MyRunner()
                    asset_name_str = ''
                    print "匹配的主机:"
                    for inv in runner.inventory.get_hosts(pattern=pattern):
                        print inv.name
                        asset_name_str += '%s ' % inv.name

                    if not asset_name_str:
                        color_print('没有匹配的主机')
                        continue
                    tmp_dir = get_tmp_dir()
                    logger.debug('Upload tmp dir: %s' % tmp_dir)
                    os.chdir(tmp_dir)
                    subprocess.call('rz', shell=True)
                    filename_str = ' '.join(os.listdir(tmp_dir))
                    if not filename_str:
                        color_print("上传文件为空")
                        continue
                    logger.debug('上传文件: %s' % filename_str)

                    runner = MyRunner()
                    runner.run('copy',
                               module_args='src=%s dest=%s directory_mode' %
                               (tmp_dir, '/tmp'),
                               pattern=pattern)
                    ret = runner.results
                    FileLog(
                        host=asset_name_str,
                        filename=filename_str,
                        remote_ip=remote_ip,
                        type='upload',
                        result=ret).save()
                    logger.debug('Upload file: %s' % ret)
                    if ret.get('failed'):
                        error = '上传目录: %s \n上传失败: [ %s ] \n上传成功 [ %s ]' % (
                            tmp_dir, ', '.join(ret.get('failed').keys()),
                            ', '.join(ret.get('ok').keys()))
                        color_print(error)
                    else:
                        msg = '上传目录: %s \n传送成功 [ %s ]' % (
                            tmp_dir, ', '.join(ret.get('ok').keys()))
                        color_print(msg, 'green')
                    print

            except IndexError:
                pass

    def download(self):
        while True:
            try:
                print "进入批量下载模式"
                print "请输入IP或ip正则如(10.3.*), 多个主机:分隔,q退出"
                pattern = raw_input("\033[1;32mIP正则选中一组机器>:\033[0m ").strip()
                if pattern == 'q':
                    break
                else:
                    runner = MyRunner()
                    asset_name_str = ''
                    print "匹配的主机:\n"
                    for inv in runner.inventory.get_hosts(pattern=pattern):
                        asset_name_str += '%s ' % inv.name
                        print ' %s' % inv.name
                    if not asset_name_str:
                        color_print('没有匹配的主机')
                        continue
                    print
                    while True:
                        tmp_dir = get_tmp_dir()
                        logger.debug('Download tmp dir: %s' % tmp_dir)
                        print "请输入文件路径(不支持目录)"
                        file_path = raw_input(
                            "\033[1;32mPath>:\033[0m ").strip()
                        if file_path == 'q':
                            break

                        if not file_path:
                            color_print("文件路径为空")
                            continue

                        runner.run('fetch',
                                   module_args='src=%s dest=%s' %
                                   (file_path, tmp_dir),
                                   pattern=pattern)
                        ret = runner.results
                        FileLog(
                            host=asset_name_str,
                            filename=file_path,
                            type='download',
                            remote_ip=remote_ip,
                            result=ret).save()
                        logger.debug('Download file result: %s' % ret)
                        os.chdir('/tmp')
                        tmp_dir_name = os.path.basename(tmp_dir)
                        if not os.listdir(tmp_dir):
                            color_print('下载全部失败')
                            continue
                        subprocess.call(
                            'tar czf %s.tar.gz %s && sz %s.tar.gz' %
                            (tmp_dir, tmp_dir_name, tmp_dir),
                            shell=True)

                        if ret.get('failed'):
                            error = '文件名称: %s \n下载失败: [ %s ] \n下载成功 [ %s ]' % \
                                    ('%s.tar.gz' % tmp_dir_name, ', '.join(ret.get('failed').keys()), ', '.join(ret.get('ok').keys()))
                            color_print(error)
                        else:
                            msg = '文件名称: %s \n下载成功 [ %s ]' % (
                                '%s.tar.gz' % tmp_dir_name,
                                ', '.join(ret.get('ok').keys()))
                            color_print(msg, 'green')
                        print
            except IndexError:
                pass


def main():
    """
    主程序
    """
    if not login_user:  # 判断用户是否存在
        color_print('没有该用户，或许你是以root运行的 No that user.', exits=True)

    if not os.path.isfile(get_private_key_file()):
        color_print('没有pub key 请找运维加上')

    gid_pattern = re.compile(r'^g\d+$')
    nav = Nav(login_user)
    nav.print_nav()

    try:
        while True:
            try:
                option = raw_input(
                    "\033[1;32m输入g显示能操作的机器 or 输入ID直接登录机器>:\033[0m ").strip()
            except EOFError:
                nav.print_nav()
                continue
            except KeyboardInterrupt:
                if is_log2db:
                    db.close()
                sys.exit(0)
            if option in ['P', 'p', '\n', '']:
                nav.search()
                nav.print_search_result()
                continue
            if option.startswith('/'):
                nav.search(option.lstrip('/'))
                nav.print_search_result()
            elif gid_pattern.match(option):
                nav.get_asset_group_member(str_r=option)
                nav.print_search_result()
            elif option in ['G', 'g']:
                nav.print_asset_group()
                continue
            elif option in ['E', 'e']:
                nav.exec_cmd()
                continue
            elif option in ['U', 'u']:
                nav.upload()
            elif option in ['D', 'd']:
                nav.download()
            elif option in ['H', 'h']:
                nav.print_nav()
            elif option in ['Q', 'q', 'exit']:
                if is_log2db:
                    db.close()
                sys.exit()
            else:
                nav.search(option)
                if len(nav.search_result) == 1:
                    print('Only match Host:  %s ' %
                          nav.search_result[0].get('ip'))
                    nav.try_connect()
                else:
                    nav.print_search_result()

    except IndexError, e:
        color_print(e)
        time.sleep(5)


if __name__ == '__main__':
    main()
