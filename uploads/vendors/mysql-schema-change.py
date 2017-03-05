#!/usr/bin/env python
# coding: utf-8

import argparse
import MySQLdb
import os
import settings
import threading
import multiprocessing
import time
import signal
import subprocess
import pipes
import types

manager = None
interrupt_counter = 0

#globals used for the worker sigint handler
proc = None
p1 = None
p2 = None


def worker_signal_handler(signum, frame):
    global interrupt_counter, manager
    interrupt_counter += 1
    if interrupt_counter == 1:
        print "PID {0} received interrupt, initiating soft shutdown".format(
            os.getpid())
        if manager.settings.OPTIONS['mode'] == 'online':
            raise KeyboardInterrupt
        manager.shutdown = True
    elif interrupt_counter == 2:
        print "PID {0} received interrupt again, initiating hard shutdown".format(
            os.getpid())
        if manager.settings.OPTIONS['mode'] == 'online':
            raise SystemExit
        elif manager.settings.OPTIONS['mode'] == 'direct':
            raise KeyboardInterrupt


def main_signal_handler(signum, frame):
    global interrupt_counter, manager
    interrupt_counter += 1
    if interrupt_counter == 1:
        manager.awaiting_shutdown = True
        print "Main process received interrupt, waiting for threads to soft shutdown "
    elif interrupt_counter == 2:
        print "Main process received second interrupt, waiting on threads to complete hard shutdown"


class AlterManager:
    def __init__(self, settings):
        self.settings = settings
        self.response_queue = multiprocessing.Queue()
        self.errors = {}
        self.completed = {}
        self.unknownitems = {}
        self.running = {}
        self.queues = {}
        self.threads = {}
        self.shutdown = False
        self.shards = {}
        self.interrupt_counter = 0
        self.awaiting_shutdown = False
        self.watcher = None
        self.manager_queues = {}

    def log(self, shard_name, log_lines):

        pass

    def run_alter(self):
        signal.signal(signal.SIGINT, main_signal_handler)
        self.load_shard_locations()

        self.watcher = Watcher(self)
        self.watcher.daemon = True
        self.watcher.start()

        try:
            if len(self.settings.OPTIONS['filter_shards']) == 0 or (
                    len(self.settings.OPTIONS['filter_shards']) > 0 and
                    self.settings.MODEL_SHARD_DB_CREDENTIALS['dbname'] in
                    self.settings.OPTIONS['filter_shards']):
                mqueue = multiprocessing.Queue()
                mqueue.put({
                    'shard':
                    self.settings.MODEL_SHARD_DB_CREDENTIALS['dbname'],
                    'host': self.settings.MODEL_SHARD_DB_CREDENTIALS['host'],
                    'port': self.settings.MODEL_SHARD_DB_CREDENTIALS['port'],
                    'slave_host':
                    self.settings.MODEL_SHARD_DB_CREDENTIALS['slave_host'],
                    'slave_port':
                    self.settings.MODEL_SHARD_DB_CREDENTIALS['slave_port']
                })
                mqueue.put(None)

                # the temporary rewriting of the ignore_errors flag is so that when it gets copied to the process memory for the model shard worker, it will properly throw an error always
                tempignore = self.settings.OPTIONS['ignore_errors']
                self.settings.OPTIONS['ignore_errors'] = False
                mworker = Worker(
                    self, mqueue,
                    self.settings.MODEL_SHARD_DB_CREDENTIALS['host'],
                    self.settings.MODEL_SHARD_DB_CREDENTIALS['port'], 0,
                    self.response_queue, None)
                mworker.start()
                self.settings.OPTIONS['ignore_errors'] = tempignore
                while mworker.is_alive():
                    mworker.join(1)

                if self.awaiting_shutdown:
                    self.shutdown = True

                if len(self.errors) or len(self.unknownitems):
                    print "Applying DDL to model shard failed, not continuing with remaining shards"
                    self.shutdown_watcher()
                    self.flush_queues()
                    if len(self.errors):
                        print "\n\nErrors received"
                        for shard, e in self.errors.iteritems():
                            print "{0}: {1}".format(shard, str(e))
                        print "\n"
                    return

                if self.settings.OPTIONS['running_mode'] == 'dry-run':
                    print "Dry run completed successfully"
                    self.shutdown_watcher()
                    self.flush_queues()
                    return

            for queue_key, queue in self.queues.iteritems():
                self.threads[queue_key] = []
                self.manager_queues[queue_key] = []
                for worker_id in range(0,
                                       self.settings.OPTIONS['concurrency']):
                    # put a marker job in the queue to stop this worker
                    queue.put(None)
                    host, port = queue_key.split(":")
                    manager_queue = multiprocessing.Queue()
                    worker = Worker(self, queue, host, port, worker_id,
                                    self.response_queue, manager_queue)
                    self.threads[queue_key].append(worker)
                    self.manager_queues[queue_key].append(manager_queue)
                    worker.start()

            for g, threads in self.threads.iteritems():
                for t in threads:
                    while t.is_alive():
                        if self.awaiting_shutdown:
                            self.shutdown_threads()
                        t.join(.1)

        except Exception as e:
            print "Caught exception in main thread, exiting"

        self.flush_queues()
        self.shutdown_watcher()
        self.output_state()

        # set the shutdown flag so that any remaining threads exit
        self.shutdown = True

    def flush_queues(self):
        for g, queue in self.queues.iteritems():
            try:
                while True:
                    queue.get(False)
            except:
                pass

    def shutdown_watcher(self):
        self.response_queue.put(None)
        try:
            while self.watcher.is_alive():
                self.watcher.join(1)
        # sometimes the join operation above will throw a RuntimeError if the thread shuts down between the is_alive check and the join operation
        except RuntimeError:
            pass

    def shutdown_threads(self):
        self.awaiting_shutdown = True
        for g, queues in self.manager_queues.iteritems():
            for q in queues:
                q.put("shutdown")
        for g, threads in self.threads.iteritems():
            for t in threads:
                t.join()

        self.shutdown = True
        self.shutdown_watcher()

    def add_shard(self,
                  shard_name,
                  host,
                  port,
                  slave_host=None,
                  slave_port=None):
        queue_id = host + ':' + str(port)
        if not queue_id in self.queues:
            self.queues[queue_id] = multiprocessing.Queue()
        self.shards[shard_name] = {
            'shard': shard_name,
            'host': host,
            'port': port,
            'slave_host': slave_host,
            'slave_port': slave_port
        }
        self.queues[queue_id].put({
            'shard': shard_name,
            'host': host,
            'port': port,
            'slave_host': slave_host,
            'slave_port': slave_port
        })

    def load_shard_locations(self):
        dbconn = MySQLdb.connect(
            host=self.settings.LOCATOR_DB_CREDENTIALS['host'],
            port=self.settings.LOCATOR_DB_CREDENTIALS['port'],
            user=self.settings.LOCATOR_DB_CREDENTIALS['user'],
            passwd=self.settings.LOCATOR_DB_CREDENTIALS['password'],
            db=self.settings.LOCATOR_DB_CREDENTIALS['dbname'])
        db = dbconn.cursor()

        whereclause = ''
        if settings.LOCATOR_TABLE['where_clause']:
            whereclause = " " + settings.LOCATOR_TABLE['where_clause']

        sql = "select " + settings.LOCATOR_TABLE['shardname_col'] + ", " + settings.LOCATOR_TABLE['host_col'] + ", " \
                   + settings.LOCATOR_TABLE['port_col'] + ", " + settings.LOCATOR_TABLE['slave_host_col'] + ", " \
                   + settings.LOCATOR_TABLE['slave_port_col'] + " from " + settings.LOCATOR_TABLE['tablename'] + whereclause
        db.execute(sql)
        rows = db.fetchall()
        if not rows:
            print "No shards were found using the following query: " + sql
            exit()
        for row in rows:
            if len(self.settings.OPTIONS['filter_shards']) > 0 and row[
                    0] not in self.settings.OPTIONS['filter_shards']:
                continue
            self.add_shard(row[0], row[1], row[2], row[3], row[4])

    def output_state(self):
        if len(self.errors) == 0 and len(self.unknownitems) == 0 and len(
                self.completed) - 1 == len(self.shards):
            print "\n\nDDL operation successfully completed on all shards"
        else:
            print "\n\nDDL operation did not complete successfully on all shards\n"
            if len(self.errors):
                print "\n\nErrors received"
                for shard, e in self.errors.iteritems():
                    print "{0}: {1}".format(shard, str(e))
                print "\n"
            if len(self.unknownitems) or len(self.running) != len(
                    self.completed) + len(self.errors):
                print "The following shards are in an unknown state due to abort"
                print "---------------------------------------------------------"
                for k in self.unknownitems.keys():
                    print k,
                for k in self.running.keys():
                    if k not in self.completed and k not in self.unknownitems and k not in self.errors:
                        print k,
                print "\n---------------------------------------------------------"
                print "\n\n"
            if len(self.errors):
                print "The following shards had errors"
                print "-------------------------------"
                for k in self.errors.keys():
                    print k,
                print "\n-------------------------------"
                print "\n\n"
            if len(self.completed):
                print "The following shards completed successfully (this is the list to use if rollback is needed)"
                print "-------------------------------------------------------------------------------------------"
                for k in self.completed.keys():
                    print k,
                print "\n-------------------------------------------------------------------------------------------"
                print "\n\n"
            if len(self.running) < len(self.shards) + 1:
                print "DDL operation was not attempted on the following shards"
                print "-------------------------------------------------------"
                for k in self.shards.keys():
                    if k not in self.completed and k not in self.errors and k not in self.unknownitems and k not in self.running:
                        print k,
                print "\n-------------------------------------------------------"
                print "\n\n"


class OnlineStderrConsumer(threading.Thread):
    def __init__(self, subproc, response_queue, worker_tag):
        self.subproc = subproc
        self.response_queue = response_queue
        self.worker_tag = worker_tag
        threading.Thread.__init__(self)

    def run(self):
        nextline = None
        buf = ''
        while True:
            #--- extract line using read(1)
            out = self.subproc.stderr.read(1)
            if out == '' and self.subproc.poll() != None: break
            if out != '':
                buf += out
                if out == '\n':
                    nextline = buf
                    buf = ''
            if not nextline: continue
            line = nextline
            nextline = None

            self.response_queue.put(('status:stderr', self.worker_tag, line))

        self.subproc.stderr.close()


class OnlineStdoutConsumer(threading.Thread):
    def __init__(self, subproc, response_queue, worker_tag):
        self.subproc = subproc
        self.response_queue = response_queue
        self.worker_tag = worker_tag
        threading.Thread.__init__(self)

    def run(self):
        nextline = None
        buf = ''
        while True:
            #--- extract line using read(1)
            out = self.subproc.stdout.read(1)
            if out == '' and self.subproc.poll() != None: break
            if out != '':
                buf += out
                if out == '\n':
                    nextline = buf
                    buf = ''
            if not nextline: continue
            line = nextline
            nextline = None

            self.response_queue.put(('status:stdout', self.worker_tag, line))

        self.subproc.stdout.close()


class ManagerQueueConsumer(threading.Thread):
    def __init__(self, alter_manager, manager_queue):
        self.manager = alter_manager
        self.manager_queue = manager_queue
        threading.Thread.__init__(self)

    def run(self):
        while not self.manager.shutdown:
            try:
                item = self.manager_queue.get(False)
            except:
                time.sleep(.1)
                continue
            if item == 'shutdown':
                manager.shutdown = True


class Worker(multiprocessing.Process):
    def __init__(self, alter_manager, queue, host, port, worker_id,
                 response_queue, manager_queue):
        self.manager = alter_manager
        self.__queue = queue
        self.host = host
        self.port = port
        self.id = worker_id
        self.manager_queue = manager_queue
        # self.stop = multiprocessing.Event()
        # self.term = multiprocessing.Event()
        self.response_queue = response_queue
        print "Initializing worker {0} for {1}:{2}".format(worker_id, host,
                                                           port)
        multiprocessing.Process.__init__(self)

    def run(self):
        signal.signal(signal.SIGTERM, worker_signal_handler)
        signal.signal(signal.SIGINT, worker_signal_handler)
        if self.manager_queue:
            # p1 = threading.Thread(target=manager_queue_thread, args=(self.manager, self.manager_queue)) #thread to wait for commands from the main process
            p1 = ManagerQueueConsumer(self.manager, self.manager_queue)
            p1.daemon = True
            p1.start()
        while not self.manager.shutdown:
            try:
                item = self.__queue.get()
                if item is None:
                    break  # reached end of queue
                self.response_queue.put(('running', item['shard'], ''))

                time.sleep(.2)
                if self.manager.settings.OPTIONS['mode'] == 'direct':
                    self.direct(item)
                elif self.manager.settings.OPTIONS['mode'] == 'online':
                    self.online(item)
            except (KeyboardInterrupt, SystemExit):
                print "Shutting down worker {0} for {1}:{2}".format(
                    self.id, self.host, self.port)
                return
            except:
                if self.manager.settings.OPTIONS['ignore_errors']:
                    print "Error in worker {0} for {1}:{2}".format(
                        self.id, self.host, self.port)
                    if not self.manager.settings.OPTIONS['ignore_errors']:
                        return
            # this sleep is to give time for the queues to finish sending messages back and forth (there is some synchronization issues in error catching shutdown cases)
            time.sleep(0.1)
        print "Worker {0} for {1}:{2} complete".format(self.id, self.host,
                                                       self.port)

    def direct(self, item):
        print "running direct for shard: " + str(item['shard'])
        try:
            dbconn = MySQLdb.connect(
                host=item['host'],
                port=item['port'],
                user=self.manager.settings.SHARD_DB_CREDENTIALS['user'],
                passwd=self.manager.settings.SHARD_DB_CREDENTIALS['password'],
                db=item['shard'])
            db = dbconn.cursor()
            if self.manager.settings.OPTIONS['running_mode'] == 'dry-run':
                temptable = '_' + self.manager.settings.OPTIONS[
                    'tablename'] + '_dry_run'
                sql = "CREATE TABLE {0} LIKE {1}".format(
                    temptable, self.manager.settings.OPTIONS['tablename'])
                db.execute(sql)
                try:
                    sql = "ALTER TABLE {0} {1}".format(
                        temptable, self.manager.settings.OPTIONS['alter'])
                    db.execute(sql)
                except:
                    raise
                finally:
                    db.execute("DROP TABLE IF EXISTS {0}".format(temptable))
            elif self.manager.settings.OPTIONS['running_mode'] == 'execute':
                if isinstance(self.manager.settings.OPTIONS['direct_query'],
                              types.StringTypes):
                    db.execute(self.manager.settings.OPTIONS['direct_query'])
                elif isinstance(self.manager.settings.OPTIONS['direct_query'],
                                types.ListType):
                    for query in self.manager.settings.OPTIONS['direct_query']:
                        if query.strip():
                            db.execute(query)

            self.response_queue.put(('complete', item['shard'], ''))
            dbconn.close()
        except KeyboardInterrupt:
            print "Thread received hard shutdown signal"
            # the alter is in an unknown state at this point, as the query may continue running
            self.response_queue.put(('unknown', item['shard'], ''))
            raise
        except Exception as e:
            self.response_queue.put(('error', item['shard'], e))
            raise

    def online(self, item):
        global proc, p1, p2
        print "running online for shard: " + str(item['shard'])

        command = self.manager.settings.PT_OSC
        for k, v in self.manager.settings.PT_OSC_OPTIONS.iteritems():
            if k == "recursion-method" and item['slave_host'] is not None:
                continue
            if v is not None:
                command += " --{0}".format(k)
                if v != '':
                    command += "={0}".format(v)

        if self.manager.settings.SHARD_DB_CREDENTIALS['password']:
            command += ' --password={0}'.format(
                pipes.quote(self.manager.settings.SHARD_DB_CREDENTIALS[
                    'password']))
        if item['slave_host'] is not None:
            command += " --check-slave-lag=h=" + item['slave_host']
            if item['slave_port'] is not None:
                command += ",P=" + str(item['slave_port'])
        command += " --host={0} --user={1} --port={2} --alter={3} D={4},t={5}".format(
            item['host'], self.manager.settings.SHARD_DB_CREDENTIALS['user'],
            item['port'],
            pipes.quote(self.manager.settings.OPTIONS['online_alter']),
            item['shard'], self.manager.settings.OPTIONS['tablename'])

        command += " --{0}".format(self.manager.settings.OPTIONS[
            'running_mode'])
        print command
        proc = subprocess.Popen(
            command,
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            shell=True)  #output-producing process
        p1 = OnlineStdoutConsumer(
            proc, self.response_queue, "{0}:{1}:{2}:{3}".format(
                self.host, self.port, self.id, item['shard']))
        p2 = OnlineStderrConsumer(
            proc, self.response_queue, "{0}:{1}:{2}:{3}".format(
                self.host, self.port, self.id, item['shard']))
        try:
            p1.daemon = True
            p1.start()
            p2.daemon = True
            p2.start()

            while proc.poll() is None:
                time.sleep(.1)

            if proc.returncode == 0:
                self.response_queue.put(('complete', item['shard'], ''))
            else:
                self.response_queue.put((
                    'error', item['shard'],
                    'pt-online-schema-change exited with exit code {0}'.format(
                        proc.returncode)))

        except (KeyboardInterrupt, SystemExit), e:
            self.response_queue.put(('unknown', item['shard'], ''))
            if p1 and p1.is_alive():
                p1.join()
            if p2 and p2.is_alive():
                p2.join()
            raise
        except Exception as e:
            self.response_queue.put(('error', item['shard'], e))
            if p1 and p1.is_alive():
                p1.join()
            if p2 and p2.is_alive():
                p2.join()
            raise

        if p1 and p1.is_alive():
            p1.join()
        if p2 and p2.is_alive():
            p2.join()


class Watcher(threading.Thread):
    def __init__(self, alter_manager):
        self.manager = alter_manager
        print "Initializing error monitor"
        threading.Thread.__init__(self)

    def run(self):
        while not self.manager.shutdown:
            item = self.manager.response_queue.get()
            if item is None:
                break
            if item[0] == 'error':
                self.manager.errors[item[1]] = item[2]

                if not self.manager.settings.OPTIONS['ignore_errors']:
                    if not self.manager.awaiting_shutdown:
                        self.manager.awaiting_shutdown = True
            elif item[0] == 'complete':
                self.manager.completed[item[1]] = item[2]
            elif item[0] == 'running':
                self.manager.running[item[1]] = item[2]
            elif item[0] == 'unknown':
                self.manager.unknownitems[item[1]] = item[2]
            elif item[0][0:6] == 'status':
                output_type = item[0][7:]
                print "{0}({1}): {2}".format(item[1], output_type, item[2]),


def main():
    global manager
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--table', help='Name of table to alter')
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        '--alter',
        help='Alter operations portion of an alter statement similar to pt-online-schema-change, eg: "ADD COLUMN foo VARCHAR(10) AFTER bar, DROP COLUMN baz, ENGINE=InnoDB"'
    )
    group.add_argument(
        '--create',
        help='Create table statement to use for create type',
        metavar='CREATE_STATEMENT')
    group.add_argument(
        '--script',
        help='Run provided SQL script against all shards',
        metavar='SCRIPT_PATH')
    parser.add_argument(
        '-n',
        '--concurrency',
        type=int,
        help='Number of concurrent operations to run on each database node')
    parser.add_argument(
        '--type',
        help='Type of operation to run',
        choices=['alter', 'create', 'drop', 'script'],
        default='alter')
    parser.add_argument(
        '--mode',
        help='Set the mode of alter to run the alter directly or use pt-online-schema-change to perform online alter (default defined in settings)',
        choices=['direct', 'online'])
    parser.add_argument(
        '--ignore-errors',
        action='store_true',
        help='Ignore errors on single shards and continue with the DDL operation. Shards that had errors will be listed in a report at the end of the run.'
    )
    parser.add_argument(
        '--shards',
        nargs='+',
        help='Space separated list of shards to run against (used to filter the global list from locator DB). Used for rolling back or resuming changes that have only been partially applied',
        metavar='SHARD_NAME')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        '--dry-run',
        help='Perform a dry run of the operation on the model shard. No direct DDL change statements will be run, and pt-osc will be run with --dry-run',
        action='store_true')
    group.add_argument(
        '--execute', help='execute the operation', action='store_true')
    ptgroup = parser.add_argument_group(
        title='pt-online-schema-change options',
        description='options get passed to all pt-online-schema-change processes when performing online alter, refer to the documentation for pt-online-schema-change. Some or all of theses options may be defined in the settings file.'
    )
    ptgroup.add_argument('--check-interval', type=int)
    ptgroup.add_argument('--chunk-size', type=int)
    ptgroup.add_argument('--chunk-size-limit', type=float)
    ptgroup.add_argument('--chunk-time', type=float)
    group = ptgroup.add_mutually_exclusive_group()
    group.add_argument('--drop-new-table', action='store_true')
    group.add_argument('--nodrop-new-table', action='store_true')
    group = ptgroup.add_mutually_exclusive_group()
    group.add_argument('--drop-old-table', action='store_true')
    group.add_argument('--nodrop-old-table', action='store_true')
    ptgroup.add_argument('--max-lag', type=int)
    ptgroup.add_argument('--progress')
    ptgroup.add_argument('--recursion-method')
    ptgroup.add_argument('--recurse')
    ptgroup.add_argument('--max-load')
    ptgroup.add_argument('--chunk-index')
    ptgroup.add_argument('--chunk-index-columns')

    args = parser.parse_args()

    ptosc_option_map = [
        'check_interval',
        'chunk_size',
        'chunk_size_limit',
        'chunk_time',
        'drop_new_table',
        'nodrop_new_table',
        'drop_old_table',
        'nodrop_old_table',
        'max_lag',
        'progress',
        'recursion_method',
        'recurse',
        'max_load',
        'chunk_index',
        'chunk_index_columns',
    ]

    for k in ptosc_option_map:
        value = getattr(args, k)
        if value is not None:
            if k == 'drop_new_table':
                if value:
                    settings.PT_OSC_OPTIONS['drop-new-table'] = ''
                    settings.PT_OSC_OPTIONS['nodrop-new-table'] = None
            elif k == 'nodrop_new_table':
                if value:
                    settings.PT_OSC_OPTIONS['drop-new-table'] = None
                    settings.PT_OSC_OPTIONS['nodrop-new-table'] = ''
            elif k == 'drop_old_table':
                if value:
                    settings.PT_OSC_OPTIONS['drop-old-table'] = ''
                    settings.PT_OSC_OPTIONS['nodrop-old-table'] = None
            elif k == 'nodrop_old_table':
                if value:
                    settings.PT_OSC_OPTIONS['drop-old-table'] = None
                    settings.PT_OSC_OPTIONS['nodrop-old-table'] = ''
            else:
                key = k.replace('_', '-')
                settings.PT_OSC_OPTIONS[key] = value

    if 'ignore_errors' in settings.OPTIONS:
        settings.OPTIONS['ignore_errors'] = settings.OPTIONS[
            'ignore_errors'] | args.ignore_errors
    else:
        settings.OPTIONS['ignore_errors'] = args.ignore_errors

    if args.concurrency:
        settings.OPTIONS['concurrency'] = args.concurrency

    if args.type == 'alter':
        if not args.table:
            print "Table name must be provided with --table to perform alter operation"
            exit()
        if not args.alter:
            print "Alter operation must be provided with --alter"
            exit()
        settings.OPTIONS['tablename'] = args.table
        if args.mode:
            settings.OPTIONS['mode'] = args.mode
        if settings.OPTIONS['mode'] == 'direct':
            settings.OPTIONS[
                'direct_query'] = 'ALTER TABLE ' + args.table + ' ' + args.alter
            settings.OPTIONS['alter'] = args.alter
        elif settings.OPTIONS['mode'] == 'online':
            settings.OPTIONS['online_alter'] = args.alter

    elif args.type == 'create':
        if not args.create:
            print "Create table statement must be provided with --create to perform create operation"
            exit()
        settings.OPTIONS['mode'] = 'direct'
        settings.OPTIONS['direct_query'] = args.create

    elif args.type == 'drop':
        if not args.table:
            print "Table name must be provided with --table to perform drop operation"
            exit()
        settings.OPTIONS['mode'] = 'direct'
        settings.OPTIONS['direct_query'] = 'DROP TABLE ' + args.table

    elif args.type == 'script':
        if not args.script:
            print "Path to script must be provided with --script"
            exit()

        with open(args.script, "r") as f:
            data = f.read()
        settings.OPTIONS['mode'] = 'direct'
        settings.OPTIONS['direct_query'] = data.split(';')

    if args.dry_run:
        settings.OPTIONS['running_mode'] = 'dry-run'
        if args.type != 'alter':
            print "--dry-run is not supported for --type={0}".format(args.type)
            exit(255)
    elif args.execute:
        settings.OPTIONS['running_mode'] = 'execute'

    manager = AlterManager(settings)
    manager.run_alter()


if __name__ == "__main__":
    main()
