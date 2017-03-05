#!/usr/bin/env python
# coding: utf-8
"""
Usage:
  report_slow.py [options]
  report_slow.py [options] <query_tag> ...
  report_slow.py [options] --days=<D> [<query_tag> ...]
  report_slow.py [options] --start-date=<start_date> [<query_tag> ...]
  report_slow.py [options] --start-date=<start_date> --end-date=<end_date> [<query_tag> ...]
  report_slow.py (-h | --help)
  report_slow.py (-v | --version)

Options:
  -h, --help                Show the help
  -t <N>, --top=<N>         Report on the resent top N queries
  -v, --version             Show the current version
  --no-sql                  Don't show sql for the query tag

Others:
  -d=<D>, --days=<D>         Report for <D> days from today
  --start-date=<start_date>  Report starting from <start_date>
  --end-date=<end_date>      Report ending at <end_date>

Examples:
    report_slow.py
      With no options the script will report on top level statistics.

    report_slow.py 0x71091F7BB15C9A47
      Adding a query tag will reports on a specific query.

    report_slow.py --top=5 --days=10
      Report on the lastest top 5 queries and show 5 days worth of data

    report_slow.py --top=5 --start-date=2016-01-10
      Report on the lastest top 5 queries from start-date to the current date.
      The date formating is very flexible you can enter dates like
      1/1/16 1/01/2016

"""
"""
need to add a date range query option
"""
import os
import glob
import re
from datetime import datetime, timedelta
from dateutil.parser import parse
import itertools
import traceback
from docopt import docopt
import sqlparse

__version__ = 0.11


def translate_unit(unit):
    assert unit in ['G', 'M', 'k', 'us', 's', 'ms', ''], 'bad unit pased'
    if unit == 'G':
        value = 1000000000
    elif unit == 'M':
        value = 1000000
    elif unit == 'k':
        value = 1000
    elif unit == 's':
        value = 1
    elif unit == 'ms':
        value = .001
    elif unit == 'us':
        value = .000001
    else:
        value = 1
    return value


def getnumber(s):
    num = float(
        reduce(lambda x, y: x if len(x) > 0 else y,
               re.split(r'G|M|k|ms|s|us', s)))
    unit = reduce(lambda x, y: x if len(x) > 0 else y, re.split(r'[0-9.]*', s))
    unit_value = translate_unit(unit)
    return num * unit_value


def get_report_date(f):
    f.seek(0, 0)
    ltimerange = [l for n, l in enumerate(f) if n < 10 and 'Time range' in l]
    timerange = ltimerange[0].split()
    try:
        time = ' '.join(timerange[6:8])
        datetime.strptime(time, '%Y-%m-%d %H:%M:%S')
        date = datetime.strptime(timerange[6], '%Y-%m-%d')
        time = datetime.strptime(timerange[7], '%H:%M:%S')
    except ValueError, e:
        date = datetime.strptime(timerange[3], '%Y-%m-%d')
        time = datetime.strptime(timerange[4], '%H:%M:%S')
    f.seek(0)
    return date, time


def get_top_n_tags(n):
    '''
    Get the top N query tags

    # Query size         5.57G       0   1.25M  172.04  381.65   1.10k  107.34

    # Profile
    # Rank Query ID           Response time    Calls    R/Call V/M   Item
    # ==== ================== ================ ======== ====== ===== =========
    #    1 0x71091F7BB15C9A47 23497.2507 12.1%   109369 0.2148  0.53 SELECT phys_availabilities
    #    2 0x8331E48027474CF6 22663.5199 11.6%     8595 2.6368  1.36 SELECT users physician_types_users phys_availabilities provider_details provider_affiliations provider_profiles licenses phys_availabilities

    #  385 0xDE071DCD8172D475     9.4817  0.0%       15 0.6321  0.63 SELECT users
    #  394 0xED16593745E587E4     9.0296  0.0%       18 0.5016  1.05 SELECT activity_histories users user_statuses
    ...
    # MISC 0xMISC             31859.9749 16.4% 31133657 0.0010   0.0 <14030 ITEMS>

    # Query 1: 1.28 QPS, 0.28x concurrency, ID 0x71091F7BB15C9A47 at byte 5383552058
    # This item is included in the report because it matches --limit.

    # Query 1:
    :param n: top N tags
    :return: list of tags
    '''
    tags = None
    log_path = 'log' if os.uname()[1].split('.')[0] == 'SUN-IT608L' else ''
    files = glob.glob(os.path.join(log_path, 'slow_201?-*log'))
    p = re.compile(r'# Profile.*# Query 1:', re.DOTALL)

    if files is not []:
        #file = [f for f in sorted(files, reverse=True) if ][0]
        for file in sorted(files, reverse=True):
            if os.path.getsize(file) < 512:
                continue
            else:
                with open(file, 'r') as f:
                    buff = f.read()
                break
        m = p.search(buff)
        n = int(n) + 3
        plist = m.group(0).splitlines()[3:+n]
        plist = [e.split() for e in plist]
        tags = [e[2] for e in plist]
    return tags


def get_top_level_data(data):
    '''
    Outputs the top level of the report:

    # 8387.7s user time, 20.2s system time, 756.93M rss, 842.61M vsz
    # Current date: Tue Jan 19 09:21:44 2016
    # Hostname: MDLI01VMD01
    # Files: STDIN
    # Overall: 29.77M total, 11.80k unique, 352.31 QPS, 1.80x concurrency ____
    # Time range: 2016-01-18 07:00:02 to 2016-01-19 06:28:26
    # Attribute          total     min     max     avg     95%  stddev  median
    # ============     ======= ======= ======= ======= ======= ======= =======
    # Exec time        152222s     6us    436s     5ms     3ms   209ms   176us
    # Lock time          5432s       0    436s   182us   204us   102ms    63us
    # Rows sent         72.35M       0 558.77k    2.55    1.96  130.97    0.99
    # Rows examine      86.38G       0   1.40G   3.04k    9.83 510.14k    0.99
    # Rows affecte       3.18M       0  35.07k    0.11    0.99   14.68       0
    # Bytes sent        29.16G       0   7.59M   1.03k   3.35k   5.80k  299.03
    # Query size         4.76G       0   7.03M  171.83  420.77   1.70k  107.34
    '''
    top_data = {}
    overall = [l for l in data if 'Overall:' in l][0].split()
    timerange = [l for l in data if 'Time range:' in l][0].split()
    exectime = [
        getnumber(d) for d in [l for l in data
                               if 'Exec time' in l][0].split()[3:]
    ]
    locktime = [
        getnumber(d) for d in [l for l in data
                               if 'Lock time' in l][0].split()[3:]
    ]
    rowsent = [
        getnumber(d) for d in [l for l in data
                               if 'Rows sent' in l][0].split()[3:]
    ]
    rowsaffecte = [
        getnumber(d) for d in [l for l in data
                               if 'Rows affecte' in l][0].split()[3:]
    ]
    bytessent = [
        getnumber(d) for d in [l for l in data
                               if 'Bytes sent' in l][0].split()[3:]
    ]
    querysize = [
        getnumber(d) for d in [l for l in data
                               if 'Query size' in l][0].split()[3:]
    ]

    top_data['tot_count'] = getnumber(overall[2])
    top_data['unique_queries'] = getnumber(overall[4])
    top_data['tot_exectime'] = exectime[0]
    top_data['tot_locktime'] = locktime[0]
    top_data['tot_rowssent'] = rowsent[0]
    top_data['tot_bytessent'] = bytessent[0]
    top_data['tot_querysize'] = querysize[0]
    top_data['tot_rowsaffecte'] = rowsaffecte[0]

    try:
        time = ' '.join(timerange[6:8])
        datetime.strptime(time, '%Y-%m-%d %H:%M:%S')
        top_data['date'] = timerange[6]
        top_data['time'] = timerange[7]
    except ValueError, e:
        top_data['date'] = timerange[3]
        top_data['time'] = timerange[4]
    return top_data


def format_query_tag(date, time, qdata, hdata):
    '''
    # Query 1: 0.04 QPS, 0.12x concurrency, ID 0x0344CA752955E058 at byte 1238726570
    # This item is included in the report because it matches --limit.
    # Scores: V/M = 1.24
    # Time range: 2016-01-01 07:05:32 to 2016-01-02 06:27:05
    # Attribute    pct   total     min     max     avg     95%  stddev  median
    # ============ === ======= ======= ======= ======= ======= ======= =======
    # Count          0    3690
    # Exec time     12  10054s   330ms      7s      3s      5s      2s      1s
    # Lock time      0      2s   307us     7ms   430us   596us   232us   384us
    # Rows sent      0  60.59k       0      56   16.81   44.60   11.81    9.83
    # Rows examine  10   3.91G 220.15k   1.89M   1.09M   1.86M 569.64k 717.31k
    # Rows affecte   0       0       0       0       0       0       0       0
    # Bytes sent     0  10.65M     966   7.55k   2.96k   6.01k   1.40k   2.16k
    # Query size     0   7.04M   1.95k   1.96k   1.95k   1.86k    2.22   1.86k
    # String:
    # Databases    telehealth
    # Hosts        199.79.51.132
    # Last errno   1292
    # Users        rubyuser
    '''
    aveqtime = qdata['exectime'] / qdata['count'] if qdata['count'] > 0 else 0
    taveqtime = hdata['tot_exectime'] / hdata['tot_count'] if hdata[
        'tot_count'] > 0 else 0
    pct_exectime = qdata['exectime'] / hdata['tot_exectime'] * 100 if hdata[
        'tot_exectime'] > 0 else 0
    pct_count = qdata['count'] / hdata['tot_count'] * 100 if hdata[
        'tot_count'] > 0 else 0
    sdate = datetime.strftime(date, '%Y-%m-%d')
    stime = datetime.strftime(time, '%H:%M:%S')
    #
    #print('{0:10} {1:8}  {2:>10}   {3:>9}   {4:>9}   {5:>12}   {6:>11s}  {7:>6s}  {8:>12s} {9:>11s} {10:11s}'.format(
    print(
        '{0:10} {1:8}  {2[count]:>10.0f}   {2[exectime]:>9.0f}   {2[locktime]:>9.0f}   '
        '{3:>12.5f}   {4:>11.2f}  {5:>6.2f}  '
        '{6[tot_count]:>12.0f} {6[tot_exectime]:>11.0f}  {7:>11.2f}'.format(
            sdate, stime, qdata, aveqtime, pct_exectime, pct_count, hdata,
            taveqtime * 1000))


def format(data):
    tot_aveqtime = data['tot_exectime'] / data['tot_count'] * 1000
    print(
        '{0[date]:10}  {0[time]:8}   {0[tot_count]:>12.0f}   {0[unique_queries]:>6.0f}   '
        '{0[tot_exectime]:>9.0f}   {0[tot_locktime]:>9.0f}   {1:>12.5f}'.
        format(data, tot_aveqtime))


def top_head(f, N):
    """
    Extract the top level header of the report
    :param f: file
    :param N: line count
    :return: list of data
    """
    p = re.compile(
        r'Exec time|Current date:|Time range:|Overall|Lock time|Rows sent|Rows examined|Rows affecte|Bytes sent|Query size'
    )
    f.seek(0, 0)
    head = list(itertools.islice(f, N))
    data = [l.strip() for l in head if p.search(l)]
    tdata = get_top_level_data(data)
    return tdata


def get_query_data(data):
    """
    # Query 1: 0.04 QPS, 0.12x concurrency, ID 0x0344CA752955E058 at byte 1238726570
    # This item is included in the report because it matches --limit.
    # Scores: V/M = 1.24
    # Time range: 2016-01-01 07:05:32 to 2016-01-02 06:27:05
                             0       1       2       3      4        5       6
    # Attribute    pct   total     min     max     avg     95%  stddev  median
    # ============ === ======= ======= ======= ======= ======= ======= =======
    # Count          0    3690
    # Exec time     12  10054s   330ms      7s      3s      5s      2s      1s
    # Lock time      0      2s   307us     7ms   430us   596us   232us   384us
    # Rows sent      0  60.59k       0      56   16.81   44.60   11.81    9.83
    # Rows examine  10   3.91G 220.15k   1.89M   1.09M   1.86M 569.64k 717.31k
    # Rows affecte   0       0       0       0       0       0       0       0
    # Bytes sent     0  10.65M     966   7.55k   2.96k   6.01k   1.40k   2.16k
    # Query size     0   7.04M   1.95k   1.96k   1.95k   1.86k    2.22   1.86k
    # String:
    # Databases    telehealth
    # Hosts        199.79.51.132
    # Last errno   1292
    # Users        rubyuser
    :param data:
    :return:
    """
    qdata = {}
    try:
        qdata['count'] = getnumber([l for l in data
                                    if 'Count' in l][0].split()[3])
        exectime = [
            getnumber(d) for d in [l for l in data
                                   if 'Exec time' in l][0].split()[4:]
        ]
        locktime = [
            getnumber(d) for d in [l for l in data
                                   if 'Lock time' in l][0].split()[4:]
        ]
        rowsent = [
            getnumber(d) for d in [l for l in data
                                   if 'Rows sent' in l][0].split()[4:]
        ]
        rowsaffecte = [
            getnumber(d)
            for d in [l for l in data if 'Rows affecte' in l][0].split()[4:]
        ]
        bytessent = [
            getnumber(d) for d in [l for l in data
                                   if 'Bytes sent' in l][0].split()[4:]
        ]
        querysize = [
            getnumber(d) for d in [l for l in data
                                   if 'Query size' in l][0].split()[4:]
        ]

        qdata['exectime'] = exectime[0]
        qdata['locktime'] = locktime[0]
        qdata['rowssent'] = rowsent[0]
        qdata['bytessent'] = bytessent[0]
        qdata['querysize'] = querysize[0]
        qdata['rowsaffecte'] = rowsaffecte[0]
    except IndexError, e:
        qdata['count'] = 0
        qdata['exectime'] = 0
        qdata['locktime'] = 0
        qdata['rowssent'] = 0
        qdata['bytessent'] = 0
        qdata['querysize'] = 0
        qdata['rowsaffecte'] = 0
    return qdata


def head_match(f, match, N):
    '''
    finds a query tag and returns head of the report
    '''
    p = re.compile(
        r'# Count|# Exec time|# Lock time|# Rows |# Bytes sent|# Query size|# Databases|# Hosts|#Users'
    )
    sqlp = re.compile(
        r'# EXPLAIN \/\*!50100 PARTITIONS\*\/|call |COMMIT|update|insert')
    head = None
    sql = None
    is_match = lambda x: True if match in x[1] else False
    matches = filter(is_match, enumerate(f))
    if len(matches) == 2:
        f.seek(0, 0)
        S = matches[1][0]
        buff = f.readlines()
        E = buff[S:].index('\n')
        head = [l.strip() for l in buff[S:S + E]]
        #skip to start of query tag
        #skip = [l.strip() for n,l in enumerate(f.next()) if n<L]
        #head = [l.strip() for l in f.next()]
        try:
            s = [i for i, l in enumerate(head) if sqlp.search(l)][0]
            sql = [re.sub(r'\\G', ';', l) for l in head[s:]]
        except ValueError, e:
            sql = ''
    # find explain sql
    '''# EXPLAIN /*!50100 PARTITIONS*/ match
       /n end
    '''
    qdata = [l for l in head if p.search(l)] if head else []
    qdata = get_query_data(qdata)
    return qdata, sql


def gfiles(days=None, start_date=None, end_date=None):
    """
    Generator to get the files that meet date criteria
    :param days: int number of days from now
    :param start_date: datetime
    :param end_date: datetime
    :return: iterable
    """
    log_path = 'log' if os.uname()[1].split('.')[0] == 'SUN-IT608L' else ''
    files = glob.glob(os.path.join(log_path, 'slow_201?-*log'))
    days = days if isinstance(days, int) or days is None else int(days)
    start = parse(start_date) if start_date else start_date
    end = parse(end_date) if end_date else end_date
    if days:
        compare = lambda d: d > datetime.now().date() - timedelta(days=int(days))
        for file in sorted(files, reverse=True):
            if os.path.getsize(file) < 512:
                continue
            with open(file, 'r') as f:
                date, time = get_report_date(f)
            if compare(date.date()):
                yield file
            else:
                break
    elif start_date:
        if end_date:
            compare = lambda d: d >= start.date() and d <= end.date()
        else:
            compare = lambda d: d >= start.date()
        for file in sorted(files, reverse=True):
            with open(file, 'r') as f:
                date, time = get_report_date(f)
            if compare(date.date()):
                yield file


def do_query_tag_report(query_tag, i, days, start, end, no_show_sql):
    first = True
    print('\nSlow report for tag #{} {}\n'.format(i + 1, query_tag))
    for file in gfiles(days, start, end):
        with open(file, 'r') as f:
            date, time = get_report_date(f)
            qdata, sql = head_match(f, query_tag, 70)
            hdata = top_head(f, 70)
            if first:
                first = False
                if not no_show_sql:
                    try:
                        print(sqlparse.format(
                            '\n'.join(sql),
                            reindent=True,
                            keyword_case='upper'))
                    except IndexError, e:
                        print(sqlparse.format(
                            '\n'.join(sql), keyword_case='upper'))
                    print('')

                print(
                    '{0:10} {1:8}  {2:>10}   {3:>9}   {4:>9}   {5:>12}   {6:>11s}  '
                    '{7:>6s}  {8:>12s} {9:>11s} {10:11s}'.format(
                        'Date',
                        'Time',
                        'Count',
                        'Exec_Time',
                        'Lock_Time',
                        'QAve_Resp',
                        '%Qexec_time',  #6
                        '%Count',
                        'Tot_Q_Count',
                        'Tot_time',
                        'Tot_ave_resp'))
        format_query_tag(date, time, qdata, hdata)


def main_tags(query_tag, days=None, start=None, end=None, no_show_sql=False):
    for i, tag in enumerate(query_tag):
        do_query_tag_report(tag, i, days, start, end, no_show_sql)


def main_top(days=None, start=None, end=None):
    print('{0:10}  {1:8}  {2:12}   {3:6}   {4:9}   {5:9}   {6:12}'.format(
        'Date', 'Time', 'Total_Queries', 'Unique', 'Exec_Time', 'Lock_Time',
        'Ave_Response'))
    for file in gfiles(days, start, end):
        with open(file, 'r') as f:
            data = top_head(f, 70)
        try:
            format(data)
        except Exception, e:
            print(e.__doc__)
            print(e.message)
            print(traceback.format_exc())
            #print(file)
            pass


def main(**args):
    print type(args)
    if args['<query_tag>'] == [] and args['--top'] is None:
        main_top(args['--days'], args['--start-date'], args['--end-date'])
    elif len(args['<query_tag>']) > 0:
        main_tags(args['<query_tag>'], args['--days'], args['--start-date'],
                  args['--end-date'], args['--no-sql'])
    else:
        tags = get_top_n_tags(args['--top'])
        main_tags(tags, args['--days'], args['--start-date'],
                  args['--end-date'], args['--no-sql'])


if __name__ == '__main__':
    args = docopt(__doc__, version=__version__)
    print args
    """
    {
      "--days": null,
      "--end-date": null,
      "--help": false,
      "--start-date": null,
      "--top": null,
      "--version": true,
      "<query_tag>": []
    }
    """
    main(**args)
    """
    print [d for d in gfiles(start_date=datetime.strptime('2016-01-03', '%Y-%m-%d'),
                            end_date=datetime.strptime('2016-01-07', '%Y-%m-%d'))]
    print '\n'.join([d for d in gfiles(
            start_date=datetime.strptime('2016-01-10', '%Y-%m-%d'))
           ])
    """
