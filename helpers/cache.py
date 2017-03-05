#!/usr/bin/env python
# -*- coding:utf8 -*-

import hashlib
import redis
import simplejson as json
import functools
from configs import redis_conf
from logger import log_error
redis_pool = redis.ConnectionPool(**redis_conf)
r = redis.StrictRedis(connection_pool=redis_pool)


def get_cache_key(prefix, *args, **kwargs):
    def md5(input):
        m2 = hashlib.md5()
        m2.update(input)
        return str(m2.hexdigest())

    parsed_args = ",".join(map(lambda x: str(x), args))
    parsed_kwargs = ",".join(
        map(lambda x: '%s=%s' % (x, str(kwargs[x])), kwargs))
    parsed = filter(lambda x: x != '', [parsed_args, parsed_kwargs])
    key = prefix + ','.join(parsed)
    return prefix + '_' + md5(str(key))


def cache(ttl=3600, prefix='', op='select'):
    def handle_func(func):
        @functools.wraps(func)
        def handle_args(*args, **kwargs):
            ckey = get_cache_key(prefix + func.__name__, *args, **kwargs)
            if op == 'select':
                obj = r.get(ckey)
                if obj == None:
                    result = func(*args, **kwargs)
                    try:
                        r.setex(ckey, ttl, json.dumps(result))
                    except Exception as e:
                        log_error(e)
                    return result
                else:
                    return json.loads(obj)
            elif op == 'del' or op == 'delete' or op == 'remove':
                r.delete(ckey)
            elif op == 'insert' or op == 'update':
                result = func(*args, **kwargs)
                r.setex(ckey, ttl, json.dumps(result))
                return result

        return handle_args

    return handle_func
