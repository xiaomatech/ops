#!/usr/bin/env python
# -*- coding:utf8 -*-
import logging
from logging.handlers import RotatingFileHandler
from configs import log_error_config, log_common, log_debug_config
import sys, os
import traceback

log_dir = os.path.dirname(log_error_config.get('log_file'))
if not os.path.isdir(log_dir):
    os.makedirs(log_dir, 0777)

logger = logging.getLogger(__name__)
handler = RotatingFileHandler(log_error_config.get('log_file'), **log_common)
handler.setFormatter(
    logging.Formatter(
        '%(asctime)s %(levelname)-8s[%(filename)s:%(lineno)d(%(funcName)s)] %(message)s'
    ))
logger.addHandler(handler)

logger_debug = logging.getLogger(__name__ + '_debug')
handler = RotatingFileHandler(log_debug_config.get('log_file'), **log_common)
handler.setFormatter(
    logging.Formatter(
        '%(asctime)s %(levelname)-8s[%(filename)s:%(lineno)d(%(funcName)s)] %(message)s'
    ))
logger_debug.addHandler(handler)


def print_stack():
    ex_type, value, tb = sys.exc_info()
    errorlist = [
        line.lstrip()
        for line in traceback.format_exception(ex_type, value, tb)
    ]
    errorlist.reverse()
    return '\n' + ''.join(errorlist)


def log_debug(msg, *args, **kwargs):
    logger_debug.setLevel(logging.DEBUG)
    logger_debug.debug(msg, *args, **kwargs)


def log_info(msg, *args, **kwargs):
    logger_debug.setLevel(logging.INFO)
    logger_debug.info(msg, *args, **kwargs)


def log_error(msg, *args, **kwargs):
    logger.setLevel(logging.ERROR)
    logger.error(str(msg) + print_stack(), *args, **kwargs)


def log_exception(msg, *args, **kwargs):
    logger_debug.setLevel(logging.DEBUG)
    logger_debug.exception(msg, *args, **kwargs)


def log_warning(msg, *args, **kwargs):
    logger_debug.setLevel(logging.WARNING)
    logger_debug.warning(msg, *args, **kwargs)


def log_critical(msg, *args, **kwargs):
    logger.setLevel(logging.CRITICAL)
    logger.critical(str(msg) + print_stack(), *args, **kwargs)
