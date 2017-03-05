#!/usr/bin/env python
# -*- coding:utf8 -*-

import os
import sys
import inspect
import re
import imp
from configs import log_loader, log_common, autoloader_dir

import traceback
import logging.handlers
log_dir = os.path.dirname(log_loader.get('log_file'))
if not os.path.isdir(log_dir):
    os.makedirs(log_dir, 0777)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
handler = logging.handlers.RotatingFileHandler(
    log_loader.get('log_file'), **log_common)
handler.setFormatter(
    logging.Formatter(
        '%(asctime)s %(levelname)-8s[%(filename)s:%(lineno)d(%(funcName)s)] %(message)s'
    ))
logger.addHandler(handler)


def print_stack():
    ex_type, value, tb = sys.exc_info()
    errorlist = [
        line.lstrip()
        for line in traceback.format_exception(ex_type, value, tb)
    ]
    errorlist.reverse()
    return '\n' + ''.join(errorlist)


class Loader(object):
    def __init__(self, **kwargs):
        self.application_path = kwargs['application_path']
        self.kwargs = kwargs
        self.app_modules_list = autoloader_dir
        self.modules = {}
        self.classes = {}
        self.files = {}
        self.logger = logger
        self.sys_path = sys.path
        sys.path.insert(0, os.path.abspath(self.application_path))
        for m in self.app_modules_list:
            self.modules[m] = {}
        map(self._load_application, self.app_modules_list)

    def cls(self, name):
        return self.classes[name]

    def get_cls(self, name):
        return self.classes[name]

    def model(self, name):
        return self._load('models', name)

    def ctrl(self, name):
        return self._load('controllers', name)

    def helper(self, name):
        return self._load('helpers', name)

    def library(self, name):
        return self._load('library', name)

    def get_module_name(self, name, categroy):
        for key in self.modules[categroy].keys():
            if name.lower() == key.lower():
                return key

    def _load(self, categroy, name, is_reload=False, count=0):
        try:
            if count > 1:
                self.logger.error("load " + categroy + "  " + name + " fail" +
                                  print_stack())
                return None
            if not is_reload:
                shortname = os.path.basename(name)
                mname = self.get_module_name(shortname, categroy)
                return self.modules[categroy][mname]['instance']
            else:
                raise KeyError('reload')
        except KeyError as e:
            return None

    def load_file(self, filename):
        try:
            if not os.path.exists(os.path.abspath(filename)):
                self.logger.warn('file %s not exist' % filename)
                return None

            if filename.endswith('.py') and filename not in self.files.keys():

                self.files[filename] = os.stat(filename).st_mtime
            filename = os.path.abspath(filename)
            name = filename.replace('.pyc', '').replace('.py', '')
            if not os.path.exists(
                    os.path.join(os.path.dirname(name), '__init__.py')
            ) and not os.path.exists(
                    os.path.join(os.path.dirname(name), '__init__.pyc')):
                sys.path.insert(0, os.path.join(os.path.dirname(name)))
                name = os.path.basename(name)
                fn_, path, desc = imp.find_module(name,
                                                  [os.path.dirname(filename)])
                mod = imp.load_module("%s" % (name), fn_,
                                      os.path.abspath(path), desc)
            else:
                dname = os.path.basename(os.path.dirname(name))
                name = os.path.basename(name)
                _fn_, _path, _desc = imp.find_module(
                    dname, [os.path.dirname(os.path.dirname(filename))])
                imp.load_module(dname, _fn_, os.path.abspath(_path), _desc)
                fn_, path, desc = imp.find_module(name,
                                                  [os.path.dirname(filename)])
                dname = os.path.basename(os.path.dirname(path))
                mod = imp.load_module("%s.%s" % (dname, name), fn_,
                                      os.path.abspath(path), desc)
            return mod
        except Exception as e:
            self.logger.error("load module error filename:" + filename + str(e)
                              + print_stack())

    def load_module(self, mod_dir):
        try:
            names = {}
            modules = []
            funcs = {}
            for fn_ in os.listdir(mod_dir):
                if fn_.startswith('_'):
                    continue
                if (fn_.endswith(('.py', '.pyc', '.pyo', '.so')) or
                        os.path.isdir(fn_)):
                    extpos = fn_.rfind('.')
                    if extpos > 0:
                        _name = fn_[:extpos]
                    else:
                        _name = fn_
                    names[_name] = os.path.join(mod_dir, fn_)
            for name in names:
                try:
                    fn_, path, desc = imp.find_module(name, [mod_dir])
                    mod = imp.load_module(name, fn_, path, desc)
                except:
                    continue
                modules.append(mod)
            for mod in modules:
                for attr in dir(mod):
                    if attr.startswith('_'):
                        continue
                    if callable(getattr(mod, attr)):
                        func = getattr(mod, attr)
                        if isinstance(func, type):
                            if any([
                                    'Error' in func.__name__,
                                    'Exception' in func.__name__
                            ]):
                                continue
                        try:
                            funcs['{0}.{1}'.format(mod.__name__, attr)] = func
                        except Exception as e:
                            self.logger.error("load module error dir:" +
                                              mod_dir + str(e) + print_stack())
                            continue
            return funcs
        except Exception as e:
            self.logger.error("load module error dir:" + mod_dir + str(e) +
                              print_stack())

    def regcls(self, name, aclass):
        self.classes[name] = aclass

    def _load_application(self, module_name, path=None):
        if path == None:
            path = self.application_path
        module_path = path + os.path.sep + module_name
        autoload = {}
        is_autoload = True

        if not os.path.isdir(module_path):
            self.logger.info(module_path + ' not exists')
            return
        if module_path not in sys.path:
            sys.path = self.sys_path
        files = os.listdir(path + os.path.sep + module_name)

        if is_autoload:
            self._load_application3(module_name, path)
            return

        if len(autoload) == 0:
            return

        for file in files:
            file_path = path + os.path.sep + module_name + os.path.sep + file
            if os.path.isfile(file_path) and (
                    file.endswith('.py') or
                    file.endswith('.pyc')) and file != '__init__.py':
                for m in autoload.keys():
                    if m == file.split('.')[0]:
                        module = self.load_file(file_path)
                        self._register_instance(module, autoload[m],
                                                module_name)
                        break

    def _load_application3(self, module_name, path=None):
        if path == None:
            path = self.application_path
        module_path = path + os.path.sep + module_name
        if not os.path.isdir(module_path):
            self.logger.info(module_path + ' not exists')
            return
        if module_path not in sys.path:
            sys.path = self.sys_path
        files = os.listdir(path + os.path.sep + module_name)

        for file in files:
            file_path = path + os.path.sep + module_name + os.path.sep + file
            if os.path.isfile(file_path) and (
                    file.endswith('.py') or
                    file.endswith('.pyc')) and file != '__init__.py':
                module = self.load_file(file_path)
                if module != None and module.__name__ in dir(module):
                    m = module.__name__
                    if (isinstance(getattr(module, m), type) or
                            type(getattr(module, m)).__name__ == 'classobj'
                        ) and module != None and not m.startswith('_'):
                        self._register_instance(module, m, module_name)
                        continue

                for m in dir(module):
                    if (isinstance(getattr(module, m), type) or
                            type(getattr(module, m)).__name__ == 'classobj'
                        ) and module != None and not m.startswith('_'):
                        self._register_instance(module, m, module_name)

    def _register_instance(self, module, module_name, module_category_name):
        aclass = getattr(module, module_name)
        has_init = hasattr(aclass, '__init__')
        if has_init:
            init_member = getattr(aclass, '__init__')
            arginfo = str(init_member)
            if re.match(r'^<unbound method', arginfo):
                arginfo = inspect.getargspec(init_member)
            else:
                arginfo = ''
        else:
            arginfo = ''
        if module_name not in self.modules[module_category_name].keys():
            _instance = None
            try:
                if str(arginfo).find('kwargs') > 0:
                    init = getattr(module, module_name)
                    _instance = init(**self.kwargs)

                else:
                    init = getattr(module, module_name)
                    _instance = init()
                self.logger.info('load module ' + module_name + ' of ' +
                                 module_category_name + " successfull. \t" +
                                 str(_instance))

            except Exception as e:
                self.logger.error('create ' + module_name + ' of  ' +
                                  module_category_name +
                                  ' failed ,please check parameters, ' + str(
                                      e) + print_stack())

            self.modules[module_category_name][module_name] = {
                'aclass': getattr(module, module_name),
                'instance': _instance
            }
            self.classes[module_name] = getattr(module, module_name)

    def _load_application2(self, module_name, path=None):
        if path == None:
            path = self.application_path
        module_path = path + os.path.sep + module_name
        if not os.path.isdir(module_path):
            self.logger.info(module_path + ' not exists')
            return
        if module_path not in sys.path:
            sys.path = self.sys_path
        files = os.listdir(path + os.path.sep + module_name)

        for file in files:
            file_path = path + os.path.sep + module_name + os.path.sep + file
            if os.path.isfile(file_path) and file.endswith(
                    '.py') and file != '__init__.py':
                try:
                    module = file.split('.')[0]
                    exec ("from " + module + " import " + module)
                    cmodule = __import__(module)

                    self._register_instance(cmodule, module, module_name)

                except Exception as e:
                    self.logger.error("load " + module + " module error " +
                                      str(e) + print_stack())

            elif os.path.isdir(file_path):
                self._load(module_name, file_path)


if __name__ == '__main__':
    loader = Loader(application_path=r'./', app=None)
    print(loader.ctrl('zabbix'))
