#!/usr/bin/env python
# -*- coding:utf8 -*-

import collections
import threading
import socket
import json

from helpers.logger import log_debug, log_exception
"""
a simple client to talk to ovsdb over json rpc
"""


class OVSDBConnection(threading.Thread):
    """Connects to an ovsdb server that has manager set using

        ovs-vsctl set-manager ptcp:6632

        clients can make calls and register a callback for results, callbacks
         are linked based on the message ids.

        clients can also register methods which they are interested in by
        providing a callback.
    """

    def __init__(self, ip, port, **handlers):
        super(OVSDBConnection, self).__init__()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((ip, port))
        self.responses = []
        self.callbacks = {}
        self.read_on = True
        self.handlers = handlers or {"echo": self.default_echo_handler}
        self.start()

    def send(self, message, callback=None):
        if callback:
            self.callbacks[message['id']] = callback
        self.socket.send(json.dumps(message))

    def response(self, id):
        return [x for x in self.responses if x['id'] == id]

    def set_handler(self, method_name, handler):
        self.handlers[method_name] = handler

    def _on_remote_message(self, message):
        log_debug("message %s", message)
        try:
            json_m = json.loads(
                message, object_pairs_hook=collections.OrderedDict)
            # handler for it
            handler_method = json_m.get('method', None)
            if handler_method:
                self.handlers.get(handler_method,
                                  self.default_message_handler)(json_m, self)
            elif json_m.get("result", None) and json_m['id'] in self.callbacks:
                id = json_m['id']
                if not self.callbacks[id](json_m, self):
                    self.callbacks.pop(id)

            else:
                self.default_message_handler(message, self)
        except Exception as e:
            log_exception("exception [%s] while handling message [%s]",
                          e.message, message)

    def __echo_response(message, self):
        self.send({
            "result": message.get("params", None),
            "error": None,
            "id": message['id']
        })

    def run(self):

        chunks = []
        lc = rc = 0
        while self.read_on:
            try:
                response = self.socket.recv(4096)
                if response:
                    response = response.decode('utf8')
                    message_mark = 0
                    for i, c in enumerate(response):
                        if c == '{':
                            lc += 1
                        elif c == '}':
                            rc += 1

                        if rc > lc:
                            raise Exception("json string not valid")

                        elif lc == rc and lc is not 0:
                            chunks.append(response[message_mark:i + 1])
                            message = "".join(chunks)
                            self._on_remote_message(message)
                            lc = rc = 0
                            message_mark = i + 1
                            chunks = []

                    chunks.append(response[message_mark:])
            except (KeyboardInterrupt, SystemExit):
                self.read_on = False

    def stop(self, force=False):
        self.read_on = False
        if force:
            self.socket.close()

    @staticmethod
    def default_echo_handler(message, ovsconn):
        log_debug("responding to echo")
        ovsconn.send({
            "result": message.get("params", None),
            "error": None,
            "id": message['id']
        })

    @staticmethod
    def default_message_handler(message, ovsconn):
        log_debug("default handler called for method %s", message['method'])
        ovsconn.responses.append(message)
