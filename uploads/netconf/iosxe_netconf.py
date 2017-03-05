'''Netconf implementation for IOSXE devices'''

from ncclient import manager
from ncclient.transport.errors import TransportError
from ncclient.operations.rpc import RPCError
import xmltodict


def compare_proposed_to_running(proposed_config, running_config):
    '''Return diff between *proposed_config* and *running_config*.'''

    # remove empty lines from playbook
    for line in proposed_config:
        if len(line) == 0:
            proposed_config.remove(line)

    final_config = proposed_config[:]

    # all commands starting with "no "
    no_commands = [
        line.strip() for line in final_config if line.startswith('no ')
    ]
    # all other commands
    commands = [
        line.strip() for line in final_config if not line.startswith('no ')
    ]

    # commands starting with "no " that have a matching line in running_config
    # which means that it shall be included in the final_config committed to
    # device. all other "no " commands shall be disregarded when committing
    # the configuration.
    no_commands_real = []

    for line in running_config:
        for no_line in no_commands:
            if line == no_line.lstrip('no '):
                no_commands_real.append(no_line)
        if line in commands:
            commands.remove(line)

    return commands + no_commands_real


def reconnect_device(func):
    '''When a method is using this decorator and self.reconnect == True, try
       to reconnect to the device if a TransportError exception is thrown by
       ncclient. This typically happens if the router has disconnected the
       connection due to inactivity.'''

    def inner(self, *args, **kwargs):
        '''Wrap decorated function and reconnect as wanted.'''
        if self.reconnect == True:
            try:
                return func(self, *args, **kwargs)
            except TransportError:
                self.connect()
                return func(self, *args, **kwargs)
        else:
            return func(self, *args, **kwargs)

    return inner


class IfMissingError(Exception):
    '''raise if interface is missing in router'''
    pass


class BGPMissingError(Exception):
    '''raise if BGP configuration is missing in router'''
    pass


class VRFMissingError(Exception):
    '''raise if VRF configuration is missing in router'''
    pass


class ConfigDeployError(Exception):
    '''raise if configuration could not be deployed to router'''
    pass


class IOSXEDevice(object):
    '''Implements methods for configuration retrieval and update'''

    def __init__(self, hostname, username, password, reconnect=True, port=22):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.reconnect = reconnect
        self.port = port
        self.handle = None

    def connect(self):
        '''Returns True if connect to device is successful.'''
        self.handle = manager.connect_ssh(
            self.hostname,
            username=self.username,
            password=self.password,
            port=self.port,
            hostkey_verify=False)

    def disconnect(self):
        '''Returns True if disconnect from device is successful.'''
        try:
            self.handle.close_session()
        except TransportError:
            return True  # already disconnected

    @reconnect_device
    def get_config(self):
        '''Returns running config in device as list.'''
        response = xmltodict.parse(self.handle.get().xml)
        return response['rpc-reply']['data']['cli-config-data-block'].split(
            '\n')

    @reconnect_device
    def exec_command(self, command):
        '''Returns output of executed command as list.'''
        netconf_filter = """
<filter>
<config-format-text-block>
<text-filter-spec>| begin ^end </text-filter-spec>
</config-format-text-block>
<oper-data-format-text-block>
<exec>{command}</exec>
</oper-data-format-text-block>
</filter>""".format(command=command)
        response = xmltodict.parse(self.handle.get(netconf_filter).xml)
        return response['rpc-reply'] \
                       ['data']['cli-oper-data-block']['item']['response'].split('\n')

    @reconnect_device
    def edit_config(self, commands):
        '''Returns True if commit of *commands* to running configuration is
        successful.'''
        config = """
<config>
<cli-config-data-block>
{commands}
</cli-config-data-block>
</config>""".format(commands=commands)
        try:
            response = xmltodict.parse(
                self.handle.edit_config(
                    target='running', config=config).xml)
            return 'ok' in response['rpc-reply']  # Got <ok /> tag
        except RPCError:
            raise ConfigDeployError

    @reconnect_device
    def save_config(self):
        '''Returns true if save of running configuration is successful.'''
        return '[OK]' in self.exec_command('copy running startup')

    def get_interface_config(self, interface_name):
        '''Return configuration for *interface_name*'''
        config = self.get_config()
        interface_config = None
        in_interface = False
        for line in config:
            if not in_interface:
                if line.startswith('interface {interface_name}'.format(
                        interface_name=interface_name)):
                    interface_config = [line]
                    in_interface = True
            else:
                if line.startswith('!'):  # end of interface block
                    break
                else:
                    interface_config.append(line)

        if interface_config is None:
            raise IfMissingError
        else:
            return [x.strip('\n') for x in interface_config]

    def get_bgp_config(self):
        '''Return bgp configuration in device'''
        config = self.get_config()
        bgp_config = None
        in_bgp = False
        for line in config:
            if not in_bgp:
                if line.startswith('router bgp'):
                    bgp_config = [line]
                    in_bgp = True
            else:
                if line.startswith('!'):  # end of router bgp block
                    break
                else:
                    bgp_config.append(line)

        if bgp_config is None:
            raise BGPMissingError
        else:
            return [x.strip('\n') for x in bgp_config]

    def get_vrf_definition_config(self, vrf_name):
        '''Return vrf definition configuration in device'''
        config = self.get_config()
        vrf_definition_config = None
        in_vrf_definition = False
        for line in config:
            if not in_vrf_definition:
                if line.startswith('vrf definition {0}'.format(vrf_name)):
                    vrf_definition_config = [line]
                    in_vrf_definition = True
            else:
                if line.startswith('!'):  # end of vrf definition block
                    break
                else:
                    vrf_definition_config.append(line)

        if vrf_definition_config is None:
            raise VRFMissingError
        else:
            return [x.strip('\n') for x in vrf_definition_config]
