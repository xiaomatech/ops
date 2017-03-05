HUAWEI_SWITCH_CREATE_VLAN = """
<config>
<vlan xmlns="http://www.huawei.com/netconf/vrp"content-version="1.0" format-version="1.0">
    <vlans>
        <vlan operation="create">
        <vlanId>%s</vlanId>
        <vlanName></vlanName>
        <vlanDesc></vlanDesc>
        <vlanType>common</vlanType>
        <vlanif>
        <cfgBand></cfgBand>
        <dampTime></dampTime>
        </vlanif>
        </vlan>
    </vlans>
</vlan>
</config>
"""

HUAWEI_SWITCH_DELETE_VLAN = """
<config>
<vlan xmlns="http://www.huawei.com/netconf/vrp"content-version="1.0" format-version="1.0">
    <vlans>
        <vlan operation="delete">
        <vlanId>%s</vlanId>
        <vlanName></vlanName>
        <vlanDesc></vlanDesc>
        <vlanType>common</vlanType>
        <vlanif>
        <cfgBand></cfgBand>
        <dampTime></dampTime>
        </vlanif>
        </vlan>
    </vlans>
</vlan>
</config>
"""

HUAWEI_SWITCH_CONFIG_PORT = """
<config>
<ethernet xmlns="http://www.huawei.com/netconf/vrp" content-version="1.0" format-version="1.0">
    <ethernetIfs>
        <ethernetIf operation="merge">
            <ifName>%s</ifName>
            <l2Attribute>
                <trunkVlans>%s:%s</trunkVlans>
            </l2Attribute>
        </ethernetIf>
    </ethernetIfs>
</ethernet>
</config>
"""
