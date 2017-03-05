# Create VLAN (vlan_id)
brocade_CREATE_VLAN_INTERFACE = """
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
        <interface-vlan xmlns="urn:brocade.com:mgmt:brocade-interface">
            <interface>
                <vlan>
                    <name>{vlan_id}</name>
                </vlan>
            </interface>
        </interface-vlan>
    </config>
"""

# Delete VLAN (vlan_id)
brocade_DELETE_VLAN_INTERFACE = """
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
        <interface-vlan xmlns="urn:brocade.com:mgmt:brocade-interface">
            <interface>
                <vlan operation="delete">
                    <name>{vlan_id}</name>
                </vlan>
            </interface>
        </interface-vlan>
    </config>
"""

# Create AMPP port-profile (port_profile_name)
brocade_CREATE_PORT_PROFILE = """
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
        <port-profile xmlns="urn:brocade.com:mgmt:brocade-port-profile">
            <name>{name}</name>
        </port-profile>
    </config>
"""

# Create VLAN sub-profile for port-profile (port_profile_name)
brocade_CREATE_VLAN_PROFILE_FOR_PORT_PROFILE = """
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
        <port-profile xmlns="urn:brocade.com:mgmt:brocade-port-profile">
            <name>{name}</name>
            <vlan-profile/>
        </port-profile>
    </config>
"""

# Configure L2 mode for VLAN sub-profile (port_profile_name)
brocade_CONFIGURE_L2_MODE_FOR_VLAN_PROFILE = """
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
        <port-profile xmlns="urn:brocade.com:mgmt:brocade-port-profile">
            <name>{name}</name>
            <vlan-profile>
                <switchport/>
            </vlan-profile>
        </port-profile>
    </config>
"""

# Configure trunk mode for VLAN sub-profile (port_profile_name)
brocade_CONFIGURE_TRUNK_MODE_FOR_VLAN_PROFILE = """
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
        <port-profile xmlns="urn:brocade.com:mgmt:brocade-port-profile">
            <name>{name}</name>
            <vlan-profile>
                <switchport>
                    <mode>
                        <vlan-mode>trunk</vlan-mode>
                    </mode>
                </switchport>
            </vlan-profile>
        </port-profile>
    </config>
"""

# Configure allowed VLANs for VLAN sub-profile
# (port_profile_name, allowed_vlan, native_vlan)
brocade_CONFIGURE_ALLOWED_VLANS_FOR_VLAN_PROFILE = """
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
        <port-profile xmlns="urn:brocade.com:mgmt:brocade-port-profile">
            <name>{name}</name>
            <vlan-profile>
                <switchport>
                    <trunk>
                        <allowed>
                            <vlan>
                                <add>{vlan_id}</add>
                            </vlan>
                        </allowed>
                    </trunk>
                </switchport>
            </vlan-profile>
        </port-profile>
    </config>
"""

# Delete port-profile (port_profile_name)
brocade_DELETE_PORT_PROFILE = """
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
        <port-profile
xmlns="urn:brocade.com:mgmt:brocade-port-profile" operation="delete">
            <name>{name}</name>
        </port-profile>
    </config>
"""

# Activate port-profile (port_profile_name)
brocade_ACTIVATE_PORT_PROFILE = """
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
        <port-profile-global xmlns="urn:brocade.com:mgmt:brocade-port-profile">
            <port-profile>
                <name>{name}</name>
                <activate/>
            </port-profile>
        </port-profile-global>
    </config>
"""

# Deactivate port-profile (port_profile_name)
brocade_DEACTIVATE_PORT_PROFILE = """
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
        <port-profile-global xmlns="urn:brocade.com:mgmt:brocade-port-profile">
            <port-profile>
                <name>{name}</name>
                <activate
xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="delete" />
            </port-profile>
        </port-profile-global>
    </config>
"""

# Associate MAC address to port-profile (port_profile_name, mac_address)
brocade_ASSOCIATE_MAC_TO_PORT_PROFILE = """
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
        <port-profile-global xmlns="urn:brocade.com:mgmt:brocade-port-profile">
            <port-profile>
                <name>{name}</name>
                <static>
                    <mac-address>{mac_address}</mac-address>
                </static>
            </port-profile>
        </port-profile-global>
    </config>
"""

# Dissociate MAC address from port-profile (port_profile_name, mac_address)
brocade_DISSOCIATE_MAC_FROM_PORT_PROFILE = """
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
        <port-profile-global xmlns="urn:brocade.com:mgmt:brocade-port-profile">
            <port-profile>
                <name>{name}</name>
                <static
xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="delete">
                    <mac-address>{mac_address}</mac-address>
                </static>
            </port-profile>
        </port-profile-global>
    </config>
"""
