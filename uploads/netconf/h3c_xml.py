NC_VLAN_GROUP = """<VLAN xc:operation='%s'>
                    <VLANs>%s</VLANs>
                 </VLAN>
              """
NC_VLAN = """<VLANID><ID>%s</ID></VLANID>"""

NC_TRUNK_INTERFACE = """<Interface>
                         <IfIndex>%s</IfIndex>
                         <PermitVlanList>%s</PermitVlanList>
                     </Interface>
                  """
NC_VLAN_TRUNK = """<VLAN><TrunkInterfaces>%s</TrunkInterfaces></VLAN>"""
NC_PORT = """<Port><Name>%s</Name><IfIndex></IfIndex></Port>"""
NC_IFINDEX = """<Ifmgr><Ports>%s</Ports></Ifmgr>"""
NC_LINKTYPE_INTERFACE = """<Interface>
                           <IfIndex>%s</IfIndex>
                           <LinkType>%s</LinkType>
                        </Interface>"""
NC_LINKTYPE = """<Ifmgr>
                 <Interfaces>%s</Interfaces>
               </Ifmgr>"""

change_sysname = """
<config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    <top xmlns="http://www.h3c.com/netconf/config:1.0">
        <Device>
            <Base>
                <HostName> %s </HostName>
            </Base>
        </Device>
    </top>
</config>
"""
get_vlans = '''
                <top xmlns="http://www.h3c.com/netconf/data:1.0">
                    <VLAN>
                        <VLANs>
                        </VLANs>
                    </VLAN>
                </top>
               '''

add_vlan = """
<config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    <top xmlns="http://www.h3c.com/netconf/config:1.0">
        <VLAN>
            <VLANs>
                <VLANID>
                    <ID> %s </ID>
                </VLANID>
            </VLANs>
        </VLAN>
    </top>
</config>
"""

CREATE_AC = """
<config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"
 xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
    <top xmlns="http://www.h3c.com/netconf/config:1.0">
        <L2VPN xc:operation="merge">
            <ACs>
                <AC>
                    <IfIndex>{if_index}</IfIndex>
                    <SrvID>{service_id}</SrvID>
                    <VsiName>{vsi_name}</VsiName>
                </AC>
            </ACs>
        </L2VPN>
    </top>
</config>
"""

DELETE_AC = """
<config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"
 xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
    <top xmlns="http://www.h3c.com/netconf/config:1.0">
        <L2VPN xc:operation="remove">
            <ACs>
                <AC>
                    <IfIndex>{if_index}</IfIndex>
                    <SrvID>{service_id}</SrvID>
                </AC>
            </ACs>
        </L2VPN>
    </top>
</config>
"""

CREATE_SERVICE = """
<config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"
 xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
    <top xmlns="http://www.h3c.com/netconf/config:1.0">
        <L2VPN xc:operation="merge">
            <SRVs>
                <SRV>
                    <IfIndex>{if_index}</IfIndex>
                    <SrvID>{service_id}</SrvID>
                    <Encap>4</Encap>
                    <SVlanRange>{s_vid}</SVlanRange>
                </SRV>
            </SRVs>
        </L2VPN>
    </top>
</config>
"""

DELETE_SERVICE = """
<config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"
 xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
    <top xmlns="http://www.h3c.com/netconf/config:1.0">
        <L2VPN xc:operation="remove">
            <SRVs>
                <SRV>
                    <IfIndex>{if_index}</IfIndex>
                    <SrvID>{service_id}</SrvID>
                </SRV>
            </SRVs>
        </L2VPN>
    </top>
</config>
"""

INTERFACE_VLAN_TRUNK_ACCESS = """
<config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"
 xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
    <top xmlns="http://www.h3c.com/netconf/config:1.0">
        <Ifmgr xc:operation="merge">
            <Interfaces>
                <Interface>
                    <IfIndex>{if_index}</IfIndex>
                    <LinkType>{link_type}</LinkType>
                </Interface>
            </Interfaces>
        </Ifmgr>
    </top>
</config>
"""

INTERFACE_TRUNK_PERMIT_VLAN = """
<config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"
 xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
    <top xmlns="http://www.h3c.com/netconf/config:1.0">
        <VLAN xc:operation="merge">
            <TrunkInterfaces>
                <Interface>
                    <IfIndex>{if_index}</IfIndex>
                    <PermitVlanList>{vlan_list}</PermitVlanList>
                </Interface>
            </TrunkInterfaces>
        </VLAN>
    </top>
</config>
"""

CREATE_VXLAN_VSI = """
    <config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"
     xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
      <top xmlns="http://www.h3c.com/netconf/config:1.0">
        <VXLAN xc:operation="merge">
          <VXLANs>
              <Vxlan>
                  <VxlanID>{vxlanid}</VxlanID>
                  <VsiName>{vsiname}</VsiName>
              </Vxlan>
          </VXLANs>
        </VXLAN>
      </top>
    </config>
"""

DELETE_VXLAN = """
    <config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"
     xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
      <top xmlns="http://www.h3c.com/netconf/config:1.0">
        <VXLAN xc:operation="remove">
          <VXLANs>
              <Vxlan>
                  <VxlanID>{vxlanid}</VxlanID>
              </Vxlan>
          </VXLANs>
        </VXLAN>
      </top>
    </config>
"""

CREATE_TUNNEL = """
    <config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"
     xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
      <top xmlns="http://www.h3c.com/netconf/config:1.0">
        <TUNNEL xc:operation="merge">
          <Tunnels>
              <Tunnel>
                  <ID>{tunnel_id}</ID>
                  <Mode>24</Mode>
                  <IPv4Addr>
                      <SrcAddr>{src_addr}</SrcAddr>
                      <DstAddr>{dst_addr}</DstAddr>
                  </IPv4Addr>
              </Tunnel>
          </Tunnels>
        </TUNNEL>
      </top>
    </config>
"""

DELETE_TUNNEL = """
    <config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"
     xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
      <top xmlns="http://www.h3c.com/netconf/config:1.0">
        <TUNNEL xc:operation="remove">
          <Tunnels>
              <Tunnel>
                  <ID>{tunnel_id}</ID>
              </Tunnel>
          </Tunnels>
        </TUNNEL>
      </top>
    </config>
"""

RETRIEVE_AVAILABLE_TUNNEL_ID = """
    <top xmlns="http://www.h3c.com/netconf/data:1.0">
        <TUNNEL xmlns:web="http://www.h3c.com/netconf/base:1.0">
                <AvailableTunnelID>
                </AvailableTunnelID>
        </TUNNEL>
    </top>
"""

EDIT_VXLAN_TUNNEL = """
    <config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"
     xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
      <top xmlns="http://www.h3c.com/netconf/config:1.0">
        <VXLAN xc:operation="merge">
          <Tunnels>
              <Tunnel>
                  <VxlanID>{vxlanid}</VxlanID>
                  <TunnelID>{tunnelid}</TunnelID>
              </Tunnel>
          </Tunnels>
        </VXLAN>
      </top>
    </config>
"""

VSI_OPERATION = """
<config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"
 xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
  <top xmlns="http://www.h3c.com/netconf/config:1.0">
    <L2VPN xc:operation="{operation}">
      <VSIs>
        <VSI>
          <VsiName>{vsiname}</VsiName>
        </VSI>
      </VSIs>
    </L2VPN>
  </top>
</config>
"""

RETRIEVE_ALL_INTERFACES = """
    <top xmlns="http://www.h3c.com/netconf/data:1.0">
        <Ifmgr xmlns:web="http://www.h3c.com/netconf/base:1.0">
            <Interfaces>
            </Interfaces>
        </Ifmgr>
    </top>
"""

RETRIEVE_SPECIAL_INTERFACES = """
    <top xmlns="http://www.h3c.com/netconf/data:1.0">
        <Ifmgr xmlns:web="http://www.h3c.com/netconf/base:1.0">
            <Interfaces>
                <Interface>
                    <IfIndex>{if_index}</IfIndex>
                </Interface>
            </Interfaces>
        </Ifmgr>
    </top>
"""

RETRIEVE_TUNNELS = """
    <top xmlns="http://www.h3c.com/netconf/data:1.0">
        <TUNNEL xmlns:web="http://www.h3c.com/netconf/base:1.0">
                <Tunnels>
                </Tunnels>
        </TUNNEL>
    </top>
"""

CREATE_ACL = """
            <config>
                <top xmlns="http://www.h3c.com/netconf/config:1.0">
                    <ACL>
                        <Groups>
                            <Group>
                                <GroupType>1</GroupType>
                                <GroupID>{acl_num}</GroupID>
                            </Group>
                        </Groups>
                    </ACL>
                </top>
            </config>
        """

display_command = """
                <rpc message-id="101" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
                    <CLI>
                        <Execution> %s </Execution>
                    </CLI>
                </rpc>
                """

vsi_xml = """
        <config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"
         xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
          <top xmlns="http://www.h3c.com/netconf/config:1.0">
            <L2VPN xc:operation="{operation}">
              <VSIs>
                <VSI>
                  <VsiName>{vsiname}</VsiName>
                </VSI>
              </VSIs>
            </L2VPN>
          </top>
        </config>
    """
create_vxlan_xml = """
        <config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"
         xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
          <top xmlns="http://www.h3c.com/netconf/config:1.0">
            <VXLAN xc:operation="merge">
              <VXLANs>
                  <Vxlan>
                      <VxlanID>{vxlanid}</VxlanID>
                      <VsiName>{vsiname}</VsiName>
                  </Vxlan>
              </VXLANs>
            </VXLAN>
          </top>
        </config>
    """
delete_vxlan_xml = """
        <config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"
         xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
          <top xmlns="http://www.h3c.com/netconf/config:1.0">
            <VXLAN xc:operation="remove">
              <VXLANs>
                  <Vxlan>
                      <VxlanID>{vxlanid}</VxlanID>
                  </Vxlan>
              </VXLANs>
            </VXLAN>
          </top>
        </config>
    """
edit_vxlan_xml = """
        <config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"
         xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
          <top xmlns="http://www.h3c.com/netconf/config:1.0">
            <VXLAN xc:operation="merge">
              <Tunnels>
                  <Tunnel>
                      <VxlanID>{vxlanid}</VxlanID>
                      <TunnelID>{tunnelid}</TunnelID>
                  </Tunnel>
              </Tunnels>
            </VXLAN>
          </top>
        </config>
    """
create_tunnel_xml = """
        <config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"
         xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
          <top xmlns="http://www.h3c.com/netconf/config:1.0">
            <TUNNEL xc:operation="merge">
              <Tunnels>
                  <Tunnel>
                      <ID>{tunnel_id}</ID>
                      <Mode>24</Mode>
                      <IPv4Addr>
                          <SrcAddr>{src_addr}</SrcAddr>
                          <DstAddr>{dst_addr}</DstAddr>
                      </IPv4Addr>
                  </Tunnel>
              </Tunnels>
            </TUNNEL>
          </top>
        </config>
    """
delete_tunnel_xml = """
        <config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"
         xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
          <top xmlns="http://www.h3c.com/netconf/config:1.0">
            <TUNNEL xc:operation="remove">
              <Tunnels>
                  <Tunnel>
                      <ID>{tunnel_id}</ID>
                  </Tunnel>
              </Tunnels>
            </TUNNEL>
          </top>
        </config>
    """
create_ac_xml = """
    <config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"
     xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
        <top xmlns="http://www.h3c.com/netconf/config:1.0">
            <L2VPN xc:operation="merge">
                <ACs>
                    <AC>
                        <IfIndex>{if_index}</IfIndex>
                        <SrvID>{service_id}</SrvID>
                        <VsiName>{vsi_name}</VsiName>
                    </AC>
                </ACs>
            </L2VPN>
        </top>
    </config>
    """
delete_ac_xml = """
    <config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"
     xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
        <top xmlns="http://www.h3c.com/netconf/config:1.0">
            <L2VPN xc:operation="remove">
                <ACs>
                    <AC>
                        <IfIndex>{if_index}</IfIndex>
                        <SrvID>{service_id}</SrvID>
                    </AC>
                </ACs>
            </L2VPN>
        </top>
    </config>
    """
create_service_xml = """
    <config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"
     xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
        <top xmlns="http://www.h3c.com/netconf/config:1.0">
            <L2VPN xc:operation="merge">
                <SRVs>
                    <SRV>
                        <IfIndex>{if_index}</IfIndex>
                        <SrvID>{service_id}</SrvID>
                        <Encap>4</Encap>
                        <SVlanRange>{s_vid}</SVlanRange>
                    </SRV>
                </SRVs>
            </L2VPN>
        </top>
    </config>
    """
delete_service_xml = """
    <config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"
     xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
        <top xmlns="http://www.h3c.com/netconf/config:1.0">
            <L2VPN xc:operation="remove">
                <SRVs>
                    <SRV>
                        <IfIndex>{if_index}</IfIndex>
                        <SrvID>{service_id}</SrvID>
                    </SRV>
                </SRVs>
            </L2VPN>
        </top>
    </config>
    """
