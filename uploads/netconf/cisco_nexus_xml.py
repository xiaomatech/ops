nexus_EXEC_CONF_SNIPPET = """
      <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
        <configure>
          <__XML__MODE__exec_configure>%s
          </__XML__MODE__exec_configure>
        </configure>
      </config>
"""

nexus_CMD_VLAN_CONF_SNIPPET = """
            <vlan>
              <vlan-id-create-delete>
                <__XML__PARAM_value>%s</__XML__PARAM_value>
                <__XML__MODE_vlan>
                  <name>
                    <vlan-name>%s</vlan-name>
                  </name>
                </__XML__MODE_vlan>
              </vlan-id-create-delete>
            </vlan>
"""

nexus_CMD_VLAN_ACTIVE_SNIPPET = """
            <vlan>
              <vlan-id-create-delete>
                <__XML__PARAM_value>%s</__XML__PARAM_value>
                <__XML__MODE_vlan>
                  <state>
                    <vstate>active</vstate>
                  </state>
                </__XML__MODE_vlan>
              </vlan-id-create-delete>
            </vlan>
"""

nexus_CMD_VLAN_NO_SHUTDOWN_SNIPPET = """
            <vlan>
              <vlan-id-create-delete>
                <__XML__PARAM_value>%s</__XML__PARAM_value>
                <__XML__MODE_vlan>
                  <no>
                    <shutdown/>
                  </no>
                </__XML__MODE_vlan>
              </vlan-id-create-delete>
            </vlan>
"""

nexus_CMD_NO_VLAN_CONF_SNIPPET = """
          <no>
          <vlan>
            <vlan-id-create-delete>
              <__XML__PARAM_value>%s</__XML__PARAM_value>
            </vlan-id-create-delete>
          </vlan>
          </no>
"""

nexus_CMD_INT_VLAN_HEADER = """
          <interface>
            <%s>
              <interface>%s</interface>
              <__XML__MODE_if-ethernet-switch>
                <switchport>
                  <trunk>
                    <allowed>
                      <vlan>"""

nexus_CMD_VLAN_ID = """
                          <vlan_id>%s</vlan_id>"""

nexus_CMD_VLAN_ADD_ID = """
                        <add>%s
                        </add>""" % nexus_CMD_VLAN_ID

nexus_CMD_INT_VLAN_TRAILER = """
                      </vlan>
                    </allowed>
                  </trunk>
                </switchport>
              </__XML__MODE_if-ethernet-switch>
            </%s>
          </interface>
"""

nexus_CMD_INT_VLAN_SNIPPET = (
    nexus_CMD_INT_VLAN_HEADER + nexus_CMD_VLAN_ID + nexus_CMD_INT_VLAN_TRAILER)

nexus_CMD_INT_VLAN_ADD_SNIPPET = (
    nexus_CMD_INT_VLAN_HEADER + nexus_CMD_VLAN_ID + nexus_CMD_INT_VLAN_TRAILER)

nexus_CMD_PORT_TRUNK = """
          <interface>
            <%s>
              <interface>%s</interface>
              <__XML__MODE_if-ethernet-switch>
                <switchport></switchport>
                <switchport>
                  <mode>
                    <trunk>
                    </trunk>
                  </mode>
                </switchport>
              </__XML__MODE_if-ethernet-switch>
            </%s>
          </interface>
"""

nexus_CMD_NO_SWITCHPORT = """
          <interface>
            <%s>
              <interface>%s</interface>
              <__XML__MODE_if-ethernet-switch>
                <no>
                  <switchport>
                  </switchport>
                </no>
              </__XML__MODE_if-ethernet-switch>
            </%s>
          </interface>
"""

nexus_CMD_NO_VLAN_INT_SNIPPET = """
          <interface>
            <%s>
              <interface>%s</interface>
              <__XML__MODE_if-ethernet-switch>
                <switchport></switchport>
                <switchport>
                  <trunk>
                    <allowed>
                      <vlan>
                        <remove>
                          <vlan>%s</vlan>
                        </remove>
                      </vlan>
                    </allowed>
                  </trunk>
                </switchport>
              </__XML__MODE_if-ethernet-switch>
            </%s>
          </interface>
"""

nexus_FILTER_SHOW_VLAN_BRIEF_SNIPPET = """
      <show xmlns="http://www.cisco.com/nxos:1.0:vlan_mgr_cli">
        <vlan>
          <brief/>
        </vlan>
      </show>
"""

nexus_CMD_VLAN_SVI_SNIPPET = """
<interface>
    <vlan>
        <vlan>%s</vlan>
        <__XML__MODE_vlan>
            <no>
              <shutdown/>
            </no>
            <ip>
                <address>
                    <address>%s</address>
                </address>
            </ip>
        </__XML__MODE_vlan>
    </vlan>
</interface>
"""

nexus_CMD_NO_VLAN_SVI_SNIPPET = """
<no>
    <interface>
        <vlan>
            <vlan>%s</vlan>
        </vlan>
    </interface>
</no>
"""
