"""
Copyright 2023 Sophos Ltd.  All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing
permissions and limitations under the License.
"""


class Interface:
    """Class for working with Interface(s)."""

    def __init__(self, api_client):
        self.client = api_client

    def get(self, name, operator):
        """Get Interface object(s)

        Args:
            name (str, optional): Interface name. Returns all objects if not specified.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like.
        """
        if name:
            return self.client.get_tag_with_filter(
                xml_tag="Interface", key="Name", value=name, operator=operator
            )
        return self.client.get_tag(xml_tag="Interface")


class Vlan:
    """Class for working with Vlan(s)."""

    def __init__(self, api_client):
        self.client = api_client

    def get(self, name, operator):
        """Get VLAN object(s)

        Args:
            name (str, optional): VLAN name. Returns all objects if not specified.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like.
        """
        if name:
            return self.client.get_tag_with_filter(
                xml_tag="VLAN", key="Name", value=name, operator=operator
            )
        return self.client.get_tag(xml_tag="VLAN")


class Zone:
    """Class for working with Zone(s)."""

    def __init__(self, api_client):
        self.client = api_client

    def get(self, name, operator="="):
        """Get zone(s)

        Args:
            name (str, optional): Name of zone to query. Returns all if not specified.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like.

        Returns:
            dict: XML response converted to Python dictionary
        """
        if name:
            return self.client.get_tag_with_filter(
                xml_tag="Zone", key="Name", value=name, operator=operator
            )
        return self.client.get_tag(xml_tag="Zone")

    def create(self, name: str, zone_type: str, zone_params: dict = None, debug: bool = False):
        """Create a zone.

        Args:
            name (str): Zone name
            zone_type (str): Zone type
            zone_params (dict): Configuration parmeters for the zone, see Keyword Args for supported parameters.

        Keyword Args:
            name (str): Name of the Zone
            zone_type (str): Type of the zone (LAN/DMZ)
            description (str, optional): Description for the Zone
            https (str, optional): Enable/Disable HTTPS administrative service
            ssh (str, optional): Enable/Disable SSH administrative service
            client_authen (str, optional): Enable/Disable client authentication service
            captive_portal (str, optional): Enable/Disable captive portal
            ad_sso (str, optional): Enable/Disable SSO with Active Directory
            radius_sso (str, optional): Enable/Disable SSO with Radius
            chromebook_sso (str, optional): Enable/Disable Chromebook SSO
            dns (str, optional): Enable/Disable DNS
            ping (str, optional): Enable/Disable ping
            ipsec (str, optional): Enable/Disable ipsec
            red (str, optional): Enable/Disable RED
            sslvpn (str, optional): Enable/Disable SSL VPN
            vpn_portal (str, optional): Enable/Disable VPN Portal
            web_proxy (str, optional): Enable/Disable Web proxy
            wireless_protection (str, optional): Enable/Disable wireless protection
            user_portal (str, optional): Enable/Disable user portal
            dynamic_routing (str, optional): Enable/Disable dynamic routing
            smtp_relay (str, optional): Enable/Disable SMTP Relay
            snmp (str, optional): Enable/Disable SNMP
        
        Returns:
            dict: XML response converted to Python dictionary
        """
        zone_params["name"] = name
        zone_params["zone_type"] = zone_type
        resp = self.client.submit_template(
            "createzone.j2", template_vars=zone_params, debug=debug
        )
        return resp
    
    def update(self, name: str, zone_params: dict = None, debug: bool = False):
        """Update a zone.

        Args:
            name (str): Name of the Zone
            zone_params (dict): Configuration parmeters for the zone, see Keyword Args for supported parameters.

        Keyword Args:
            description (str, optional): Description for the Zone
            https (str, optional): Enable/Disable HTTPS administrative service
            ssh (str, optional): Enable/Disable SSH administrative service
            client_authen (str, optional): Enable/Disable client authentication service
            captive_portal (str, optional): Enable/Disable captive portal
            ad_sso (str, optional): Enable/Disable SSO with Active Directory
            radius_sso (str, optional): Enable/Disable SSO with Radius
            chromebook_sso (str, optional): Enable/Disable Chromebook SSO
            dns (str, optional): Enable/Disable DNS
            ping (str, optional): Enable/Disable ping
            ipsec (str, optional): Enable/Disable ipsec
            red (str, optional): Enable/Disable RED
            sslvpn (str, optional): Enable/Disable SSL VPN
            vpn_portal (str, optional): Enable/Disable VPN Portal
            web_proxy (str, optional): Enable/Disable Web proxy
            wireless_protection (str, optional): Enable/Disable wireless protection
            user_portal (str, optional): Enable/Disable user portal
            dynamic_routing (str, optional): Enable/Disable dynamic routing
            smtp_relay (str, optional): Enable/Disable SMTP Relay
            snmp (str, optional): Enable/Disable SNMP
        
        Returns:
            dict: XML response converted to Python dictionary
        """
        exist_zone = self.get(name=name)["Response"]["Zone"]
        updated_zone_params=dict(name=name, zone_type=exist_zone["Type"])

        if zone_params.get("description"):
            updated_zone_params["description"] = zone_params.get("description")

        if zone_params.get("https"):
            updated_zone_params["https"] = zone_params.get("https")
        else:
            updated_zone_params["https"] = self.check_exists(exist_zone, "AdminServices", "HTTPS")

        if zone_params.get("ssh"):
            updated_zone_params["ssh"] = zone_params.get("ssh")
        else:
            updated_zone_params["ssh"] = self.check_exists(exist_zone, "AdminServices", "SSH")

        if zone_params.get("client_authen"):
            updated_zone_params["client_authen"] = zone_params.get("client_authen")
        else:
            updated_zone_params["client_authen"] = self.check_exists(exist_zone, "AuthenticationServices", "ClientAuthentication")

        if zone_params.get("captive_portal"):
            updated_zone_params["captive_portal"] = zone_params.get("captive_portal")
        else:
            updated_zone_params["captive_portal"] = self.check_exists(exist_zone, "AuthenticationServices", "CaptivePortal")

        if zone_params.get("ad_sso"):
            updated_zone_params["ad_sso"] = zone_params.get("ad_sso")
        else:
            updated_zone_params["ad_sso"] = self.check_exists(exist_zone, "AuthenticationServices", "ADSSO")

        if zone_params.get("radius_sso"):
            updated_zone_params["radius_sso"] = zone_params.get("radius_sso")
        else:
            updated_zone_params["radius_sso"] = self.check_exists(exist_zone, "AuthenticationServices", "RadiusSSO")

        if zone_params.get("chromebook_sso"):
            updated_zone_params["chromebook_sso"] = zone_params.get("chromebook_sso")
        else:
            updated_zone_params["chromebook_sso"] = self.check_exists(exist_zone, "AuthenticationServices", "ChromebookSSO")

        if zone_params.get("dns"):
            updated_zone_params["dns"] = zone_params.get("dns")
        else:
            updated_zone_params["dns"] = self.check_exists(exist_zone, "NetworkServices", "DNS")

        if zone_params.get("ping"):
            updated_zone_params["ping"] = zone_params.get("ping")
        else:
            updated_zone_params["ping"] = self.check_exists(exist_zone, "NetworkServices", "Ping")

        if zone_params.get("ipsec"):
            updated_zone_params["ipsec"] = zone_params.get("ipsec")
        else:
            updated_zone_params["ipsec"] = self.check_exists(exist_zone, "VPNServices", "IPsec")

        if zone_params.get("red"):
            updated_zone_params["red"] = zone_params.get("red")
        else:
            updated_zone_params["red"] = self.check_exists(exist_zone, "VPNServices", "RED")

        if zone_params.get("sslvpn"):
            updated_zone_params["sslvpn"] = zone_params.get("sslvpn")
        else:
            updated_zone_params["sslvpn"] = self.check_exists(exist_zone, "VPNServices", "SSLVPN")

        if zone_params.get("vpn_portal"):
            updated_zone_params["vpn_portal"] = zone_params.get("vpn_portal")
        else:
            updated_zone_params["vpn_portal"] = self.check_exists(exist_zone, "VPNServices", "VPNPortal")

        if zone_params.get("web_proxy"):
            updated_zone_params["web_proxy"] = zone_params.get("web_proxy")
        else:
            updated_zone_params["web_proxy"] = self.check_exists(exist_zone, "OtherServices", "WebProxy")

        if zone_params.get("wireless_protection"):
            updated_zone_params["wireless_protection"] = zone_params.get("wireless_protection")
        else:
            updated_zone_params["wireless_protection"] = self.check_exists(exist_zone, "OtherServices", "WirelessProtection")

        if zone_params.get("user_portal"):
            updated_zone_params["user_portal"] = zone_params.get("user_portal")
        else:
            updated_zone_params["user_portal"] = self.check_exists(exist_zone, "OtherServices", "UserPortal")

        if zone_params.get("dynamic_routing"):
            updated_zone_params["dynamic_routing"] = zone_params.get("dynamic_routing")
        else:
            updated_zone_params["dynamic_routing"] = self.check_exists(exist_zone, "OtherServices", "DynamicRouting")

        if zone_params.get("smtp_relay"):
            updated_zone_params["smtp_relay"] = zone_params.get("smtp_relay")
        else:
            updated_zone_params["smtp_relay"] = self.check_exists(exist_zone, "OtherServices", "SMTPRelay")

        if zone_params.get("snmp"):
            updated_zone_params["snmp"] = zone_params.get("snmp")
        else:
            updated_zone_params["snmp"] = self.check_exists(exist_zone, "OtherServices", "SNMP")

        resp = self.client.submit_template(
            "updatezone.j2", template_vars=updated_zone_params, debug=debug
        )
        return resp

    def check_exists(self, existing_dict, container, key):
        """Search API response to get current value for key.

        Args:
            existing_dict (dict): The response from getting the current settings
            container (str): The top-level container to begin searching
            key (str): The key to search for, and if found return the value

        Returns:
            str: Returns the value of the key or None
        """
        if "ApplianceAccess" in existing_dict:
            if container in existing_dict["ApplianceAccess"]:
                if key in existing_dict["ApplianceAccess"][container]:
                    return existing_dict["ApplianceAccess"][container][key]
        return None