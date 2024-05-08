"""
firewallapi.py - Module for working with the Sophos Firewall API

Copyright 2023 Sophos Ltd.  All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing
permissions and limitations under the License.
"""

import os
import re
from ipaddress import IPv4Network, IPv4Address
import requests
import xmltodict
import urllib3
from jinja2 import Environment, FileSystemLoader


urllib3.disable_warnings()


class SophosFirewallIPAddressingError(Exception):
    """Error raised when invalid IP address detected"""


class SophosFirewallAuthFailure(Exception):
    """Error raised when authentication to firewall fails"""


class SophosFirewallAPIError(Exception):
    """Error raised when an API operation fails"""


class SophosFirewallZeroRecords(Exception):
    """Error raised when a get request returns zero records"""


class SophosFirewallOperatorError(Exception):
    """Error raised when an invalid operator is specified"""


class SophosFirewallInvalidArgument(Exception):
    """Error raised when an invalid argument is specified"""


class SophosFirewall:
    """Class used for interacting with the Sophos Firewall XML API"""

    def __init__(self, username, password, hostname, port, verify=True):
        self.username = username
        self.password = password
        self.hostname = hostname
        self.port = port
        self.url = f"https://{hostname}:{port}/webconsole/APIController"
        self.verify = verify

    # INTERNAL UTILITY CLASS METHODS

    def _validate_ip_network(self, ip_subnet, mask):
        """Validate IP network and mask

        Args:
            ip_subnet (str): IP network address
            mask (str): Subnet mask

        Raises:
            SophosFirewallIPAddressingError: Custom error class
        """
        try:
            IPv4Network(f"{ip_subnet}/{mask}")
        except Exception as exc:
            raise SophosFirewallIPAddressingError(
                f"Invalid network or mask provided - {ip_subnet}/{mask}"
            ) from exc

    def _validate_ip_address(self, ip_address):
        """Validate IP network and mask

        Args:
            ip_subnet (str): IP network address
            mask (str): Subnet mask

        Raises:
            SophosFirewallIPAddressingError: Custom error class
        """
        try:
            IPv4Address(ip_address)
        except Exception as exc:
            raise SophosFirewallIPAddressingError(
                f"Invalid IP address provided - {ip_address}"
            ) from exc

    def _post(self, xmldata: str) -> requests.Response:
        """Post XML request to the firewall returning response as a dict object

        Args:
            xmldata (str): XML payload
            verify (bool):  SSL certificate verification. Default=True.

        Returns:
            requests.Response object
        """
        headers = {"Accept": "application/xml"}
        resp = requests.post(
            self.url,
            headers=headers,
            data={"reqxml": xmldata},
            verify=self.verify,
            timeout=30,
        )

        resp_dict = xmltodict.parse(resp.content.decode())["Response"]
        if "Status" in resp_dict:
            if resp_dict["Status"]["@code"] == "534":
                # IP not allowed in API Access List
                raise SophosFirewallAPIError(resp_dict["Status"]["#text"])

            if resp_dict["Status"]["@code"] == "532":
                # API access not enabled
                raise SophosFirewallAPIError(resp_dict["Status"]["#text"])

        if "Login" in resp_dict:
            if resp_dict["Login"]["status"] == "Authentication Failure":
                raise SophosFirewallAuthFailure("Login failed!")
        return resp

    def _validate_arg(self, arg_name, arg_value, valid_choices):
        if not arg_value in valid_choices:
            raise SophosFirewallInvalidArgument(
                f"Invalid choice for {arg_name} argument, valid choices are {valid_choices}"
            )

    def submit_template(
        self,
        filename: str,
        template_vars: dict,
        template_dir: str = None,
        debug: bool = False,
    ) -> dict:
        """Submits XML payload stored as a Jinja2 file

        Args:
            filename (str): Jinja2 template filename. Place in "templates" directory or configure template_dir.
            template_vars (dict): Dictionary of variables to inject into the template. Username and password are passed in by default.
            template_dir (str): Directory to look for templates. Default is "./templates".
            debug (bool, optional): Enable debug mode to display XML payload. Defaults to False.

        Returns:
            dict
        """
        if not template_dir:
            template_dir = os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "templates"
            )
        environment = Environment(
            trim_blocks=True,
            lstrip_blocks=True,
            loader=FileSystemLoader(template_dir),
            autoescape=True,
        )
        template = environment.get_template(filename)
        template_vars["username"] = self.username
        template_vars["password"] = self.password
        payload = template.render(**template_vars)
        if debug:
            print(f"REQUEST: {payload}")
        resp = self._post(xmldata=payload)

        resp_dict = xmltodict.parse(resp.content.decode())["Response"]
        success_pattern = "2[0-9][0-9]"
        for key in resp_dict:
            if "Status" in resp_dict[key]:
                if not re.search(success_pattern, resp_dict[key]["Status"]["@code"]):
                    raise SophosFirewallAPIError(resp_dict[key])
        return xmltodict.parse(resp.content.decode())

    def login(self, output_format: str = "dict"):
        """Test login credentials.

        Args:
            output_format(str): Output format. Valid options are "dict" or "xml". Defaults to dict.
        """
        payload = f"""
        <Request>
            <Login>
                <Username>{self.username}</Username>
                <Password>{self.password}</Password>
            </Login>
        </Request>
        """
        resp = self._post(xmldata=payload)
        if output_format == "xml":
            return resp.content.decode()
        return xmltodict.parse(resp.content.decode())

    def get_tag(self, xml_tag: str, output_format: str = "dict"):
        """Execute a get for a specified XML tag.

        Args:
            xml_tag (str): XML tag for the request
            output_format(str): Output format. Valid options are "dict" or "xml". Defaults to dict.
        """
        payload = f"""
        <Request>
            <Login>
                <Username>{self.username}</Username>
                <Password>{self.password}</Password>
            </Login>
            <Get>
                <{xml_tag}>
                </{xml_tag}>
            </Get>
        </Request>
        """
        resp = self._post(xmldata=payload)
        self._error_check(resp, xml_tag)
        if output_format == "xml":
            return resp.content.decode()
        return xmltodict.parse(resp.content.decode())

    def get_tag_with_filter(
        self,
        xml_tag: str,
        key: str,
        value: str,
        operator: str = "like",
        output_format: str = dict,
    ):
        """Execute a get for a specified XML tag with filter criteria.

        Args:
            xml_tag (str): XML tag for the request.
            key (str): Search key
            value (str): Search value
            operator (str, optional): Operator for search (“=”,”!=”,”like”). Defaults to "like".
            output_format(str): Output format. Valid options are "dict" or "xml". Defaults to dict.
        """
        valid_operators = ["=", "!=", "like"]
        if operator not in valid_operators:
            raise SophosFirewallOperatorError(
                f"Invalid operator '{operator}'!  Supported operators: [ {', '.join(valid_operators)} ]"
            )
        payload = f"""
        <Request>
            <Login>
                <Username>{self.username}</Username>
                <Password>{self.password}</Password>
            </Login>
            <Get>
                <{xml_tag}>
                    <Filter>
                        <key name="{key}" criteria="{operator}">{value}</key>
                    </Filter>
                </{xml_tag}>
            </Get>
        </Request>
        """
        resp = self._post(xmldata=payload)
        self._error_check(resp, xml_tag)
        if output_format == "xml":
            return resp.content.decode()
        return xmltodict.parse(resp.content.decode())

    def remove(self, xml_tag: str, name: str, output_format: str = "dict"):
        """Remove an object from the firewall.

        Args:
            xml_tag (str): The XML tag indicating the type of object to be removed.
            name (str): The name of the object to be removed.
            output_format (str): Output format. Valid options are "dict" or "xml". Defaults to dict.
        """
        payload = f"""
        <Request>
            <Login>
                <Username>{self.username}</Username>
                <Password>{self.password}</Password>
            </Login>
            <Remove>
              <{xml_tag}>
                <Name>{name}</Name>
              </{xml_tag}>
            </Remove>
        </Request>
        """
        resp = self._post(xmldata=payload)
        self._error_check(resp, xml_tag)
        if output_format == "xml":
            return resp.content.decode()
        return xmltodict.parse(resp.content.decode())

    def update(
        self,
        xml_tag: str,
        update_params: dict,
        name: str = None,
        output_format: str = "dict",
        debug: bool = False
    ):
        """Update an existing object on the firewall.

        Args:
            xml_tag (str): The XML tag indicating the type of object to be updated.
            update_params (dict): Keys/values to be updated. Keys must match an existing XML key.
            name (str, optional): The name of the object to be updated, if applicable.
            output_format(str): Output format. Valid options are "dict" or "xml". Defaults to dict.
            debug (bool): Displays the XML payload that was submitted 
        """
        if name:
            resp = self.get_tag_with_filter(
                xml_tag=xml_tag, key="Name", value=name, operator="="
            )
        else:
            resp = self.get_tag(xml_tag=xml_tag)

        for key in update_params:
            resp["Response"][xml_tag][key] = update_params[key]

        update_body = {}
        update_body[xml_tag] = resp["Response"][xml_tag]
        xml_update_body = xmltodict.unparse(update_body, pretty=True).lstrip(
            '<?xml version="1.0" encoding="utf-8"?>'
        )
        payload = f"""
        <Request>
            <Login>
                <Username>{self.username}</Username>
                <Password>{self.password}</Password>
            </Login>
            <Set operation="update"> 
                {xml_update_body}
            </Set>
        </Request>
        """
        if debug:
            print(payload)
        resp = self._post(xmldata=payload)
        self._error_check(resp, xml_tag)
        if output_format == "xml":
            return resp.content.decode()
        return xmltodict.parse(resp.content.decode())

    def _dict_to_lower(self, target_dict):
        """Convert the keys of a dictionary to lower-case

        Args:
            target_dict (dict): Dictionary to be converted

        Returns:
            dict: Dictionary with all keys converted to lower case
        """
        return {key.lower(): val for key, val in target_dict.items()}

    def _error_check(self, api_response, xml_tag):
        """Check for errors in the API response and raise exception if present

        Args:
            api_response (Requests.response): The response object returned from the requests module
            xml_tag (str): The XML tag being operated on

        Raises:
            SophosFirewallZeroRecords: Error raised when there are no records matching the request parameters
            SophosFirewallAPIError: Error raised when there is a problem with the request parameters
        """
        response = xmltodict.parse(api_response.content.decode())["Response"]
        lower_response = self._dict_to_lower(response)
        if xml_tag.lower() in lower_response:
            resp_dict = lower_response[xml_tag.lower()]
            if "Status" in resp_dict:
                if (
                    resp_dict["Status"] == "Number of records Zero."
                    or resp_dict["Status"] == "No. of records Zero."
                ):
                    raise SophosFirewallZeroRecords(resp_dict["Status"])
                if "@code" in resp_dict["Status"]:
                    if not resp_dict["Status"]["@code"].startswith("2"):
                        raise SophosFirewallAPIError(
                            f"{resp_dict['Status']['@code']}: {resp_dict['Status']['#text']}"
                        )
        else:
            raise SophosFirewallAPIError(
                str(xmltodict.parse(api_response.content.decode()))
            )

    # METHODS FOR OBJECT RETRIEVAL (GET)

    def get_fw_rule(self, name: str = None, operator: str = "="):
        """Get firewall rule(s)

        Args:
            name (str, optional): Firewall Rule name.  Returns all rules if not specified.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like.
            debug(bool, optional): Enable debug mode
        """
        if name:
            return self.get_tag_with_filter(
                xml_tag="FirewallRule", key="Name", value=name, operator=operator
            )
        return self.get_tag(xml_tag="FirewallRule")

    def get_ip_host(
        self, name: str = None, ip_address: str = None, operator: str = "="
    ):
        """Get IP Host object(s)

        Args:
            name (str, optional): IP object name. Returns all objects if not specified.
            ip_address (str, optional): Query by IP Address.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like.
        """
        if name:
            return self.get_tag_with_filter(
                xml_tag="IPHost", key="Name", value=name, operator=operator
            )
        if ip_address:
            return self.get_tag_with_filter(
                xml_tag="IPHost",
                key="IPAddress",
                value=ip_address,
                operator=operator,
            )
        return self.get_tag(xml_tag="IPHost")

    def get_interface(self, name: str = None, operator: str = "="):
        """Get Interface object(s)

        Args:
            name (str, optional): Interface name. Returns all objects if not specified.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like.
        """
        if name:
            return self.get_tag_with_filter(
                xml_tag="Interface", key="Name", value=name, operator=operator
            )
        return self.get_tag(xml_tag="Interface")

    def get_vlan(self, name: str = None, operator: str = "="):
        """Get VLAN object(s)

        Args:
            name (str, optional): VLAN name. Returns all objects if not specified.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like.
        """
        if name:
            return self.get_tag_with_filter(
                xml_tag="VLAN", key="Name", value=name, operator=operator
            )
        return self.get_tag(xml_tag="VLAN")

    def get_ip_hostgroup(self, name: str = None, operator: str = "="):
        """Get IP hostgroup(s)

        Args:
            name (str, optional): Name of IP host group. Returns all if not specified.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like.
        """
        if name:
            return self.get_tag_with_filter(
                xml_tag="IPHostGroup",
                key="Name",
                value=name,
                operator=operator,
            )
        return self.get_tag(xml_tag="IPHostGroup")

    def get_fqdn_host(self, name: str = None, operator: str = "="):
        """Get FQDN object(s)

        Args:
            name (str, optional): FQDN object name. Returns all objects if not specified.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like.
        """
        if name:
            return self.get_tag_with_filter(
                xml_tag="FQDNHost", key="Name", value=name, operator=operator
            )
        return self.get_tag(xml_tag="FQDNHost")

    def get_acl_rule(self, name: str = None, operator: str = "="):
        """Get ACL rules

        Args:
            name (str, optional): Name of rule to retrieve. Returns all if not specified.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like.

        Returns:
            dict: XML response converted to Python dictionary
        """
        if name:
            return self.get_tag_with_filter(
                xml_tag="LocalServiceACL", key="Name", value=name, operator=operator
            )
        return self.get_tag(xml_tag="LocalServiceACL")

    def get_user(self, name: str = None, operator: str = "="):
        """Get local users

        Args:
            name (str, optional): Name of user. Retrieves all users if not specified.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like.

        Returns:
            dict: XML response converted to Python dictionary
        """
        if name:
            return self.get_tag_with_filter(
                xml_tag="User", key="Name", value=name, operator=operator
            )
        return self.get_tag(xml_tag="User")

    def get_admin_profile(self, name: str = None, operator: str = "="):
        """Get admin profiles

        Args:
            name (str, optional): Name of profile. Returns all if not specified.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like.

        Returns:
            dict: XML response converted to Python dictionary
        """
        if name:
            return self.get_tag_with_filter(
                xml_tag="AdministrationProfile",
                key="Name",
                value=name,
                operator=operator,
            )
        return self.get_tag(xml_tag="AdministrationProfile")

    def get_zone(self, name: str = None, operator: str = "="):
        """Get zone(s)

        Args:
            name (str, optional): Name of zone to query. Returns all if not specified.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like.

        Returns:
            dict: XML response converted to Python dictionary
        """
        if name:
            return self.get_tag_with_filter(
                xml_tag="Zone", key="Name", value=name, operator=operator
            )
        return self.get_tag(xml_tag="Zone")

    def get_admin_authen(self):
        """Get admin authentication settings

        Returns:
            dict: XML response converted to Python dictionary
        """
        return self.get_tag(xml_tag="AdminAuthentication")

    def get_ips_policy(self, name: str = None):
        """Get IPS policy

        Args:
            name (str, optional): Name of a policy to filter on. Returns all if not specified.

        Returns:
            dict: XML response converted to Python dictionary
        """
        if name:
            return self.get_tag_with_filter(xml_tag="IPSPolicy", key="Name", value=name)
        return self.get_tag(xml_tag="IPSPolicy")

    def get_syslog_server(self, name: str = None):
        """Get syslog server.

        Args:
            name (str, optional): Name of syslog server. Returns all if not specified.

        Returns:
            dict: XML response converted to Python dictionary
        """
        if name:
            return self.get_tag_with_filter(
                xml_tag="SyslogServers", key="Name", value=name
            )
        return self.get_tag(xml_tag="SyslogServers")

    def get_notification(self, name: str = None):
        """Get notification.

        Args:
            name (str, optional): Name of notification. Returns all if not specified.

        Returns:
            dict: XML response converted to Python dictionary
        """
        if name:
            return self.get_tag_with_filter(
                xml_tag="Notification", key="Name", value=name
            )
        return self.get_tag(xml_tag="Notification")

    def get_notification_list(self, name: str = None):
        """Get notification list.

        Args:
            name (str, optional): Name of notification list. Returns all if not specified.

        Returns:
            dict: XML response converted to Python dictionary
        """
        if name:
            return self.get_tag_with_filter(
                xml_tag="NotificationList", key="Name", value=name
            )
        return self.get_tag(xml_tag="NotificationList")

    def get_backup(self, name: str = None):
        """Get backup details.

        Args:
            name (str, optional): Name of backup schedule. Returns all if not specified.

        Returns:
            dict: XML response converted to Python dictionary
        """
        if name:
            return self.get_tag_with_filter(
                xml_tag="BackupRestore", key="Name", value=name
            )
        return self.get_tag(xml_tag="BackupRestore")

    def get_reports_retention(self, name: str = None):
        """Get Reports retention period.

        Args:
            name (str, optional): Name of backup schedule. Returns all if not specified.

        Returns:
            dict: XML response converted to Python dictionary
        """
        if name:
            return self.get_tag_with_filter(
                xml_tag="DataManagement", key="Name", value=name
            )
        return self.get_tag(xml_tag="DataManagement")

    def get_admin_settings(self):
        """Get Web Admin Settings (Administration > Settings)

        Returns:
            dict: XML response converted to Python dictionary
        """
        return self.get_tag(xml_tag="AdminSettings")

    def get_dns_forwarders(self):
        """Get DNS forwarders.

        Returns:
            dict: XML response converted to Python dictionary
        """
        return self.get_tag(xml_tag="DNS")

    def get_snmpv3_user(self):
        """Get SNMP v3 Users

        Returns:
            dict: XML response converted to Python dictionary
        """
        return self.get_tag(xml_tag="SNMPv3User")

    def get_urlgroup(self, name: str = None, operator: str = "="):
        """Get URLGroup(s)

        Args:
            name (str, optional): Get URLGroup by name. Defaults to None.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like.

        Returns:
            dict: XML response converted to Python dictionary
        """
        if name:
            return self.get_tag_with_filter(
                xml_tag="WebFilterURLGroup", key="Name", operator=operator, value=name
            )
        return self.get_tag(xml_tag="WebFilterURLGroup")

    def get_service(
        self,
        name: str = None,
        operator: str = "=",
        dst_proto: str = None,
        dst_port: str = None,
    ):
        """Get Service(s)

        Args:
            name (str, optional): Get Service by name. Defaults to None.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like.
            dst_proto(str, optional): Specify TCP or UDP
            dst_port(str, optional): Specify dest TCP or UDP port. Use : to specify ranges (ex. 67:68)

        Returns:
            dict: XML response converted to Python dictionary
        """
        if name:
            return self.get_tag_with_filter(
                xml_tag="Services", key="Name", value=name, operator=operator
            )
        if dst_proto and dst_port:
            resp = self.get_tag(xml_tag="Services")
            svc_list = resp["Response"]["Services"].copy()
            for svc in svc_list:
                matched = False
                if isinstance(svc["ServiceDetails"]["ServiceDetail"], dict):
                    port = svc["ServiceDetails"]["ServiceDetail"].get("DestinationPort")
                    if "Protocol" in svc["ServiceDetails"]["ServiceDetail"]:
                        proto = svc["ServiceDetails"]["ServiceDetail"]["Protocol"]
                    if "ProtocolName" in svc["ServiceDetails"]["ServiceDetail"]:
                        proto = svc["ServiceDetails"]["ServiceDetail"]["ProtocolName"]
                    if proto == dst_proto.upper() and port == dst_port:
                        matched = True
                elif isinstance(svc["ServiceDetails"]["ServiceDetail"], list):
                    for subsvc in svc["ServiceDetails"]["ServiceDetail"]:
                        port = subsvc.get("DestinationPort")
                        if "Protocol" in subsvc:
                            proto = subsvc["Protocol"]
                        if "ProtocolName" in subsvc:
                            proto = subsvc["ProtocolName"]
                        if proto == dst_proto.upper() and port == dst_port:
                            matched = True
                if not matched:
                    resp["Response"]["Services"].remove(svc)
            return resp
        return self.get_tag(xml_tag="Services")

    # METHODS FOR OBJECT CREATION

    def create_rule(self, rule_params: dict, debug: bool = False):
        """Create a firewall rule

        Args:
            rule_params (dict): Configuration parmeters for the rule, see Keyword Args for supported parameters.

        Keyword Args:
            rulename(str): Name of the firewall rule
            after_rulename(str): Name of the rule to insert this rule after
            action(str): Accept, Drop, Reject
            description(str): Rule description
            log(str): Enable, Disable
            src_zones(list): Name(s) of the source zone(s)
            dst_zones(list): Name(s) of the destination zone(s)
            src_networks(list): Name(s) of the source network(s)
            dst_networks(list): Name(s) of the destination network(s)
            service_list(list): Name(s) of service(s)
        Returns:
            dict: XML response converted to Python dictionary
        """
        resp = self.submit_template(
            "createfwrule.j2", template_vars=rule_params, debug=debug
        )
        return resp

    def create_ip_network(
        self,
        name: str,
        ip_network: str,
        mask: str,
        debug: bool = False,
    ):
        """Create IP address object

        Args:
            name (str): Name of the object
            ip_network (str): IP network address
            mask (str): Subnet mask
            debug (bool, optional): Turn on debugging. Defaults to False.
        Returns:
            dict: XML response converted to Python dictionary
        """
        self._validate_ip_network(ip_network, mask)

        params = {"name": name, "ip_network": ip_network, "mask": mask}
        resp = self.submit_template(
            "createipnetwork.j2", template_vars=params, debug=debug
        )
        return resp

    def create_ip_host(self, name: str, ip_address: str, debug: bool = False):
        """Create IP address object

        Args:
            name (str): Name of the object
            ip_address (str): Host IP address
            debug (bool, optional): Turn on debugging. Defaults to False.
        Returns:
            dict: XML response converted to Python dictionary
        """
        self._validate_ip_address(ip_address)

        params = {"name": name, "ip_address": ip_address}
        resp = self.submit_template(
            "createiphost.j2", template_vars=params, debug=debug
        )
        return resp

    def create_ip_range(
        self,
        name: str,
        start_ip: str,
        end_ip: str,
        debug: bool = False,
    ):
        """Create IP range object

        Args:
            name (str): Name of the object
            start_ip (str): Starting IP address
            end_ip (str): Ending IP address
            debug (bool, optional): Turn on debugging. Defaults to False.
        Returns:
            dict: XML response converted to Python dictionary
        """
        self._validate_ip_address(start_ip)
        self._validate_ip_address(end_ip)

        params = {"name": name, "start_ip": start_ip, "end_ip": end_ip}
        resp = self.submit_template(
            "createiprange.j2", template_vars=params, debug=debug
        )
        return resp

    def create_service(
        self,
        name: str,
        service_list: list[dict],
        debug: bool = False,
    ):
        """Create a TCP or UDP service

        Args:
        name (str): Service name
        service_list(list): List of dictionaries containing the below keys for each port/proto pair
            src_port (str, optional): Source TCP/UDP port. Default=1:65535.
            dst_port (str): Destination TCP/UDP port
            protocol (str): TCP or UDP
        debug (bool, optional): Enable debug mode. Defaults to False.
        Returns:
            dict: XML response converted to Python dictionary
        """
        params = {"name": name, "service_list": service_list}
        resp = self.submit_template(
            "createservice.j2", template_vars=params, debug=debug
        )
        return resp

    def create_ip_hostgroup(
        self,
        name: str,
        description: str,
        host_list: list,
        debug: bool = False,
    ):
        """Create an IP Host Group

        Args:
            name (str): IP Host Group name
            description (str): Host Group description
            host_list (list): List of existing IP hosts to add to the group
            debug (bool, optional): Enable debug mode. Defaults to False.
        Returns:
            dict: XML response converted to Python dictionary
        """
        params = {"name": name, "description": description, "host_list": host_list}
        resp = self.submit_template(
            "createiphostgroup.j2", template_vars=params, debug=debug
        )
        return resp

    def create_urlgroup(self, name: str, domain_list: list, debug: bool = False):
        """Create a web URL Group

        Args:
            name (str): URL Group name.
            domain_list (list): List of domains to added/removed/replaced.
            debug (bool, optional): Enable debug mode. Defaults to False.

        Returns:
            dict: XML response converted to Python dictionary
        """
        params = {"name": name, "domain_list": domain_list}
        resp = self.submit_template(
            "createurlgroup.j2", template_vars=params, debug=debug
        )
        return resp

    def create_user(self, debug: bool = False, **kwargs):
        """Create a User

        Args:
            debug: (bool, optional): Enable debug mode. Defaults to False.

        Keyword Args:
            user (str): Username
            name (str): User Display Name
            description (str): User description
            user_password (str): User password
            user_type (str): User Type (Administrator/User)
            profile (str): Profile name
            group (str): Group name
            email (str): User email address
            access_time_policy (str, optional): Access time policy
            sslvpn_policy (str, optional): SSL VPN policy
            clientless_policy (str, optional): Clientless policy
            l2tp (str, optional): L2TP Enable/Disable
            pptp (str, optional): PPTP Enable/Disable
            cisco (str, optional): CISCO Enable/Disable
            quarantine_digest (str, optional): Quarantine Digest Enable/Disable
            mac_binding (str, optional): MAC binding Enable/Disable
            login_restriction (str, optional): Login restriction. Default = UserGroupNode.
            isencryptcert (str, optional): Enable/Disable. Default = Disable.
            simultaneous_logins (str, optional): Enable/Disable simultaneous login.
            surfingquota_policy (str, optional): Surfing quota policy. Default = Unlimited.
            applianceaccess_schedule (str, optional): Schedule for appliance access.  Default = All The Time.
            login_restriction (str, optional): Login restriction for appliance. Default = AnyNode.

        Returns:
            dict: XML response converted to Python dictionary
        """

        resp = self.submit_template("createuser.j2", template_vars=kwargs, debug=debug)
        return resp

    def update_user_password(
        self, username: str, new_password: str, debug: bool = False
    ):
        """Update user password.

        Args:
            username (str): Username
            new_password (str): New password. Must meet complexity requirements.
            debug (bool, optional): Enable debug mode. Defaults to False.

        Returns:
            dict: XML response converted to Python dictionary
        """
        # Get the existing user
        resp = self.get_user(name=username)
        user_params = resp["Response"]["User"]
        user_params["Password"] = new_password
        user_params.pop("PasswordHash")

        # Update the user
        resp = self.submit_template(
            "updateuserpassword.j2", template_vars=user_params, debug=debug
        )
        return resp

    def update_admin_password(
        self, current_password: str, new_password: str, debug: bool = False
    ):
        """Update the admin password.

        Args:
            current_password (str): Current admin password.
            new_password (str): New admin password. Must meet complexity requirements.
            debug (bool, optional): Enable debug mode. Defaults to False.

        Returns:
            dict: XML response converted to Python dictionary
        """
        params = {"current_password": current_password, "new_password": new_password}

        resp = self.submit_template(
            "updateadminpassword.j2", template_vars=params, debug=debug
        )
        return resp

    def update_urlgroup(
        self, name: str, domain_list: list, action: str = "add", debug: bool = False
    ):
        """Add or remove a specified domain to/from a web URL Group

        Args:
            name (str): URL Group name.
            domain_list (list): List of domains to added/removed/replaced.
            action (str): Options are 'add', 'remove' or 'replace'. Defaults to 'add'.
            debug (bool, optional): Enable debug mode. Defaults to False.

        Returns:
            dict: XML response converted to Python dictionary
        """
        if not isinstance(domain_list, list):
            raise SophosFirewallInvalidArgument(
                "The update_urlgroup() argument `domain_list` must be of type list!"
            )

        if action:
            self._validate_arg(
                arg_name="action",
                arg_value=action,
                valid_choices=["add", "remove", "replace"],
            )

        # Get the existing URL list first, if any
        resp = self.get_urlgroup(name=name)
        if "URLlist" in resp["Response"]["WebFilterURLGroup"]:
            exist_list = (
                resp.get("Response").get("WebFilterURLGroup").get("URLlist").get("URL")
            )
        else:
            exist_list = None
        if action == "replace":
            exist_list = None
        new_domain_list = []
        if exist_list:
            if isinstance(exist_list, str):
                new_domain_list.append(exist_list)
            elif isinstance(exist_list, list):
                for domain in exist_list:
                    new_domain_list.append(domain)
        for domain in domain_list:
            if action.lower() == "add" and domain not in new_domain_list:
                new_domain_list.append(domain)
            elif action.lower() == "remove" and domain in new_domain_list:
                new_domain_list.remove(domain)
            elif action.lower() == "replace":
                new_domain_list.append(domain)

        params = {"name": name, "domain_list": new_domain_list}
        resp = self.submit_template(
            "updateurlgroup.j2", template_vars=params, debug=debug
        )
        return resp

    def update_service(
        self, name: str, service_list: list[dict], action: str = "add", debug: bool = False
    ):
        """Add or remove a service entry to/from a service

        Args:
            name (str): Service name.
            service_list (list[dict]): List of dicts containing port/protocol pairs to be added or removed.
              src_port(str, optional): Source TCP/UDP port range. Default=1:65535.
              dst_port(str): Destination TCP/UDP port range.
              protocol(str): TCP or UDP
            action (str): Options are 'add', 'remove' or 'replace'. Defaults to 'add'.
            debug (bool, optional): Enable debug mode. Defaults to False.

        Returns:
            dict: XML response converted to Python dictionary
        """
        if not isinstance(service_list, list):
            raise SophosFirewallInvalidArgument(
                "The update_service() argument `service_list` must be of type list!"
            )

        if action:
            self._validate_arg(
                arg_name="action",
                arg_value=action,
                valid_choices=["add", "remove", "replace"],
            )

        # Get the existing Service list first
        resp = self.get_service(name=name)
        if "ServiceDetail" in resp["Response"]["Services"]["ServiceDetails"]:
            exist_list = (
                resp.get("Response").get("Services").get("ServiceDetails").get("ServiceDetail")
            )
        else:
            exist_list = None

        # Add src_port to input if not present
        for service in service_list:
            if not "src_port" in service:
                service["src_port"] = "1:65535"
        if action == "replace":
            exist_list = None
        new_service_list = []
        if exist_list:
            if isinstance(exist_list, dict):
                new_service_list.append({"src_port": exist_list["SourcePort"],
                                         "dst_port": exist_list["DestinationPort"],
                                         "protocol": exist_list["Protocol"]})
            elif isinstance(exist_list, list):
                for service in exist_list:
                    new_service_list.append({"src_port": service["SourcePort"],
                                             "dst_port": service["DestinationPort"],
                                             "protocol": service["Protocol"]})
        for service in service_list:
            if action.lower() == "add" and service not in new_service_list:
                new_service_list.append(service)
            elif action.lower() == "remove" and service in new_service_list:
                new_service_list.remove(service)
            elif action.lower() == "replace":
                new_service_list.append(service)

        params = {"name": name, "service_list": new_service_list}
        resp = self.submit_template(
            "updateservice.j2", template_vars=params, debug=debug
        )
        return resp

    def update_ip_hostgroup(
        self,
        name: str,
        host_list: list,
        description: str = None,
        action: str = "add",
        debug: bool = False,
    ):
        """Add or remove a specified domain to/from a web URL Group

        Args:
            name (str): IP Host Group name.
            description (str): IP Host Group description.
            host_list (str): List of IP Hosts to be added to or removed from the Host List.
            action (str): Options are 'add', 'remove' or 'replace'. Specify None to disable updating Host List. Defaults to 'add'.
            debug (bool, optional): Enable debug mode. Defaults to False.

        Returns:
            dict: XML response converted to Python dictionary
        """
        # Get the existing Host list first, if any

        if action:
            self._validate_arg(
                arg_name="action",
                arg_value=action,
                valid_choices=["add", "remove", "replace"],
            )

        resp = self.get_ip_hostgroup(name=name)
        if "HostList" in resp["Response"]["IPHostGroup"]:
            exist_list = (
                resp.get("Response").get("IPHostGroup").get("HostList").get("Host")
            )
        else:
            exist_list = None

        if action.lower() == "replace":
            exist_list = None

        new_host_list = []
        if exist_list:
            if isinstance(exist_list, str):
                new_host_list.append(exist_list)
            elif isinstance(exist_list, list):
                new_host_list = exist_list
        for ip_host in host_list:
            if action:
                if action.lower() == "add" and not ip_host in new_host_list:
                    new_host_list.append(ip_host)
                elif action.lower() == "remove" and ip_host in new_host_list:
                    new_host_list.remove(ip_host)
                elif action.lower() == "replace":
                    new_host_list.append(ip_host)
        if not description:
            description = resp.get("Response").get("IPHostGroup").get("Description")

        params = {"name": name, "description": description, "host_list": new_host_list}
        resp = self.submit_template(
            "updateiphostgroup.j2", template_vars=params, debug=debug
        )
        return resp

    def update_backup(self, backup_params: dict, debug: bool = False):
        """Updates scheduled backup settings

        Args:
            backup_params (dict): Dict containing backup settings
            debug (bool, optional): Enable debug mode. Defaults to False.

        Keyword Args:
            BackupMode (str): Backup mode (FTP/Mail/Local)
            BackupPrefix (str): Backup Prefix
            FTPServer (str, optional): FTP Server IP Address
            Username (str, optional): FTP Server username
            Password (str, optional): FTP Server password
            FtpPath (str, optional): FTP Server path
            EmailAddress (str): Email address
            BackupFrequency (str): Never/Daily/Weekly/Monthly
            Day (str): Day
            Hour (str): Hour
            Minute (str): Minute
            Date (str): Numeric representation of month
            EncryptionPassword (str, optional): Encryption password

        Returns:
            dict: XML response converted to Python dictionary
        """
        updated_params = {}
        current_params = self.get_backup()['Response']['BackupRestore']['ScheduleBackup']
        for param in current_params:
            if param in backup_params:
                updated_params[param] = backup_params[param]
            else:
                updated_params[param] = current_params[param]
            
        resp = self.submit_template(
            "updatebackup.j2", template_vars=updated_params, debug=debug
        )
        return resp

    def update_service_acl(
        self,
        host_list: list = None,
        service_list: list = None,
        action: str = "add",
        debug: bool = False,
    ):
        """Update Local Service ACL (System > Administration > Device Access > Local service ACL exception)

        Args:
            host_list (list, optional): List of network or host groups. Defaults to [].
            service_list (list, optional): List of services. Defaults to [].
            action (str, optional): Indicate 'add' or 'remove' from list. Default is 'add'.
            verify (bool, optional): SSL Certificate checking. Defaults to True.
            debug (bool, optional): Enable debug mode. Defaults to False.
        """
        if action:
            self._validate_arg(
                arg_name="action", arg_value=action, valid_choices=["add", "remove"]
            )
        resp = self.get_acl_rule()

        exist_hosts = resp["Response"]["LocalServiceACL"]["Hosts"]["Host"]
        exist_services = resp["Response"]["LocalServiceACL"]["Services"]["Service"]

        if not host_list:
            host_list = []
        if not service_list:
            service_list = []

        if action == "add":
            template_vars = {
                "host_list": exist_hosts + host_list,
                "service_list": exist_services + service_list,
            }
        elif action == "remove":
            for host in host_list:
                exist_hosts.remove(host)
            for service in service_list:
                exist_services.remove(service)
            template_vars = {"host_list": exist_hosts, "service_list": exist_services}
        resp = self.submit_template(
            "updateserviceacl.j2", template_vars=template_vars, debug=debug
        )

        return resp
