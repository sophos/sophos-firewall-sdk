"""firewallapi.py - Module for working with the Sophos Firewall API
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
    """Error raised when invalid IP address detected
    """

class SophosFirewallAuthFailure(Exception):
    """Error raised when authentication to firewall fails
    """

class SophosFirewallAPIError(Exception):
    """Error raised when an API operation fails
    """

class SophosFirewallZeroRecords(Exception):
    """Error raised when a get request returns zero records
    """

class SophosFirewallOperatorError(Exception):
    """Error raised when an invalid operator is specified
    """

class SophosFirewall:
    """Class used for interacting with the Sophos Firewall XML API
    """
    def __init__(self, username, password, hostname, port):
        self.username = username
        self.password = password
        self.hostname = hostname
        self.port = port
        self.url = f"https://{hostname}:{port}/webconsole/APIController"

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

    def _post(self, xmldata: str, verify: bool = True) -> requests.Response:
        """Post XML request to the firewall returning response as a dict object

        Args:
            xmldata (str): XML payload
            verify (bool):  SSL certificate verification. Default=True.

        Returns:
            requests.Response object
        """
        headers = {"Accept": "application/xml"}
        resp = requests.post(
            self.url, headers=headers, data={"reqxml": xmldata}, verify=verify, timeout=30
        )
        if (
            xmltodict.parse(resp.content.decode())["Response"]["Login"]["status"]
            == "Authentication Failure"
        ):
            raise SophosFirewallAuthFailure("Login failed!")
        return resp

    def submit_template(
        self,
        filename: str,
        template_vars: dict,
        template_dir: str = None,
        verify: bool = True,
        debug: bool = False,
    ) -> dict:
        """Submits XML payload stored as a Jinja2 file

        Args:
            filename (str): Jinja2 template filename (must be in a directory called "templates")
            template_vars (dict): Dictionary of variables to inject into the template. Username and password are passed in by default.
            verify (bool, optional): SSL certificate verification. Defaults to True.
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
            autoescape=True
        )
        template = environment.get_template(filename)
        template_vars["username"] = self.username
        template_vars["password"] = self.password
        payload = template.render(**template_vars)
        if debug:
            print(f"REQUEST: {payload}")
        resp = self._post(xmldata=payload, verify=verify)

        resp_dict = xmltodict.parse(resp.content.decode())["Response"]
        success_pattern = "2[0-9][0-9]"
        for key in resp_dict:
            if "Status" in resp_dict[key]:
                if not re.search(success_pattern, resp_dict[key]["Status"]["@code"]):
                    raise SophosFirewallAPIError(resp_dict[key])
        return xmltodict.parse(resp.content.decode())

    def get_tag(self, xml_tag: str, output_format: str = "dict", verify: bool = True):
        """Execute a get for a specified XML tag.

        Args:
            xml_tag (str): XML tag for the request
            output_format(str): Output format. Valid options are "dict" or "xml". Defaults to dict.
            verify (bool, optional): SSL certificate checking. Defaults to True.
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
        resp = self._post(xmldata=payload, verify=verify)
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
        verify: bool = True,
    ):
        """Execute a get for a specified XML tag with filter criteria.

        Args:
            xml_tag (str): XML tag for the request.
            key (str): Search key
            value (str): Search value
            operator (str, optional): Operator for search (“=”,”!=”,”like”). Defaults to "like".
            output_format(str): Output format. Valid options are "dict" or "xml". Defaults to dict.
            verify (bool): SSL certificate checking. Defaults to True.
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
        resp = self._post(xmldata=payload, verify=verify)
        self._error_check(resp, xml_tag)
        if output_format == "xml":
            return resp.content.decode()
        return xmltodict.parse(resp.content.decode())

    def _error_check(self, api_response, xml_tag):
        """Check for errors in the API response and raise exception if present

        Args:
            api_response (Requests.response): The response object returned from the requests module
            xml_tag (str): The XML tag being operated on

        Raises:
            SophosFirewallZeroRecords: Error raised when there are no records matching the request parameters
            SophosFirewallAPIError: Error raised when there is a problem with the request parameters
        """
        if xml_tag in xmltodict.parse(api_response.content.decode())["Response"]:
            resp_dict = xmltodict.parse(api_response.content.decode())["Response"][
                xml_tag
            ]
            if "Status" in resp_dict:
                if resp_dict["Status"] == "No. of records Zero.":
                    raise SophosFirewallZeroRecords(resp_dict["Status"])
        else:
            raise SophosFirewallAPIError(
                str(xmltodict.parse(api_response.content.decode()))
            )

    # METHODS FOR OBJECT RETRIEVAL (GET)

    def get_fw_rule(self, name: str = None, verify: bool = True):
        """Get firewall rule(s)

        Args:
            name (str, optional): Firewall Rule name.  Returns all rules if not specified.
            verify (bool, optional): SSL certificate checking. Defaults to True.
            debug(bool, optional): Enable debug mode
        """
        if name:
            return self.get_tag_with_filter(
                xml_tag="FirewallRule",
                key="Name",
                value=name,
                operator="=",
                verify=verify,
            )
        return self.get_tag(xml_tag="FirewallRule", verify=verify)

    def get_ip_host(
        self, name: str = None, ip_address: str = None, verify: bool = True
    ):
        """Get IP Host object(s)

        Args:
            name (str, optional): IP object name. Returns all objects if not specified.
            verify (bool, optional): SSL certificate checking. Defaults to True.
        """
        if name:
            return self.get_tag_with_filter(
                xml_tag="IPHost", key="Name", value=name, operator="=", verify=verify
            )
        if ip_address:
            return self.get_tag_with_filter(
                xml_tag="IPHost",
                key="IPAddress",
                value=ip_address,
                operator="=",
                verify=verify,
            )
        return self.get_tag(xml_tag="IPHost", verify=verify)

    def get_ip_hostgroup(self, name: str = None, verify: bool = True):
        """Get IP hostgroup(s)

        Args:
            name (str, optional): Name of IP host group. Returns all if not specified.
            verify (bool, optional): SSL certificate checking. Defaults to True.
        """
        if name:
            return self.get_tag_with_filter(
                xml_tag="IPHostGroup",
                key="Name",
                value=name,
                operator="=",
                verify=verify,
            )
        return self.get_tag(xml_tag="IPHostGroup", verify=verify)

    def get_fqdn_host(self, name: str = None, verify: bool = True):
        """Get FQDN object(s)

        Args:
            name (str, optional): FQDN object name. Returns all objects if not specified.
            verify (bool, optional): SSL certificate checking. Defaults to True.
        """
        if name:
            return self.get_tag_with_filter(
                xml_tag="FQDNHost", key="Name", value=name, operator="=", verify=verify
            )
        return self.get_tag(xml_tag="FQDNHost", verify=verify)

    def get_acl_rule(self, name: str = None, verify: bool = True):
        """Get ACL rules

        Args:
            name (str, optional): Name of rule to retrieve. Returns all if not specified.
            verify (bool, optional):  Toggle on/off SSL certificate check.

        Returns:
            dict: XML response converted to Python dictionary
        """
        if name:
            return self.get_tag_with_filter(
                xml_tag="LocalServiceACL",
                key="Name",
                value=name,
                operator="=",
                verify=verify,
            )
        return self.get_tag(xml_tag="LocalServiceACL", verify=verify)

    def get_user(self, name: str = None, verify: bool = True):
        """Get local users

        Args:
            name (str, optional): Name of user. Retrieves all users if not specified.
            verify (bool, optional):  Toggle on/off SSL certificate check.

        Returns:
            dict: XML response converted to Python dictionary
        """
        if name:
            return self.get_tag_with_filter(
                xml_tag="User", key="Name", value=name, operator="=", verify=verify
            )
        return self.get_tag(xml_tag="User", verify=verify)

    def get_admin_profile(self, name: str = None, verify: bool = True):
        """Get admin profiles

        Args:
            name (str, optional): Name of profile. Returns all if not specified.
            verify (bool, optional):  Toggle on/off SSL certificate check.

        Returns:
            dict: XML response converted to Python dictionary
        """
        if name:
            return self.get_tag_with_filter(
                xml_tag="AdministrationProfile",
                key="Name",
                value=name,
                operator="=",
                verify=verify,
            )
        return self.get_tag(xml_tag="AdministrationProfile", verify=verify)

    def get_zone(self, name: str = None, verify: bool = True):
        """Get zone(s)

        Args:
            name (str, optional): Name of zone to query. Returns all if not specified.
            verify (bool, optional):  Toggle on/off SSL certificate check.

        Returns:
            dict: XML response converted to Python dictionary
        """
        if name:
            return self.get_tag_with_filter(
                xml_tag="Zone", key="Name", value=name, operator="=", verify=verify
            )
        return self.get_tag(xml_tag="Zone", verify=False)

    def get_admin_authen(self, verify: bool = True):
        """Get admin authentication settings

        Args:
            verify (bool, optional):  Toggle on/off SSL certificate check.

        Returns:
            dict: XML response converted to Python dictionary
        """
        return self.get_tag(xml_tag="AdminAuthentication", verify=verify)

    def get_ips_policy(self, name: str = None, verify: bool = True):
        """Get IPS policy

        Args:
            name (str, optional): Name of a policy to filter on. Returns all if not specified.
            verify (bool, optional):  Toggle on/off SSL certificate check.

        Returns:
            dict: XML response converted to Python dictionary
        """
        if name:
            return self.get_tag_with_filter(
                xml_tag="IPSPolicy", key="Name", value=name, verify=verify
            )
        return self.get_tag(xml_tag="IPSPolicy", verify=verify)

    def get_syslog_server(self, name: str = None, verify: bool = True):
        """Get syslog server.

        Args:
            name (str, optional): Name of syslog server. Returns all if not specified.
            verify (bool, optional):  Toggle on/off SSL certificate check.

        Returns:
            dict: XML response converted to Python dictionary
        """
        if name:
            return self.get_tag_with_filter(
                xml_tag="SyslogServers", key="Name", value=name, verify=verify
            )
        return self.get_tag(xml_tag="SyslogServers", verify=verify)

    def get_notification(self, name: str = None, verify: bool = True):
        """Get notification.

        Args:
            name (str, optional): Name of notification. Returns all if not specified.
            verify (bool, optional):  Toggle on/off SSL certificate check.

        Returns:
            dict: XML response converted to Python dictionary
        """
        if name:
            return self.get_tag_with_filter(
                xml_tag="Notification", key="Name", value=name, verify=verify
            )
        return self.get_tag(xml_tag="Notification", verify=verify)

    def get_notification_list(self, name: str = None, verify: bool = True):
        """Get notification list.

        Args:
            name (str, optional): Name of notification list. Returns all if not specified.
            verify (bool, optional):  Toggle on/off SSL certificate check.

        Returns:
            dict: XML response converted to Python dictionary
        """
        if name:
            return self.get_tag_with_filter(
                xml_tag="NotificationList", key="Name", value=name, verify=verify
            )
        return self.get_tag(xml_tag="NotificationList", verify=verify)

    def get_backup(self, name: str = None, verify: bool = True):
        """Get backup details.

        Args:
            name (str, optional): Name of backup schedule. Returns all if not specified.
            verify (bool, optional):  Toggle on/off SSL certificate check.

        Returns:
            dict: XML response converted to Python dictionary
        """
        if name:
            return self.get_tag_with_filter(
                xml_tag="BackupRestore", key="Name", value=name, verify=verify
            )
        return self.get_tag(xml_tag="BackupRestore", verify=verify)

    def get_reports_retention(self, name: str = None, verify: bool = True):
        """Get Reports retention period.

        Args:
            name (str, optional): Name of backup schedule. Returns all if not specified.
            verify (bool, optional):  Toggle on/off SSL certificate check.

        Returns:
            dict: XML response converted to Python dictionary
        """
        if name:
            return self.get_tag_with_filter(
                xml_tag="DataManagement", key="Name", value=name, verify=verify
            )
        return self.get_tag(xml_tag="DataManagement", verify=verify)

    def get_admin_settings(self, verify: bool = True):
        """Get Web Admin Settings (Administration > Settings)

        Args:
            verify (bool, optional):  Toggle on/off SSL certificate check.

        Returns:
            dict: XML response converted to Python dictionary
        """
        return self.get_tag(xml_tag="AdminSettings", verify=verify)

    def get_dns_forwarders(self, verify: bool = True):
        """Get DNS forwarders.

        Args:
            verify (bool, optional):  Toggle on/off SSL certificate check.

        Returns:
            dict: XML response converted to Python dictionary
        """
        return self.get_tag(xml_tag="DNS", verify=verify)

    def get_snmpv3_user(self, verify: bool = True):
        """Get SNMP v3 Users

        Args:
            verify (bool, optional):  Toggle on/off SSL certificate check.

        Returns:
            dict: XML response converted to Python dictionary
        """
        return self.get_tag(xml_tag="SNMPv3User", verify=verify)

    def get_urlgroup(self, name: str = None, verify: bool = True):
        """Get URLGroup(s)

        Args:
            name (str, optional): Get URLGroup by name. Defaults to None.
            verify (bool, optional): Toggle on/off SSL certificate check. Defaults to True.

        Returns:
            dict: XML response converted to Python dictionary
        """
        if name:
            return self.get_tag_with_filter(
                xml_tag="WebFilterURLGroup", key="Name", value=name, verify=verify
            )
        return self.get_tag(xml_tag="WebFilterURLGroup", verify=verify)

    def get_service(
        self,
        name: str = None,
        dst_proto: str = None,
        dst_port: str = None,
        verify: bool = True,
    ):
        """Get Service(s)

        Args:
            name (str, optional): Get Service by name. Defaults to None.
            dst_proto(str, optional): Specify TCP or UDP
            dst_port(str, optional): Specify dest TCP or UDP port. Use : to specify ranges (ex. 67:68)
            verify (bool, optional): Toggle on/off SSL certificate check. Defaults to True.

        Returns:
            dict: XML response converted to Python dictionary
        """
        if name:
            return self.get_tag_with_filter(
                xml_tag="Services", key="Name", value=name, operator="=", verify=verify
            )
        if dst_proto and dst_port:
            resp = self.get_tag(xml_tag="Services", verify=verify)
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
        return self.get_tag(xml_tag="Services", verify=verify)

    # METHODS FOR OBJECT CREATION

    def create_rule(self, rule_params: dict, verify: bool = True, debug: bool = False):
        """Create a firewall rule

        Args:
            rule_params (dict): Configuration parmeters for the rule, see Keyword Args for supported parameters.
            verify (bool, optional): SSL certificate checking. Defaults to True.

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
            "createfwrule.j2", template_vars=rule_params, verify=verify, debug=debug
        )
        return resp

    def create_ip_network(
        self,
        name: str,
        ip_network: str,
        mask: str,
        verify: bool = True,
        debug: bool = False,
    ):
        """Create IP address object

        Args:
            name (str): Name of the object
            ip_network (str): IP network address
            mask (str): Subnet mask
            verify (bool, optional): SSL certificate checking. Defaults to True.
            debug (bool, optional): Turn on debugging. Defaults to False.
        Returns:
            dict: XML response converted to Python dictionary
        """
        self._validate_ip_network(ip_network, mask)

        params = {
                  "name": name, 
                  "ip_network": ip_network,
                  "mask": mask
                  }
        resp = self.submit_template(
            "createipnetwork.j2", template_vars=params, verify=verify, debug=debug
        )
        return resp

    def create_ip_host(
        self, name: str, ip_address: str, verify: bool = True, debug: bool = False
    ):
        """Create IP address object

        Args:
            name (str): Name of the object
            ip_address (str): Host IP address
            verify (bool, optional): SSL certificate checking. Defaults to True.
            debug (bool, optional): Turn on debugging. Defaults to False.
        Returns:
            dict: XML response converted to Python dictionary
        """
        self._validate_ip_address(ip_address)

        params = {
            "name": name,
            "ip_address": ip_address
        }
        resp = self.submit_template(
            "createiphost.j2", template_vars=params, verify=verify, debug=debug
        )
        return resp

    def create_ip_range(
        self,
        name: str,
        start_ip: str,
        end_ip: str,
        verify: bool = True,
        debug: bool = False,
    ):
        """Create IP range object

        Args:
            name (str): Name of the object
            start_ip (str): Starting IP address
            end_ip (str): Ending IP address
            verify (bool, optional): SSL certificate checking. Defaults to True.
            debug (bool, optional): Turn on debugging. Defaults to False.
        Returns:
            dict: XML response converted to Python dictionary
        """
        self._validate_ip_address(start_ip)
        self._validate_ip_address(end_ip)

        params = {
            "name": name,
            "start_ip": start_ip,
            "end_ip": end_ip
        }
        resp = self.submit_template(
            "createiprange.j2", template_vars=params, verify=verify, debug=debug
        )
        return resp

    def create_service(
        self,
        name: str,
        port: str,
        protocol: str,
        verify: bool = True,
        debug: bool = False,
    ):
        """Create a TCP or UDP service

        Args:
            name (str): Service name
            port (str): TCP/UDP port
            protocol (str): TCP or UDP
            verify (bool, optional): SSL certificate verification. Defaults to True.
            debug (bool, optional): Enable debug mode. Defaults to False.
        Returns:
            dict: XML response converted to Python dictionary
        """
        params = {
            "name": name,
            "port": port,
            "protocol": protocol
        }
        resp = self.submit_template(
            "createservice.j2", template_vars=params, verify=verify, debug=debug
        )
        return resp

    def create_hostgroup(
        self,
        name: str,
        description: str,
        host_list: list,
        verify: bool = True,
        debug: bool = False,
    ):
        """Create a Host Group

        Args:
            name (str): Host Group name
            description (str): Host Group description
            host_list (list): List of existing IP hosts to add to the group
            verify (bool, optional): SSL certificate verification. Defaults to True.
            debug (bool, optional): Enable debug mode. Defaults to False.
        Returns:
            dict: XML response converted to Python dictionary
        """
        params = {
            "name": name,
            "description": description,
            "host_list": host_list
        }
        resp = self.submit_template(
            "createhostgroup.j2", template_vars=params, verify=verify, debug=debug
        )
        return resp

    def update_urlgroup(
        self, name: str, domain: str, verify: bool = True, debug: bool = False
    ):
        """Adds a specified domain to a web URL Group

        Args:
            name (str): URL Group name
            domain (str): Domain to be added to URL Group
            verify (bool, optional): SSL certificate verification. Defaults to True.
            debug (bool, optional): Enable debug mode. Defaults to False.

        Returns:
            dict: XML response converted to Python dictionary
        """
        # Get the existing URL list first, if any
        resp = self.get_urlgroup(name=name, verify=verify)
        exist_list = (
            resp.get("Response").get("WebFilterURLGroup").get("URLlist").get("URL")
        )
        domain_list = []
        if exist_list:
            if isinstance(exist_list,str):
                domain_list.append(exist_list)
            elif isinstance(exist_list, list):
                domain_list = exist_list
        domain_list.append(domain)

        params = {
            "name": name,
            "domain_list": domain_list
        }
        resp = self.submit_template(
            "updateurlgroup.j2", template_vars=params, verify=verify, debug=debug
        )
        return resp
