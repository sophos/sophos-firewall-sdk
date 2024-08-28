"""
firewallapi.py - Module for working with the Sophos Firewall API

Copyright 2023 Sophos Ltd.  All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing
permissions and limitations under the License.
"""

import urllib3
from sophosfirewall_python.api_client import (
    APIClient,
    SophosFirewallZeroRecords,
    SophosFirewallInvalidArgument,
    SophosFirewallAPIError,
    SophosFirewallAuthFailure,
    SophosFirewallOperatorError
)
from sophosfirewall_python.firewallrule import FirewallRule
from sophosfirewall_python.host import (
    IPHost,
    IPHostGroup,
    FQDNHost,
    FQDNHostGroup,
    URLGroup,
    IPNetwork,
    IPRange,
)
from sophosfirewall_python.service import Service, ServiceGroup
from sophosfirewall_python.network import Interface, Vlan, Zone
from sophosfirewall_python.admin import AclRule, Notification
from sophosfirewall_python.authen import User, AdminAuthen
from sophosfirewall_python.profile import AdminProfile
from sophosfirewall_python.ips import IPS
from sophosfirewall_python.system import Syslog, NotificationList
from sophosfirewall_python.backup import Backup
from sophosfirewall_python.reports import Retention

urllib3.disable_warnings()

class SophosFirewall:
    """Class used for interacting with the Sophos Firewall XML API"""

    def __init__(self, username, password, hostname, port, verify=True):
        self.client = APIClient(
            username=username,
            password=password,
            hostname=hostname,
            port=port,
            verify=verify,
        )
        self.username = self.client.username
        self.password = self.client.password
        self.hostname = self.client.hostname
        self.port = self.client.port
        self.verify = self.client.verify

    def login(self, output_format: str = "dict"):
        """Test login credentials.

        Args:
            output_format(str): Output format. Valid options are "dict" or "xml". Defaults to dict.
        """
        return self.client.login(output_format)

    def get_tag(self, xml_tag: str, output_format: str = "dict"):
        """Execute a get for a specified XML tag.

        Args:
            xml_tag (str): XML tag for the request
            output_format(str): Output format. Valid options are "dict" or "xml". Defaults to dict.
        """
        return self.client.get_tag(xml_tag, output_format)
    
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
        return self.client.get_tag_with_filter(xml_tag, key, value, operator, output_format)

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
        return self.client.submit_template(filename, template_vars, template_dir, debug)

    def submit_xml(
        self,
        template_data: str,
        template_vars: dict = None,
        set_operation: str = "add",
        debug: bool = False,
    ) -> dict:
        """Submits XML payload as a string to the API. 
        Args:
            template_data (str): A string containing the XML payload. Variables can be optionally passed in the string using Jinja2 syntax (ex. {{ some_var }})
            template_vars (dict, optional): Dictionary of variables to inject into the XML string. 
            set_operation (str): Specify 'add' or 'update' set operation. Default is add. 

        Returns:
            dict
        """
        return self.client.submit_xml(template_data, template_vars, set_operation, debug)

    def remove(self, xml_tag: str, name: str, key: str = "Name", output_format: str = "dict"):
        """Remove an object from the firewall.

        Args:
            xml_tag (str): The XML tag indicating the type of object to be removed.
            name (str): The name of the object to be removed.
            key (str): The primary XML key that is used to look up the object. Defaults to Name.
            output_format (str): Output format. Valid options are "dict" or "xml". Defaults to dict.
        """
        return self.client.remove(xml_tag, name, key, output_format)

    def update(
        self,
        xml_tag: str,
        update_params: dict,
        name: str = None,
        output_format: str = "dict",
        debug: bool = False,
    ):
        """Update an existing object on the firewall.

        Args:
            xml_tag (str): The XML tag indicating the type of object to be updated.
            update_params (dict): Keys/values to be updated. Keys must match an existing XML key.
            name (str, optional): The name of the object to be updated, if applicable.
            output_format(str): Output format. Valid options are "dict" or "xml". Defaults to dict.
            debug (bool): Displays the XML payload that was submitted
        """
        return self.client.update(xml_tag, update_params, name, output_format, debug)

    # METHODS FOR OBJECT RETRIEVAL (GET)

    def get_fw_rule(self, name: str = None, operator: str = "="):
        """Get firewall rule(s). DEPRECATED: Use `get_rule()` instead. Will be removed in a later version.

        Args:
            name (str, optional): Firewall Rule name.  Returns all rules if not specified.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like.
        """
        return FirewallRule(self.client).get(name=name, operator=operator)
    
    def get_rule(self, name: str = None, operator: str = "="):
        """Get firewall rule(s)

        Args:
            name (str, optional): Firewall Rule name.  Returns all rules if not specified.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like.
        """
        return FirewallRule(self.client).get(name=name, operator=operator)

    def get_ip_host(
        self, name: str = None, ip_address: str = None, operator: str = "="
    ):
        """Get IP Host object(s)

        Args:
            name (str, optional): IP object name. Returns all objects if not specified.
            ip_address (str, optional): Query by IP Address.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like.
        """
        return IPHost(self.client).get(name, ip_address, operator)

    def get_ip_hostgroup(self, name: str = None, operator: str = "="):
        """Get IP hostgroup(s)

        Args:
            name (str, optional): Name of IP host group. Returns all if not specified.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like.
        """
        return IPHostGroup(self.client).get(name, operator)

    def get_fqdn_host(self, name: str = None, operator: str = "="):
        """Get FQDN Host object(s)

        Args:
            name (str, optional): FQDN Host name. Returns all objects if not specified.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like.
        """
        return FQDNHost(self.client).get(name, operator)

    def get_fqdn_hostgroup(self, name: str = None, operator: str = "="):
        """Get FQDN HostGroup object(s)

        Args:
            name (str, optional): FQDN HostGroup name. Returns all objects if not specified.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like.
        """
        return FQDNHostGroup(self.client).get(name, operator)

    def get_service_group(self, name: str = None, operator: str = "="):
        """Get Service Group object(s)

        Args:
            name (str, optional): Service Group name. Returns all objects if not specified.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like.
        """
        return ServiceGroup(self.client).get(name, operator)

    def get_interface(self, name: str = None, operator: str = "="):
        """Get Interface object(s)

        Args:
            name (str, optional): Interface name. Returns all objects if not specified.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like.
        """
        return Interface(self.client).get(name, operator)

    def get_vlan(self, name: str = None, operator: str = "="):
        """Get VLAN object(s)

        Args:
            name (str, optional): VLAN name. Returns all objects if not specified.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like.
        """
        return Vlan(self.client).get(name, operator)

    def get_acl_rule(self, name: str = None, operator: str = "="):
        """Get Local Service ACL Exception rule(s) (System > Administration > Device Access > Local service ACL exception)

        Args:
            name (str, optional): Name of rule to retrieve. Returns all if not specified.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like.

        Returns:
            dict: XML response converted to Python dictionary
        """
        return AclRule(self.client).get(name, operator)

    def get_user(self, name: str = None, operator: str = "="):
        """Get local users

        Args:
            name (str, optional): Name of user. Retrieves all users if not specified.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like.

        Returns:
            dict: XML response converted to Python dictionary
        """
        return User(self.client).get(name, operator)

    def get_admin_profile(self, name: str = None, operator: str = "="):
        """Get admin profiles

        Args:
            name (str, optional): Name of profile. Returns all if not specified.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like.

        Returns:
            dict: XML response converted to Python dictionary
        """
        return AdminProfile(self.client).get(name, operator)

    def get_zone(self, name: str = None, operator: str = "="):
        """Get zone(s)

        Args:
            name (str, optional): Name of zone to query. Returns all if not specified.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like.

        Returns:
            dict: XML response converted to Python dictionary
        """
        return Zone(self.client).get(name, operator)

    def get_admin_authen(self):
        """Get admin authentication settings

        Returns:
            dict: XML response converted to Python dictionary
        """
        return AdminAuthen(self.client).get()

    def get_ips_policy(self, name: str = None):
        """Get IPS policy

        Args:
            name (str, optional): Name of a policy to filter on. Returns all if not specified.

        Returns:
            dict: XML response converted to Python dictionary
        """
        return IPS(self.client).get(name)

    def get_syslog_server(self, name: str = None):
        """Get syslog server.

        Args:
            name (str, optional): Name of syslog server. Returns all if not specified.

        Returns:
            dict: XML response converted to Python dictionary
        """
        return Syslog(self.client).get(name)

    def get_notification(self, name: str = None):
        """Get notification.

        Args:
            name (str, optional): Name of notification. Returns all if not specified.

        Returns:
            dict: XML response converted to Python dictionary
        """
        return Notification(self.client).get(name)

    def get_notification_list(self, name: str = None):
        """Get notification list.

        Args:
            name (str, optional): Name of notification list. Returns all if not specified.

        Returns:
            dict: XML response converted to Python dictionary
        """
        return NotificationList(self.client).get(name)

    def get_backup(self, name: str = None):
        """Get backup details.

        Args:
            name (str, optional): Name of backup schedule. Returns all if not specified.

        Returns:
            dict: XML response converted to Python dictionary
        """
        return Backup(self.client).get(name)

    def get_reports_retention(self, name: str = None):
        """Get Reports retention period.

        Args:
            name (str, optional): Name of backup schedule. Returns all if not specified.

        Returns:
            dict: XML response converted to Python dictionary
        """
        return Retention(self.client).get(name)

    def get_admin_settings(self):
        """Get Web Admin Settings (Administration > Settings)

        Returns:
            dict: XML response converted to Python dictionary
        """
        return self.client.get_tag(xml_tag="AdminSettings")

    def get_dns_forwarders(self):
        """Get DNS forwarders.

        Returns:
            dict: XML response converted to Python dictionary
        """
        return self.client.get_tag(xml_tag="DNS")

    def get_snmpv3_user(self):
        """Get SNMP v3 Users

        Returns:
            dict: XML response converted to Python dictionary
        """
        return self.client.get_tag(xml_tag="SNMPv3User")

    def get_urlgroup(self, name: str = None, operator: str = "="):
        """Get URLGroup(s)

        Args:
            name (str, optional): Get URLGroup by name. Defaults to None.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like.

        Returns:
            dict: XML response converted to Python dictionary
        """
        return URLGroup(self.client).get(name, operator)

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
        return Service(self.client).get(name, operator, dst_proto, dst_port)

    # METHODS FOR OBJECT CREATION

    def create_acl_rule(self,
                         name: str,
                         description: str = None,
                         position: str = "Bottom",
                         source_zone: str = "Any",
                         source_list: list = None,
                         dest_list: list = None,
                         service_list: list = None,
                         action: str = "Accept",
                         debug: bool = False):
        """Create Local Service ACL Exception Rule (System > Administration > Device Access > Local service ACL exception)

        Args:
            name (str): Name of the ACL exception rule to create.
            description (str): Rule description. 
            position (str): Location to place the ACL (Top or Bottom). 
            source_zone (str): Source Zone. Defaults to Any. 
            source_list (list, optional): List of source network or host groups. Defaults to None.
            dest_list (list, optional): List of destination hosts. Defaults to None.
            service_list (list, optional): List of services. Defaults to None.
            action (str, optional): Accept or Drop. Default is Accept.
            debug (bool, optional): Enable debug mode. Defaults to False.
        """
        return AclRule(self.client).create(name,
                                           description, 
                                           position, 
                                           source_zone, 
                                           source_list, 
                                           dest_list, 
                                           service_list, 
                                           action, 
                                           debug)

    def create_rule(self, rule_params: dict, debug: bool = False):
        """Create a firewall rule

        Args:
            rule_params (dict): Configuration parmeters for the rule, see Keyword Args for supported parameters.

        Keyword Args:
            rulename(str): Name of the firewall rule
            status(str): Enable/Disable
            position(str): Where the rule should be positioned (top/bottom/after/before)
            after_rulename(str, optional): Name of the rule to insert this rule after if position = after
            before_rulename(str, optional): Name of the rule to insert this rule before if position = before
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
        return FirewallRule(self.client).create(rule_params, debug)

    def create_ip_host(
        self,
        name: str,
        ip_address: str = None,
        mask: str = None,
        start_ip: str = None,
        end_ip: str = None,
        host_type: str = "IP",
        debug: bool = False,
    ):
        """Create IP Host.

        Args:
            name (str): Name of the object
            ip_address (str): Host IP address or network in case of host_type=Network.
            mask (str): Subnet mask in dotted decimal format (ex. 255.255.255.0). Only used with type: Network.
            start_ip (str): Starting IP address in case of host_type=IPRange.
            end_ip (str): Ending IP address in case of host_type=IPRange.
            host_type (str, optional): Type of Host. Valid options: IP, Network, IPRange.
            debug (bool, optional): Turn on debugging. Defaults to False.
        Returns:
            dict: XML response converted to Python dictionary
        """
        return IPHost(self.client).create(
            name, ip_address, mask, start_ip, end_ip, host_type, debug
        )

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
            mask (str): Subnet mask in dotted decimal format (ex. 255.255.255.0)
            debug (bool, optional): Turn on debugging. Defaults to False.
        Returns:
            dict: XML response converted to Python dictionary
        """
        return IPNetwork(self.client).create(name, ip_network, mask, debug)

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
        return IPRange(self.client).create(name, start_ip, end_ip, debug)

    def create_fqdn_host(
        self,
        name: str,
        fqdn: str,
        fqdn_group_list: list = None,
        description: str = None,
        debug: bool = False,
    ):
        """Create FQDN Host object.

        Args:
            name (str): Name of the object.
            fqdn (str): FQDN string.
            fqdn_group_list (list, optional): List containing FQDN Host Group(s) to associate the FQDN Host.
            description (str): Description.
            debug (bool, optional): Turn on debugging. Defaults to False.
        Returns:
            dict: XML response converted to Python dictionary.
        """
        return FQDNHost(self.client).create(
            name, fqdn, fqdn_group_list, description, debug
        )

    def create_fqdn_hostgroup(
        self,
        name: str,
        fqdn_host_list: list = None,
        description: str = None,
        debug: bool = False,
    ):
        """Create FQDN HostGroup object.

        Args:
            name (str): Name of the object.
            fqdn_host_list (list, optional): List containing FQDN Host(s) to associate the FQDN Host Group.
            description (str): Description.
            debug (bool, optional): Turn on debugging. Defaults to False.
        Returns:
            dict: XML response converted to Python dictionary.
        """
        return FQDNHostGroup(self.client).create(
            name, fqdn_host_list, description, debug
        )

    def create_service(
        self,
        name: str,
        service_type: str,
        service_list: list[dict],
        debug: bool = False,
    ):
        """Create a TCP or UDP service

        Args:
            name (str): Service name.
            service_type (str): Service type. Valid values are TCPorUDP, IP, ICMP, or ICMPv6.
            service_list(list): List of dictionaries.
                For type TCPorUDP, src_port(str, optional) default=1:65535, dst_port(str), and protocol(str).
                For type IP, protocol(str). For type ICMP and ICMPv6, icmp_type (str) and icmp_code (str).
            debug (bool, optional): Enable debug mode. Defaults to False.
        Returns:
            dict: XML response converted to Python dictionary
        """
        return Service(self.client).create(name, service_type, service_list, debug)

    def create_service_group(
        self,
        name: str,
        service_list: list = None,
        description: str = None,
        debug: bool = False,
    ):
        """Create Service Group object.

        Args:
            name (str): Name of the object.
            service_list (list, optional): List containing Service(s) to associate the Services Group.
            description (str): Description.
            debug (bool, optional): Turn on debugging. Defaults to False.
        Returns:
            dict: XML response converted to Python dictionary.
        """
        return ServiceGroup(self.client).create(name, service_list, description, debug)

    def create_ip_hostgroup(
        self,
        name: str,
        host_list: list,
        description: str = None,
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
        return IPHostGroup(self.client).create(name, host_list, description, debug)

    def create_urlgroup(self, name: str, domain_list: list, debug: bool = False):
        """Create a web URL Group

        Args:
            name (str): URL Group name.
            domain_list (list): List of domains to added/removed/replaced.
            debug (bool, optional): Enable debug mode. Defaults to False.

        Returns:
            dict: XML response converted to Python dictionary
        """
        return URLGroup(self.client).create(name, domain_list, debug)

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
        return User(self.client).create(debug, **kwargs)

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
        return User(self.client).update_user_password(username, new_password, debug)

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
        return User(self.client).update_admin_password(
            current_password, new_password, debug
        )

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
        return URLGroup(self.client).update(name, domain_list, action, debug)

    def update_service(
        self,
        name: str,
        service_type: str,
        service_list: list[dict],
        action: str = "add",
        debug: bool = False,
    ):
        """Add or remove a service entry to/from a service

        Args:
            name (str): Service name.
            service_type (str): Service type. Valid values are TCPorUDP, IP, ICMP, or ICMPv6.
            service_list(list): List of dictionaries.
                For type TCPorUDP, src_port(str, optional) default=1:65535, dst_port(str), and protocol(str).
                For type IP, protocol(str). For type ICMP and ICMPv6, icmp_type (str) and icmp_code (str).
            action (str): Options are 'add', 'remove' or 'replace'. Defaults to 'add'.
            debug (bool, optional): Enable debug mode. Defaults to False.

        Returns:
            dict: XML response converted to Python dictionary
        """
        return Service(self.client).update(
            name, service_type, service_list, action, debug
        )

    def update_ip_hostgroup(
        self,
        name: str,
        host_list: list,
        description: str = None,
        action: str = "add",
        debug: bool = False,
    ):
        """Add or remove an IP Host from an IP HostGroup.

        Args:
            name (str): IP Host Group name.
            description (str): IP Host Group description.
            host_list (str): List of IP Hosts to be added to or removed from the Host List.
            action (str): Options are 'add', 'remove' or 'replace'. Specify None to disable updating Host List. Defaults to 'add'.
            debug (bool, optional): Enable debug mode. Defaults to False.

        Returns:
            dict: XML response converted to Python dictionary
        """
        return IPHostGroup(self.client).update(
            name, host_list, description, action, debug
        )

    def update_fqdn_hostgroup(
        self,
        name: str,
        fqdn_host_list: list,
        description: str = None,
        action: str = "add",
        debug: bool = False,
    ):
        """Add or remove a FQDN Host from an FQDN Host Group.

        Args:
            name (str): FQDN Host Group name.
            description (str): FQDN Host Group description.
            fqdn_host_list (str): List of FQDN Hosts to be added to or removed from the FQDN Host list.
            action (str): Options are 'add', 'remove' or 'replace'. Specify None to disable updating FQDN Host List. Defaults to 'add'.
            debug (bool, optional): Enable debug mode. Defaults to False.

        Returns:
            dict: XML response converted to Python dictionary
        """
        return FQDNHostGroup(self.client).update(
            name, description, fqdn_host_list, action, debug
        )

    def update_service_group(
        self,
        name: str,
        service_list: list,
        description: str = None,
        action: str = "add",
        debug: bool = False,
    ):
        """Add or remove a Service from an Service Group.

        Args:
            name (str): Service Group name.
            description (str): Service Group description.
            service_list (str): List of Service(s) to be added to or removed from the Service Group.
            action (str): Options are 'add', 'remove' or 'replace'. Specify None to disable updating Service Group List. Defaults to 'add'.
            debug (bool, optional): Enable debug mode. Defaults to False.

        Returns:
            dict: XML response converted to Python dictionary
        """
        # Get the existing Host list first, if any
        return ServiceGroup(self.client).update(
            name, service_list, description, action, debug
        )

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
        return Backup(self.client).update(backup_params, debug)

    def update_acl_rule(
        self,
        name: str,
        description: str = None,
        source_zone: str = None,
        source_list: list = None,
        dest_list: list = None,
        service_list: list = None,
        action: str = None,
        update_action: str = "add",
        debug: bool = False,
    ):
        """Update Local Service ACL Exception Rule (System > Administration > Device Access > Local service ACL exception)

        Args:
            name (str): Name of the ACL rule to update.
            description (str): Rule description.
            source_zone (str): Name of the source zone. Defaults to None. 
            source_list (list, optional): List of network or host groups. Defaults to [].
            dest_list (list, optional): List of destinations. Defaults to [].
            service_list (list, optional): List of services. Defaults to [].
            action (str, optional): Accept or Drop.
            update_action (str, optional): Indicate whether to 'add' or 'remove' from source, dest, or service lists, or to 'replace' the lists. Default is 'add'.
            debug (bool, optional): Enable debug mode. Defaults to False.
        """
        params = {
                    "name": name,
                    "description": description,
                    "source_zone": source_zone,
                    "source_list": source_list,
                    "dest_list": dest_list,
                    "service_list": service_list,
                    "action": action,
                    "update_action": update_action,
                    "debug": debug
                  }
        return AclRule(self.client).update(**params)

    def update_rule(self, name: str, rule_params: dict, debug: bool = False):
        """Update a firewall rule

        Args:
            name(str): Name of the firewall rule to be updated.
            rule_params (dict): Configuration parmeters for the rule, see Keyword Args for supported parameters.

        Keyword Args:
            position(str): Where the rule should be positioned (top/bottom/after/before)
            after_rulename(str): Name of the rule to insert this rule after if position = after
            before_rulename(str): Name of the rule to insert this rule before if position = before
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
        return FirewallRule(self.client).update(name, rule_params, debug)

# Export the error classes for backward compatibility
__all__ = [
    "SophosFirewall",
    "SophosFirewallZeroRecords",
    "SophosFirewallAPIError",
    "SophosFirewallAuthFailure",
    "SophosFirewallInvalidArgument",
    "SophosFirewallOperatorError",
]