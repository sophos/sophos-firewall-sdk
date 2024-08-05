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
from sophosfirewall_python.api_client import APIClient
from sophosfirewall_python.firewallrule import FirewallRule
from sophosfirewall_python.host import (
    IPHost,
    IPHostGroup,
    FQDNHost, 
    FQDNHostGroup, 
    URLGroup,
    IPNetwork,
    IPRange
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
            verify=verify
        )
        self.firewall_rule = FirewallRule(self.client)
        self.ip_host = IPHost(self.client)
        self.ip_hostgroup = IPHostGroup(self.client)
        self.fqdn_host = FQDNHost(self.client)
        self.fqdn_hostgroup = FQDNHostGroup(self.client)
        self.ip_network = IPNetwork(self.client)
        self.ip_range = IPRange(self.client)
        self.service = Service(self.client)
        self.service_group = ServiceGroup(self.client)
        self.interface = Interface(self.client)
        self.vlan = Vlan(self.client)
        self.acl_rule = AclRule(self.client)
        self.user = User(self.client)
        self.admin_profile = AdminProfile(self.client)
        self.admin_auth = AdminAuthen(self.client)
        self.zone = Zone(self.client)
        self.ips = IPS(self.client)
        self.syslog_server = Syslog(self.client)
        self.notification = Notification(self.client)
        self.notification_list = NotificationList(self.client)
        self.backup = Backup(self.client)
        self.report_retention = Retention(self.client)
        self.url_group = URLGroup(self.client)

    # METHODS FOR OBJECT RETRIEVAL (GET)

    def get_fw_rule(self, name: str = None, operator: str = "="):
        """Get firewall rule(s)

        Args:
            name (str, optional): Firewall Rule name.  Returns all rules if not specified.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like.
        """
        return self.firewall_rule.get(name=name, operator=operator)

    def get_ip_host(
        self, name: str = None, ip_address: str = None, operator: str = "="
    ):
        """Get IP Host object(s)

        Args:
            name (str, optional): IP object name. Returns all objects if not specified.
            ip_address (str, optional): Query by IP Address.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like.
        """
        return self.ip_host.get(name, ip_address, operator)
    
    def get_ip_hostgroup(self, name: str = None, operator: str = "="):
        """Get IP hostgroup(s)

        Args:
            name (str, optional): Name of IP host group. Returns all if not specified.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like.
        """
        return self.ip_hostgroup.get(name, operator)
    
    def get_ip_network(
        self, name: str = None, ip_address: str = None, operator: str = "="
    ):
        """Get IP Network object(s)

        Args:
            name (str, optional): IP object name. Returns all objects if not specified.
            ip_address (str, optional): Query by IP Address.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like.
        """
        return self.ip_network.get(name, ip_address, operator)
    
    def get_ip_range(
        self, name: str = None, operator: str = "="
    ):
        """Get IP Range object(s)

        Args:
            name (str, optional): IP object name. Returns all objects if not specified.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like.
        """
        return self.ip_range.get(name, operator)

    def get_fqdn_host(
        self, name: str = None, operator: str = "="
    ):
        """Get FQDN Host object(s)

        Args:
            name (str, optional): FQDN Host name. Returns all objects if not specified.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like.
        """
        return self.fqdn_host.get(name, operator)
    
    def get_fqdn_hostgroup(
        self, name: str = None, operator: str = "="
    ):
        """Get FQDN HostGroup object(s)

        Args:
            name (str, optional): FQDN HostGroup name. Returns all objects if not specified.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like.
        """
        return self.fqdn_hostgroup.get(name, operator)

    
    def get_service_group(
        self, name: str = None, operator: str = "="
        ):
        """Get Service Group object(s)

        Args:
            name (str, optional): Service Group name. Returns all objects if not specified.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like.
        """
        return self.service_group.get(name, operator)

    def get_interface(self, name: str = None, operator: str = "="):
        """Get Interface object(s)

        Args:
            name (str, optional): Interface name. Returns all objects if not specified.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like.
        """
        return self.interface.get(name, operator)


    def get_vlan(self, name: str = None, operator: str = "="):
        """Get VLAN object(s)

        Args:
            name (str, optional): VLAN name. Returns all objects if not specified.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like.
        """
        return self.vlan.get(name, operator)

    def get_acl_rule(self, name: str = None, operator: str = "="):
        """Get ACL rules

        Args:
            name (str, optional): Name of rule to retrieve. Returns all if not specified.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like.

        Returns:
            dict: XML response converted to Python dictionary
        """
        return self.acl_rule.get(name, operator)


    def get_user(self, name: str = None, operator: str = "="):
        """Get local users

        Args:
            name (str, optional): Name of user. Retrieves all users if not specified.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like.

        Returns:
            dict: XML response converted to Python dictionary
        """
        return self.user.get(name, operator)


    def get_admin_profile(self, name: str = None, operator: str = "="):
        """Get admin profiles

        Args:
            name (str, optional): Name of profile. Returns all if not specified.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like.

        Returns:
            dict: XML response converted to Python dictionary
        """
        return self.admin_profile.get(name, operator)


    def get_zone(self, name: str = None, operator: str = "="):
        """Get zone(s)

        Args:
            name (str, optional): Name of zone to query. Returns all if not specified.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like.

        Returns:
            dict: XML response converted to Python dictionary
        """
        return self.zone.get(name, operator)

    def get_admin_authen(self):
        """Get admin authentication settings

        Returns:
            dict: XML response converted to Python dictionary
        """
        return self.admin_auth.get()

    def get_ips_policy(self, name: str = None):
        """Get IPS policy

        Args:
            name (str, optional): Name of a policy to filter on. Returns all if not specified.

        Returns:
            dict: XML response converted to Python dictionary
        """
        return self.ips.get(name)

    def get_syslog_server(self, name: str = None):
        """Get syslog server.

        Args:
            name (str, optional): Name of syslog server. Returns all if not specified.

        Returns:
            dict: XML response converted to Python dictionary
        """
        return self.syslog_server.get(name)

    def get_notification(self, name: str = None):
        """Get notification.

        Args:
            name (str, optional): Name of notification. Returns all if not specified.

        Returns:
            dict: XML response converted to Python dictionary
        """
        return self.notification.get(name)


    def get_notification_list(self, name: str = None):
        """Get notification list.

        Args:
            name (str, optional): Name of notification list. Returns all if not specified.

        Returns:
            dict: XML response converted to Python dictionary
        """
        self.notification_list.get(name)

    def get_backup(self, name: str = None):
        """Get backup details.

        Args:
            name (str, optional): Name of backup schedule. Returns all if not specified.

        Returns:
            dict: XML response converted to Python dictionary
        """
        return self.backup.get(name)

    def get_reports_retention(self, name: str = None):
        """Get Reports retention period.

        Args:
            name (str, optional): Name of backup schedule. Returns all if not specified.

        Returns:
            dict: XML response converted to Python dictionary
        """
        return self.report_retention.get(name)

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
        return self.url_group.get(name, operator)


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
        return self.service.get(name, operator, dst_proto, dst_port)

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
        return self.firewall_rule.create(rule_params, debug)      

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
        return self.ip_network.create(name, ip_network, mask, debug)

    def create_ip_host(self, name: str, ip_address: str, debug: bool = False):
        """Create IP address object

        Args:
            name (str): Name of the object
            ip_address (str): Host IP address
            debug (bool, optional): Turn on debugging. Defaults to False.
        Returns:
            dict: XML response converted to Python dictionary
        """
        return self.ip_host.create(name, ip_address, debug)
    
    def create_fqdn_host(self, name: str,
                         fqdn: str,
                         fqdn_group_list: list = None,
                         description: str = None,
                         debug: bool = False):
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
        return self.fqdn_host.create(name, fqdn, fqdn_group_list, description, debug)

    def create_fqdn_hostgroup(self, name: str,
                         fqdn_host_list: list = None,
                         description: str = None,
                         debug: bool = False):
        """Create FQDN HostGroup object.

        Args:
            name (str): Name of the object.
            fqdn_host_list (list, optional): List containing FQDN Host(s) to associate the FQDN Host Group.
            description (str): Description.
            debug (bool, optional): Turn on debugging. Defaults to False.
        Returns:
            dict: XML response converted to Python dictionary.
        """
        self.fqdn_hostgroup.create(name, fqdn_host_list, description, debug)
        

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
        return self.ip_range.create(name, start_ip, end_ip, debug)

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
        self.service.create(name, service_type, service_list, debug)
        

    def create_service_group(self, name: str,
                         service_list: list = None,
                         description: str = None,
                         debug: bool = False):
        """Create Service Group object.

        Args:
            name (str): Name of the object.
            service_list (list, optional): List containing Service(s) to associate the Services Group.
            description (str): Description. 
            debug (bool, optional): Turn on debugging. Defaults to False.
        Returns:
            dict: XML response converted to Python dictionary.
        """
        return self.service_group.create(name, service_list, description, debug)

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
        self.ip_hostgroup.create(name, host_list, description, debug)
        

    def create_urlgroup(self, name: str, domain_list: list, debug: bool = False):
        """Create a web URL Group

        Args:
            name (str): URL Group name.
            domain_list (list): List of domains to added/removed/replaced.
            debug (bool, optional): Enable debug mode. Defaults to False.

        Returns:
            dict: XML response converted to Python dictionary
        """
        return self.url_group.create(name, domain_list, debug)
        

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
        return self.user.create(debug, **kwargs)


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
        return self.user.update_user_password(username, new_password, debug)
        

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
        return self.user.update_admin_password(current_password, new_password, debug)

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
        return self.url_group.update(name, domain_list, action, debug)

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
        return self.service.update(name, service_type, service_list, action, debug)

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
        return self.ip_hostgroup.update(name, host_list, description, action, debug)

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
        return self.fqdn_hostgroup.update(name, description,fqdn_host_list, action, debug)

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
        return self.service_group.update(name, service_list, description, action, debug)

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
        return self.backup.update(backup_params, debug)

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
        return self.acl_rule.update(host_list, service_list, action, debug)
