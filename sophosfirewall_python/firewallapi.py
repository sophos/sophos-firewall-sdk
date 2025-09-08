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
    SophosFirewallOperatorError,
)
from sophosfirewall_python.firewallrule import FirewallRule
from sophosfirewall_python.firewallrulegroup import FirewallRuleGroup
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
from sophosfirewall_python.admin import AclRule, Notification, AdminSettings
from sophosfirewall_python.authen import User, AdminAuthen
from sophosfirewall_python.profile import AdminProfile
from sophosfirewall_python.ips import IPS
from sophosfirewall_python.system import Syslog, NotificationList
from sophosfirewall_python.backup import Backup
from sophosfirewall_python.reports import Retention
from sophosfirewall_python.web import WebFilterPolicy, UserActivity

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

    def get_tag(self, xml_tag: str, timeout: int = 30, output_format: str = "dict"):
        """Execute a get for a specified XML tag.

        Args:
            xml_tag (str): XML tag for the request
            timeout (int): Request timeout in seconds. Defaults to 30 seconds.
            output_format(str): Output format. Valid options are "dict" or "xml". Defaults to dict.
        """
        return self.client.get_tag(xml_tag, timeout, output_format)

    def get_tag_with_filter(
        self,
        xml_tag: str,
        key: str,
        value: str,
        operator: str = "like",
        timeout: int = 30,
        output_format: str = dict,
    ):
        """Execute a get for a specified XML tag with filter criteria.

        Args:
            xml_tag (str): XML tag for the request.
            key (str): Search key
            value (str): Search value
            operator (str, optional): Operator for search (“=”,”!=”,”like”). Defaults to "like".
            timeout (int): Request timeout in seconds. Defaults to 30 seconds.
            output_format(str): Output format. Valid options are "dict" or "xml". Defaults to dict.
        """
        return self.client.get_tag_with_filter(
            xml_tag, key, value, operator, timeout, output_format
        )

    def submit_template(
        self,
        filename: str,
        template_vars: dict,
        template_dir: str = None,
        timeout: int = 30, 
        debug: bool = False,
    ) -> dict:
        """Submits XML payload stored as a Jinja2 file

        Args:
            filename (str): Jinja2 template filename. Place in "templates" directory or configure template_dir.
            template_vars (dict): Dictionary of variables to inject into the template. Username and password are passed in by default.
            template_dir (str): Directory to look for templates. Default is "./templates".
            timeout (int): Request timeout in seconds. Defaults to 30 seconds.
            debug (bool, optional): Enable debug mode to display XML payload. Defaults to False.

        Returns:
            dict
        """
        return self.client.submit_template(filename, template_vars, template_dir, timeout, debug)

    def submit_xml(
        self,
        template_data: str,
        template_vars: dict = None,
        set_operation: str = "add",
        timeout: int = 30,
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
        return self.client.submit_xml(
            template_data, template_vars, set_operation, timeout, debug
        )

    def remove(
        self, xml_tag: str, name: str, key: str = "Name", timeout: int = 30, output_format: str = "dict"
    ):
        """Remove an object from the firewall.

        Args:
            xml_tag (str): The XML tag indicating the type of object to be removed.
            name (str): The name of the object to be removed.
            key (str): The primary XML key that is used to look up the object. Defaults to Name.
            output_format (str): Output format. Valid options are "dict" or "xml". Defaults to dict.
        """
        return self.client.remove(xml_tag, name, key, timeout, output_format)

    def update(
        self,
        xml_tag: str,
        update_params: dict,
        name: str = None,
        lookup_key: str = "Name",
        output_format: str = "dict",
        timeout: int = 30,
        debug: bool = False,
    ):
        """Update an existing object on the firewall.

        Args:
            xml_tag (str): The XML tag indicating the type of object to be updated.
            update_params (dict): Keys/values to be updated. Keys must match an existing XML key.
            name (str, optional): The name of the object to be updated, if applicable.
            lookup_key (str, optional): The XML key name to look up the name of the object. Default is "Name".
            output_format(str): Output format. Valid options are "dict" or "xml". Defaults to dict.
            timeout (int): Request timeout in seconds. Defaults to 30 seconds.
            debug (bool): Displays the XML payload that was submitted
        """
        return self.client.update(
            xml_tag, update_params, name, lookup_key, output_format, timeout, debug
        )

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

    def get_rulegroup(self, name: str = None, operator: str = "="):
        """Get firewall rule group(s)

        Args:
            name (str, optional): Firewall Rule Group name.  Returns all rule groups if not specified.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like.
        """
        return FirewallRuleGroup(self.client).get(name=name, operator=operator)

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

    def get_user(self, name: str = None, username: str = None, operator: str = "="):
        """Get local users

        Args:
            name (str, optional): User display name. Retrieves all users if not specified.
            username (str, optional): Username.  Retrieves all users if not specified.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like.

        Returns:
            dict: XML response converted to Python dictionary
        """
        return User(self.client).get(name, username, operator)

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
        return AdminSettings(self.client).get()

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

    def get_webfilterpolicy(self, name: str = None):
        """Get Web Filter Policy object(s)

        Args:
            name (str, optional): Web Filter Policy name. Returns all objects if not specified.
        """
        return WebFilterPolicy(self.client).get(name)

    def get_useractivity(self, name: str = None):
        """Get User Activity object(s)

        Args:
            name (str, optional): User Activity name. Returns all objects if not specified.
        """
        return UserActivity(self.client).get(name)

    # METHODS FOR OBJECT CREATION

    def create_acl_rule(
        self,
        name: str,
        description: str = None,
        position: str = "Bottom",
        source_zone: str = "Any",
        source_list: list = None,
        dest_list: list = None,
        service_list: list = None,
        action: str = "Accept",
        debug: bool = False,
    ):
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
        return AclRule(self.client).create(
            name,
            description,
            position,
            source_zone,
            source_list,
            dest_list,
            service_list,
            action,
            debug,
        )

    def create_admin_profile(
        self, name: str, default_permission: str = None, debug: bool = False, **kwargs
    ):
        """Create an administration profile.

        Args:
            name (str): Name of administration profile
            default_permission (str, optional): Permissions to use for unspecified settings (None, Read-Only, Read-Write). Defaults to None.
            debug (bool, optional): Turn on debugging. Defaults to False.

        Keyword Args:
            dashboard (str, optional): Dashboard permission (None, Read-Only, Read-Write). Defaults to None.
            wizard (str, optional): Wizard permission (None, Read-Only, Read-Write). Defaults to None.
            set_system_profile (str, optional): System Profile permission (None, Read-Only, Read-Write). Defaults to None.
            profile (str, optional): Profile permission (None, Read-Only, Read-Write). Defaults to None.
            system_password (str, optional): System Password permission (None, Read-Only, Read-Write). Defaults to None.
            central_management (str, optional): Central management permission (None, Read-Only, Read-Write). Defaults to None.
            backup (str, optional): Backup permission (None, Read-Only, Read-Write). Defaults to None.
            restore (str, optional): Restore permission (None, Read-Only, Read-Write). Defaults to None.
            firmware (str, optional): Firmware permission (None, Read-Only, Read-Write). Defaults to None.
            licensing (str, optional): Licensing permission (None, Read-Only, Read-Write). Defaults to None.
            services (str, optional): Services permission (None, Read-Only, Read-Write). Defaults to None.
            updates (str, optional): Updates permission (None, Read-Only, Read-Write). Defaults to None.
            reboot_shutdown (str, optional): Reboot/Shutdown permission (None, Read-Only, Read-Write). Defaults to None.
            ha (str, optional): HA permission (None, Read-Only, Read-Write). Defaults to None.
            download_certificates (str, optional): Download certificates permission (None, Read-Only, Read-Write). Defaults to None.
            other_certificate_configuration (str, optional): Other certificate configuration permission (None, Read-Only, Read-Write). Defaults to None.
            diagnostics (str, optional): Diagnostics permission (None, Read-Only, Read-Write). Defaults to None.
            other_system_configuration (str, optional): Other system configuration permission (None, Read-Only, Read-Write). Defaults to None.
            wireless_protection_overview (str, optional): Wireless protection overview permission (None, Read-Only, Read-Write). Defaults to None.
            wireless_protection_settings (str, optional): Wireless protection settings permission (None, Read-Only, Read-Write). Defaults to None.
            wireless_protection_network (str, optional): Wireless protection network permission (None, Read-Only, Read-Write). Defaults to None.
            wireless_protection_access_point (str, optional): Wireless protection access point permission (None, Read-Only, Read-Write). Defaults to None.
            wireless_protection_mesh (str, optional): Wireless protection mesh permission (None, Read-Only, Read-Write). Defaults to None.
            objects (str, optional): Objects permission (None, Read-Only, Read-Write). Defaults to None.
            network (str, optional): Network permission (None, Read-Only, Read-Write). Defaults to None.
            set_identity_profile (str, optional): Set identity profile permission (None, Read-Only, Read-Write). Defaults to None.
            authentication (str, optional): Authentication permission (None, Read-Only, Read-Write). Defaults to None.
            groups (str, optional): Groups permission (None, Read-Only, Read-Write). Defaults to None.
            guest_users_management (str, optional): Guest users management permission (None, Read-Only, Read-Write). Defaults to None.
            other_guest_user_settings (str, optional): Other guest user settings permission (None, Read-Only, Read-Write). Defaults to None.
            policy (str, optional): Policy permissions (None, Read-Only, Read-Write). Defaults to None.
            test_external_server_connectivity (str, optional): Test external server connectivity permission (None, Read-Only, Read-Write). Defaults to None.
            disconnect_live_user (str, optional): Disconnect live user permission (None, Read-Only, Read-Write). Defaults to None.
            firewall (str, optional): Firewall permission (None, Read-Only, Read-Write). Defaults to None.
            set_vpn_profile (str, optional): Set vpn profile permission (None, Read-Only, Read-Write). Defaults to None.
            connect_tunnel (str, optional): Connect tunnel permission (None, Read-Only, Read-Write). Defaults to None.
            other_vpn_configurations (str, optional): Other VPN configuration permission (None, Read-Only, Read-Write). Defaults to None.
            ips (str, optional): IPS permission (None, Read-Only, Read-Write). Defaults to None.
            web_filter (str, optional): Web filter permission (None, Read-Only, Read-Write). Defaults to None.
            cloud_application_dashboard (str, optional): Cloud application dashboard permission (None, Read-Only, Read-Write). Defaults to None.
            zero_day_protection (str, optional): Zero day protection permission (None, Read-Only, Read-Write). Defaults to None.
            application_filter (str, optional): Application filter permission (None, Read-Only, Read-Write). Defaults to None.
            set_waf_profile (str, optional): Set WAF profile permission (None, Read-Only, Read-Write). Defaults to None.
            alerts (str, optional): Alerts permission (None, Read-Only, Read-Write). Defaults to None.
            other_waf_configuration (str, optional): Other WAF configuration permission (None, Read-Only, Read-Write). Defaults to None.
            qos (str, optional): QoS permission (None, Read-Only, Read-Write). Defaults to None.
            set_anti_virus_profile (str, optional): Set AntiVirus profile permission (None, Read-Only, Read-Write). Defaults to None.
            download_quarantine_mail (str, optional): Download quarantine mail permission (None, Read-Only, Read-Write). Defaults to None.
            other_antivirus_configurations (str, optional): Other antivirus configuration permission (None, Read-Only, Read-Write). Defaults to None.
            set_anti_spam_profile (str, optional): Set antispam profile permission (None, Read-Only, Read-Write). Defaults to None.
            download_release_quarantine_mail (str, optional): Download release quarantine mail permission (None, Read-Only, Read-Write). Defaults to None.
            other_anti_spam_configurations (str, optional): Other anti spam configurations permission (None, Read-Only, Read-Write). Defaults to None.
            traffic_discovery (str, optional): Traffic discovery permission (None, Read-Only, Read-Write). Defaults to None.
            set_logs_reports_profile (str, optional): Set logs reports profile permission (None, Read-Only, Read-Write). Defaults to None.
            configuration (str, optional): Log reports configuration permission (None, Read-Only, Read-Write). Defaults to None.
            log_viewer (str, optional): Log viewer permission (None, Read-Only, Read-Write). Defaults to None.
            reports_access (str, optional): Reports access permission (None, Read-Only, Read-Write). Defaults to None.
            four_eye_authentication_settings (str, optional): Four-eye authentication settings permission (None, Read-Only, Read-Write). Defaults to None.
            de_anonymization (str, optional): Log De-anonymization permission (None, Read-Only, Read-Write). Defaults to None.

        Returns:
            dict: XML response converted to Python dictionary
        """
        return AdminProfile(self.client).create(
            name=name, default_permission=default_permission, debug=debug, **kwargs
        )

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
            web_filter(str): Name of the web filter policy to apply
            web_category_traffic_shaping(str): Name of the web category traffic shaping policy to apply
            block_quic(str): Enable/Disable QUIC blocking
            scan_virus(str): Enable/Disable virus scanning
            proxy_mode(str): Enable/Disable proxy mode
            decrypt_https(str): Enable/Disable HTTPS decryption
            source_security_heartbeat(str): Enable/Disable source security heartbeat
            minimum_source_hb_permitted(str): Minimum source heartbeat permitted
            dest_security_heartbeat(str): Enable/Disable destination security heartbeat
            minimum_dest_hb_permitted(str): Minimum destination heartbeat permitted
            application_control(str): Enable/Disable application control
            application_base_qos_policy(str): Name of the application base QoS policy to apply
            intrusion_prevention(str): Enable/Disable intrusion prevention
            qos_policy(str): Name of the QoS traffic shaping policy to apply
            dscp_marking(str): DSCP marking value
            scan_smtp(str): Enable/Disable SMTP scanning
            scan_smtps(str): Enable/Disable SMTPS scanning
            scan_imap(str): Enable/Disable IMAP scanning
            scan_imaps(str): Enable/Disable IMAPS scanning
            scan_pop3(str): Enable/Disable POP3 scanning
            scan_pop3s(str): Enable/Disable POP3S scanning
        Returns:
            dict: XML response converted to Python dictionary
        """
        return FirewallRule(self.client).create(rule_params, debug)

    def create_rulegroup(
        self,
        name: str,
        description: str,
        policy_list: list,
        source_zones: list,
        dest_zones: list,
        policy_type: str,
        debug: bool = False,
    ):
        """Create a firewall rule group

        Args:
            name(str): Name of the firewall rule group
            description(str): Description for the firewall rule group
            policy_list(list): List of firewall rules to add to firewall group
            source_zones(list): List of source zones
            dest_zones(list): List of destination zones
            policy_type(str): Policy type. Valid values are User/network rule, Network rule, User rule, WAF rule, Any

        Returns:
            dict: XML response converted to Python dictionary
        """
        return FirewallRuleGroup(self.client).create(
            name, description, policy_list, source_zones, dest_zones, policy_type, debug
        )

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

    def create_zone(
        self, name: str, zone_type: str, zone_params: dict = None, debug: bool = False
    ):
        """Create a zone.

        Args:
            name (str): Zone name
            zone_type (str): Zone type

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
        return Zone(self.client).create(
            name=name, zone_type=zone_type, zone_params=zone_params, debug=debug
        )
    
    def create_webfilterpolicy(self, name, default_action, download_file_size_restriction='0',
                                 enable_reporting="Enable", download_file_size_restriction_enabled='0',
                                 goog_app_domain_list=None, goog_app_domain_list_enabled='0',
                                 youtube_filter_is_strict='0', youtube_filter_enabled='0',
                                 enforce_safe_search='0', enforce_image_licensing='0',
                                 xff_enabled='0', office_365_tenants_list=None,
                                 office_365_directory_id=None, office_365_enabled='0',
                                 quota_limit=60, description=None, rules=None, debug: bool = False):
        """Create a Web Filter Policy

        Args:
            name (str): Specify a name for the Web Filter Policy. Max 50 chars.
            default_action (str): Default action of the policy ('Allow' or 'Deny').
            download_file_size_restriction (int): Specify maximum allowed file download size in MB (0-1536).
            enable_reporting (str, optional): Select to enable reporting of policy. Defaults to "Enable". (API Default: Enable)
            download_file_size_restriction_enabled (str, optional): Enable ('1') or disable ('0') checking for maximum allowed file download size. Defaults to None.
            goog_app_domain_list (str, optional): Comma-separated list of domains allowed to access Google services. Max 256 chars. Defaults to None.
            goog_app_domain_list_enabled (str, optional): Enable ('1') or disable ('0') specifying domains for Google services. Defaults to None.
            youtube_filter_is_strict (str, optional): Adjust the policy used for YouTube Restricted Mode ('1' for strict, '0' for moderate). Defaults to None.
            youtube_filter_enabled (str, optional): Enable ('1') or disable ('0') YouTube Restricted Mode. Defaults to None.
            enforce_safe_search (str, optional): Enable ('1') or disable ('0') blocking of pornography and explicit content in search results. Defaults to None.
            enforce_image_licensing (str, optional): Enable ('1') or disable ('0') limiting search results to Creative Commons licensed images. Defaults to None.
            xff_enabled (str, optional): Enable ('1') or disable ('0') X-Forwarded-For header. Defaults to None.
            office_365_tenants_list (str, optional): Comma-separated list of domain names and domain IDs allowed to access Microsoft 365. Max 4096 chars. Defaults to None.
            office_365_directory_id (str, optional): Domain ID allowed to access the Microsoft 365 service. Max 50 chars. Defaults to None.
            office_365_enabled (str, optional): Turn on ('1') or off ('0') specifying domains/IDs for Microsoft 365. Defaults to None.
            quota_limit (int, optional): Maximum allowed time (1-1440 minutes) for browsing restricted web content under quota policy action. Defaults to 60. (API Default: 60)
            description (str, optional): Specify Policy description. Max 255 chars. Defaults to None.
            rules (list of dict, optional): Specify the rules contained in this policy. Defaults to None. See rule list structure below:
                - categories (list of dict): List of rule categories containing:
                    - id (str): Category Name
                    - type (str): Category type. Valid types are 'WebCategory', 'FileType', 'URLGroup', or 'UserActivity'.
                - http_action (str, optional): HTTP action (Allow/Deny). Defaults to Deny.
                - https_action (str, optional): HTTPS action (Allow/Deny). Defaults to Deny.
                - follow_http_action (str, optional): '1' to enable, '0' to disable. Defaults to 1.
                - schedule (str, optional): Schedule name. Defaults to 'All The Time'
                - policy_rule_enabled (str, optional): '1' to enable, '0' to disable. Defaults to 1.
                - ccl_rule_enabled (str, optional): '1' to enable, '0' to disable. Defaults to 0.
        Returns:
            dict: XML response converted to Python dictionary
        """
        return WebFilterPolicy(self.client).create(
            name=name,
            default_action=default_action,
            enable_reporting=enable_reporting,
            download_file_size_restriction=download_file_size_restriction,
            download_file_size_restriction_enabled=download_file_size_restriction_enabled,
            goog_app_domain_list=goog_app_domain_list,
            goog_app_domain_list_enabled=goog_app_domain_list_enabled,
            youtube_filter_is_strict=youtube_filter_is_strict,
            youtube_filter_enabled=youtube_filter_enabled,
            enforce_safe_search=enforce_safe_search,
            enforce_image_licensing=enforce_image_licensing,
            xff_enabled=xff_enabled,
            office_365_tenants_list=office_365_tenants_list,
            office_365_directory_id=office_365_directory_id,
            office_365_enabled=office_365_enabled,
            quota_limit=quota_limit,
            description=description,
            rules=rules,
            debug=debug
        )
    
    def create_useractivity(
        self,name: str, description: str = None, category_list: list[dict] = None, debug: bool = False):
        """Create a User Activity object

        Args:
            name (str): Specify a name for the User Activity. Max 50 chars.
            description (str, optional): Specify a description for the User Activity. Defaults to None.
            category_list (list of dict, optional): List of categories to apply to this User Activity. Defaults to None. Category dict structure below:

                Each category dict should contain:
                    - id (str): Category Name
                    - type (str): Category type. Supports 'web category', 'file type', or 'url group'.

        Returns:
            dict: XML response converted to Python dictionary
        """
        return UserActivity(self.client).create(
            name=name, description=description, category_list=category_list, debug=debug
        )

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

    def update_admin_profile(self, name: str, debug: bool = False, **kwargs):
        """Update an administration profile.

        Args:
            name (str): Name of administration profile
            debug (bool, optional): Turn on debugging. Defaults to False.

        Keyword Args:
            dashboard (str, optional): Dashboard permission (None, Read-Only, Read-Write). Defaults to None.
            wizard (str, optional): Wizard permission (None, Read-Only, Read-Write). Defaults to None.
            set_system_profile (str, optional): System Profile permission (None, Read-Only, Read-Write). Defaults to None.
            profile (str, optional): Profile permission (None, Read-Only, Read-Write). Defaults to None.
            system_password (str, optional): System Password permission (None, Read-Only, Read-Write). Defaults to None.
            central_management (str, optional): Central management permission (None, Read-Only, Read-Write). Defaults to None.
            backup (str, optional): Backup permission (None, Read-Only, Read-Write). Defaults to None.
            restore (str, optional): Restore permission (None, Read-Only, Read-Write). Defaults to None.
            firmware (str, optional): Firmware permission (None, Read-Only, Read-Write). Defaults to None.
            licensing (str, optional): Licensing permission (None, Read-Only, Read-Write). Defaults to None.
            services (str, optional): Services permission (None, Read-Only, Read-Write). Defaults to None.
            updates (str, optional): Updates permission (None, Read-Only, Read-Write). Defaults to None.
            reboot_shutdown (str, optional): Reboot/Shutdown permission (None, Read-Only, Read-Write). Defaults to None.
            ha (str, optional): HA permission (None, Read-Only, Read-Write). Defaults to None.
            download_certificates (str, optional): Download certificates permission (None, Read-Only, Read-Write). Defaults to None.
            other_certificate_configuration (str, optional): Other certificate configuration permission (None, Read-Only, Read-Write). Defaults to None.
            diagnostics (str, optional): Diagnostics permission (None, Read-Only, Read-Write). Defaults to None.
            other_system_configuration: Other system configuration permission (None, Read-Only, Read-Write). Defaults to None.
            objects (str, optional): Objects permission (None, Read-Only, Read-Write). Defaults to None.
            network (str, optional): Network permission (None, Read-Only, Read-Write). Defaults to None.
            set_identity_profile (str, optional): Set identity profile permission (None, Read-Only, Read-Write). Defaults to None.
            authentication (str, optional): Authentication permission (None, Read-Only, Read-Write). Defaults to None.
            groups (str, optional): Groups permission (None, Read-Only, Read-Write). Defaults to None.
            administrator_users (str, optional): Administrator users permission (None, Read-Only, Read-Write). Defaults to None.
            guest_users_management (str, optional): Guest users management permission (None, Read-Only, Read-Write). Defaults to None.
            other_guest_user_settings (str, optional): Other guest user settings permission (None, Read-Only, Read-Write). Defaults to None.
            policy (str, optional): Policy permissions (None, Read-Only, Read-Write). Defaults to None.
            test_external_server_connectivity (str, optional): Test external server connectivity permission (None, Read-Only, Read-Write). Defaults to None.
            disconnect_live_user (str, optional): Disconnect live user permission (None, Read-Only, Read-Write). Defaults to None.
            firewall (str, optional): Firewall permission (None, Read-Only, Read-Write). Defaults to None.
            set_vpn_profile (str, optional): Set vpn profile permission (None, Read-Only, Read-Write). Defaults to None.
            connect_tunnel (str, optional): Connect tunnel permission (None, Read-Only, Read-Write). Defaults to None.
            other_vpn_configurations (str, optional): Other VPN configuration permission (None, Read-Only, Read-Write). Defaults to None.
            ips (str, optional): IPS permission (None, Read-Only, Read-Write). Defaults to None.
            web_filter (str, optional): Web filter permission (None, Read-Only, Read-Write). Defaults to None.
            cloud_application_dashboard (str, optional): Cloud application dashboard permission (None, Read-Only, Read-Write). Defaults to None.
            zero_day_protection (str, optional): Zero day protection permission (None, Read-Only, Read-Write). Defaults to None.
            application_filter (str, optional): Application filter permission (None, Read-Only, Read-Write). Defaults to None.
            set_waf_profile (str, optional): Set WAF profile permission (None, Read-Only, Read-Write). Defaults to None.
            alerts (str, optional): Alerts permission (None, Read-Only, Read-Write). Defaults to None.
            other_waf_configuration (str, optional): Other WAF configuration permission (None, Read-Only, Read-Write). Defaults to None.
            qos (str, optional): QoS permission (None, Read-Only, Read-Write). Defaults to None.
            email_protection (str, optional): Email protection permission (None, Read-Only, Read-Write). Defaults to None.
            set_anti_virus_profile (str, optional): Set AntiVirus profile permission (None, Read-Only, Read-Write). Defaults to None.
            download_quarantine_mail (str, optional): Download quarantine mail permission (None, Read-Only, Read-Write). Defaults to None.
            other_antivirus_configurations (str, optional): Other antivirus configuration permission (None, Read-Only, Read-Write). Defaults to None.
            set_anti_spam_profile (str, optional): Set antispam profile permission (None, Read-Only, Read-Write). Defaults to None.
            download_release_quarantine_mail (str, optional): Download release quarantine mail permission (None, Read-Only, Read-Write). Defaults to None.
            other_anti_spam_configurations (str, optional): Other anti spam configurations permission (None, Read-Only, Read-Write). Defaults to None.
            traffic_discovery (str, optional): Traffic discovery permission (None, Read-Only, Read-Write). Defaults to None.
            set_logs_reports_profile (str, optional): Set logs reports profile permission (None, Read-Only, Read-Write). Defaults to None.
            configuration (str, optional): Log reports configuration permission (None, Read-Only, Read-Write). Defaults to None.
            log_viewer (str, optional): Log viewer permission (None, Read-Only, Read-Write). Defaults to None.
            reports_access (str, optional): Reports access permission (None, Read-Only, Read-Write). Defaults to None.
            four_eye_authentication_settings (str, optional): Four-eye authentication settings permission (None, Read-Only, Read-Write). Defaults to None.
            de_anonymization (str, optional): Log De-anonymization permission (None, Read-Only, Read-Write). Defaults to None.

        Returns:
            dict: XML response converted to Python dictionary
        """
        return AdminProfile(self.client).update(name=name, debug=debug, **kwargs)

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
            "debug": debug,
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
            web_filter(str): Name of the web filter policy to apply
            web_category_traffic_shaping(str): Name of the web category traffic shaping policy to apply
            block_quic(str): Enable/Disable QUIC blocking
            scan_virus(str): Enable/Disable virus scanning
            proxy_mode(str): Enable/Disable proxy mode
            decrypt_https(str): Enable/Disable HTTPS decryption
            source_security_heartbeat(str): Enable/Disable source security heartbeat
            minimum_source_hb_permitted(str): Minimum source heartbeat permitted
            dest_security_heartbeat(str): Enable/Disable destination security heartbeat
            minimum_dest_hb_permitted(str): Minimum destination heartbeat permitted
            application_control(str): Enable/Disable application control
            application_base_qos_policy(str): Name of the application base QoS policy to apply
            intrusion_prevention(str): Enable/Disable intrusion prevention
            qos_policy(str): Name of the QoS traffic shaping policy to apply
            dscp_marking(str): DSCP marking value
            scan_smtp(str): Enable/Disable SMTP scanning
            scan_smtps(str): Enable/Disable SMTPS scanning
            scan_imap(str): Enable/Disable IMAP scanning
            scan_imaps(str): Enable/Disable IMAPS scanning
            scan_pop3(str): Enable/Disable POP3 scanning
            scan_pop3s(str): Enable/Disable POP3S scanning
        Returns:
            dict: XML response converted to Python dictionary
        """
        return FirewallRule(self.client).update(name, rule_params, debug)

    def update_rulegroup(
        self,
        name: str,
        description: str = None,
        policy_list: list = None,
        source_zones: list = None,
        dest_zones: list = None,
        policy_type: str = None,
        source_zone_action: str = "add",
        dest_zone_action: str = "add",
        debug: bool = False,
    ):
        """Create a firewall rule group

        Args:
            name(str): Name of the firewall rule group
            description(str): Description for the firewall rule group
            policy_list(list): List of firewall rules to add to firewall group
            source_zones(list): List of source zones
            dest_zones(list): List of destination zones
            policy_type(str): Policy type. Valid values are User/network rule, Network rule, User rule, WAF rule, Any
            source_zone_action(str): Specify add to add a new rule to the list. Specify remove to remove a rule from the list. Specify replace to replace the list. Default=add.
            dest_zone_action(str): Specify add to add a new rule to the list. Specify remove to remove a rule from the list. Specify replace to replace the list. Default=add.
        Returns:
            dict: XML response converted to Python dictionary
        """

        return FirewallRuleGroup(self.client).update(
            name,
            description,
            policy_list,
            source_zones,
            dest_zones,
            policy_type,
            source_zone_action,
            dest_zone_action,
            debug,
        )

    def update_hostname_settings(
        self, hostname: str = None, description: str = None, debug: bool = False
    ):
        """Update hostname admin settings. System > Administration > Admin and user settings.

        Args:
            hostname (str, optional): Hostname. Defaults to None.
            description (str, optional): Hostname description. Defaults to None.

        Returns:
            dict: XML response converted to Python dictionary
        """
        return AdminSettings(self.client).update_hostname_settings(
            hostname, description, debug
        )

    def update_webadmin_settings(
        self,
        certificate: str = None,
        https_port: str = None,
        userportal_https_port: str = None,
        vpnportal_https_port: str = None,
        portal_redirect_mode: str = None,
        portal_custom_hostname: str = None,
        debug: bool = False,
    ):
        """Update webadmin settings. System > Administration > Admin and user settings.

        Args:
            certificate (str, optional): SSL Certificate name. Defaults to None.
            https_port (str, optional): HTTPS port for admin interface. Defaults to None.
            userportal_https_port (str, optional): HTTPS port for User portal. Defaults to None.
            vpnportal_https_port (str, optional): HTTPS port for VPN portal. Defaults to None.
            portal_redirect_mode (str, optional): Portal redirect mode. Defaults to None.
            portal_custom_hostname (str, optional): Portal custom hostname. Defaults to None.

        Returns:
            dict: XML response converted to Python dictionary
        """
        return AdminSettings(self.client).update_webadmin_settings(
            certificate,
            https_port,
            userportal_https_port,
            vpnportal_https_port,
            portal_redirect_mode,
            portal_custom_hostname,
            debug,
        )

    def update_loginsecurity_settings(
        self,
        logout_session: str = None,
        block_login: str = None,
        unsuccessful_attempt: str = None,
        duration: str = None,
        minutes: str = None,
        debug: bool = False,
    ):
        """Update login security settings. System > Administration > Admin and user settings.

        Args:
            logout_session (str, optional): Enable to logout Admin Session after configured timeout. Specify number of minutes to enable (1-120). Defaults to None.
            block_login (str, optional): Enable to block Admin login after configured number of failed attempts within configured time span. Defaults to None.
            unsuccessful_attempt (str, optional): Allowed number of failed Admin login attempts from the same IP address (1-5). Defaults to None.
            duration (str, optional): Time span within which if Admin Login attempts exceed configured Unsuccessful Attempts, then Admin Login gets blocked. (1-120). Defaults to None.
            minutes (str, optional): Time interval for which Admin Login is blocked (1-60). Defaults to None.

        Returns:
            dict: XML response converted to Python dictionary
        """
        return AdminSettings(self.client).update_loginsecurity_settings(
            logout_session, block_login, unsuccessful_attempt, duration, minutes, debug
        )

    def update_passwordcomplexity_settings(
        self,
        complexity_check: str = None,
        enforce_min_length: str = None,
        include_alpha: str = None,
        include_numeric: str = None,
        include_special: str = None,
        min_length: str = None,
        debug: bool = False,
    ):
        """Update hostname admin settings. System > Administration > Admin and user settings.

        Args:
            complexity_check (str, optional): Enable/disable password complexity check. Defaults to None.
            enforce_min_length (str, optional): Enforce minimum required password length. Defaults to None.
            include_alpha (str, optional): Enforce inclusion of alphanumeric characters. Defaults to None.
            include_numeric (str, optional): Enforce inclusion numeric characters. Defaults to None.
            include_special (str, optional): Enforce inclusion of special characters. Defaults to None.
            min_length (str, optional): Minimul required password length. Defaults to None.

        Returns:
            dict: XML response converted to Python dictionary
        """
        return AdminSettings(self.client).update_passwordcomplexity_settings(
            complexity_check,
            enforce_min_length,
            include_alpha,
            include_numeric,
            include_special,
            min_length,
            debug,
        )

    def update_login_disclaimer(self, enabled: bool = False, debug: bool = False):
        """Update login disclaimer. System > Administration > Admin and user settings.

        Args:
            enabled (bool, optional): Enable or disable Login Disclaimer. Defaults to True.

        Returns:
            dict: XML response converted to Python dictionary
        """
        return AdminSettings(self.client).update_login_disclaimer(enabled, debug)

    def update_zone(self, name: str, zone_params: dict = None, debug: bool = False):
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
        return Zone(self.client).update(name, zone_params, debug)

    def update_webfilterpolicy(self, name, default_action=None, download_file_size_restriction='0',
                                 enable_reporting="Enable", download_file_size_restriction_enabled='0',
                                 goog_app_domain_list=None, goog_app_domain_list_enabled='0',
                                 youtube_filter_is_strict='0', youtube_filter_enabled='0',
                                 enforce_safe_search='0', enforce_image_licensing='0',
                                 xff_enabled='0', office_365_tenants_list=None,
                                 office_365_directory_id=None, office_365_enabled='0',
                                 quota_limit=60, description=None, rules=None, rule_action="add", debug: bool = False):
        """Update a Web Filter Policy

        Args:
            name (str): Specify a name for the Web Filter Policy. Max 50 chars. (Mandatory for identification)
            default_action (str, optional): Default action of the policy ('Allow' or 'Deny').
            enable_reporting (str, optional): Select to enable reporting of policy.
            download_file_size_restriction (int, optional): Specify maximum allowed file download size in MB (0-1536).
            download_file_size_restriction_enabled (str, optional): Enable ('1') or disable ('0') checking for maximum allowed file download size.
            goog_app_domain_list (str, optional): Comma-separated list of domains allowed to access Google services. Max 256 chars.
            goog_app_domain_list_enabled (str, optional): Enable ('1') or disable ('0') specifying domains for Google services.
            youtube_filter_is_strict (str, optional): Adjust the policy used for YouTube Restricted Mode ('1' for strict, '0' for moderate).
            youtube_filter_enabled (str, optional): Enable ('1') or disable ('0') YouTube Restricted Mode.
            enforce_safe_search (str, optional): Enable ('1') or disable ('0') blocking of pornography and explicit content in search results.
            enforce_image_licensing (str, optional): Enable ('1') or disable ('0') limiting search results to Creative Commons licensed images.
            xff_enabled (str, optional): Enable ('1') or disable ('0') X-Forwarded-For header.
            office_365_tenants_list (str, optional): Comma-separated list of domain names and domain IDs allowed to access Microsoft 365. Max 4096 chars.
            office_365_directory_id (str, optional): Domain ID allowed to access the Microsoft 365 service. Max 50 chars.
            office_365_enabled (str, optional): Turn on ('1') or off ('0') specifying domains/IDs for Microsoft 365.
            quota_limit (int, optional): Maximum allowed time (1-1440 minutes) for browsing restricted web content under quota policy action.
            description (str, optional): Specify Policy description. Max 255 chars.
            rules (list of dict, optional): Specify the rules contained in this policy. Defaults to None. See rule list structure below:
                - categories (list of dict): List of rule categories containing:
                    - id (str): Category Name
                    - type (str): Category type. Valid types are 'WebCategory', 'FileType', 'URLGroup', or 'UserActivity'.
                - http_action (str, optional): HTTP action (Allow/Deny). Defaults to Deny.
                - https_action (str, optional): HTTPS action (Allow/Deny). Defaults to Deny.
                - follow_http_action (str, optional): '1' to enable, '0' to disable. Defaults to 1.
                - schedule (str, optional): Schedule name. Defaults to 'All The Time'
                - policy_rule_enabled (str, optional): '1' to enable, '0' to disable. Defaults to 1.
                - ccl_rule_enabled (str, optional): '1' to enable, '0' to disable. Defaults to 0.
            rule_action (str, optional): Action for rules ('add' or 'replace'). To remove rules, use 'replace' with the new complete list. Defaults to "add".
            
        Returns:
            dict: XML response converted to Python dictionary
        """
        return WebFilterPolicy(self.client).update(
            name=name,
            default_action=default_action,
            enable_reporting=enable_reporting,
            download_file_size_restriction=download_file_size_restriction,
            download_file_size_restriction_enabled=download_file_size_restriction_enabled,
            goog_app_domain_list=goog_app_domain_list,
            goog_app_domain_list_enabled=goog_app_domain_list_enabled,
            youtube_filter_is_strict=youtube_filter_is_strict,
            youtube_filter_enabled=youtube_filter_enabled,
            enforce_safe_search=enforce_safe_search,
            enforce_image_licensing=enforce_image_licensing,
            xff_enabled=xff_enabled,
            office_365_tenants_list=office_365_tenants_list,
            office_365_directory_id=office_365_directory_id,
            office_365_enabled=office_365_enabled,
            quota_limit=quota_limit,
            description=description,
            rules=rules,
            rule_action=rule_action,
            debug=debug
        )

# Export the error classes for backward compatibility
__all__ = [
    "SophosFirewall",
    "SophosFirewallZeroRecords",
    "SophosFirewallAPIError",
    "SophosFirewallAuthFailure",
    "SophosFirewallInvalidArgument",
    "SophosFirewallOperatorError",
]
