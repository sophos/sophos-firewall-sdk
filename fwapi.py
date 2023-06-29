import requests
import xmltodict
import urllib3
from jinja2 import Environment, FileSystemLoader
from ipaddress import IPv4Network, IPv4Address

urllib3.disable_warnings()

class IPAddressingError(Exception):
    pass

class SophosFirewall:
    def __init__(self, username, password, hostname, port):
        self.username = username
        self.password = password
        self.hostname = hostname
        self.port = port
        self.url = f"https://{hostname}:{port}/webconsole/APIController"

    # INTERNAL UTILITY CLASS METHODS

    def validate_ip_network(self, ip_subnet, mask):
        """Validate IP network and mask

        Args:
            ip_subnet (str): IP network address
            mask (str): Subnet mask

        Raises:
            IPAddressingError: Custom error class
        """
        try:
            IPv4Network(f"{ip_subnet}/{mask}")
        except Exception as e:
            raise IPAddressingError(f"Invalid network or mask provided - {ip_subnet}/{mask}")
        
    def validate_ip_address(self, ip_address):
        """Validate IP network and mask

        Args:
            ip_subnet (str): IP network address
            mask (str): Subnet mask

        Raises:
            IPAddressingError: Custom error class
        """
        try:
            IPv4Address(ip_address)
        except Exception as e:
            raise IPAddressingError(f"Invalid IP address provided - {ip_address}")


    def post(self, xmldata: str, verify: bool = True) -> requests.Response:
        """Post XML request to the firewall returning response as a dict object

        Args:
            xmldata (str): XML payload
            verify (bool):  SSL certificate verification. Default=True.

        Returns:
            requests.Response object
        """
        headers = {
            "Accept": "application/xml"
        }
        resp = requests.post(self.url, headers=headers, data=dict(reqxml=xmldata), verify=verify)
        return resp
    
    def submit_template(self, filename: str, vars: dict = dict(), verify: bool = True, debug: bool = False) -> requests.Response:
        """Submits XML payload stored as a Jinja2 file

        Args:
            filename (str): Jinja2 template filename (must be in a directory called "templates")
            vars (dict): Dictionary of variables to inject into the template. Username and password are passed in by default.
            verify (bool, optional): SSL certificate verification. Defaults to True.

        Returns:
            requests.Response object
        """
        environment = Environment(trim_blocks=True, lstrip_blocks=True, loader=FileSystemLoader("templates"))
        template = environment.get_template(filename)
        vars["username"] = self.username
        vars["password"] = self.password
        payload = template.render(**vars)
        if debug == True:
            print(f"REQUEST: {payload}")
        resp = self.post(xmldata=payload, verify=verify)
        return resp
    
    def get_tag(self, xml_tag: str, verify: bool = True):
        """Execute a get for a specified XML tag. 

        Args:
            xml_tag (str): XML tag for the request
            verify (bool, optional): SSL certificate checking. Defaults to True.
        """
        payload = f'''
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
        '''
        resp = self.post(xmldata=payload, verify=verify)
        return xmltodict.parse(resp.content.decode())
    
    def get_tag_with_filter(self, xml_tag: str, key: str, value: str, operator: str = "like", verify: bool = True):
        """Execute a get for a specified XML tag with filter criteria.

        Args:
            xml_tag (str): XML tag for the request.
            key (str): Search key
            value (str): Search value
            operator (str, optional): Operator for search (“=”,”!=”,”like”). Defaults to "like".
            verify (bool): SSL certificate checking. Defaults to True. 
        """
        payload = f'''
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
        '''
        resp = self.post(xmldata=payload, verify=verify)
        return xmltodict.parse(resp.content.decode())
        
    # METHODS FOR OBJECT RETRIEVAL (GET)
    
    def get_fw_rule(self, name: str = None, verify: bool = True):
        """Get firewall rule(s)

        Args:
            name (str, optional): Firewall Rule name.  Returns all rules if not specified.
            verify (bool, optional): SSL certificate checking. Defaults to True.
            debug(bool, optional): Enable debug mode
        """
        if name:
            return self.get_tag_with_filter(xml_tag="FirewallRule", key="Name", value=name, operator="=", verify=verify)
        else:
            return self.get_tag(xml_tag="FirewallRule", verify=verify)
    
    
    def get_ip_address(self, name: str = None, verify: bool = True):
        """Get IP object(s)

        Args:
            name (str, optional): IP object name. Returns all objects if not specified. 
            verify (bool, optional): SSL certificate checking. Defaults to True.
        """
        if name:
            return self.get_tag_with_filter(xml_tag="IPHost", key="Name", value=name, operator="=", verify=verify)
        else:
            return self.get_tag(xml_tag="IPHost", verify=verify)
        
    def get_ip_hostgroup(self, name: str = None, verify: bool = True):
        """Get IP hostgroup(s)

        Args:
            name (str, optional): Name of IP host group. Returns all if not specified.
            verify (bool, optional): SSL certificate checking. Defaults to True.
        """
        if name:
            return self.get_tag_with_filter(xml_tag="IPHostGroup", key="Name", value=name, operator="=", verify=verify)
        else:
            return self.get_tag(xml_tag="IPHostGroup", verify=verify)
    
    def get_acl_rule(self, name: str = None, verify: bool = True):
        """Get ACL rules 

        Args:
            name (str, optional): Name of rule to retrieve. Returns all if not specified.
            verify (bool, optional):  Toggle on/off SSL certificate check.

        Returns:
            dict: XML response converted to Python dictionary
        """
        if name:
            return self.get_tag_with_filter(xml_tag="LocalServiceACL", key="Name", value=name, operator="=", verify=verify)
        else:
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
            return self.get_tag_with_filter(xml_tag="User", key="Name", value=name, operator="=", verify=verify)
        else:
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
            return self.get_tag_with_filter(xml_tag="AdministrationProfile", key="Name", value=name, operator="=", verify=verify)
        else:
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
            return self.get_tag_with_filter(xml_tag="Zone", key="Name", value=name, operator="=", verify=verify)
        else:
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
            return self.get_tag_with_filter(xml_tag="IPSPolicy", key="Name", value=name, verify=verify)
        else:
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
            return self.get_tag_with_filter(xml_tag="SyslogServers", key="Name", value=name, verify=verify)
        else:
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
            return self.get_tag_with_filter(xml_tag="Notification", key="Name", value=name, verify=verify)
        else:
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
            return self.get_tag_with_filter(xml_tag="NotificationList", key="Name", value=name, verify=verify)
        else:
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
            return self.get_tag_with_filter(xml_tag="BackupRestore", key="Name", value=name, verify=verify)
        else:
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
            return self.get_tag_with_filter(xml_tag="DataManagement", key="Name", value=name, verify=verify)
        else:
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

    # METHODS FOR OBJECT CREATION
    
    def create_rule(self, rule_params: dict, verify: bool = True, debug: bool = False):
        """Create a firewall rule

        Args:
            rule_params (dict): Configuration of the rule (see below)
            verify (bool, optional): SSL certificate checking. Defaults to True.

            rule_params (Required parameters):
              rulename(str): Name of the firewall rule
              after_rulename(str): Name of the rule to insert this rule after
              action(str): Accept, Drop, Reject
              log(str): Enable, Disable
              src_zones(list): Name(s) of the source zone(s)
              dst_zones(list): Name(s) of the destination zone(s)
              src_networks(list): Name(s) of the source network(s)
              dst_networks(list): Name(s) of the destination network(s)
              service_list(list): Name(s) of service(s)

            rule_params (Optional parameters NOT YET IMPLEMENTED):
              webfilter(str):  Default = Allow All
              blockquic(str):  Default = Enable
              scanvirus(str):  Default = Enable
              zeroday(str): Default = Disable
              proxymode(str): Default = Disable
              decrypthttps(str): Default = Enable
              appcontrol(str): Default = Allow All
              intrusionprevention(str): Default = None
              trafficshapingpolicy(str): Default = None
              scansmtp(str): Default = Disable
              scansmtps(str): Default = Disable
              scanimap(str): Default = Disable
        """
        resp = self.submit_template("createfwrule.j2", vars=rule_params, verify=verify, debug=debug)
        return resp
    
    def create_ip_network(self, name: str, ip_network: str, mask: str,  verify: bool = True, debug: bool = False):
        """Create IP address object

        Args:
            name (str): Name of the object
            ip_network (str): IP network address
            mask (str): Subnet mask
            verify (bool, optional): SSL certificate checking. Defaults to True.
            debug (bool, optional): Turn on debugging. Defaults to False.

        """
        self.validate_ip_network(ip_network, mask)

        params = dict(
            name=name,
            ip_network=ip_network,
            mask=mask
        )
        resp = self.submit_template("createipnetwork.j2", vars=params, verify=verify, debug=debug)
        return resp
    
    def create_ip_host(self, name: str, ip_address: str, verify: bool = True, debug: bool = False):
        """Create IP address object

        Args:
            name (str): Name of the object
            ip_address (str): Host IP address
            verify (bool, optional): SSL certificate checking. Defaults to True.
            debug (bool, optional): Turn on debugging. Defaults to False.

        """
        self.validate_ip_address(ip_address)

        params = dict(
            name=name,
            ip_address=ip_address
        )
        resp = self.submit_template("createiphost.j2", vars=params, verify=verify, debug=debug)
        return resp
    
    def create_ip_range(self, name: str, start_ip: str,  end_ip: str, verify: bool = True, debug: bool = False):
        """Create IP range object

        Args:
            name (str): Name of the object
            start_ip (str): Starting IP address
            end_ip (str): Ending IP address
            verify (bool, optional): SSL certificate checking. Defaults to True.
            debug (bool, optional): Turn on debugging. Defaults to False.
        """
        self.validate_ip_address(start_ip)
        self.validate_ip_address(end_ip)

        params = dict(
            name=name,
            start_ip=start_ip,
            end_ip=end_ip
        )
        resp = self.submit_template("createiprange.j2", vars=params, verify=verify, debug=debug)
        return resp
    
    def create_service(self, name: str, port: str,  protocol: str, verify: bool = True, debug: bool = False):
        """Create a TCP or UDP service

        Args:
            name (str): Service name
            port (str): TCP/UDP port
            protocol (str): TCP or UDP
            verify (bool, optional): SSL certificate verification. Defaults to True.
            debug (bool, optional): Enable debug mode. Defaults to False.

        """
        params = dict(
            name=name,
            port=port,
            protocol=protocol
        )
        resp = self.submit_template("createservice.j2", vars=params, verify=verify, debug=debug)
        return resp
    
    def create_hostgroup(self, name: str, description: str,  host_list: list, verify: bool = True, debug: bool = False):
        """Create a Host Group
        Args:
            name (str): Host Group name
            description (str): Host Group description
            host_list (list):  List of existing IP hosts to add to the group
            verify (bool, optional): SSL certificate verification. Defaults to True.
            debug (bool, optional): Enable debug mode. Defaults to False.

        """

        params = dict(
            name=name,
            description=description,
            host_list=host_list
        )
        resp = self.submit_template("createhostgroup.j2", vars=params, verify=verify, debug=debug)
        return resp
    
