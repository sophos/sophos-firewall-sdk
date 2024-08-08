"""
Copyright 2023 Sophos Ltd.  All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing
permissions and limitations under the License.
"""
from sophosfirewall_python.utils import Utils
from sophosfirewall_python.api_client import SophosFirewallInvalidArgument


class IPHost:
    """Class for working with IP Host(s)."""

    def __init__(self, api_client):
        self.client = api_client

    def get(self, name, ip_address, operator):
        """Get IP Host object(s)

        Args:
            name (str, optional): IP object name. Returns all objects if not specified.
            ip_address (str, optional): Query by IP Address.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like.
        """
        if name:
            return self.client.get_tag_with_filter(
                xml_tag="IPHost", key="Name", value=name, operator=operator
            )
        if ip_address:
            return self.client.get_tag_with_filter(
                xml_tag="IPHost",
                key="IPAddress",
                value=ip_address,
                operator=operator,
            )
        return self.client.get_tag(xml_tag="IPHost")

    def create(self, name, ip_address, mask, start_ip, end_ip, host_type, debug):
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
        self.client.validate_arg("host_type", host_type, ["IP", "Network", "IPRange"])

        if host_type == "IP":
            Utils.validate_ip_address(ip_address)
            params = {"name": name, "ip_address": ip_address, "host_type": host_type}

        if host_type == "Network":
            Utils.validate_ip_network(ip_address, mask)
            params = {
                "name": name,
                "ip_address": ip_address,
                "mask": mask,
                "host_type": host_type,
            }

        if host_type == "IPRange":
            Utils.validate_ip_address(start_ip)
            Utils.validate_ip_address(end_ip)
            params = {
                "name": name,
                "start_ip": start_ip,
                "end_ip": end_ip,
                "host_type": host_type,
            }

        resp = self.client.submit_template(
            "createiphost.j2", template_vars=params, debug=debug
        )

        return resp


class IPHostGroup:
    """Class for working with IP Host Group(s)."""

    def __init__(self, api_client):
        self.client = api_client

    def get(self, name, operator="="):
        """Get IP Host object(s)

        Args:
            name (str, optional): IP object name. Returns all objects if not specified.
            ip_address (str, optional): Query by IP Address.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like.
        """
        if name:
            return self.client.get_tag_with_filter(
                xml_tag="IPHostGroup",
                key="Name",
                value=name,
                operator=operator,
            )
        return self.client.get_tag(xml_tag="IPHostGroup")

    def create(self, name, host_list, description, debug):
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
        resp = self.client.submit_template(
            "createiphostgroup.j2", template_vars=params, debug=debug
        )
        return resp

    def update(self, name, host_list, description, action, debug):
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
        if action:
            self.client.validate_arg(
                arg_name="action",
                arg_value=action,
                valid_choices=["add", "remove", "replace"],
            )

        resp = self.get(name=name)
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
        resp = self.client.submit_template(
            "updateiphostgroup.j2", template_vars=params, debug=debug
        )
        return resp


class FQDNHost:
    """Class for working with FQDN Hosts."""

    def __init__(self, api_client):
        self.client = api_client

    def get(self, name, operator="="):
        """Get FQDN Host object(s)

        Args:
            name (str, optional): FQDN Host name. Returns all objects if not specified.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like.
        """
        if name:
            return self.client.get_tag_with_filter(
                xml_tag="FQDNHost", key="Name", value=name, operator=operator
            )

        return self.client.get_tag(xml_tag="FQDNHost")

    def create(self, name, fqdn, fqdn_group_list, description, debug):
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
        params = {
            "name": name,
            "description": description,
            "fqdn": fqdn,
            "fqdn_group_list": fqdn_group_list,
        }
        resp = self.client.submit_template(
            "createfqdnhost.j2", template_vars=params, debug=debug
        )
        return resp

    def update(self, name, fqdn_host_list, description, action, debug):
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
        if action:
            self.client.validate_arg(
                arg_name="action",
                arg_value=action,
                valid_choices=["add", "remove", "replace"],
            )

        resp = self.get(name=name)
        if "FQDNHostList" in resp["Response"]["FQDNHostGroup"]:
            exist_list = (
                resp.get("Response")
                .get("FQDNHostGroup")
                .get("FQDNHostList")
                .get("FQDNHost")
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
        for fqdn_host in fqdn_host_list:
            if action:
                if action.lower() == "add" and not fqdn_host in new_host_list:
                    new_host_list.append(fqdn_host)
                elif action.lower() == "remove" and fqdn_host in new_host_list:
                    new_host_list.remove(fqdn_host)
                elif action.lower() == "replace":
                    new_host_list.append(fqdn_host)
        if not description:
            description = resp.get("Response").get("FQDNHostGroup").get("Description")

        params = {
            "name": name,
            "description": description,
            "fqdn_host_list": new_host_list,
        }
        resp = self.client.submit_template(
            "updatefqdnhostgroup.j2", template_vars=params, debug=debug
        )
        return resp


class FQDNHostGroup:
    """Class for working with FQDN HostGroup(s)."""

    def __init__(self, api_client):
        self.client = api_client

    def get(self, name, operator="="):
        """Get FQDN HostGroup object(s)

        Args:
            name (str, optional): FQDN HostGroup name. Returns all objects if not specified.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like.
        """
        if name:
            return self.client.get_tag_with_filter(
                xml_tag="FQDNHostGroup", key="Name", value=name, operator=operator
            )

        return self.client.get_tag(xml_tag="FQDNHostGroup")

    def create(self, name, fqdn_host_list, description, debug):
        """Create FQDN HostGroup object.

        Args:
            name (str): Name of the object.
            fqdn_host_list (list, optional): List containing FQDN Host(s) to associate the FQDN Host Group.
            description (str): Description.
            debug (bool, optional): Turn on debugging. Defaults to False.
        Returns:
            dict: XML response converted to Python dictionary.
        """
        params = {
            "name": name,
            "description": description,
            "fqdn_host_list": fqdn_host_list,
        }
        resp = self.client.submit_template(
            "createfqdnhostgroup.j2", template_vars=params, debug=debug
        )
        return resp

    def update(self, name, description, fqdn_host_list, action, debug):
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
        if action:
            self.client.validate_arg(
                arg_name="action",
                arg_value=action,
                valid_choices=["add", "remove", "replace"],
            )

        resp = self.get(name=name)
        if "FQDNHostList" in resp["Response"]["FQDNHostGroup"]:
            exist_list = (
                resp.get("Response")
                .get("FQDNHostGroup")
                .get("FQDNHostList")
                .get("FQDNHost")
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
        for fqdn_host in fqdn_host_list:
            if action:
                if action.lower() == "add" and not fqdn_host in new_host_list:
                    new_host_list.append(fqdn_host)
                elif action.lower() == "remove" and fqdn_host in new_host_list:
                    new_host_list.remove(fqdn_host)
                elif action.lower() == "replace":
                    new_host_list.append(fqdn_host)
        if not description:
            description = resp.get("Response").get("FQDNHostGroup").get("Description")

        params = {
            "name": name,
            "description": description,
            "fqdn_host_list": new_host_list,
        }
        resp = self.client.submit_template(
            "updatefqdnhostgroup.j2", template_vars=params, debug=debug
        )
        return resp


class URLGroup:
    """Class for working with URL Group(s)."""

    def __init__(self, api_client):
        self.client = api_client

    def get(self, name, operator="="):
        """Get URLGroup(s)

        Args:
            name (str, optional): Get URLGroup by name. Defaults to None.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like.

        Returns:
            dict
        """
        if name:
            return self.client.get_tag_with_filter(
                xml_tag="WebFilterURLGroup", key="Name", operator=operator, value=name
            )
        return self.client.get_tag(xml_tag="WebFilterURLGroup")

    def create(self, name, domain_list, debug):
        """Create a web URL Group

        Args:
            name (str): URL Group name.
            domain_list (list): List of domains to added/removed/replaced.
            debug (bool, optional): Enable debug mode. Defaults to False.

        Returns:
            dict: XML response converted to Python dictionary
        """
        params = {"name": name, "domain_list": domain_list}
        resp = self.client.submit_template(
            "createurlgroup.j2", template_vars=params, debug=debug
        )
        return resp

    def update(self, name, domain_list, action, debug):
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
            self.client.validate_arg(
                arg_name="action",
                arg_value=action,
                valid_choices=["add", "remove", "replace"],
            )

        # Get the existing URL list first, if any
        resp = self.get(name=name)
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
        resp = self.client.submit_template(
            "updateurlgroup.j2", template_vars=params, debug=debug
        )
        return resp


class IPNetwork:
    """Class for working with Host of type Network."""

    def __init__(self, api_client):
        self.client = api_client

    def create(self, name, ip_network, mask, debug):
        """Create IP Host of type Network.

        Args:
            name (str): Name of the object
            ip_network (str): IP network address
            mask (str): Subnet mask in dotted decimal format (ex. 255.255.255.0)
            debug (bool, optional): Turn on debugging. Defaults to False.
        Returns:
            dict: XML response converted to Python dictionary
        """
        Utils.validate_ip_network(ip_network, mask)

        params = {"name": name, "ip_network": ip_network, "mask": mask}
        resp = self.client.submit_template(
            "createipnetwork.j2", template_vars=params, debug=debug
        )
        return resp


class IPRange:
    """Class for working with Host of type IPRange."""

    def __init__(self, api_client):
        self.client = api_client

    def create(self, name, start_ip, end_ip, debug):
        """Create IP Host of type IPRange.

        Args:
            name (str): Name of the object
            start_ip (str): Starting IP address
            end_ip (str): Ending IP address
            debug (bool, optional): Turn on debugging. Defaults to False.
        Returns:
            dict: XML response converted to Python dictionary
        """
        Utils.validate_ip_address(start_ip)
        Utils.validate_ip_address(end_ip)

        params = {"name": name, "start_ip": start_ip, "end_ip": end_ip}
        resp = self.client.submit_template(
            "createiprange.j2", template_vars=params, debug=debug
        )
        return resp
