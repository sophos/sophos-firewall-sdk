"""
Copyright 2023 Sophos Ltd.  All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing
permissions and limitations under the License.
"""
from sophosfirewall_python.api_client import SophosFirewallInvalidArgument


class Service:
    """Class for working with Service(s)."""

    def __init__(self, api_client):
        self.client = api_client

    def get(self, name, operator="=", dst_proto=None, dst_port=None):
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
            return self.client.get_tag_with_filter(
                xml_tag="Services", key="Name", value=name, operator=operator
            )
        if dst_proto and dst_port:
            resp = self.client.get_tag(xml_tag="Services")
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
        return self.client.get_tag(xml_tag="Services")

    def create(self, name, service_type, service_list, debug):
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
        params = {"name": name, "service_list": service_list, "type": service_type}
        resp = self.client.submit_template(
            "createservice.j2", template_vars=params, debug=debug
        )
        return resp

    def update(self, name, service_type, service_list, action, debug):
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
        if not isinstance(service_list, list):
            raise SophosFirewallInvalidArgument(
                "The update_service() argument `service_list` must be of type list!"
            )

        if action:
            self.client.validate_arg(
                arg_name="action",
                arg_value=action,
                valid_choices=["add", "remove", "replace"],
            )

        # Get the existing Service list first
        resp = self.get(name=name)
        if "ServiceDetail" in resp["Response"]["Services"]["ServiceDetails"]:
            exist_list = (
                resp.get("Response")
                .get("Services")
                .get("ServiceDetails")
                .get("ServiceDetail")
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
                if service_type == "TCPorUDP":
                    new_service_list.append(
                        {
                            "src_port": exist_list["SourcePort"],
                            "dst_port": exist_list["DestinationPort"],
                            "protocol": exist_list["Protocol"],
                        }
                    )
                if service_type == "IP":
                    new_service_list.append({"protocol": exist_list["ProtocolName"]})
                if service_type == "ICMP":
                    new_service_list.append(
                        {
                            "icmp_type": exist_list["ICMPType"],
                            "icmp_code": exist_list["ICMPCode"],
                        }
                    )
                if service_type == "ICMPv6":
                    new_service_list.append(
                        {
                            "icmp_type": exist_list["ICMPv6Type"],
                            "icmp_code": exist_list["ICMPv6Code"],
                        }
                    )
            elif isinstance(exist_list, list):
                for service in exist_list:
                    if service_type == "TCPorUDP":
                        new_service_list.append(
                            {
                                "src_port": service["SourcePort"],
                                "dst_port": service["DestinationPort"],
                                "protocol": service["Protocol"],
                            }
                        )
                    if service_type == "IP":
                        new_service_list.append({"protocol": service["ProtocolName"]})
                    if service_type == "ICMP":
                        new_service_list.append(
                            {
                                "icmp_type": service["ICMPType"],
                                "icmp_code": service["ICMPCode"],
                            }
                        )
                    if service_type == "ICMPv6":
                        new_service_list.append(
                            {
                                "icmp_type": service["ICMPv6Type"],
                                "icmp_code": service["ICMPv6Code"],
                            }
                        )
        for service in service_list:
            if action.lower() == "add" and service not in new_service_list:
                new_service_list.append(service)
            elif action.lower() == "remove" and service in new_service_list:
                new_service_list.remove(service)
            elif action.lower() == "replace":
                new_service_list.append(service)

        params = {"name": name, "service_list": new_service_list, "type": service_type}
        resp = self.client.submit_template(
            "updateservice.j2", template_vars=params, debug=debug
        )
        return resp


class ServiceGroup:
    """Class for working with Service Group(s)."""

    def __init__(self, api_client):
        self.client = api_client

    def get(self, name, operator="="):
        """Get Service Group object(s)

        Args:
            name (str, optional): Service Group name. Returns all objects if not specified.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like.
        """
        if name:
            return self.client.get_tag_with_filter(
                xml_tag="ServiceGroup", key="Name", value=name, operator=operator
            )

        return self.client.get_tag(xml_tag="ServiceGroup")

    def create(self, name, service_list, description, debug):
        """Create Service Group object.

        Args:
            name (str): Name of the object.
            service_list (list, optional): List containing Service(s) to associate the Services Group.
            description (str): Description.
            debug (bool, optional): Turn on debugging. Defaults to False.
        Returns:
            dict: XML response converted to Python dictionary.
        """
        params = {
            "name": name,
            "description": description,
            "service_list": service_list,
        }
        resp = self.client.submit_template(
            "createservicegroup.j2", template_vars=params, debug=debug
        )
        return resp

    def update(self, name, service_list, description, action, debug):
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
        if action:
            self.client.validate_arg(
                arg_name="action",
                arg_value=action,
                valid_choices=["add", "remove", "replace"],
            )

        resp = self.get(name=name)
        if "ServiceList" in resp["Response"]["ServiceGroup"]:
            exist_list = (
                resp.get("Response")
                .get("ServiceGroup")
                .get("ServiceList")
                .get("Service")
            )
        else:
            exist_list = None

        if action.lower() == "replace":
            exist_list = None

        new_service_list = []
        if exist_list:
            if isinstance(exist_list, str):
                new_service_list.append(exist_list)
            elif isinstance(exist_list, list):
                new_service_list = exist_list
        for service_name in service_list:
            if action:
                if action.lower() == "add" and not service_name in new_service_list:
                    new_service_list.append(service_name)
                elif action.lower() == "remove" and service_name in new_service_list:
                    new_service_list.remove(service_name)
                elif action.lower() == "replace":
                    new_service_list.append(service_name)
        if not description:
            description = resp.get("Response").get("ServiceGroup").get("Description")

        params = {
            "name": name,
            "description": description,
            "service_list": new_service_list,
        }
        resp = self.client.submit_template(
            "updateservicegroup.j2", template_vars=params, debug=debug
        )
        return resp
