"""
Copyright 2023 Sophos Ltd.  All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing
permissions and limitations under the License.
"""


class AclRule:
    """Class for working with ACL Exception Rules."""

    def __init__(self, api_client):
        self.client = api_client

    def get(self, name=None, operator="="):
        """Get ACL rules

        Args:
            name (str, optional): Name of rule to retrieve. Returns all if not specified.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like.

        Returns:
            dict: XML response converted to Python dictionary
        """
        if name:
            return self.client.get_tag_with_filter(
                xml_tag="LocalServiceACL", key="Name", value=name, operator=operator
            )
        return self.client.get_tag(xml_tag="LocalServiceACL")

    def update(self, host_list, service_list, action, debug):
        """Update Local Service ACL (System > Administration > Device Access > Local service ACL exception)

        Args:
            host_list (list, optional): List of network or host groups. Defaults to [].
            service_list (list, optional): List of services. Defaults to [].
            action (str, optional): Indicate 'add' or 'remove' from list. Default is 'add'.
            verify (bool, optional): SSL Certificate checking. Defaults to True.
            debug (bool, optional): Enable debug mode. Defaults to False.
        """
        if action:
            self.client.validate_arg(
                arg_name="action", arg_value=action, valid_choices=["add", "remove"]
            )
        resp = self.get()

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
        resp = self.client.submit_template(
            "updateserviceacl.j2", template_vars=template_vars, debug=debug
        )

        return resp


class Notification:
    """Class for working with Notification settings."""

    def __init__(self, api_client):
        self.client = api_client

    def get(self, name):
        """Get notification.

        Args:
            name (str, optional): Name of notification. Returns all if not specified.

        Returns:
            dict: XML response converted to Python dictionary
        """
        if name:
            return self.client.get_tag_with_filter(
                xml_tag="Notification", key="Name", value=name
            )
        return self.client.get_tag(xml_tag="Notification")
