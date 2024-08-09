"""
Copyright 2023 Sophos Ltd.  All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing
permissions and limitations under the License.
"""
from sophosfirewall_python.utils import Utils

class AclRule:
    """Class for working with Local Service ACL Exception Rules."""

    def __init__(self, api_client):
        self.client = api_client

    def get(self, name=None, operator="="):
        """Get Local ACL Exception rules

        Args:
            name (str, optional): Name of rule to retrieve. Returns all if not specified.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like.

        Returns:
            dict: XML response converted to Python dictionary
        """
        if name:
            return self.client.get_tag_with_filter(
                xml_tag="LocalServiceACL", key="RuleName", value=name, operator=operator
            )
        return self.client.get_tag(xml_tag="LocalServiceACL")
    
    def create(self, name, description, position, source_zone, source_list, dest_list, service_list, action, debug):
        """Create Local Service ACL Exception Rule (System > Administration > Device Access > Local service ACL exception)

        Args:
            name (str): Name of the ACL exception rule to update.
            description (str): Rule description.
            position (str): Location to place the ACL (Top or Bottom). 
            source_zone (str): Source Zone. Defaults to Any. 
            source_list (list, optional): List of source network or host groups. Defaults to None.
            dest_list (list, optional): List of destination hosts. Defaults to None.
            service_list (list, optional): List of services. Defaults to None.
            action (str, optional): Accept or Drop. Default is Accept.
            debug (bool, optional): Enable debug mode. Defaults to False.
        """
        template_vars = {
            "name": name,
            "description": description,
            "position": position,
            "source_zone": source_zone,
            "source_list": source_list,
            "dest_list": dest_list,
            "service_list": service_list,
            "action": action
        }
        resp = self.client.submit_template(
            "createserviceacl.j2", template_vars=template_vars, debug=debug
        )

        return resp

    def update(self, name, description, source_zone, source_list, dest_list, service_list, action, update_action, debug):
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
        if update_action:
            self.client.validate_arg(
                arg_name="update_action", arg_value=update_action, valid_choices=["add", "remove", "replace"]
            )

        if action:
            self.client.validate_arg(
                arg_name="action", arg_value=action.lower(), valid_choices=["accept", "drop"]
            )

        resp = self.get(name=name)

        if not source_zone:
            source_zone = resp["Response"]["LocalServiceACL"]["SourceZone"]

        if not description:
            description = resp["Response"]["LocalServiceACL"]["Description"]

        if not action:
            action = resp["Response"]["LocalServiceACL"]["Action"]

        if "Host" in resp["Response"]["LocalServiceACL"]["Hosts"]:
            exist_sources = Utils.ensure_list(resp["Response"]["LocalServiceACL"]["Hosts"]["Host"])
        else:
            exist_sources = []
        if "DstHost" in resp["Response"]["LocalServiceACL"]["Hosts"]:    
            exist_dests = Utils.ensure_list(resp["Response"]["LocalServiceACL"]["Hosts"]["DstHost"])
        else:
            exist_dests = []
        if "Service" in resp["Response"]["LocalServiceACL"]["Services"]:
            exist_services = Utils.ensure_list(resp["Response"]["LocalServiceACL"]["Services"]["Service"])
        else:
            exist_services = []

        if not source_list:
            source_list = []
        if not dest_list:
            dest_list = []
        if not service_list:
            service_list = []

        if update_action == "add":
            template_vars = {
                "name": name,
                "description": description,
                "source_zone": source_zone,
                "source_list": exist_sources + source_list,
                "dest_list": exist_dests + dest_list,
                "service_list": exist_services + service_list,
                "action": action
            }
        elif update_action == "replace":
            template_vars = {
                "name": name,
                "description": description,
                "source_zone": source_zone,
                "source_list": source_list if source_list else exist_sources,
                "dest_list": dest_list if dest_list else exist_dests,
                "service_list": service_list if service_list else exist_services,
                "action": action
            }
        elif update_action == "remove":
            for host in source_list:
                exist_sources.remove(host)
            for host in dest_list:
                exist_dests.remove(host)
            for service in service_list:
                exist_services.remove(service)
            template_vars = {
                "name": name,
                "description": description,
                "source_zone": source_zone,
                "source_list": exist_sources,
                "dest_list": exist_dests,
                "service_list": exist_services,
                "action": action
            }

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
