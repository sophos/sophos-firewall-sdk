"""
Copyright 2023 Sophos Ltd.  All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing
permissions and limitations under the License.
"""
from sophosfirewall_python.api_client import SophosFirewallInvalidArgument


class FirewallRuleGroup:
    """Class for working with firewall rule group(s)."""

    def __init__(self, api_client):
        self.client = api_client

    def get(self, name, operator="="):
        """Get firewall rule group(s)

        Args:
            name (str, optional): Firewall Rule Group name.  Returns all rule groups if not specified.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like.
        """
        if name:
            return self.client.get_tag_with_filter(
                xml_tag="FirewallRuleGroup", key="Name", value=name, operator=operator
            )
        return self.client.get_tag(xml_tag="FirewallRuleGroup")

    def create(
        self,
        name,
        description,
        policy_list,
        source_zones,
        dest_zones,
        policy_type,
        debug,
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
        if "Any" in source_zones:
            source_zones = None
        if "Any" in dest_zones:
            dest_zones = None

        template_vars = dict(
            name=name,
            description=description,
            policy_list=policy_list,
            source_zones=source_zones,
            dest_zones=dest_zones,
            policy_type=policy_type,
        )

        resp = self.client.submit_template(
            "createfwrulegroup.j2", template_vars=template_vars, debug=debug
        )
        return resp

    def update(
        self,
        name,
        description,
        policy_list,
        source_zones,
        dest_zones,
        policy_type,
        source_zone_action,
        dest_zone_action,
        debug,
    ):
        """Update a firewall rule group.

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

        # Get the existing rule group
        exist_rulegroup = self.get(name=name)["Response"]["FirewallRuleGroup"]

        updated_params = dict(name=name)

        if description:
            updated_params["description"] = description
        else:
            updated_params["description"] = exist_rulegroup["Description"]

        if policy_list:
            if isinstance(exist_rulegroup["SecurityPolicyList"]["SecurityPolicy"], list):
                updated_params["policy_list"] = (
                    policy_list + exist_rulegroup["SecurityPolicyList"]["SecurityPolicy"]
                )
            elif isinstance(exist_rulegroup["SecurityPolicyList"]["SecurityPolicy"], str):
                policy_list.append(exist_rulegroup["SecurityPolicyList"]["SecurityPolicy"])
                updated_params["policy_list"] = policy_list
        else:
            if isinstance(exist_rulegroup["SecurityPolicyList"]["SecurityPolicy"], list):
                updated_params["policy_list"] = exist_rulegroup["SecurityPolicyList"]["SecurityPolicy"]
            elif isinstance(exist_rulegroup["SecurityPolicyList"]["SecurityPolicy"], str):
                updated_params["policy_list"] = [exist_rulegroup["SecurityPolicyList"]["SecurityPolicy"]]

        if source_zones:
            if source_zone_action == "add":
                if exist_rulegroup.get("SourceZones"):
                    if isinstance(exist_rulegroup["SourceZones"]["Zone"], list):
                        updated_params["source_zones"] = (
                            source_zones + exist_rulegroup["SourceZones"]["Zone"]
                        )
                    elif isinstance(exist_rulegroup["SourceZones"]["Zone"], str):
                        source_zones.append(exist_rulegroup["SourceZones"]["Zone"])
                        updated_params["source_zones"] = source_zones
                else:
                    updated_params["source_zones"] = source_zones
            elif source_zone_action == "remove":
                for zone in source_zones:
                    try:
                        exist_rulegroup["SourceZones"]["Zone"].remove(zone)
                    except ValueError:
                        continue
                updated_params["source_zones"] = exist_rulegroup["SourceZones"]["Zone"]
            elif source_zone_action == "replace":
                if "Any" in source_zones:
                    updated_params["source_zones"] = None
                else:
                    updated_params["source_zones"] = source_zones
            else:
                raise SophosFirewallInvalidArgument(
                    "Invalid source_zone_action argument specified!"
                )
        else:
            if exist_rulegroup.get("SourceZones"):
                if isinstance(exist_rulegroup["SourceZones"]["Zone"], list):
                    updated_params["source_zones"] = exist_rulegroup["SourceZones"]["Zone"]
                elif isinstance(exist_rulegroup["SourceZones"]["Zone"], str):
                    updated_params["source_zones"] = [exist_rulegroup["SourceZones"]["Zone"]]

        if dest_zones:
            if dest_zone_action == "add":
                if exist_rulegroup.get("DestinationZones"):
                    if isinstance(exist_rulegroup["DestinationZones"]["Zone"], list):
                        updated_params["dest_zones"] = (
                            dest_zones + exist_rulegroup["DestinationZones"]["Zone"]
                        )
                    elif isinstance(exist_rulegroup["DestinationZones"]["Zone"], str):
                        dest_zones.append(exist_rulegroup["DestinationZones"]["Zone"])
                        updated_params["dest_zones"] = dest_zones
                else:
                    updated_params["dest_zones"] = dest_zones
            elif dest_zone_action == "remove":
                for zone in dest_zones:
                    try:
                        exist_rulegroup["DestinationZones"]["Zone"].remove(zone)
                    except ValueError:
                        continue
                updated_params["dest_zones"] = exist_rulegroup["DestinationZones"]["Zone"]
            elif dest_zone_action == "replace":
                if "Any" in dest_zones:
                    updated_params["dest_zones"] = None
                else:
                    updated_params["dest_zones"] = dest_zones
            else:
                raise SophosFirewallInvalidArgument(
                    "Invalid dest_zone_action argument specified!"
                )
        else:
            if exist_rulegroup.get("DestinationZones"):
                if isinstance(exist_rulegroup["DestinationZones"]["Zone"], list):
                    updated_params["dest_zones"] = exist_rulegroup["DestinationZones"]["Zone"]
                elif isinstance(exist_rulegroup["DestinationZones"]["Zone"], str):
                    updated_params["dest_zones"] = [exist_rulegroup["DestinationZones"]["Zone"]]

        if policy_type:
            updated_params["policy_type"] = policy_type
        else:
            updated_params["policy_type"] = exist_rulegroup["Policytype"]

        resp = self.client.submit_template(
            "updatefwrulegroup.j2", template_vars=updated_params, debug=debug
        )

        return resp
