"""
Copyright 2023 Sophos Ltd.  All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing
permissions and limitations under the License.
"""
from sophosfirewall_python.utils import Utils

class FirewallRule:
    """Class for working with firewall rule(s)."""

    def __init__(self, api_client):
        self.client = api_client

    def get(self, name, operator="="):
        """Get firewall rule(s)

        Args:
            name (str, optional): Firewall Rule name.  Returns all rules if not specified.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like.
        """
        if name:
            return self.client.get_tag_with_filter(
                xml_tag="FirewallRule", key="Name", value=name, operator=operator
            )
        return self.client.get_tag(xml_tag="FirewallRule")

    def create(self, rule_params, debug):
        """Create a firewall rule

        Args:
            rule_params (dict): Configuration parmeters for the rule, see Keyword Args for supported parameters.

        Keyword Args:
            rulename(str): Name of the firewall rule
            status(str): Enable/Disable
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
        resp = self.client.submit_template(
            "createfwrule.j2", template_vars=rule_params, debug=debug
        )
        return resp

    def update(self, name, rule_params, debug):
        """Update a firewall rule.

        Args:
            name(str): Name of the firewall rule to be updated
            rule_params (dict): Configuration parmeters for the rule, see Keyword Args for supported parameters.

        Keyword Args:
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
        updated_rule_params = dict(rulename=name)

        # Get the existing rule
        exist_rule = self.get(name=name)["Response"]["FirewallRule"]

        if rule_params.get("action"):
            updated_rule_params["action"] = rule_params.get("action")
        else:
            updated_rule_params["action"] = exist_rule["NetworkPolicy"]["Action"]
        
        if rule_params.get("description"):
            updated_rule_params["description"] = rule_params.get("description")
        else:
            updated_rule_params["description"] = exist_rule["Description"]

        if rule_params.get("status"):
            updated_rule_params["status"] = rule_params.get("status")

        if rule_params.get("position"):
            updated_rule_params["position"] = rule_params.get("position")

        if rule_params.get("after_rulename"):
            updated_rule_params["after_rulename"] = rule_params.get("after_rulename")
        
        if rule_params.get("before_rulename"):
            updated_rule_params["before_rulename"] = rule_params.get("before_rulename")

        if rule_params.get("log"):
            updated_rule_params["log"] = rule_params.get("log")
        else:
            updated_rule_params["log"] = exist_rule["NetworkPolicy"]["LogTraffic"]

        if rule_params.get("src_zones"):
            updated_rule_params["src_zones"] = rule_params.get("src_zones")
        else:
            if "SourceZones" in exist_rule["NetworkPolicy"]:
                updated_rule_params["src_zones"] = Utils.ensure_list(exist_rule["NetworkPolicy"]["SourceZones"]["Zone"])
            else:
                updated_rule_params["src_zones"] = None

        if rule_params.get("dst_zones"):
            updated_rule_params["dst_zones"] = rule_params.get("dst_zones")
        else:
            if "DestinationZones" in exist_rule["NetworkPolicy"]:
                updated_rule_params["dst_zones"] = Utils.ensure_list(exist_rule["NetworkPolicy"]["DestinationZones"]["Zone"])
            else:
                updated_rule_params["dst_zones"] = None

        if rule_params.get("src_networks"):
            updated_rule_params["src_networks"] = rule_params.get("src_networks")
        else:
            if "SourceNetworks" in exist_rule["NetworkPolicy"]:
                updated_rule_params["src_networks"] = Utils.ensure_list(exist_rule["NetworkPolicy"]["SourceNetworks"]["Network"])
            else:
                updated_rule_params["src_networks"] = None

        if rule_params.get("dst_networks"):
            updated_rule_params["dst_networks"] = rule_params.get("dst_networks")
        else:
            if "DestinationNetworks" in exist_rule["NetworkPolicy"]:
                updated_rule_params["dst_networks"] = Utils.ensure_list(exist_rule["NetworkPolicy"]["DestinationNetworks"]["Network"])
            else:
                updated_rule_params["dst_networks"] = None

        if rule_params.get("service_list"):
            updated_rule_params["service_list"] = rule_params.get("service_list")
        else:
            if "Services" in exist_rule["NetworkPolicy"]:
                updated_rule_params["service_list"] = Utils.ensure_list(exist_rule["NetworkPolicy"]["Services"]["Service"])
            else:
                updated_rule_params["service_list"] = None

        resp = self.client.submit_template(
            "updatefwrule.j2", template_vars=updated_rule_params, debug=debug
        )
        return resp