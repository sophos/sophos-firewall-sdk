"""
Copyright 2023 Sophos Ltd.  All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing
permissions and limitations under the License.
"""


class FirewallRule:
    """Class for working with firewall rule(s)."""

    def __init__(self, api_client):
        self.client = api_client

    def get(self, name, operator):
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
        resp = self.client.submit_template(
            "createfwrule.j2", template_vars=rule_params, debug=debug
        )
        return resp
