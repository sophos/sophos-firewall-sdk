"""
Copyright 2023 Sophos Ltd.  All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing
permissions and limitations under the License.
"""


class Interface:
    """Class for working with Interface(s)."""

    def __init__(self, api_client):
        self.client = api_client

    def get(self, name, operator):
        """Get Interface object(s)

        Args:
            name (str, optional): Interface name. Returns all objects if not specified.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like.
        """
        if name:
            return self.client.get_tag_with_filter(
                xml_tag="Interface", key="Name", value=name, operator=operator
            )
        return self.client.get_tag(xml_tag="Interface")


class Vlan:
    """Class for working with Vlan(s)."""

    def __init__(self, api_client):
        self.client = api_client

    def get(self, name, operator):
        """Get VLAN object(s)

        Args:
            name (str, optional): VLAN name. Returns all objects if not specified.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like.
        """
        if name:
            return self.client.get_tag_with_filter(
                xml_tag="VLAN", key="Name", value=name, operator=operator
            )
        return self.client.get_tag(xml_tag="VLAN")


class Zone:
    """Class for working with Zone(s)."""

    def __init__(self, api_client):
        self.client = api_client

    def get(self, name, operator):
        """Get zone(s)

        Args:
            name (str, optional): Name of zone to query. Returns all if not specified.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like.

        Returns:
            dict: XML response converted to Python dictionary
        """
        if name:
            return self.client.get_tag_with_filter(
                xml_tag="Zone", key="Name", value=name, operator=operator
            )
        return self.client.get_tag(xml_tag="Zone")
