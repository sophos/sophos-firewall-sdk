"""
Copyright 2023 Sophos Ltd.  All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing
permissions and limitations under the License.
"""


class Retention:
    """Class for working with Report Retention settings."""

    def __init__(self, api_client):
        self.client = api_client

    def get(self, name):
        """Get Reports retention period.

        Args:
            name (str, optional): Name of backup schedule. Returns all if not specified.

        Returns:
            dict: XML response converted to Python dictionary
        """
        if name:
            return self.client.get_tag_with_filter(
                xml_tag="DataManagement", key="Name", value=name
            )
        return self.client.get_tag(xml_tag="DataManagement")
