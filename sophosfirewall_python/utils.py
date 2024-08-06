"""
Copyright 2023 Sophos Ltd.  All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing
permissions and limitations under the License.
"""
from ipaddress import IPv4Network, IPv4Address


class SophosFirewallIPAddressingError(Exception):
    """Error raised when invalid IP address detected"""


class Utils:
    """Class containing utility methods."""

    @staticmethod
    def validate_ip_network(ip_subnet, mask):
        """Validate IP network and mask

        Args:
            ip_subnet (str): IP network address
            mask (str): Subnet mask

        Raises:
            SophosFirewallIPAddressingError: Custom error class
        """
        try:
            IPv4Network(f"{ip_subnet}/{mask}")
        except Exception as exc:
            raise SophosFirewallIPAddressingError(
                f"Invalid network or mask provided - {ip_subnet}/{mask}"
            ) from exc

    @staticmethod
    def validate_ip_address(ip_address):
        """Validate IP address.

        Args:
            ip_address (str): IP address

        Raises:
            SophosFirewallIPAddressingError: Custom error class
        """
        try:
            IPv4Address(ip_address)
        except Exception as exc:
            raise SophosFirewallIPAddressingError(
                f"Invalid IP address provided - {ip_address}"
            ) from exc
    
    @staticmethod
    def ensure_list(val):
        """Checks whether provided object is a string or a list.
           If string, create a new list and append it to the list.
           If list, just return the list as-is. 

        Args:
            val (str or list): A string or a list
        """
        if isinstance(val, str):
            new_list = [val]
            return new_list
        return val