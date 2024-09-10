"""
Copyright 2023 Sophos Ltd.  All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing
permissions and limitations under the License.
"""


class User:
    """Class for working with User(s)."""

    def __init__(self, api_client):
        self.client = api_client

    def get(self, name=None, username=None, operator="="):
        """Get local users

        Args:
            name (str, optional): User display name. Retrieves all users if not specified.
            username (str, optional): Username.  Retrieves all users if not specified.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like.

        Returns:
            dict: XML response converted to Python dictionary
        """
        if name:
            return self.client.get_tag_with_filter(
                xml_tag="User", key="Name", value=name, operator=operator
            )
        if username:
            return self.client.get_tag_with_filter(
                xml_tag="User", key="Username", value=username, operator=operator
            )
        return self.client.get_tag(xml_tag="User")

    def create(self, debug, **kwargs):
        """Create a User

        Args:
            debug: (bool, optional): Enable debug mode. Defaults to False.

        Keyword Args:
            user (str): Username
            name (str): User Display Name
            description (str): User description
            user_password (str): User password
            user_type (str): User Type (Administrator/User)
            profile (str): Profile name
            group (str): Group name
            email (str): User email address
            access_time_policy (str, optional): Access time policy
            sslvpn_policy (str, optional): SSL VPN policy
            clientless_policy (str, optional): Clientless policy
            l2tp (str, optional): L2TP Enable/Disable
            pptp (str, optional): PPTP Enable/Disable
            cisco (str, optional): CISCO Enable/Disable
            quarantine_digest (str, optional): Quarantine Digest Enable/Disable
            mac_binding (str, optional): MAC binding Enable/Disable
            login_restriction (str, optional): Login restriction. Default = UserGroupNode.
            isencryptcert (str, optional): Enable/Disable. Default = Disable.
            simultaneous_logins (str, optional): Enable/Disable simultaneous login.
            surfingquota_policy (str, optional): Surfing quota policy. Default = Unlimited.
            applianceaccess_schedule (str, optional): Schedule for appliance access.  Default = All The Time.
            login_restriction (str, optional): Login restriction for appliance. Default = AnyNode.

        Returns:
            dict: XML response converted to Python dictionary
        """
        resp = self.client.submit_template(
            "createuser.j2", template_vars=kwargs, debug=debug
        )
        return resp

    def update_user_password(self, username, new_password, debug):
        """Update user password.

        Args:
            username (str): Username
            new_password (str): New password. Must meet complexity requirements.
            debug (bool, optional): Enable debug mode. Defaults to False.

        Returns:
            dict: XML response converted to Python dictionary
        """
        # Get the existing user
        resp = self.get(username=username)
        user_params = resp["Response"]["User"]
        user_params["Password"] = new_password
        user_params.pop("PasswordHash")

        # Update the user
        resp = self.client.submit_template(
            "updateuserpassword.j2", template_vars=user_params, debug=debug
        )
        return resp

    def update_admin_password(self, current_password, new_password, debug):
        """Update the admin password.

        Args:
            current_password (str): Current admin password.
            new_password (str): New admin password. Must meet complexity requirements.
            debug (bool, optional): Enable debug mode. Defaults to False.

        Returns:
            dict: XML response converted to Python dictionary
        """
        params = {"current_password": current_password, "new_password": new_password}

        resp = self.client.submit_template(
            "updateadminpassword.j2", template_vars=params, debug=debug
        )
        return resp


class AdminAuthen:
    """Class for working with Admin Authentication Settings."""

    def __init__(self, api_client):
        self.client = api_client

    def get(self):
        """Get admin authentication settings

        Returns:
            dict: XML response converted to Python dictionary
        """
        return self.client.get_tag(xml_tag="AdminAuthentication")
