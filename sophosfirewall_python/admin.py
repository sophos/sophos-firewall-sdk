"""
Copyright 2023 Sophos Ltd.  All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing
permissions and limitations under the License.
"""
from sophosfirewall_python.utils import Utils
from xmltodict import unparse

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

class AdminSettings:
    """Class for working with Admin and user settings (System > Administration)."""

    def __init__(self, api_client):
        self.client = api_client

    def get(self):
        """Get Admin and user settings

        Returns:
            dict: XML response converted to Python dictionary
        """
        return self.client.get_tag(xml_tag="AdminSettings")
    
    def update_hostname_settings(self, hostname=None, description=None, debug=False):
        """Update hostname admin settings. 

        Args:
            hostname (str, optional): Hostname. Defaults to None.
            description (str, optional): Hostname description. Defaults to None.

        Returns:
            dict: XML response converted to Python dictionary
        """
        exist_settings = self.get()["Response"]["AdminSettings"]["HostnameSettings"]

        template_data = """
        <AdminSettings>
          <HostnameSettings>
            <HostName>{{ hostname }}</HostName>
            <HostNameDesc>{{ description }}</HostNameDesc>
          </HostnameSettings>
        </AdminSettings>
        """
        template_vars = {
            "hostname": hostname if hostname else exist_settings["HostName"],
            "description": description if description else exist_settings["HostNameDesc"]
            }

        return self.client.submit_xml(template_data=template_data, template_vars=template_vars, set_operation="update", debug=debug)
                
    def update_webadmin_settings(self, certificate=None,
                                 https_port=None,
                                 userportal_https_port=None,
                                 vpnportal_https_port=None,
                                 portal_redirect_mode=None,
                                 portal_custom_hostname=None,
                                 debug=False):
        """Update webadmin settings. System > Administration > Admin and user settings.

        Args:
            certificate (str, optional): SSL Certificate name. Defaults to None.
            https_port (str, optional): HTTPS port for admin interface. Defaults to None.
            userportal_https_port (str, optional): HTTPS port for User portal. Defaults to None.
            vpnportal_https_port (str, optional): HTTPS port for VPN portal. Defaults to None.
            portal_redirect_mode (str, optional): Portal redirect mode. Defaults to None.
            portal_custom_hostname (str, optional): Portal custom hostname. Defaults to None.

        Returns:
            dict: XML response converted to Python dictionary
        """
        exist_settings = self.get()["Response"]["AdminSettings"]["WebAdminSettings"]

        template_data = """
        <AdminSettings>
          <WebAdminSettings>
            <Certificate>{{ certificate }}</Certificate>
            <HTTPSport>{{ https_port }}</HTTPSport>
            <UserPortalHTTPSPort>{{ userportal_https_port }}</UserPortalHTTPSPort>
            <VPNPortalHTTPSPort>{{ vpnportal_https_port }}</VPNPortalHTTPSPort>
            <PortalRedirectMode>{{ portal_redirect_mode }}</PortalRedirectMode>
            <PortalCustomHostname>{{ port_custom_hostname }}</PortalCustomHostname>
          </WebAdminSettings>
        </AdminSettings>
        """
        template_vars = {
            "certificate": certificate if certificate else exist_settings["Certificate"],
            "https_port": https_port if https_port else exist_settings["HTTPSport"],
            "userportal_https_port": userportal_https_port if userportal_https_port else exist_settings["UserPortalHTTPSPort"],
            "vpnportal_https_port": vpnportal_https_port if vpnportal_https_port else exist_settings["VPNPortalHTTPSPort"],
            "portal_redirect_mode": portal_redirect_mode if portal_redirect_mode else exist_settings["PortalRedirectMode"],
            "portal_custom_hostname": portal_custom_hostname if portal_custom_hostname else exist_settings["PortalCustomHostname"]
            }

        return self.client.submit_xml(template_data=template_data, template_vars=template_vars, set_operation="update", debug=debug)

    def update_loginsecurity_settings(self, logout_session=None, block_login=None, unsuccessful_attempt=None, duration=None, minutes=None, debug=False):
        """Update login security admin settings. System > Administration > Admin and user settings.

        Args:
            logout_session (str, optional): Enable/disable logout session. Specify number of minutes to enable. Defaults to None.
            block_login (str, optional): Enable/disable block login. Defaults to None.
            unsuccessful_attempt (str, optional): Set number of unsuccessful attempts. Defaults to None.
            duration (str, optional): Set block login duration. Defaults to None.
            minutes (str, optional): Set number of minutes for block login. Defaults to None. 

        Returns:
            dict: XML response converted to Python dictionary
        """
        exist_settings = self.get()["Response"]["AdminSettings"]["LoginSecurity"]

        template_data = """
        <AdminSettings>
          <LoginSecurity>
            <LogoutSession>{{ logout_session }}</LogoutSession>
            <BlockLogin>{{ block_login }}</BlockLogin>
            {% if block_login == 'Enable' %}
            <BlockLoginSettings>
              <UnsucccessfulAttempt>{{ unsuccessful_attempt }}</UnsucccessfulAttempt>
              <Duration>{{ duration }}</Duration>
              <ForMinutes>{{ minutes }}</ForMinutes>
            </BlockLoginSettings>
            {% endif %}
          </LoginSecurity>
        </AdminSettings>
        """
        if not unsuccessful_attempt and "BlockLoginSettings" in exist_settings:
            unsuccessful_attempt = exist_settings["BlockLoginSettings"]["UnsucccessfulAttempt"]
        if not duration and "BlockLoginSettings" in exist_settings:
            duration = exist_settings["BlockLoginSettings"]["Duration"]
        if not minutes and "BlockLoginSettings" in exist_settings:
            minutes = exist_settings["BlockLoginSettings"]["ForMinutes"]
        template_vars = {
            "logout_session": logout_session if logout_session else exist_settings["LogoutSession"],
            "block_login": block_login if block_login else exist_settings["BlockLogin"],
            "unsuccessful_attempt": unsuccessful_attempt if unsuccessful_attempt else "5",
            "duration": duration if duration else "5",
            "minutes": minutes if minutes else "60"
            }

        return self.client.submit_xml(template_data=template_data, template_vars=template_vars, set_operation="update", debug=debug)
    
    def update_passwordcomplexity_settings(self, complexity_check=None, enforce_min_length=None, include_alpha=None, include_numeric=None, include_special=None, min_length=None, debug=False):
        """Update password complexity settings. System > Administration > Admin and user settings.

        Args:
            complexity_check (str, optional): Enable/disable password complexity check. Defaults to None.
            enforce_min_length (str, optional): Enforce minimum required password length. Defaults to None.
            include_alpha (str, optional): Enforce inclusion of alphanumeric characters. Defaults to None.
            include_numeric (str, optional): Enforce inclusion numeric characters. Defaults to None.
            include_special (str, optional): Enforce inclusion of special characters. Defaults to None. 
            min_length (str, optional): Minimul required password length. Defaults to None. 

        Returns:
            dict: XML response converted to Python dictionary
        """
        exist_settings = self.get()["Response"]["AdminSettings"]["PasswordComplexitySettings"]

        template_data = """
        <AdminSettings>
          <PasswordComplexitySettings>
            <PasswordComplexityCheck>{{ complexity_check }}</PasswordComplexityCheck>
            <PasswordComplexity>
              <MinimumPasswordLength>{{ enforce_min_length }}</MinimumPasswordLength>
              <IncludeAlphabeticCharacters>{{ include_alpha }}</IncludeAlphabeticCharacters>
              <IncludeNumericCharacter>{{ include_special }}</IncludeNumericCharacter>
              <IncludeSpecialCharacter>{{ include_special }}</IncludeSpecialCharacter>
              <MinimumPasswordLengthValue>{{ min_length }}</MinimumPasswordLengthValue>
            </PasswordComplexity>
          </PasswordComplexitySettings>
        </AdminSettings>
        """

        template_vars = {
            "complexity_check": complexity_check if complexity_check else exist_settings["PasswordComplexityCheck"],
            "enforce_min_length": enforce_min_length if enforce_min_length else exist_settings["PasswordComplexity"]["MinimumPasswordLength"],
            "include_alpha": include_alpha if include_alpha else exist_settings["PasswordComplexity"]["IncludeAlphabeticCharacters"],
            "include_numeric": include_numeric if include_numeric else exist_settings["PasswordComplexity"]["IncludeNumericCharacter"],
            "include_special": include_special if include_special else exist_settings["PasswordComplexity"]["IncludeSpecialCharacter"],
            "min_length": min_length if min_length else exist_settings["PasswordComplexity"]["MinimumPasswordLengthValue"]
            }

        return self.client.submit_xml(template_data=template_data, template_vars=template_vars, set_operation="update", debug=debug)
    
    def update_login_disclaimer(self, enabled: bool = False, debug: bool = False):
        """Update login disclaimer. System > Administration > Admin and user settings.

        Args:
            enabled (bool, optional): Enable or disable Login Disclaimer. Defaults to True.
        
        Returns:
            dict: XML response converted to Python dictionary
        """
        if enabled:
            setting = "Enable"
        else:
            setting = "Disable"

        template_data = """
            <AdminSettings>
              <LoginDisclaimer>{{ setting }}</LoginDisclaimer>
            </AdminSettings>
        """
        template_vars = {"setting": setting}

        return self.client.submit_xml(template_data=template_data, template_vars=template_vars, set_operation="update", debug=debug)
