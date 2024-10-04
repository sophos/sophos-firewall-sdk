"""
Copyright 2023 Sophos Ltd.  All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing
permissions and limitations under the License.
"""


class AdminProfile:
    """Class for working with Administration Profile(s)."""

    def __init__(self, api_client):
        self.client = api_client

    def get(self, name, operator="="):
        """Get admin profiles

        Args:
            name (str, optional): Name of profile. Returns all if not specified.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like.

        Returns:
            dict: XML response converted to Python dictionary
        """
        if name:
            return self.client.get_tag_with_filter(
                xml_tag="AdministrationProfile",
                key="Name",
                value=name,
                operator=operator,
            )
        return self.client.get_tag(xml_tag="AdministrationProfile")
    
    def create(self, name: str, default_permission: str=None, debug: bool=False, **kwargs):
        """Create an administration profile.

        Args:
            name (str): Name of administration profile
            default_permission (str, optional): Permissions to use for unspecified settings (None, Read-Only, Read-Write). Defaults to None.
            debug (bool, optional): Turn on debugging. Defaults to False.

        Keyword Args:
            dashboard (str, optional): Dashboard permission (None, Read-Only, Read-Write). Defaults to None.
            wizard (str, optional): Wizard permission (None, Read-Only, Read-Write). Defaults to None.
            set_system_profile (str, optional): System Profile permission (None, Read-Only, Read-Write). Defaults to None.
            profile (str, optional): Profile permission (None, Read-Only, Read-Write). Defaults to None.
            system_password (str, optional): System Password permission (None, Read-Only, Read-Write). Defaults to None.
            central_management (str, optional): Central management permission (None, Read-Only, Read-Write). Defaults to None.
            backup (str, optional): Backup permission (None, Read-Only, Read-Write). Defaults to None.
            restore (str, optional): Restore permission (None, Read-Only, Read-Write). Defaults to None.
            firmware (str, optional): Firmware permission (None, Read-Only, Read-Write). Defaults to None.
            licensing (str, optional): Licensing permission (None, Read-Only, Read-Write). Defaults to None.
            services (str, optional): Services permission (None, Read-Only, Read-Write). Defaults to None.
            updates (str, optional): Updates permission (None, Read-Only, Read-Write). Defaults to None.
            reboot_shutdown (str, optional): Reboot/Shutdown permission (None, Read-Only, Read-Write). Defaults to None.
            ha (str, optional): HA permission (None, Read-Only, Read-Write). Defaults to None.
            download_certificates (str, optional): Download certificates permission (None, Read-Only, Read-Write). Defaults to None.
            other_certificate_configuration (str, optional): Other certificate configuration permission (None, Read-Only, Read-Write). Defaults to None.
            diagnostics (str, optional): Diagnostics permission (None, Read-Only, Read-Write). Defaults to None.
            other_system_configuration (str, optional): Other system configuration permission (None, Read-Only, Read-Write). Defaults to None.
            wireless_protection_overview (str, optional): Wireless protection overview permission (None, Read-Only, Read-Write). Defaults to None.
            wireless_protection_settings (str, optional): Wireless protection settings permission (None, Read-Only, Read-Write). Defaults to None.
            wireless_protection_network (str, optional): Wireless protection network permission (None, Read-Only, Read-Write). Defaults to None.
            wireless_protection_access_point (str, optional): Wireless protection access point permission (None, Read-Only, Read-Write). Defaults to None.
            wireless_protection_mesh (str, optional): Wireless protection mesh permission (None, Read-Only, Read-Write). Defaults to None.
            objects (str, optional): Objects permission (None, Read-Only, Read-Write). Defaults to None.
            network (str, optional): Network permission (None, Read-Only, Read-Write). Defaults to None.
            set_identity_profile (str, optional): Set identity profile permission (None, Read-Only, Read-Write). Defaults to None.
            authentication (str, optional): Authentication permission (None, Read-Only, Read-Write). Defaults to None.
            groups (str, optional): Groups permission (None, Read-Only, Read-Write). Defaults to None.
            guest_users_management (str, optional): Guest users management permission (None, Read-Only, Read-Write). Defaults to None.
            other_guest_user_settings (str, optional): Other guest user settings permission (None, Read-Only, Read-Write). Defaults to None.
            policy (str, optional): Policy permissions (None, Read-Only, Read-Write). Defaults to None.
            test_external_server_connectivity (str, optional): Test external server connectivity permission (None, Read-Only, Read-Write). Defaults to None.
            disconnect_live_user (str, optional): Disconnect live user permission (None, Read-Only, Read-Write). Defaults to None.
            firewall (str, optional): Firewall permission (None, Read-Only, Read-Write). Defaults to None.
            set_vpn_profile (str, optional): Set vpn profile permission (None, Read-Only, Read-Write). Defaults to None.
            connect_tunnel (str, optional): Connect tunnel permission (None, Read-Only, Read-Write). Defaults to None.
            other_vpn_configurations (str, optional): Other VPN configuration permission (None, Read-Only, Read-Write). Defaults to None.
            ips (str, optional): IPS permission (None, Read-Only, Read-Write). Defaults to None.
            web_filter (str, optional): Web filter permission (None, Read-Only, Read-Write). Defaults to None.
            cloud_application_dashboard (str, optional): Cloud application dashboard permission (None, Read-Only, Read-Write). Defaults to None.
            zero_day_protection (str, optional): Zero day protection permission (None, Read-Only, Read-Write). Defaults to None.
            application_filter (str, optional): Application filter permission (None, Read-Only, Read-Write). Defaults to None.
            set_waf_profile (str, optional): Set WAF profile permission (None, Read-Only, Read-Write). Defaults to None.
            alerts (str, optional): Alerts permission (None, Read-Only, Read-Write). Defaults to None.
            other_waf_configuration (str, optional): Other WAF configuration permission (None, Read-Only, Read-Write). Defaults to None.
            email_protection (str, optional): Email protection permission (None, Read-Only, Read-Write). Defaults to None.
            qos (str, optional): QoS permission (None, Read-Only, Read-Write). Defaults to None.
            traffic_discovery (str, optional): Traffic discovery permission (None, Read-Only, Read-Write). Defaults to None.
            set_logs_reports_profile (str, optional): Set logs reports profile permission (None, Read-Only, Read-Write). Defaults to None.
            configuration (str, optional): Log reports configuration permission (None, Read-Only, Read-Write). Defaults to None.
            log_viewer (str, optional): Log viewer permission (None, Read-Only, Read-Write). Defaults to None.
            reports_access (str, optional): Reports access permission (None, Read-Only, Read-Write). Defaults to None.
            four_eye_authentication_settings (str, optional): Four-eye authentication settings permission (None, Read-Only, Read-Write). Defaults to None.
            de_anonymization (str, optional): Log De-anonymization permission (None, Read-Only, Read-Write). Defaults to None.

        Returns:
            dict: XML response converted to Python dictionary
        """

        template_vars = {
            "name": name,
            "default_permission": default_permission,
            }

        template_vars = {**template_vars, **kwargs}
        
        return self.client.submit_template(filename="createadminprofile.j2",
                                           template_vars=template_vars,
                                           debug=debug)

    def update(self, name, debug: bool=False, **kwargs):
        """Update an administration profile.

        Args:
            name (str): Name of administration profile
            debug (bool, optional): Turn on debugging. Defaults to False.

        Keyword Args:
            dashboard (str, optional): Dashboard permission (None, Read-Only, Read-Write). Defaults to None.
            wizard (str, optional): Wizard permission (None, Read-Only, Read-Write). Defaults to None.
            set_system_profile (str, optional): System Profile permission (None, Read-Only, Read-Write). Defaults to None.
            profile (str, optional): Profile permission (None, Read-Only, Read-Write). Defaults to None.
            system_password (str, optional): System Password permission (None, Read-Only, Read-Write). Defaults to None.
            central_management (str, optional): Central management permission (None, Read-Only, Read-Write). Defaults to None.
            backup (str, optional): Backup permission (None, Read-Only, Read-Write). Defaults to None.
            restore (str, optional): Restore permission (None, Read-Only, Read-Write). Defaults to None.
            firmware (str, optional): Firmware permission (None, Read-Only, Read-Write). Defaults to None.
            licensing (str, optional): Licensing permission (None, Read-Only, Read-Write). Defaults to None.
            services (str, optional): Services permission (None, Read-Only, Read-Write). Defaults to None.
            updates (str, optional): Updates permission (None, Read-Only, Read-Write). Defaults to None.
            reboot_shutdown (str, optional): Reboot/Shutdown permission (None, Read-Only, Read-Write). Defaults to None.
            ha (str, optional): HA permission (None, Read-Only, Read-Write). Defaults to None.
            download_certificates (str, optional): Download certificates permission (None, Read-Only, Read-Write). Defaults to None.
            other_certificate_configuration (str, optional): Other certificate configuration permission (None, Read-Only, Read-Write). Defaults to None.
            diagnostics (str, optional): Diagnostics permission (None, Read-Only, Read-Write). Defaults to None.
            other_system_configuration (str, optional): Other system configuration permission (None, Read-Only, Read-Write). Defaults to None.
            wireless_protection_overview (str, optional): Wireless protection overview permission (None, Read-Only, Read-Write). Defaults to None.
            wireless_protection_settings (str, optional): Wireless protection settings permission (None, Read-Only, Read-Write). Defaults to None.
            wireless_protection_network (str, optional): Wireless protection network permission (None, Read-Only, Read-Write). Defaults to None.
            wireless_protection_access_point (str, optional): Wireless protection access point permission (None, Read-Only, Read-Write). Defaults to None.
            wireless_protection_mesh (str, optional): Wireless protection mesh permission (None, Read-Only, Read-Write). Defaults to None.
            objects (str, optional): Objects permission (None, Read-Only, Read-Write). Defaults to None.
            network (str, optional): Network permission (None, Read-Only, Read-Write). Defaults to None.
            set_identity_profile (str, optional): Set identity profile permission (None, Read-Only, Read-Write). Defaults to None.
            authentication (str, optional): Authentication permission (None, Read-Only, Read-Write). Defaults to None.
            groups (str, optional): Groups permission (None, Read-Only, Read-Write). Defaults to None.
            guest_users_management (str, optional): Guest users management permission (None, Read-Only, Read-Write). Defaults to None.
            other_guest_user_settings (str, optional): Other guest user settings permission (None, Read-Only, Read-Write). Defaults to None.
            policy (str, optional): Policy permissions (None, Read-Only, Read-Write). Defaults to None.
            test_external_server_connectivity (str, optional): Test external server connectivity permission (None, Read-Only, Read-Write). Defaults to None.
            disconnect_live_user (str, optional): Disconnect live user permission (None, Read-Only, Read-Write). Defaults to None.
            firewall (str, optional): Firewall permission (None, Read-Only, Read-Write). Defaults to None.
            set_vpn_profile (str, optional): Set vpn profile permission (None, Read-Only, Read-Write). Defaults to None.
            connect_tunnel (str, optional): Connect tunnel permission (None, Read-Only, Read-Write). Defaults to None.
            other_vpn_configurations (str, optional): Other VPN configuration permission (None, Read-Only, Read-Write). Defaults to None.
            ips (str, optional): IPS permission (None, Read-Only, Read-Write). Defaults to None.
            web_filter (str, optional): Web filter permission (None, Read-Only, Read-Write). Defaults to None.
            cloud_application_dashboard (str, optional): Cloud application dashboard permission (None, Read-Only, Read-Write). Defaults to None.
            zero_day_protection (str, optional): Zero day protection permission (None, Read-Only, Read-Write). Defaults to None.
            application_filter (str, optional): Application filter permission (None, Read-Only, Read-Write). Defaults to None.
            set_waf_profile (str, optional): Set WAF profile permission (None, Read-Only, Read-Write). Defaults to None.
            alerts (str, optional): Alerts permission (None, Read-Only, Read-Write). Defaults to None.
            other_waf_configuration (str, optional): Other WAF configuration permission (None, Read-Only, Read-Write). Defaults to None.
            im (str, optional): IM permission (None, Read-Only, Read-Write). Defaults to None.
            qos (str, optional): QoS permission (None, Read-Only, Read-Write). Defaults to None.
            email_protection (str, optional): Email protection permission (None, Read-Only, Read-Write). Defaults to None.
            traffic_discovery (str, optional): Traffic discovery permission (None, Read-Only, Read-Write). Defaults to None.
            set_logs_reports_profile (str, optional): Set logs reports profile permission (None, Read-Only, Read-Write). Defaults to None.
            configuration (str, optional): Log reports configuration permission (None, Read-Only, Read-Write). Defaults to None.
            log_viewer (str, optional): Log viewer permission (None, Read-Only, Read-Write). Defaults to None.
            reports_access (str, optional): Reports access permission (None, Read-Only, Read-Write). Defaults to None.
            four_eye_authentication_settings (str, optional): Four-eye authentication settings permission (None, Read-Only, Read-Write). Defaults to None.
            de_anonymization (str, optional): Log De-anonymization permission (None, Read-Only, Read-Write). Defaults to None.

        Returns:
            dict: XML response converted to Python dictionary
        """
        exist_profile = self.get(name=name)["Response"]["AdministrationProfile"]
        
        template_vars = {
            "name": name,
            "dashboard": kwargs.get("dashboard", exist_profile["Dashboard"]),
            "wizard": kwargs.get("wizard", exist_profile["Wizard"]),
            "set_system_profile": kwargs.get("set_system_profile"),
            "profile": kwargs.get("profile", exist_profile["System"]["Profile"]),
            "system_password": kwargs.get("system_password", exist_profile["System"]["Password"]),
            "central_management": kwargs.get("central_management", exist_profile["System"]["CentralManagement"]),
            "backup": kwargs.get("backup", exist_profile["System"]["Backup"]),
            "restore": kwargs.get("restore", exist_profile["System"]["Restore"]),
            "firmware": kwargs.get("firmware", exist_profile["System"]["Firmware"]),
            "licensing": kwargs.get("licensing", exist_profile["System"]["Licensing"]),
            "services": kwargs.get("services", exist_profile["System"]["Services"]),
            "updates": kwargs.get("updates", exist_profile["System"]["Updates"]),
            "reboot_shutdown": kwargs.get("reboot_shutdown", exist_profile["System"]["RebootShutdown"]),
            "ha": kwargs.get("ha", exist_profile["System"]["HA"]),
            "download_certificates": kwargs.get("download_certificates", exist_profile["System"]["DownloadCertificates"]),
            "other_certificate_configuration": kwargs.get("other_certificate_configuration", exist_profile["System"]["OtherCertificateConfiguration"]),
            "diagnostics": kwargs.get("diagnostics", exist_profile["System"]["Diagnostics"]),
            "other_system_configuration": kwargs.get("other_system_configuration", exist_profile["System"]["OtherSystemConfiguration"]),
            "wireless_protection_overview": kwargs.get("wireless_protection_overview", exist_profile["WirelessProtection"]["WirelessProtectionOverview"]),
            "wireless_protection_settings": kwargs.get("wireless_protection_settings", exist_profile["WirelessProtection"]["WirelessProtectionSettings"]),
            "wireless_protection_network": kwargs.get("wireless_protection_network", exist_profile["WirelessProtection"]["WirelessProtectionNetworkNetwork"]),
            "wireless_protection_access_point": kwargs.get("wireless_protection_access_point", exist_profile["WirelessProtection"]["WirelessProtectionAccessPoint"]),
            "wireless_protection_mesh": kwargs.get("wireless_protection_mesh", exist_profile["WirelessProtection"]["WirelessProtectionMesh"]),
            "objects": kwargs.get("objects", exist_profile["Objects"]),
            "network": kwargs.get("network", exist_profile["Network"]),
            "set_identity_profile": kwargs.get("set_identity_profile"),
            "authentication": kwargs.get("authentication", exist_profile["Identity"]["Authentication"]),
            "groups": kwargs.get("groups", exist_profile["Identity"]["Groups"]),
            "guest_users_management": kwargs.get("guest_users_management", exist_profile["Identity"]["GuestUsersManagement"]),
            "other_guest_user_settings": kwargs.get("other_guest_user_settings", exist_profile["Identity"]["OtherGuestUserSettings"]),
            "policy": kwargs.get("policy", exist_profile["Identity"]["Policy"]),
            "test_external_server_connectivity": kwargs.get("test_external_server_connectivity", exist_profile["Identity"]["TestExternalServerConnectivity"]),
            "disconnect_live_user": kwargs.get("disconnect_live_user", exist_profile["Identity"]["DisconnectLiveUser"]),
            "firewall": kwargs.get("network", exist_profile["Firewall"]),
            "set_vpn_profile": kwargs.get("set_vpn_profile"),
            "connect_tunnel": kwargs.get("connect_tunnel", exist_profile["VPN"]["ConnectTunnel"]),
            "other_vpn_configurations": kwargs.get("other_vpn_configurations", exist_profile["VPN"]["OtherVPNConfigurations"]),
            "ips": kwargs.get("ips", exist_profile["IPS"]),
            "web_filter": kwargs.get("web_filter", exist_profile["WebFilter"]),
            "cloud_application_dashboard": kwargs.get("cloud_application_dashboard", exist_profile["CloudApplicationDashboard"]),
            "zero_day_protection": kwargs.get("zero_day_protection", exist_profile["ZeroDayProtection"]),
            "application_filter": kwargs.get("application_filter", exist_profile["ApplicationFilter"]),
            "set_waf_profile": kwargs.get("set_waf_profile"),
            "alerts": kwargs.get("alerts", exist_profile["WAF"]["Alerts"]),
            "other_waf_configuration": kwargs.get("other_waf_configuration", exist_profile["WAF"]["OtherWAFConfiguration"]),
            "im": kwargs.get("im", exist_profile["IM"]),
            "qos": kwargs.get("qos", exist_profile["QoS"]),
            "email_protection": kwargs.get("email_protection", exist_profile["EmailProtection"]),
            "traffic_discovery": kwargs.get("traffic_discovery", exist_profile["TrafficDiscovery"]),
            "set_logs_reports_profile": kwargs.get("set_logs_reports_profile"),
            "configuration": kwargs.get("configuration", exist_profile["LogsReports"]["Configuration"]),
            "log_viewer": kwargs.get("log_viewer", exist_profile["LogsReports"]["LogViewer"]),
            "reports_access": kwargs.get("reports_access", exist_profile["LogsReports"]["ReportsAccess"]),
            "four_eye_authentication_settings": kwargs.get("four_eye_authentication_settings", exist_profile["LogsReports"]["Four-EyeAuthenticationSettings"]),
            "de_anonymization": kwargs.get("de_anonymization", exist_profile["LogsReports"]["De-Anonymization"]),
        }

        return self.client.submit_template(filename="updateadminprofile.j2",
                                           template_vars=template_vars,
                                           debug=debug)