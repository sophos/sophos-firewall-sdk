"""Tests for SophosFirewall module

Copyright 2023 Sophos Ltd.  All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing
permissions and limitations under the License.
"""
import unittest
from unittest.mock import patch, Mock, MagicMock
from firewallapi import (
    SophosFirewall,
    SophosFirewallZeroRecords,
    SophosFirewallAuthFailure,
    SophosFirewallAPIError,
)


class TestSophosFirewall(unittest.TestCase):
    """Tests for SophosFirewall module"""

    def setUp(self):
        """Test setup"""
        self.fw = SophosFirewall(
            username="fakeusername",
            password="fakepassword",
            hostname="fakehostname",
            port=4444,
        )

    @patch("firewallapi.requests")
    def test_post(self, mocked_requests):
        """Test _post() method"""
        mock_response = Mock()
        mock_response.content = (
            """
        <?xml version="1.0" encoding="UTF-8"?>
        <Response APIVersion="1905.1" IPS_CAT_VER="1">
        <Login>
            <status>Authentication Successful</status>
        </Login>
        <IPHost transactionid="">
            <Name>TEST1</Name>
            <IPFamily>IPv4</IPFamily>
            <HostType>IP</HostType>
            <IPAddress>10.1.1.1</IPAddress>
        </IPHost>
        </Response>
        """.replace(
                "\n", ""
            )
            .strip()
            .encode()
        )

        mocked_requests.post.return_value = mock_response

        payload = f"""
        <Request>
            <Login>
                <Username>{self.fw.username}</Username>
                <Password>{self.fw.password}</Password>
            </Login>
            <Get>
                <IPHost>
                    <Filter>
                        <key name="Name" criteria="=">TEST1</key>
                    </Filter>
                </IPHost>
            </Get>
        </Request>
        """
        expected_result = (
            """
        <?xml version="1.0" encoding="UTF-8"?>
        <Response APIVersion="1905.1" IPS_CAT_VER="1">
        <Login>
            <status>Authentication Successful</status>
        </Login>
        <IPHost transactionid="">
            <Name>TEST1</Name>
            <IPFamily>IPv4</IPFamily>
            <HostType>IP</HostType>
            <IPAddress>10.1.1.1</IPAddress>
        </IPHost>
        </Response>
        """.replace(
                "\n", ""
            )
            .strip()
            .encode()
        )

        assert self.fw._post(xmldata=payload).content == expected_result

    @patch("firewallapi.requests")
    def test_auth_failure(self, mocked_requests):
        """Test _post() method"""
        mock_response = Mock()
        mock_response.content = (
            """
        <?xml version="1.0" encoding="UTF-8"?>
        <Response APIVersion="1905.1" IPS_CAT_VER="1">
        <Login>
            <status>Authentication Failure</status>
        </Login>
        </Response>
        """.replace(
                "\n", ""
            )
            .strip()
            .encode()
        )

        mocked_requests.post.return_value = mock_response

        payload = f"""
        <Request>
            <Login>
                <Username>{self.fw.username}</Username>
                <Password>{self.fw.password}</Password>
            </Login>
            <Get>
                <IPHost>
                    <Filter>
                        <key name="Name" criteria="=">TEST1</key>
                    </Filter>
                </IPHost>
            </Get>
        </Request>
        """

        self.assertRaises(
            SophosFirewallAuthFailure, self.fw._post, {"xmldata": payload}
        )

    @patch.object(SophosFirewall, "_post")
    def test_get_tag(self, mocked_post):
        """Test get_tag() method"""
        mock_response = Mock()
        mock_response.content = (
            """
        <?xml version="1.0" encoding="UTF-8"?>
        <Response APIVersion="1905.1" IPS_CAT_VER="1">
        <Login>
            <status>Authentication Successful</status>
        </Login>
        <IPHost transactionid="">
            <Name>TEST1</Name>
            <IPFamily>IPv4</IPFamily>
            <HostType>IP</HostType>
            <IPAddress>10.1.1.1</IPAddress>
        </IPHost>
        <IPHost transactionid="">
            <Name>TEST2</Name>
            <IPFamily>IPv4</IPFamily>
            <HostType>IP</HostType>
            <IPAddress>10.1.1.2</IPAddress>
        </IPHost>
        </Response>
        """.replace(
                "\n", ""
            )
            .strip()
            .encode()
        )
        mocked_post.return_value = mock_response

        expected_result = {
            "Response": {
                "@APIVersion": "1905.1",
                "@IPS_CAT_VER": "1",
                "Login": {"status": "Authentication Successful"},
                "IPHost": [
                    {
                        "@transactionid": "",
                        "Name": "TEST1",
                        "IPFamily": "IPv4",
                        "HostType": "IP",
                        "IPAddress": "10.1.1.1",
                    },
                    {
                        "@transactionid": "",
                        "Name": "TEST2",
                        "IPFamily": "IPv4",
                        "HostType": "IP",
                        "IPAddress": "10.1.1.2",
                    },
                ],
            }
        }
        assert self.fw.get_tag("IPHost") == expected_result

    @patch.object(SophosFirewall, "_post")
    def test_get_tag_with_filter(self, mocked_post):
        """Test get_tag_with_filter() method"""
        mock_response = Mock()
        mock_response.content = (
            """
        <?xml version="1.0" encoding="UTF-8"?>
        <Response APIVersion="1905.1" IPS_CAT_VER="1">
        <Login>
            <status>Authentication Successful</status>
        </Login>
        <IPHost transactionid="">
            <Name>TEST1</Name>
            <IPFamily>IPv4</IPFamily>
            <HostType>IP</HostType>
            <IPAddress>10.1.1.1</IPAddress>
        </IPHost>
        </Response>
        """.replace(
                "\n", ""
            )
            .strip()
            .encode()
        )
        mocked_post.return_value = mock_response

        expected_result = {
            "Response": {
                "@APIVersion": "1905.1",
                "@IPS_CAT_VER": "1",
                "Login": {"status": "Authentication Successful"},
                "IPHost": {
                    "@transactionid": "",
                    "Name": "TEST1",
                    "IPFamily": "IPv4",
                    "HostType": "IP",
                    "IPAddress": "10.1.1.1",
                },
            }
        }
        assert (
            self.fw.get_tag_with_filter(
                "IPHost", key="Name", value="TEST1", operator="="
            )
            == expected_result
        )

    @patch.object(SophosFirewall, "_post")
    def test_no_records(self, mocked_post):
        """Test get_tag_with_filter() method when no records available"""
        mock_response = Mock()
        mock_response.content = (
            """
        <?xml version="1.0" encoding="UTF-8"?>
        <Response APIVersion="1905.1" IPS_CAT_VER="1">
        <Login>
            <status>Authentication Successful</status>
        </Login>
        <IPHost transactionid="">
            <Status>Number of records Zero.</Status>
        </IPHost>
        </Response>
        """.replace(
                "\n", ""
            )
            .strip()
            .encode()
        )
        mocked_post.return_value = mock_response

        kwargs = {"xml_tag": "IPHost", "key": "Name", "value": "TEST1", "operator": "="}

        self.assertRaises(
            SophosFirewallZeroRecords, self.fw.get_tag_with_filter, **kwargs
        )

    @patch.object(SophosFirewall, "_post")
    def test_submit_template(self, mocked_post):
        """Test submit_template() method"""
        mock_response = Mock()
        mock_response.content = (
            """
            <?xml version="1.0" encoding="utf-8"?>
            <Response APIVersion="1905.1" IPS_CAT_VER="1">
            <Login>
              <status>Authentication Successful</status>
            </Login><WebFilterURLGroup transactionid="">
              <Status code="200">Configuration applied successfully.</Status>
            </WebFilterURLGroup>
            </Response>""".replace(
                "\n", ""
            )
            .strip()
            .encode()
        )
        mocked_post.return_value = mock_response

        template_vars = {
            "name": "TEST1",
            "url_list": ["testdomain1.com", "testdomain2.com"],
            "description": "Test URL list",
            "isdefault": "No",
        }

        expected_result = {
            "Response": {
                "@APIVersion": "1905.1",
                "@IPS_CAT_VER": "1",
                "Login": {"status": "Authentication Successful"},
                "WebFilterURLGroup": {
                    "@transactionid": "",
                    "Status": {
                        "@code": "200",
                        "#text": "Configuration applied successfully.",
                    },
                },
            }
        }

        assert (
            self.fw.submit_template(
                filename="urlgroup_example.j2",
                template_vars=template_vars,
                template_dir="./sophosfirewall_python",
            )
            == expected_result
        )

    @patch.object(SophosFirewall, "_post")
    def test_login(self, mocked_post):
        """Test login() method"""
        mock_response = Mock()
        mock_response.content = (
            """
            <?xml version="1.0" encoding="UTF-8"?>
            <Response APIVersion="2000.1" IPS_CAT_VER="1">
            <Login>
                <status>Authentication Successful</status>
            </Login>
            </Response>""".replace(
                "\n", ""
            )
            .strip()
            .encode()
        )
        mocked_post.return_value = mock_response

        expected_result = {
            "Response": {
                "@APIVersion": "2000.1",
                "@IPS_CAT_VER": "1",
                "Login": {
                    "status": "Authentication Successful"
                }
            }
        }

        assert (
            self.fw.login(
            )
            == expected_result
        )


    @patch.object(SophosFirewall, "_post")
    def test_create_rule(self, mocked_post):
        """Test create_rule() method"""
        mock_response = Mock()
        mock_response.content = (
            """
            <?xml version="1.0" encoding="utf-8"?>
            <Response APIVersion="1905.1" IPS_CAT_VER="1">
            <Login>
              <status>Authentication Successful</status>
            </Login><FirewallRule transactionid="">
              <Status code="200">Configuration applied successfully.</Status>
            </FirewallRule>
            </Response>""".replace(
                "\n", ""
            )
            .strip()
            .encode()
        )
        mocked_post.return_value = mock_response

        rule_params = dict(
            rulename="Test from Python",
            after_rulename="Security Data Platform – FluentD",
            description="Test change automation",
            action="Accept",
            log="Enable",
            src_zones=["LAN"],
            dst_zones=["WAN"],
            src_networks=["ABN 10.151.210.0"],
            dst_networks=["Internet IPv4 group"],
            service_list=["162 SNMP Trap"],
        )

        expected_result = {
            "Response": {
                "@APIVersion": "1905.1",
                "@IPS_CAT_VER": "1",
                "Login": {"status": "Authentication Successful"},
                "FirewallRule": {
                    "@transactionid": "",
                    "Status": {
                        "@code": "200",
                        "#text": "Configuration applied successfully.",
                    },
                },
            }
        }

        assert self.fw.create_rule(rule_params=rule_params) == expected_result

    @patch.object(SophosFirewall, "_post")
    def test_failed_create_rule(self, mocked_post):
        """Test failed creation response"""
        mock_response = Mock()
        mock_response.content = (
            """
            <?xml version="1.0" encoding="UTF-8"?>
            <Response APIVersion="1905.1" IPS_CAT_VER="1">
            <Login>
                <status>Authentication Successful</status>
            </Login>
            <FirewallRule transactionid="">
                <Status code="502">Operation failed. Entity having same name already exists.</Status>
            </FirewallRule>
            </Response>""".replace(
                "\n", ""
            )
            .strip()
            .encode()
        )
        mocked_post.return_value = mock_response

        rule_params = dict(
            rulename="Test from Python",
            after_rulename="Security Data Platform - FluentD",
            description="Test change automation",
            action="Accept",
            log="Enable",
            src_zones=["LAN"],
            dst_zones=["WAN"],
            src_networks=["ABN 10.151.210.0"],
            dst_networks=["Internet IPv4 group"],
            service_list=["162 SNMP Trap"],
        )

        self.assertRaises(
            SophosFirewallAPIError, self.fw.create_rule, {"rule_params": rule_params}
        )

    @patch.object(SophosFirewall, "_post")
    def test_create_user(self, mocked_post):
        """Test create_user() method"""
        mock_response = Mock()
        mock_response.content = (
            """
            <?xml version="1.0" encoding="utf-8"?>
            <Response APIVersion="1905.1" IPS_CAT_VER="1">
            <Login>
              <status>Authentication Successful</status>
            </Login><User transactionid="">
              <Status code="200">Configuration applied successfully.</Status>
            </User>
            </Response>""".replace(
                "\n", ""
            )
            .strip()
            .encode()
        )
        mocked_post.return_value = mock_response

        user_params = {'user': 'testuser',
                    'name': 'Test User',
                    'description': 'Test User',
                    'user_password': 'C1sc0.123456',
                    'user_type': 'Administrator',
                    'profile': 'Administrator',
                    'group': 'Open Group',
                    'email': 'test@sophos.com'}

        expected_result = {
            "Response": {
                "@APIVersion": "1905.1",
                "@IPS_CAT_VER": "1",
                "Login": {"status": "Authentication Successful"},
                "User": {
                    "@transactionid": "",
                    "Status": {
                        "@code": "200",
                        "#text": "Configuration applied successfully.",
                    },
                },
            }
        }

        assert self.fw.create_user(**user_params) == expected_result

    @patch.object(SophosFirewall, "_post")
    def test_update_backup(self, mocked_post):
        """Test update_backup() method"""
        mock_response = Mock()
        mock_response.content = (
            """
            <?xml version="1.0" encoding="utf-8"?>
            <Response APIVersion="1905.1" IPS_CAT_VER="1">
            <Login>
              <status>Authentication Successful</status>
            </Login><BackupRestore transactionid="">
              <Status code="200">Configuration applied successfully.</Status>
            </BackupRestore>
            </Response>""".replace(
                "\n", ""
            )
            .strip()
            .encode()
        )
        mocked_post.return_value = mock_response

        backup_params = {'BackupFrequency': 'Weekly',
                        'BackupMode': 'Local',
                        'BackupPrefix': 'us-bos-utm-stag-1',
                        'Day': 'Sunday',
                        'EmailAddress': 'networkalerts@sophos.com',
                        'FTPServer': None,
                        'FtpPath': None,
                        'Hour': '22',
                        'Minute': '00',
                        'Username': None,
                        'ftp': False,
                        'username': 'apiuser',
                        'password': 'password'}

        expected_result = {
            "Response": {
                "@APIVersion": "1905.1",
                "@IPS_CAT_VER": "1",
                "Login": {"status": "Authentication Successful"},
                "BackupRestore": {
                    "@transactionid": "",
                    "Status": {
                        "@code": "200",
                        "#text": "Configuration applied successfully.",
                    },
                },
            }
        }

        assert self.fw.update_backup(backup_params=backup_params) == expected_result
    
    
    @patch.object(SophosFirewall, "_post")
    @patch.object(SophosFirewall, "get_acl_rule")
    def test_update_service_acl(self, mocked_get_acl_rule, mocked_post):
        """Test update_service_acl() method"""
        mock_get = MagicMock()
        mock_get.__getitem__.return_value = {'@APIVersion': '2000.1',
                '@IPS_CAT_VER': '1',
                'Login': {'status': 'Authentication Successful'},
                'LocalServiceACL': {'@transactionid': '',
                'RuleName': 'Appliance Access',
                'Description': None,
                'Position': 'Top',
                'IPFamily': 'IPv4',
                'SourceZone': 'Any',
                'Hosts': {'Host': ['Sophos Internal ACL',
                    'Sophos External ACL',
                    'All EAA Hosts']},
                'Services': {'Service': ['Ping',
                    'HTTPS',
                    'SSH',
                    'Ping',
                    'UserPortal',
                    'VPNPortal']},
                'Action': 'accept'}}

        mock_response = Mock()
        mock_response.content = (
            """
            <?xml version="1.0" encoding="utf-8"?>
            <Response APIVersion="1905.1" IPS_CAT_VER="1">
            <Login>
              <status>Authentication Successful</status>
            </Login><LocalServiceACL transactionid="">
              <Status code="200">Configuration applied successfully.</Status>
            </LocalServiceACL>
            </Response>""".replace(
                "\n", ""
            )
            .strip()
            .encode()
        )

        mocked_get_acl_rule.return_value = mock_get
        mocked_post.return_value = mock_response

        expected_result = {
            "Response": {
                "@APIVersion": "1905.1",
                "@IPS_CAT_VER": "1",
                "Login": {"status": "Authentication Successful"},
                "LocalServiceACL": {
                    "@transactionid": "",
                    "Status": {
                        "@code": "200",
                        "#text": "Configuration applied successfully.",
                    },
                },
            }
        }

        assert self.fw.update_service_acl(host_list=["Any"], action="add") == expected_result

    @patch.object(SophosFirewall, "_post")
    @patch.object(SophosFirewall, "get_urlgroup")
    def test_update_urlgroup(self, mocked_get_urlgroup, mocked_post):
        """Test update_urlgroup() method"""
        mock_get = MagicMock()
        mock_get.__getitem__.return_value = {'@APIVersion': '2000.1',
                                            '@IPS_CAT_VER': '1',
                                            'Login': {'status': 'Authentication Successful'},
                                            'WebFilterURLGroup': {'@transactionid': '',
                                            'Name': 'TEST1',
                                            'Description': 'Test URL list',
                                            'IsDefault': 'No',
                                            'URLlist': {'URL': ['testdomain1.com', 'testdomain2.com']}}}

        mock_response = Mock()
        mock_response.content = (
            """
            <?xml version="1.0" encoding="utf-8"?>
            <Response APIVersion="1905.1" IPS_CAT_VER="1">
            <Login>
              <status>Authentication Successful</status>
            </Login><WebFilterURLGroup transactionid="">
              <Status code="200">Configuration applied successfully.</Status>
            </WebFilterURLGroup>
            </Response>""".replace(
                "\n", ""
            )
            .strip()
            .encode()
        )

        mocked_get_urlgroup.return_value = mock_get
        mocked_post.return_value = mock_response

        expected_result = {
            "Response": {
                "@APIVersion": "1905.1",
                "@IPS_CAT_VER": "1",
                "Login": {"status": "Authentication Successful"},
                "WebFilterURLGroup": {
                    "@transactionid": "",
                    "Status": {
                        "@code": "200",
                        "#text": "Configuration applied successfully.",
                    },
                },
            }
        }

        assert self.fw.update_urlgroup(name='TEST1', domain="test.com") == expected_result


    @patch.object(SophosFirewall, "_post")
    def test_get_ip_host_all(self, mocked_post):
        """Test get_ip_host() method for all hosts"""
        mock_response = Mock()
        mock_response.content = (
            """
        <?xml version="1.0" encoding="UTF-8"?>
        <Response APIVersion="1905.1" IPS_CAT_VER="1">
        <Login>
            <status>Authentication Successful</status>
        </Login>
        <IPHost transactionid="">
            <Name>TEST1</Name>
            <IPFamily>IPv4</IPFamily>
            <HostType>IP</HostType>
            <IPAddress>10.1.1.1</IPAddress>
        </IPHost>
        <IPHost transactionid="">
            <Name>TEST2</Name>
            <IPFamily>IPv4</IPFamily>
            <HostType>IP</HostType>
            <IPAddress>10.1.1.2</IPAddress>
        </IPHost>
        </Response>
        """.replace(
                "\n", ""
            )
            .strip()
            .encode()
        )
        mocked_post.return_value = mock_response

        expected_result = {
            "Response": {
                "@APIVersion": "1905.1",
                "@IPS_CAT_VER": "1",
                "Login": {"status": "Authentication Successful"},
                "IPHost": [
                    {
                        "@transactionid": "",
                        "Name": "TEST1",
                        "IPFamily": "IPv4",
                        "HostType": "IP",
                        "IPAddress": "10.1.1.1",
                    },
                    {
                        "@transactionid": "",
                        "Name": "TEST2",
                        "IPFamily": "IPv4",
                        "HostType": "IP",
                        "IPAddress": "10.1.1.2",
                    },
                ],
            }
        }
        assert self.fw.get_ip_host() == expected_result

    @patch.object(SophosFirewall, "_post")
    def test_get_ip_host_queryparams(self, mocked_post):
        """Test get_tag_ip_host() method with query parameters"""
        mock_response = Mock()
        mock_response.content = (
            """
        <?xml version="1.0" encoding="UTF-8"?>
        <Response APIVersion="1905.1" IPS_CAT_VER="1">
        <Login>
            <status>Authentication Successful</status>
        </Login>
        <IPHost transactionid="">
            <Name>TEST1</Name>
            <IPFamily>IPv4</IPFamily>
            <HostType>IP</HostType>
            <IPAddress>10.1.1.1</IPAddress>
        </IPHost>
        </Response>
        """.replace(
                "\n", ""
            )
            .strip()
            .encode()
        )
        mocked_post.return_value = mock_response

        expected_result = {
            "Response": {
                "@APIVersion": "1905.1",
                "@IPS_CAT_VER": "1",
                "Login": {"status": "Authentication Successful"},
                "IPHost": {
                    "@transactionid": "",
                    "Name": "TEST1",
                    "IPFamily": "IPv4",
                    "HostType": "IP",
                    "IPAddress": "10.1.1.1",
                },
            }
        }
        assert self.fw.get_ip_host(name="TEST1") == expected_result
