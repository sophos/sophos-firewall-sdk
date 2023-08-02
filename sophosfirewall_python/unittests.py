"""Tests for SophosFirewall module
"""
import unittest
from unittest.mock import patch, Mock
from firewallapi import SophosFirewall, SophosFirewallZeroRecords

class TestSophosFirewall(unittest.TestCase):
    """Tests for SophosFirewall module
    """

    def setUp(self):
        """Test setup
        """
        self.fw = SophosFirewall(
            username="fakeusername",
            password="fakepassword",
            hostname="fakehostname",
            port=4444
            )

    @patch('firewallapi.requests')
    def test_post(self, mocked_requests):
        """Test _post() method
        """
        mock_response = Mock()
        mock_response.content = '''
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
        '''.replace('\n', '').strip().encode()

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
        expected_result = '''
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
        '''.replace('\n', '').strip().encode()
        
        assert self.fw._post(xmldata=payload).content == expected_result

    @patch.object(SophosFirewall, "_post")
    def test_get_tag(self, mocked_post):
        """Test get_tag() method
        """
        mock_response = Mock()
        mock_response.content = '''
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
        '''.replace('\n', '').strip().encode()
        mocked_post.return_value = mock_response

        expected_result = {'Response': {'@APIVersion': '1905.1',
                            '@IPS_CAT_VER': '1',
                            'Login': {'status': 'Authentication Successful'},
                            'IPHost': [{'@transactionid': '',
                                'Name': 'TEST1',
                                'IPFamily': 'IPv4',
                                'HostType': 'IP',
                                'IPAddress': '10.1.1.1'},
                            {'@transactionid': '',
                                'Name': 'TEST2',
                                'IPFamily': 'IPv4',
                                'HostType': 'IP',
                                'IPAddress': '10.1.1.2'}
                            ]
                        }
                    }
        assert self.fw.get_tag("IPHost") == expected_result

    @patch.object(SophosFirewall, "_post")
    def test_get_tag_with_filter(self, mocked_post):
        """Test get_tag_with_filter() method
        """
        mock_response = Mock()
        mock_response.content = '''
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
        '''.replace('\n', '').strip().encode()
        mocked_post.return_value = mock_response

        expected_result = {'Response': {'@APIVersion': '1905.1',
                            '@IPS_CAT_VER': '1',
                            'Login': {'status': 'Authentication Successful'},
                            'IPHost': {'@transactionid': '',
                                'Name': 'TEST1',
                                'IPFamily': 'IPv4',
                                'HostType': 'IP',
                                'IPAddress': '10.1.1.1'}
                            
                            }
                        }
        assert self.fw.get_tag_with_filter("IPHost", key="Name", value="TEST1", operator="=") == expected_result

    @patch.object(SophosFirewall, "_post")
    def test_no_records(self, mocked_post):
        """Test get_tag_with_filter() method when no records available
        """
        mock_response = Mock()
        mock_response.content = '''
        <?xml version="1.0" encoding="UTF-8"?>
        <Response APIVersion="1905.1" IPS_CAT_VER="1">
        <Login>
            <status>Authentication Successful</status>
        </Login>
        <IPHost transactionid="">
            <Status>No. of records Zero.</Status>
        </IPHost>
        </Response>
        '''.replace('\n', '').strip().encode()
        mocked_post.return_value = mock_response

        kwargs = {"xml_tag": "IPHost",
                  "key": "Name",
                  "value": "TEST1",
                  "operator": "="}

        self.assertRaises(SophosFirewallZeroRecords, self.fw.get_tag_with_filter, **kwargs)


    @patch.object(SophosFirewall, "_post")
    def test_submit_template(self, mocked_post):
        """Test submit_template() method
        """
        mock_response = Mock()
        mock_response.content = '''
            <?xml version="1.0" encoding="utf-8"?>
            <Response APIVersion="1905.1" IPS_CAT_VER="1">
            <Login>
              <status>Authentication Successful</status>
            </Login><WebFilterURLGroup transactionid="">
              <Status code="200">Configuration applied successfully.</Status>
            </WebFilterURLGroup>
            </Response>'''.replace('\n', '').strip().encode()
        mocked_post.return_value = mock_response

        template_vars = {
            "name": "TEST1",
            "url_list": ["testdomain1.com", "testdomain2.com"],
            "description": "Test URL list",
            "isdefault": "No"
        }

        expected_result = {'Response': {'@APIVersion': '1905.1',
                            '@IPS_CAT_VER': '1',
                            'Login': {'status': 'Authentication Successful'},
                            'WebFilterURLGroup': {'@transactionid': '',
                            'Status': {'@code': '200',
                            '#text': 'Configuration applied successfully.'}}}}
        
        assert self.fw.submit_template(filename="urlgroup_example.j2", template_vars=template_vars, template_dir="./sophosfirewall_python" ) == expected_result


        