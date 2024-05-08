"""Functional tests for SophosFirewall module

Copyright 2023 Sophos Ltd.  All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing
permissions and limitations under the License.

Tests are designed to run against live Sophos XG firewall. The following environment variables must be defined:

XG_USERNAME
XG_PASSWORD 
XG_HOSTNAME
API_VERSION (ex. 2000.1) - The version is returned in the response, so it is necessary to specify which API
version is expected to be seen during testing.  

"""
import os
import pytest
from sophosfirewall_python.firewallapi import (
    SophosFirewall,
    SophosFirewallZeroRecords,
    SophosFirewallAuthFailure,
    SophosFirewallAPIError,
)


API_VERSION = os.environ["API_VERSION"]


@pytest.fixture(scope="session", autouse=True)
def setup(request):
    """Test setup."""
    fw = SophosFirewall(
        username=os.environ["XG_USERNAME"],
        password=os.environ["XG_PASSWORD"],
        hostname=os.environ["XG_HOSTNAME"],
        port=4444,
        verify=False,
    )
    yield fw

    def cleanup():
        """Test completion tasks."""

        def remove(tag, name):
            print(f"Removing {tag} {name}")
            try:
                resp = fw.remove(xml_tag=tag, name=name)
            except SophosFirewallAPIError as e:
                print(f"Error {e}")
            else:
                print(
                    f"{resp['Response'][tag]['Status']['@code']}: {resp['Response'][tag]['Status']['#text']}"
                )

        print("\nTest cleanup...")
        print("Removing FUNC_TESTHOST1 from LocalServiceACL")
        resp = fw.update_service_acl(host_list=["FUNC_TESTHOST1"], action="remove")
        print(
            f"{resp['Response']['LocalServiceACL']['Status']['@code']}: {resp['Response']['LocalServiceACL']['Status']['#text']}"
        )
        remove(tag="FirewallRule", name="FUNC_TESTRULE1")
        remove(tag="IPHost", name="FUNC_TESTNETWORK2")
        remove(tag="IPHost", name="FUNC_TESTNETWORK1")
        remove(tag="IPHostGroup", name="FUNC_TESTGROUP1")
        remove(tag="IPHost", name="FUNC_TESTHOST1")
        remove(tag="IPHost", name="FUNC_TESTHOST2")
        remove(tag="Services", name="FUNC_TESTSVC1")
        remove(tag="WebFilterURLGroup", name="FUNC_URLGROUP1")
        remove(tag="User", name="func_testuser1")

    request.addfinalizer(cleanup)


def test_login(setup):
    """Test login() method."""

    expected_result = {
        "Response": {
            "@APIVersion": API_VERSION,
            "@IPS_CAT_VER": "1",
            "Login": {"status": "Authentication Successful"},
        }
    }
    if float(API_VERSION) >= 2000.2:
        expected_result["Response"]["@IS_WIFI6"] = "0"

    assert setup.login() == expected_result


def test_create_ip_host(setup):
    """Test create_ip_host method."""

    expected_result = {
        "Response": {
            "@APIVersion": API_VERSION,
            "@IPS_CAT_VER": "1",
            "Login": {"status": "Authentication Successful"},
            "IPHost": {
                "@transactionid": "",
                "Status": {
                    "@code": "200",
                    "#text": "Configuration applied successfully.",
                },
            },
        }
    }
    if float(API_VERSION) >= 2000.2:
        expected_result["Response"]["@IS_WIFI6"] = "0"

    hosts = [
        {"name": "FUNC_TESTHOST1", "ip": "1.1.1.1"},
        {"name": "FUNC_TESTHOST2", "ip": "2.2.2.2"},
    ]
    for host in hosts:
        assert (
            setup.create_ip_host(name=host["name"], ip_address=host["ip"])
            == expected_result
        )


def test_create_ip_hostgroup(setup):
    """Test create_ip_hostgroup method."""

    expected_result = {
        "Response": {
            "@APIVersion": API_VERSION,
            "@IPS_CAT_VER": "1",
            "Login": {"status": "Authentication Successful"},
            "IPHostGroup": {
                "@transactionid": "",
                "Status": {
                    "@code": "200",
                    "#text": "Configuration applied successfully.",
                },
            },
        }
    }
    if float(API_VERSION) >= 2000.2:
        expected_result["Response"]["@IS_WIFI6"] = "0"

    assert (
        setup.create_ip_hostgroup(
            name="FUNC_TESTGROUP1",
            description="Test group created during functional test",
            host_list=["FUNC_TESTHOST1"],
        )
        == expected_result
    )


def test_create_ip_network(setup):
    """Test create_ip_network method."""

    expected_result = {
        "Response": {
            "@APIVersion": API_VERSION,
            "@IPS_CAT_VER": "1",
            "Login": {"status": "Authentication Successful"},
            "IPHost": {
                "@transactionid": "",
                "Status": {
                    "@code": "200",
                    "#text": "Configuration applied successfully.",
                },
            },
        }
    }
    if float(API_VERSION) >= 2000.2:
        expected_result["Response"]["@IS_WIFI6"] = "0"

    assert (
        setup.create_ip_network(
            name="FUNC_TESTNETWORK1",
            ip_network="1.1.1.0",
            mask="255.255.255.0",
        )
        == expected_result
    )


def test_create_ip_range(setup):
    """Test create_ip_range method."""

    expected_result = {
        "Response": {
            "@APIVersion": API_VERSION,
            "@IPS_CAT_VER": "1",
            "Login": {"status": "Authentication Successful"},
            "IPHost": {
                "@transactionid": "",
                "Status": {
                    "@code": "200",
                    "#text": "Configuration applied successfully.",
                },
            },
        }
    }
    if float(API_VERSION) >= 2000.2:
        expected_result["Response"]["@IS_WIFI6"] = "0"

    assert (
        setup.create_ip_range(
            name="FUNC_TESTNETWORK2", start_ip="2.2.2.1", end_ip="2.2.2.10"
        )
        == expected_result
    )


def test_create_service(setup):
    """Test create_service method."""

    expected_result = {
        "Response": {
            "@APIVersion": API_VERSION,
            "@IPS_CAT_VER": "1",
            "Login": {"status": "Authentication Successful"},
            "Services": {
                "@transactionid": "",
                "Status": {
                    "@code": "200",
                    "#text": "Configuration applied successfully.",
                },
            },
        }
    }
    if float(API_VERSION) >= 2000.2:
        expected_result["Response"]["@IS_WIFI6"] = "0"

    assert (
        setup.create_service(name="FUNC_TESTSVC1", service_list=[{"dst_port": 1234, "protocol": "tcp"}])
        == expected_result
    )


def test_create_rule(setup):
    """Test create_rule method."""

    expected_result = {
        "Response": {
            "@APIVersion": API_VERSION,
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
    if float(API_VERSION) >= 2000.2:
        expected_result["Response"]["@IS_WIFI6"] = "0"

    rule_params = dict(
        rulename="FUNC_TESTRULE1",
        after_rulename="Block.green.sophos",
        action="Accept",
        description="Test rule created by functional testing.",
        log="Enable",
        src_zones=["TestLab"],
        dst_zones=["LAN"],
        src_networks=["FUNC_TESTNETWORK1"],
        dst_networks=["FUNC_TESTNETWORK2"],
        service_list=["FUNC_TESTSVC1"],
    )

    assert setup.create_rule(rule_params=rule_params) == expected_result


def test_create_urlgroup(setup):
    """Test create_urlgroup method."""

    expected_result = {
        "Response": {
            "@APIVersion": API_VERSION,
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
    if float(API_VERSION) >= 2000.2:
        expected_result["Response"]["@IS_WIFI6"] = "0"

    assert (
        setup.create_urlgroup(
            name="FUNC_URLGROUP1", domain_list=["test1.com", "test2.com"]
        )
        == expected_result
    )


def test_create_user(setup):
    """Test create_user method."""

    expected_result = {
        "Response": {
            "@APIVersion": API_VERSION,
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
    if float(API_VERSION) >= 2000.2:
        expected_result["Response"]["@IS_WIFI6"] = "0"

    assert (
        setup.create_user(
            user="FUNC_TESTUSER1",
            name="FUNC_TESTUSER1",
            description="Functional Testing User 1",
            user_password="P@ssw0rd12345",
            user_type="Administrator",
            profile="Administrator",
            group="Open Group",
            email="test.user@sophos.com",
        )
        == expected_result
    )


def test_update_ip_hostgroup(setup):
    """Test update_ip_hostgroup method."""

    update_result = {
        "Response": {
            "@APIVersion": API_VERSION,
            "@IPS_CAT_VER": "1",
            "Login": {"status": "Authentication Successful"},
            "IPHostGroup": {
                "@transactionid": "",
                "Status": {
                    "@code": "200",
                    "#text": "Configuration applied successfully.",
                },
            },
        }
    }
    if float(API_VERSION) >= 2000.2:
        update_result["Response"]["@IS_WIFI6"] = "0"

    get_result = {
        "Response": {
            "@APIVersion": API_VERSION,
            "@IPS_CAT_VER": "1",
            "Login": {"status": "Authentication Successful"},
            "IPHostGroup": {
                "@transactionid": "",
                "Name": "FUNC_TESTGROUP1",
                "Description": "Test group created during functional test",
                "HostList": {"Host": ["FUNC_TESTHOST1", "FUNC_TESTHOST2"]},
                "IPFamily": "IPv4",
            },
        }
    }
    if float(API_VERSION) >= 2000.2:
        get_result["Response"]["@IS_WIFI6"] = "0"

    assert (
        setup.update_ip_hostgroup(name="FUNC_TESTGROUP1", host_list=["FUNC_TESTHOST2"])
        == update_result
    )

    assert setup.get_ip_hostgroup(name="FUNC_TESTGROUP1") == get_result


def test_update_urlgroup(setup):
    """Test update_urlgroup method."""

    update_result = {
        "Response": {
            "@APIVersion": API_VERSION,
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
    if float(API_VERSION) >= 2000.2:
        update_result["Response"]["@IS_WIFI6"] = "0"

    get_result = {
        "Response": {
            "@APIVersion": API_VERSION,
            "@IPS_CAT_VER": "1",
            "Login": {"status": "Authentication Successful"},
            "WebFilterURLGroup": {
                "@transactionid": "",
                "Name": "FUNC_URLGROUP1",
                "Description": None,
                "IsDefault": "No",
                "URLlist": {"URL": ["test1.com", "test2.com", "test3.com"]},
            },
        }
    }
    if float(API_VERSION) >= 2000.2:
        get_result["Response"]["@IS_WIFI6"] = "0"

    assert (
        setup.update_urlgroup(name="FUNC_URLGROUP1", domain_list=["test3.com"])
        == update_result
    )

    assert setup.get_urlgroup(name="FUNC_URLGROUP1") == get_result

def test_update_service(setup):
    """Test update_service method."""

    update_result = {
        "Response": {
            "@APIVersion": API_VERSION,
            "@IPS_CAT_VER": "1",
            "Login": {"status": "Authentication Successful"},
            "Services": {
                "@transactionid": "",
                "Status": {
                    "@code": "200",
                    "#text": "Configuration applied successfully.",
                },
            },
        }
    }
    if float(API_VERSION) >= 2000.2:
        update_result["Response"]["@IS_WIFI6"] = "0"

    get_result = {
        "Response": {
            "@APIVersion": API_VERSION,
            "@IPS_CAT_VER": "1",
            "Login": {"status": "Authentication Successful"},
            "Services": {
                "@transactionid": "",
                "Name": "FUNC_TESTSVC1",
                "Description": None,
                "Type": "TCPorUDP",
                "ServiceDetails": {
                    "ServiceDetail": [{
                        "SourcePort": "1:65535",
                        "DestinationPort": "1234",
                        "Protocol": "TCP"
                    },
                    {
                        "SourcePort": "1:65535",
                        "DestinationPort": "2222",
                        "Protocol": "TCP"
                    }]
                },
            },
        }
    }
    if float(API_VERSION) >= 2000.2:
        get_result["Response"]["@IS_WIFI6"] = "0"

    assert (
        setup.update_service(name="FUNC_TESTSVC1", service_list=[{"dst_port": "2222","protocol": "TCP"}])
        == update_result
    )

    assert setup.get_service(name="FUNC_TESTSVC1") == get_result

def test_update_service_acl(setup):
    """Test update_service_acl method."""

    update_result = {
        "Response": {
            "@APIVersion": API_VERSION,
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
    if float(API_VERSION) >= 2000.2:
        update_result["Response"]["@IS_WIFI6"] = "0"

    get_result = {
        "Response": {
            "@APIVersion": API_VERSION,
            "@IPS_CAT_VER": "1",
            "Login": {"status": "Authentication Successful"},
            "LocalServiceACL": {
                "@transactionid": "",
                "RuleName": "Appliance Access",
                "Description": None,
                "Position": "Top",
                "IPFamily": "IPv4",
                "SourceZone": "Any",
                "Hosts": {
                    "Host": [
                        "All EAA Hosts",
                        "FUNC_TESTHOST1",
                        "Sophos Internal ACL",
                        "Sophos External ACL",
                    ]
                },
                "Services": {
                    "Service": [
                        "Ping",
                        "HTTPS",
                        "SSH",
                        "Ping",
                        "UserPortal",
                        "VPNPortal",
                    ]
                },
                "Action": "accept",
            },
        }
    }
    if float(API_VERSION) >= 2000.2:
        get_result["Response"]["@IS_WIFI6"] = "0"
        get_result["Response"]["LocalServiceACL"]["Services"]["Service"].pop(3)  # Removal of extra 'ping' in response

    assert setup.update_service_acl(host_list=["FUNC_TESTHOST1"]) == update_result

    assert setup.get_acl_rule() == get_result
