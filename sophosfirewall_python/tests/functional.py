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
from sophosfirewall_python.firewallapi import SophosFirewall
from sophosfirewall_python.api_client import (
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

        def remove(tag, name, key=None):
            print(f"Removing {tag} {name}")
            try:
                if key:
                    resp = fw.remove(xml_tag=tag, name=name, key=key)
                else:
                    resp = fw.remove(xml_tag=tag, name=name)
            except SophosFirewallAPIError as e:
                print(f"Error {e}")
            else:
                print(
                    f"{resp['Response'][tag]['Status']['@code']}: {resp['Response'][tag]['Status']['#text']}"
                )

        print("\nTest cleanup...")
        print("Removing FUNC_TESTHOST1 from LocalServiceACL")
        resp = fw.update_acl_rule(name="FUNC_SVCACL", source_list=["FUNC_TESTHOST1"], update_action="remove")
        print(
            f"{resp['Response']['LocalServiceACL']['Status']['@code']}: {resp['Response']['LocalServiceACL']['Status']['#text']}"
        )
        remove(tag="LocalServiceACL", name="FUNC_SVCACL", key="RuleName")
        remove(tag="FirewallRule", name="FUNC_TESTRULE1")
        remove(tag="IPHost", name="FUNC_TESTNETWORK2")
        remove(tag="IPHost", name="FUNC_TESTNETWORK1")
        remove(tag="IPHostGroup", name="FUNC_TESTGROUP1")
        remove(tag="FQDNHostGroup", name="FUNC_TESTFQDNGROUP1")
        remove(tag="IPHost", name="FUNC_TESTHOST1")
        remove(tag="IPHost", name="FUNC_TESTHOST2")
        remove(tag="FQDNHost", name="FUNC_TESTFQDNHOST1")
        remove(tag="FQDNHost", name="FUNC_TESTFQDNHOST2")
        remove(tag="ServiceGroup", name="FUNC_TESTSVCGROUP1")
        remove(tag="Services", name="FUNC_TESTSVC1")
        remove(tag="Services", name="FUNC_TESTSVC2")
        remove(tag="WebFilterURLGroup", name="FUNC_URLGROUP1")
        remove(tag="User", name="func_testuser1")

    request.addfinalizer(cleanup)


def test_login(setup):
    """Test login() method."""

    expected_result = {"status": "Authentication Successful"}

    response = setup.login()

    assert response["Response"]["Login"] == expected_result


def test_create_ip_host(setup):
    """Test create_ip_host method."""

    expected_result = {
        "@code": "200",
        "#text": "Configuration applied successfully.",
    }

    hosts = [
        {"name": "FUNC_TESTHOST1", "ip": "1.1.1.1"},
        {"name": "FUNC_TESTHOST2", "ip": "2.2.2.2"},
    ]
    for host in hosts:
        response = setup.create_ip_host(name=host["name"], ip_address=host["ip"])
        assert response["Response"]["IPHost"]["Status"] == expected_result


def test_create_ip_hostgroup(setup):
    """Test create_ip_hostgroup method."""

    expected_result = {"@code": "200", "#text": "Configuration applied successfully."}
    response = setup.create_ip_hostgroup(
        name="FUNC_TESTGROUP1",
        description="Test group created during functional test",
        host_list=["FUNC_TESTHOST1"],
    )
    assert response["Response"]["IPHostGroup"]["Status"] == expected_result


def test_create_fqdn_host(setup):
    """Test create_fqdn_host method."""

    expected_result = {
        "@code": "200",
        "#text": "Configuration applied successfully.",
    }

    fqdn_hosts = [
        {"name": "FUNC_TESTFQDNHOST1", "fqdn": "*.test1.com"},
        {"name": "FUNC_TESTFQDNHOST2", "fqdn": "*.test2.com"},
    ]
    for host in fqdn_hosts:
        response = setup.create_fqdn_host(
            name=host["name"],
            description="Created during automated functional testing",
            fqdn=host["fqdn"],
        )
        assert response["Response"]["FQDNHost"]["Status"] == expected_result


def test_create_fqdn_hostgroup(setup):
    """Test create_fqdn_hostgroup method."""

    expected_result = {
        "@code": "200",
        "#text": "Configuration applied successfully.",
    }

    response = setup.create_fqdn_hostgroup(
        name="FUNC_TESTFQDNGROUP1",
        description="Test group created during functional test",
        fqdn_host_list=["FUNC_TESTFQDNHOST1"],
    )
    assert response["Response"]["FQDNHostGroup"]["Status"] == expected_result


def test_create_ip_network(setup):
    """Test create_ip_network method."""

    expected_result = {
        "@code": "200",
        "#text": "Configuration applied successfully.",
    }

    response = setup.create_ip_network(
        name="FUNC_TESTNETWORK1",
        ip_network="1.1.1.0",
        mask="255.255.255.0",
    )
    assert response["Response"]["IPHost"]["Status"] == expected_result


def test_create_ip_range(setup):
    """Test create_ip_range method."""

    expected_result = {
        "@code": "200",
        "#text": "Configuration applied successfully.",
    }
    response = setup.create_ip_range(
        name="FUNC_TESTNETWORK2", start_ip="2.2.2.1", end_ip="2.2.2.10"
    )
    assert response["Response"]["IPHost"]["Status"] == expected_result


def test_create_service(setup):
    """Test create_service method."""

    expected_result = {
        "@code": "200",
        "#text": "Configuration applied successfully.",
    }

    service_list = [
        {
            "name": "FUNC_TESTSVC1",
            "service_type": "TCPorUDP",
            "service_list": [{"dst_port": 1234, "protocol": "tcp"}],
        },
        {
            "name": "FUNC_TESTSVC2",
            "service_type": "TCPorUDP",
            "service_list": [{"dst_port": 5555, "protocol": "tcp"}],
        },
    ]

    for service in service_list:
        response = setup.create_service(
            name=service["name"],
            service_type=service["service_type"],
            service_list=service["service_list"],
        )
        assert response["Response"]["Services"]["Status"] == expected_result


def test_create_service_group(setup):
    """Test create_servicegroup method."""

    expected_result = {
        "@code": "200",
        "#text": "Configuration applied successfully.",
    }
    response = setup.create_service_group(
        name="FUNC_TESTSVCGROUP1",
        description="Test group created during functional test",
        service_list=["FUNC_TESTSVC1"],
    )
    assert response["Response"]["ServiceGroup"]["Status"] == expected_result


def test_create_rule(setup):
    """Test create_rule method."""

    expected_result = {
        "@code": "200",
        "#text": "Configuration applied successfully.",
    }

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
    response = setup.create_rule(rule_params=rule_params)
    assert response["Response"]["FirewallRule"]["Status"] == expected_result

def test_update_rule(setup):
    """Test update_rule method."""

    update_result = {
        "@code": "200",
        "#text": "Configuration applied successfully.",
    }

    response = setup.update_rule(name="FUNC_TESTRULE1", rule_params={"action": "Drop"})
    assert response["Response"]["FirewallRule"]["Status"] == update_result

    response = setup.get_rule(name="FUNC_TESTRULE1")
    assert response["Response"]["FirewallRule"]["NetworkPolicy"]["Action"] == "Drop"

def test_create_urlgroup(setup):
    """Test create_urlgroup method."""

    expected_result = {
        "@code": "200",
        "#text": "Configuration applied successfully.",
    }
    response = setup.create_urlgroup(
        name="FUNC_URLGROUP1", domain_list=["test1.com", "test2.com"]
    )
    assert response["Response"]["WebFilterURLGroup"]["Status"] == expected_result


def test_create_user(setup):
    """Test create_user method."""

    expected_result = {
        "@code": "200",
        "#text": "Configuration applied successfully.",
    }

    response = setup.create_user(
        user="FUNC_TESTUSER1",
        name="FUNC_TESTUSER1",
        description="Functional Testing User 1",
        user_password="P@ssw0rd12345",
        user_type="Administrator",
        profile="Administrator",
        group="Open Group",
        email="test.user@sophos.com",
    )
    assert response["Response"]["User"]["Status"] == expected_result


def test_update_ip_hostgroup(setup):
    """Test update_ip_hostgroup method."""

    update_result = {
        "@code": "200",
        "#text": "Configuration applied successfully.",
    }

    get_result = {
        "@transactionid": "",
        "Name": "FUNC_TESTGROUP1",
        "Description": "Test group created during functional test",
        "HostList": {"Host": ["FUNC_TESTHOST1", "FUNC_TESTHOST2"]},
        "IPFamily": "IPv4",
    }

    response = setup.update_ip_hostgroup(
        name="FUNC_TESTGROUP1", host_list=["FUNC_TESTHOST2"]
    )
    assert response["Response"]["IPHostGroup"]["Status"] == update_result

    response = setup.get_ip_hostgroup(name="FUNC_TESTGROUP1")
    assert response["Response"]["IPHostGroup"] == get_result


def test_update_fqdn_hostgroup(setup):
    """Test update_fqdn_hostgroup method."""

    update_result = {
        "@code": "200",
        "#text": "Configuration applied successfully.",
    }

    get_result = {
        "@transactionid": "",
        "Name": "FUNC_TESTFQDNGROUP1",
        "Description": "Test group created during functional test",
        "FQDNHostList": {"FQDNHost": ["FUNC_TESTFQDNHOST1", "FUNC_TESTFQDNHOST2"]},
    }

    response = setup.update_fqdn_hostgroup(
        name="FUNC_TESTFQDNGROUP1", fqdn_host_list=["FUNC_TESTFQDNHOST2"]
    )
    assert response["Response"]["FQDNHostGroup"]["Status"] == update_result

    response = setup.get_fqdn_hostgroup(name="FUNC_TESTFQDNGROUP1")
    assert response["Response"]["FQDNHostGroup"] == get_result


def test_update_service_group(setup):
    """Test update_servicegroup method."""

    update_result = {
        "@code": "200",
        "#text": "Configuration applied successfully.",
    }

    get_result = {
        "@transactionid": "",
        "Name": "FUNC_TESTSVCGROUP1",
        "Description": "Test group created during functional test",
        "ServiceList": {"Service": ["FUNC_TESTSVC1", "FUNC_TESTSVC2"]},
    }
    response = setup.update_service_group(
        name="FUNC_TESTSVCGROUP1", service_list=["FUNC_TESTSVC2"]
    )
    assert response["Response"]["ServiceGroup"]["Status"] == update_result

    response = setup.get_service_group(name="FUNC_TESTSVCGROUP1")
    assert response["Response"]["ServiceGroup"] == get_result


def test_update_urlgroup(setup):
    """Test update_urlgroup method."""

    update_result = {
        "@code": "200",
        "#text": "Configuration applied successfully.",
    }

    get_result = {
        "@transactionid": "",
        "Name": "FUNC_URLGROUP1",
        "Description": None,
        "IsDefault": "No",
        "URLlist": {"URL": ["test1.com", "test2.com", "test3.com"]},
    }

    response = setup.update_urlgroup(name="FUNC_URLGROUP1", domain_list=["test3.com"])
    assert response["Response"]["WebFilterURLGroup"]["Status"] == update_result

    response = setup.get_urlgroup(name="FUNC_URLGROUP1")
    assert response["Response"]["WebFilterURLGroup"] == get_result


def test_update_service(setup):
    """Test update_service method."""

    update_result = {
        "@code": "200",
        "#text": "Configuration applied successfully.",
    }

    get_result = {
        "@transactionid": "",
        "Name": "FUNC_TESTSVC1",
        "Description": None,
        "Type": "TCPorUDP",
        "ServiceDetails": {
            "ServiceDetail": [
                {"SourcePort": "1:65535", "DestinationPort": "1234", "Protocol": "TCP"},
                {"SourcePort": "1:65535", "DestinationPort": "2222", "Protocol": "TCP"},
            ]
        },
    }

    response = setup.update_service(
        name="FUNC_TESTSVC1",
        service_type="TCPorUDP",
        service_list=[{"dst_port": "2222", "protocol": "TCP"}],
    )
    assert response["Response"]["Services"]["Status"] == update_result

    response = setup.get_service(name="FUNC_TESTSVC1")
    assert response["Response"]["Services"] == get_result


def test_create_acl_rule(setup):
    """Test create_acl_rule method."""

    update_result = {
        "@code": "200",
        "#text": "Configuration applied successfully.",
    }

    response = setup.create_acl_rule(name="FUNC_SVCACL",
                                     description="Created by Functional testing, ok to delete",
                                     source_list=["FUNC_TESTHOST1"],
                                     dest_list=["FUNC_TESTHOST2"],
                                     service_list=["DNS"],
                                    )
    assert response["Response"]["LocalServiceACL"]["Status"] == update_result

    response = setup.get_acl_rule(name="FUNC_SVCACL")
    assert "FUNC_TESTHOST1" in response["Response"]["LocalServiceACL"]["Hosts"]["Host"]
    assert "FUNC_TESTHOST2" in response["Response"]["LocalServiceACL"]["Hosts"]["DstHost"]
    assert "DNS" in response["Response"]["LocalServiceACL"]["Services"]["Service"]

def test_update_acl_rule(setup):
    """Test update_acl_rule method."""

    update_result = {
        "@code": "200",
        "#text": "Configuration applied successfully.",
    }

    response = setup.update_acl_rule(name="FUNC_SVCACL", dest_list=["FUNC_TESTHOST2"], update_action="remove")
    assert response["Response"]["LocalServiceACL"]["Status"] == update_result

    response = setup.get_acl_rule(name="FUNC_SVCACL")
    assert "DstHost" not in response["Response"]["LocalServiceACL"]["Hosts"]
