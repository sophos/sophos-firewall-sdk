"""
Copyright 2023 Sophos Ltd.  All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing
permissions and limitations under the License.
"""
import os
import re
import requests
import xmltodict
from jinja2 import Environment, FileSystemLoader, Template


class SophosFirewallAPIError(Exception):
    """Error raised when an API operation fails"""


class SophosFirewallAuthFailure(Exception):
    """Error raised when authentication to firewall fails"""


class SophosFirewallZeroRecords(Exception):
    """Error raised when a get request returns zero records"""


class SophosFirewallOperatorError(Exception):
    """Error raised when an invalid operator is specified"""


class SophosFirewallInvalidArgument(Exception):
    """Error raised when an invalid argument is specified"""


class APIClient:
    """Class for making the requests to the firewall XML API."""

    def __init__(self, username, password, hostname, port, verify):
        self.username = username
        self.password = password
        self.hostname = hostname
        self.port = port
        self.url = f"https://{hostname}:{port}/webconsole/APIController"
        self.verify = verify

    def _dict_to_lower(self, target_dict):
        """Convert the keys of a dictionary to lower-case

        Args:
            target_dict (dict): Dictionary to be converted

        Returns:
            dict: Dictionary with all keys converted to lower case
        """
        return {key.lower(): val for key, val in target_dict.items()}

    def _error_check(self, api_response, xml_tag):
        """Check for errors in the API response and raise exception if present

        Args:
            api_response (Requests.response): The response object returned from the requests module
            xml_tag (str): The XML tag being operated on

        Raises:
            SophosFirewallZeroRecords: Error raised when there are no records matching the request parameters
            SophosFirewallAPIError: Error raised when there is a problem with the request parameters
        """
        response = xmltodict.parse(api_response.content.decode())["Response"]
        lower_response = self._dict_to_lower(response)
        if xml_tag.lower() in lower_response:
            resp_dict = lower_response[xml_tag.lower()]
            if "Status" in resp_dict:
                if (
                    resp_dict["Status"] == "Number of records Zero."
                    or resp_dict["Status"] == "No. of records Zero."
                ):
                    raise SophosFirewallZeroRecords(resp_dict["Status"])
                if "@code" in resp_dict["Status"]:
                    if not resp_dict["Status"]["@code"].startswith("2"):
                        raise SophosFirewallAPIError(
                            f"{resp_dict['Status']['@code']}: {resp_dict['Status']['#text']}"
                        )
        else:
            raise SophosFirewallAPIError(
                str(xmltodict.parse(api_response.content.decode()))
            )

    def _post(self, xmldata: str) -> requests.Response:
        """Post XML request to the firewall returning response as a dict object

        Args:
            xmldata (str): XML payload
            verify (bool):  SSL certificate verification. Default=True.

        Returns:
            requests.Response object
        """
        headers = {"Accept": "application/xml"}
        resp = requests.post(
            self.url,
            headers=headers,
            data={"reqxml": xmldata},
            verify=self.verify,
            timeout=30,
        )

        resp_dict = xmltodict.parse(resp.content.decode())["Response"]
        if "Status" in resp_dict:
            if resp_dict["Status"]["@code"] == "534":
                # IP not allowed in API Access List
                raise SophosFirewallAPIError(resp_dict["Status"]["#text"])

            if resp_dict["Status"]["@code"] == "532":
                # API access not enabled
                raise SophosFirewallAPIError(resp_dict["Status"]["#text"])

        if "Login" in resp_dict:
            if resp_dict["Login"]["status"] == "Authentication Failure":
                raise SophosFirewallAuthFailure("Login failed!")
        return resp

    def login(self, output_format):
        """Test login credentials.

        Args:
            output_format(str): Output format. Valid options are "dict" or "xml". Defaults to dict.
        """
        payload = f"""
        <Request>
            <Login>
                <Username>{self.username}</Username>
                <Password>{self.password}</Password>
            </Login>
        </Request>
        """
        resp = self._post(xmldata=payload)
        if output_format == "xml":
            return resp.content.decode()
        return xmltodict.parse(resp.content.decode())

    def submit_template(
        self,
        filename: str,
        template_vars: dict,
        template_dir: str = None,
        debug: bool = False,
    ) -> dict:
        """Submits XML payload stored as a Jinja2 file

        Args:
            filename (str): Jinja2 template filename. Place in "templates" directory or configure template_dir.
            template_vars (dict): Dictionary of variables to inject into the template. Username and password are passed in by default.
            template_dir (str): Directory to look for templates. Default is "./templates".
            debug (bool, optional): Enable debug mode to display XML payload. Defaults to False.

        Returns:
            dict
        """
        if not template_dir:
            template_dir = os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "templates"
            )
        environment = Environment(
            trim_blocks=True,
            lstrip_blocks=True,
            loader=FileSystemLoader(template_dir),
            autoescape=True,
        )
        template = environment.get_template(filename)
        template_vars["username"] = self.username
        template_vars["password"] = self.password
        payload = template.render(**template_vars)
        if debug:
            print(f"REQUEST: {payload}")
        resp = self._post(xmldata=payload)

        resp_dict = xmltodict.parse(resp.content.decode())["Response"]
        success_pattern = "2[0-9][0-9]"
        for key in resp_dict:
            if "Status" in resp_dict[key]:
                if not re.search(success_pattern, resp_dict[key]["Status"]["@code"]):
                    raise SophosFirewallAPIError(resp_dict[key])
        return xmltodict.parse(resp.content.decode())

    def submit_xml(
        self,
        template_data: str,
        template_vars: dict = None,
        set_operation: str = "add",
        debug: bool = False,
    ) -> dict:
        """Submits XML payload as a string to the API. 
        Args:
            template_data (str): A string containing the XML payload. Variables can be optionally passed in the string using Jinja2 (ex. {{ some_var }})
            template_vars (dict, optional): Dictionary of variables to inject into the XML string. 
            set_operation (str): Specify 'add' or 'update' set operation. Default is add. 

        Returns:
            dict
        """
        if not template_vars:
            template_vars = {}

        environment = Environment(
            trim_blocks=True,
            lstrip_blocks=True,
            autoescape=True,
        )

        template_string = f"""
            <Request>
                <Login>
                    <Username>{self.username}</Username>
                    <Password>{self.password}</Password>
                </Login>
            <Set operation="{set_operation}">
                {template_data}
            </Set>
            </Request>
        """
        template = environment.from_string(template_string)
        payload = template.render(**template_vars)
        if debug:
            print(f"REQUEST: {payload}")
        resp = self._post(xmldata=payload)

        resp_dict = xmltodict.parse(resp.content.decode())["Response"]
        success_pattern = "2[0-9][0-9]"
        for key in resp_dict:
            if "Status" in resp_dict[key]:
                if not re.search(success_pattern, resp_dict[key]["Status"]["@code"]):
                    raise SophosFirewallAPIError(resp_dict[key])
        return xmltodict.parse(resp.content.decode())

    def get_tag(self, xml_tag: str, output_format: str = "dict"):
        """Execute a get for a specified XML tag.

        Args:
            xml_tag (str): XML tag for the request
            output_format(str): Output format. Valid options are "dict" or "xml". Defaults to dict.
        """
        payload = f"""
        <Request>
            <Login>
                <Username>{self.username}</Username>
                <Password>{self.password}</Password>
            </Login>
            <Get>
                <{xml_tag}>
                </{xml_tag}>
            </Get>
        </Request>
        """
        resp = self._post(xmldata=payload)
        self._error_check(resp, xml_tag)
        if output_format == "xml":
            return resp.content.decode()
        return xmltodict.parse(resp.content.decode())

    def get_tag_with_filter(
        self,
        xml_tag: str,
        key: str,
        value: str,
        operator: str = "like",
        output_format: str = dict,
    ):
        """Execute a get for a specified XML tag with filter criteria.

        Args:
            xml_tag (str): XML tag for the request.
            key (str): Search key
            value (str): Search value
            operator (str, optional): Operator for search (“=”,”!=”,”like”). Defaults to "like".
            output_format(str): Output format. Valid options are "dict" or "xml". Defaults to dict.
        """
        valid_operators = ["=", "!=", "like"]
        if operator not in valid_operators:
            raise SophosFirewallOperatorError(
                f"Invalid operator '{operator}'!  Supported operators: [ {', '.join(valid_operators)} ]"
            )
        payload = f"""
        <Request>
            <Login>
                <Username>{self.username}</Username>
                <Password>{self.password}</Password>
            </Login>
            <Get>
                <{xml_tag}>
                    <Filter>
                        <key name="{key}" criteria="{operator}">{value}</key>
                    </Filter>
                </{xml_tag}>
            </Get>
        </Request>
        """
        resp = self._post(xmldata=payload)
        self._error_check(resp, xml_tag)
        if output_format == "xml":
            return resp.content.decode()
        return xmltodict.parse(resp.content.decode())

    def remove(self, xml_tag: str, name: str, key: str = "Name", output_format: str = "dict"):
        """Remove an object from the firewall.

        Args:
            xml_tag (str): The XML tag indicating the type of object to be removed.
            name (str): The name of the object to be removed.
            key (str): The primary XML key that is used to look up the object. Defaults to Name.
            output_format (str): Output format. Valid options are "dict" or "xml". Defaults to dict.
        """
        payload = f"""
        <Request>
            <Login>
                <Username>{self.username}</Username>
                <Password>{self.password}</Password>
            </Login>
            <Remove>
              <{xml_tag}>
                <{key}>{name}</{key}>
              </{xml_tag}>
            </Remove>
        </Request>
        """
        resp = self._post(xmldata=payload)
        self._error_check(resp, xml_tag)
        if output_format == "xml":
            return resp.content.decode()
        return xmltodict.parse(resp.content.decode())

    def update(
        self,
        xml_tag: str,
        update_params: dict,
        name: str = None,
        output_format: str = "dict",
        debug: bool = False,
    ):
        """Update an existing object on the firewall.

        Args:
            xml_tag (str): The XML tag indicating the type of object to be updated.
            update_params (dict): Keys/values to be updated. Keys must match an existing XML key.
            name (str, optional): The name of the object to be updated, if applicable.
            output_format(str): Output format. Valid options are "dict" or "xml". Defaults to dict.
            debug (bool): Displays the XML payload that was submitted
        """
        if name:
            resp = self.get_tag_with_filter(
                xml_tag=xml_tag, key="Name", value=name, operator="="
            )
        else:
            resp = self.get_tag(xml_tag=xml_tag)

        for key in update_params:
            resp["Response"][xml_tag][key] = update_params[key]

        update_body = {}
        update_body[xml_tag] = resp["Response"][xml_tag]
        xml_update_body = xmltodict.unparse(update_body, pretty=True).lstrip(
            '<?xml version="1.0" encoding="utf-8"?>'
        )
        payload = f"""
        <Request>
            <Login>
                <Username>{self.username}</Username>
                <Password>{self.password}</Password>
            </Login>
            <Set operation="update"> 
                {xml_update_body}
            </Set>
        </Request>
        """
        if debug:
            print(payload)
        resp = self._post(xmldata=payload)
        self._error_check(resp, xml_tag)
        if output_format == "xml":
            return resp.content.decode()
        return xmltodict.parse(resp.content.decode())

    def validate_arg(self, arg_name, arg_value, valid_choices):
        if not arg_value in valid_choices:
            raise SophosFirewallInvalidArgument(
                f"Invalid choice for {arg_name} argument, valid choices are {valid_choices}"
            )
