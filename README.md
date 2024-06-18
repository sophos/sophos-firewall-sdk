# Sophos Firewall Python SDK
The Sophos Firewall Python Software Development Kit (SDK) provides a Python module for working with the [XML API](https://doc.sophos.com/nsg/sophos-firewall/20.0/API/index.html) of Sophos Firewall. 
  
For installation and usage details please see the [documentation](https://sophosfirewall-python.readthedocs.io/)
  
## Support
The Sophos Firewall Python SDK was developed by a small community of engineers within Sophos who will be maintaining the project. Questions can be posted to the [Q&A](https://github.com/sophos/sophos-firewall-sdk/discussions/categories/q-a) section of the Github project. If you are hitting a bug, please open a new [Issue](https://github.com/sophos/sophos-firewall-sdk/issues) and fill out the Bug Report template.  If you would like to see a new feature implemented, please fill out the Feature Request template.  
  
> This project will utilize a community support model as outlined above. Support will not be provided by Sophos Technical Support. 


## Contributing
We welcome contributors to the project. To work on a new feature, fork the project and then develop your feature within the fork. When the new feature is ready for review, please submit a [Pull Request](https://github.com/sophos/sophos-firewall-sdk/pulls). 
  
To be merged into the project, the following requirements must be met:
- Passing Pylint tests
- Code formatted with Black
- Unit tests written with Pytest

### Development
The main code to be updated when developing new features is inside of the `SophosFirewall` class, which is located in the `firewallapi.py` module. Functionality is implemented by defining methods under the class. There are currently three types of methods: `GET`, `CREATE`, and `UPDATE`. The [API Documentation](https://docs.sophos.com/nsg/sophos-firewall/18.0/API/index.html) describes how the API calls are structured.
  
#### GET Methods
GET methods provide retrieval of existing firewall configuration settings. They are implemented by calling the `get_tag` and/or the `get_tag_with_filter` methods of the class. The `get_tag` method requests a specified XML tag from the API and returns the content as a Python `dict` object. The `get_tag` will return all objects for the specified XML tag. The `get_tag_with_filter` method requests an XML tag from the API with specified filter criteria such as `=`, `!=`, or `like`. This allows for filtering of the returned data. Below is an example of a GET method that requests IP Hosts from the firewall using the `IPHost` XML tag. It utilizes both the `get_tag` and the `get_tag_with_filter` class methods, depending on the options provided to the method. If the calling program specifies no options, then all records are returned using the `get_tag` method. Otherwise, the results can be filtered by specifying the name or IP address. When name or IP address are provided, the `get_tag_with_filter` method is used to filter the results. 

```python
    def get_ip_host(
        self, name: str = None, ip_address: str = None, operator: str = "="):
        """Get IP Host object(s)

        Args:
            name (str, optional): IP object name. Returns all objects if not specified.
            ip_address (str, optional): Query by IP Address.
            operator (str, optional): Operator for search. Default is "=". Valid operators: =, !=, like. 
        """
        if name:
            return self.get_tag_with_filter(
                xml_tag="IPHost", key="Name", value=name, operator=operator
            )
        if ip_address:
            return self.get_tag_with_filter(
                xml_tag="IPHost",
                key="IPAddress",
                value=ip_address,
                operator=operator,
            )
        return self.get_tag(xml_tag="IPHost")
```

#### CREATE Methods
Create methods are used to create new configuration objects on the firewall. To define a new Create method, the XML payload for the request must first be created in a template and stored in the `templates` directory. The XML payload in the template can contain [Jinja variables](https://jinja.palletsprojects.com/en/3.1.x/templates/#variables) that will be populated when the template is rendered. Below is an example template containing the XML payload to create an IP Host. In the template, the values within the double brackets `{{ var }}` are variables that are passed in by the create method arguments. 

```xml
<Request>
   <Login>
        <Username>{{username}}</Username>
        <Password >{{password}}</Password>
    </Login>
    <Set operation="add"> 
    <IPHost transactionid="">
        <Name>{{ name }}</Name>
        <IPFamily>IPv4</IPFamily>
        <HostType>IP</HostType>
        <IPAddress>{{ ip_address }}</IPAddress>
    </IPHost>
   </Set>
</Request>
```
Once the template is defined, a new create method can be written using the `submit_template` method. The `submit_template` method will render the template, passing in any variables that are specified in the new create method. It will then issue a `POST` request against the firewall API to create the new object.
  
Below is the method to create an IP Host. The source program must specify the `name` and `ip_address` as arguments when calling the function. These values are then populated in a dictionary called `params` and are passed to the `submit_template` method. There is also an optional `debug` argument which causes the API response to be output to screen for troubleshooting purposes. 
  
```python
def create_ip_host(
    self, name: str, ip_address: str, debug: bool = False
):
    """Create IP address object

    Args:
        name (str): Name of the object
        ip_address (str): Host IP address
        debug (bool, optional): Turn on debugging. Defaults to False.
    Returns:
        dict: XML response converted to Python dictionary
    """
    self._validate_ip_address(ip_address)

    params = {"name": name, "ip_address": ip_address}
    resp = self.submit_template(
        "createiphost.j2", template_vars=params, debug=debug
    )
    return resp
```
#### UPDATE Methods
Update methods provide the ability to change existing configuration on the firewall. When defining update methods, it is often necessary to first do a GET request to retrieve the existing configuration. This is because often the existing configuration must be in the payload in addition to any modifications. For example, when updating a URL Group with a new entry, the list must contain the existing entries along with the new one. Otherwise, the list will only contain the new entry when updated. Update methods can therefore first use an existing get method if defined, or can use the `get_tag` and/or `get_tag_with_filter` methods. Then, the information from the get request can be parsed and modified as necessary. Finally, the template can be submitted with the `submit_template` method, using the modified variables from the get request when rendering the template. 
  
Below is the code to update a URL Group on the firewall. It first does a get request using the existing `get_urlgroup` method. It parses the existing list of URLs from the response, and then adds the new domain to the list. Finally, it uses the `submit_template` method to submit the `updateurlgroup.j2` template, passing in as variables the name of the list to be updated and the updated domain list.

```python
    def update_urlgroup(
        self, name: str, domain: str, debug: bool = False
    ):
        """Adds a specified domain to a web URL Group

        Args:
            name (str): URL Group name
            domain (str): Domain to be added to URL Group
            debug (bool, optional): Enable debug mode. Defaults to False.

        Returns:
            dict: XML response converted to Python dictionary
        """
        # Get the existing URL list first, if any
        resp = self.get_urlgroup(name=name)
        if "URLlist" in resp["Response"]["WebFilterURLGroup"]:
            exist_list = (
                resp.get("Response").get("WebFilterURLGroup").get("URLlist").get("URL")
            )
        else:
            exist_list = None
        domain_list = []
        if exist_list:
            if isinstance(exist_list, str):
                domain_list.append(exist_list)
            elif isinstance(exist_list, list):
                domain_list = exist_list
        domain_list.append(domain)

        params = {"name": name, "domain_list": domain_list}
        resp = self.submit_template(
            "updateurlgroup.j2", template_vars=params, debug=debug
        )
        return resp
```

### Testing
#### Unit Tests
Pytest test cases are in the `unittests.py` module. The tests are executed by Github Actions on commits to the `develop` and/or `main` branch. It is not required to create new tests for Get methods, but it is recommended for Create or Update methods. Success and failure cases should be covered. The existing tests utilize the methods under test with sample input data and compare against a mocked API response. Please see the `test_create_rule` and `test_failed_create_rule` tests in the `unittests.py` for reference. 

#### Functional Tests
Functional tests can be run against an actual firewall to ensure SDK functions are working properly. The functional tests are also run with Pytest, and require a few environment variables to connect to the target firewall:

```bash
export XG_USERNAME="<your firewall username>"
export XG_PASSWORD="<your firewall password>"
export XG_HOSTNAME="<your firewall hostname>"
```
  
To run the functional tests:
```
pytest sophosfirewall_python/tests/functional.py -s -vv
```

> The tests will create objects on the firewall prefixed with `FUNC_`. At the end of the test run, these objects will be deleted. 