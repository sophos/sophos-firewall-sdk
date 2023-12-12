Examples
========

Get Functions
-------------
Request and return data from the API formatted as a Python dict object. 

.. note::
   Get methods will return all of the objects configured on the firewall if no filtering parameters are specified.

Get all IP Hosts
^^^^^^^^^^^^^^^^

.. code-block:: python

    fw.get_ip_host()

.. _get-ip-host-label:
Get IP Host by Name
^^^^^^^^^^^^^^^^^^^

.. code-block:: python

    fw.get_ip_host(name="example_host")

    {'Response': {'@APIVersion': '1905.1',
        '@IPS_CAT_VER': '1',
        'Login': {'status': 'Authentication Successful'},
        'IPHost': {'@transactionid': '',
        'Name': 'example_host',
        'IPFamily': 'IPv4',
        'HostType': 'IP',
        'IPAddress': '10.0.0.1'}}}

Get IP Host by IP Address
^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

    fw.get_ip_host(ip_address="10.0.0.1")

    {'Response': {'@APIVersion': '1905.1',
        '@IPS_CAT_VER': '1',
        'Login': {'status': 'Authentication Successful'},
        'IPHost': {'@transactionid': '',
        'Name': 'example_host',
        'IPFamily': 'IPv4',
        'HostType': 'IP',
        'IPAddress': '10.0.0.1'}}}

Generic Get Functions
^^^^^^^^^^^^^^^^^^^^^
Although this module contains several convenience methods for commonly used operations, it does not include every possible firewall configuration.
However, the information can be retrieved by looking up the associated XML tag in the `API documentation <https://docs.sophos.com/nsg/sophos-firewall/18.5/API/index.html>`_ 
and using the XML tag with the **get_tag()** and **get_tag_with_filter()** methods.

The **get_tag()** method returns all objects for the provided XML tag. It is not necessary to include the angle brackets around the tag.   

To get all interfaces using the XML tag `<Interface>`:

.. code-block:: python

   fw.get_tag("Interface")

To get a specific interface, the **get_tag_with_filter()** method can be used which allows for specification of query parameters.  

.. code-block:: python

   fw.get_tag_with_filter("Interface", key="Name", operator="=", value="Port1")

    {
        "Response": {
            "@APIVersion": "1905.1",
            "@IPS_CAT_VER": "1",
            "Login": {
                "status": "Authentication Successful"
            },
            "Interface": {
                "@transactionid": "",
                "IPv4Configuration": "Enable",
                "IPv6Configuration": "Disable",
                "Hardware": "Port1",
                "Name": "Port1",
                "NetworkZone": "LAN",
                "IPv4Assignment": "Static",
                "IPv6Assignment": null,
                "DHCPRapidCommit": "Disable",
                "InterfaceSpeed": "Auto Negotiate",
                "AutoNegotiation": "Enable",
                "FEC": "Off",
                "BreakoutMembers": "0",
                "BreakoutSource": null,
                "MTU": "1500",
                "MSS": {
                    "OverrideMSS": "Disable",
                    "MSSValue": "1460"
                },
                "Status": "Connected, 1000 Mbps - Full Duplex, FEC off",
                "MACAddress": "Default",
                "IPAddress": "10.104.10.155",
                "Netmask": "255.255.255.0"
            }
        }
    }

.. note::
    Valid operators for the `operator` parameter are "=", "!=", or "like". 


Create Functions
----------------
Submit an XML payload to create objects on the firewall. 

Create IP Host
^^^^^^^^^^^^^^

.. code-block:: python

    response = fw.create_ip_host(name="test-host", ip_address="10.0.0.1")

    {
        "Response": {
            "@APIVersion": "1905.1",
            "@IPS_CAT_VER": "1",
            "Login": {
                "status": "Authentication Successful"
            },
            "IPHost": {
                "@transactionid": "",
                "Status": {
                    "@code": "200",
                    "#text": "Configuration applied successfully."
                }
            }
        }
    }

.. note::
    The module parses the status code in the response. If the status code in the response payload is not in the 2XX range, a `SophosFirewallAPIError` will be raised indicating the failure reason. 
    Below is an example error response if attempting to create an IP Host that already exists:

    sophosfirewall_python.firewallapi.SophosFirewallAPIError: {'@transactionid': '', 'Status': {'@code': '502', '#text': 'Operation failed. Entity having same name already exists.'}}

Create Firewall Rule
^^^^^^^^^^^^^^^^^^^^
When creating a firewall rule, first create a Python dict object storing the rule parameters. Then pass the parameters to the **create_rule()** method.

.. code-block:: python

    rule_params = rule_params = dict(
        rulename="Test from Python",
        after_rulename="Security Data Platform – FluentD",
        description="Test change automation", 
        action="Accept",
        log="Enable",
        src_zones=["LAN"],
        dst_zones=["WAN"],
        src_networks=["ABN 10.151.210.0"],
        dst_networks=["Internet IPv4 group"],
        service_list=["162 SNMP Trap"]
    )
    
    response = fw.create_rule(rule_params=rule_params)

    {
        "Response": {
            "@APIVersion": "1905.1",
            "@IPS_CAT_VER": "1",
            "Login": {
                "status": "Authentication Successful"
            },
            "FirewallRule": {
                "@transactionid": "",
                "Status": {
                    "@code": "200",
                    "#text": "Configuration applied successfully."
                }
            }
        }
    }

.. note::
    Not every possible rule parameter that is configurable in the firewall UI is available to be configured with the **create_rule()** method. 
    If additional parameters are needed, a template for the XML payload would need to be built to accept the additional parameters and
    can be submitted using the **submit_template()** method as described in the next section. 

Create Using Template
^^^^^^^^^^^^^^^^^^^^^
As not every object that can be configured on the firewall has a convenience method available in this module, the **submit_template()** method can be used
to post a Jinja2 template containing the required XML payload. The XML payload can be determined by looking at the `API documentation <https://docs.sophos.com/nsg/sophos-firewall/18.5/API/index.html>`_. 
Place the XML payload into a separate file, and then replace any values in the XML file with variables that will be passed in by your program.
Variables should be surrounded by double brackets.  For example:  {{ my_var }}

Below is an example XML payload to create a URL Group on the firewall. 

.. code-block:: XML

    <Request>
        <Login>
            <Username>username</Username>
            <Password >password</Password>
        </Login>
        <Set operation="add">
            <WebFilterURLGroup>
                <Name>Name</Name>
                <URLlist>
                    <URL>URLs</URL>
                    <URL>URLs</URL>
                </URLlist>
                <Description>Text</Description>
                <IsDefault>Yes/No</IsDefault>
            </WebFilterURLGroup>
        </Set>
    </Request>
    
Here is the XML payload using Jinja2 variable substitution. There is also a for loop which allows for multiple URLs to be configured
at the same time if desired. 

.. code-block:: XML

    <Request>
        <Login>
            <Username>{{username}}</Username>
            <Password >{{password}}</Password>
        </Login>
        <Set operation="add">
            <WebFilterURLGroup>
                <Name>{{ name }} </Name>
                <URLlist>
                    {% for url in url_list %}
                    <URL>{{ url }}</URL>
                    {% endfor %}
                </URLlist>
                <Description>{{ description }}</Description>
                <IsDefault>{{ isdefault }}</IsDefault>
            </WebFilterURLGroup>
        </Set>
    </Request>

Next, create a Python dict to store the variables to be injected into the template, and use the **submit_template** method to
send the payload to the firewall. 

.. code-block:: python

    template_vars = dict(
        name="Test URL group",
        url_list=["testdomain1.com", "testdomain2.com"],
        description="Test URL group created by Python",
        isdefault="No"
    )
    response = fw.submit_template(filename="urlgroup_example.j2", template_vars=template_vars, template_dir=".")

    {
        "Response": {
            "@APIVersion": "1905.1",
            "@IPS_CAT_VER": "1",
            "Login": {
                "status": "Authentication Successful"
            },
            "WebFilterURLGroup": {
                "@transactionid": "",
                "Status": {
                    "@code": "200",
                    "#text": "Configuration applied successfully."
                }
            }
        }
    }


.. note::
    Create methods have an optional **debug** argument that can be used to print out the XML payload for troubleshooting purposes.
    Ex. fw.create_ip_host(name="test-host", ip_address="10.0.0.1", debug=True)   

Update Functions
----------------
Update an existing firewall configuration.

Update User Password
^^^^^^^^^^^^^^^^^^^^
.. code-block:: python

    response = fw.update_user_password(username="testuser", new_password="P@ssw0rd123")

    { 'Response': { '@APIVersion': '2000.1',
        '@IPS_CAT_VER': '1',
        'Login': {'status': 'Authentication Successful'},
        'User': { '@transactionid': '',
            'Status': { 
              '#text': 'Configuration applied successfully.',
              '@code': '200'}
              }
            }
        }

Update
^^^^^^
While there are several feature-specific update methods, the generic **update()** method can be used to update any object.
The **update()** method requires arguments specifying the name of the object and a dictionary of key/value pairs indicating which
object parameters should be updated. The keys must match the XML tags in the existing object. The available keys can be 
determined by reviewing the `API documentation <https://docs.sophos.com/nsg/sophos-firewall/18.5/API/index.html>`_ and/or
using the **get_tag_with_filter()** method to retrieve the object by name.
  
In the below example, we have an existing IP Host named `TESTHOST` that we are changing the IP address from 1.1.1.1 to 2.2.2.2. 
From the output of :ref:`get-ip-host-label` we can see that the XML format of the key used to set the IP address is `IPAddress`. 
Therefore, we pass in a dict setting `IPAddress` to the new IP address 2.2.2.2.

.. code-block:: python

    response = fw.update(xml_tag="IPHost", name="TESTHOST", update_params={"IPAddress": "2.2.2.2"})

    {'Response': 
        { '@APIVersion': '2000.1',
          '@IPS_CAT_VER': '1',
          'IPHost': {   
            '@transactionid': '',
            'Status': {
               '#text': 'Configuration applied successfully.',
                '@code': '200'}
                },
            'Login': {'status': 'Authentication Successful'}
            }
        }

Delete Functions
----------------
Delete objects from the firewall.

Remove
^^^^^^
The **remove()** method can be used to delete objects from the firewall. The method requires the XML tag for the type of object
being removed, and the name of the object. The below example removes an IP Host from the firewall named `TESTHOST`.

.. code-block:: python
    
    response = fw.remove(xml_tag="IPHost", name="TESTHOST")

        {
        "Response": {
            "@APIVersion": "2000.1",
            "@IPS_CAT_VER": "1",
            "Login": {
                "status": "Authentication Successful"
            },
            "IPHost": {
                "@transactionid": "",
                "Status": {
                    "@code": "200",
                    "#text": "Configuration applied successfully."
                }
            }
        }
    }

