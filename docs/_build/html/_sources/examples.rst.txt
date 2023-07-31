Examples
========

Get Functions
-------------
Request and return data from the API formatted as a Python dict object. 

.. note::
   Get methods will return all of the objects configured on the firewall if no filtering parameters are specified.

**Get all IP Hosts**

.. code-block:: python

    fw.get_ip_host()

.. warning::
    Use `verify=False` if operating against a device that does not have a valid SSL certificate. For example, `fw.get_ip_host(verify=False)`.
    An SSLError will be thrown if certificate checking is enabled and the device does not have a valid certificate.

**Get IP Host by Name**

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

**Get IP Host by IP Address**

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