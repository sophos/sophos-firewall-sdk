Usage
=====

Installation
------------

The module can be installed using pip:

.. code-block:: console

   $ pip install sophosfirewall-python

.. warning::
     It is recommended to install the module into a Python virtual environment to avoid any conflicts with packages that may already exist on the local system.

Prerequisites
-------------
On the Sophos firewall to be managed, the IP address of the system using this utility must be configured in the UI under the section **Backup & firmware > API**.

Quickstart
-----------

Import the module and create a `SophosFirewall` object:

.. code-block:: python

    from sophosfirewall_python.firewallapi import SophosFirewall

    fw = SophosFirewall(
        username=FIREWALL_USERNAME,
        password=FIREWALL_PASSWORD,
        hostname=FIREWALL_HOST_OR_IP,
        port=FIREWALL_PORT,
        verify=True
        )

.. warning::
    Use `verify=False` if operating against a device that does not have a valid SSL certificate. For example, `fw.get_ip_host(verify=False)`.
    An SSLError will be thrown if certificate checking is enabled and the device does not have a valid certificate.
    You may also specify the filename of the certificate chain in PEM format, for example `verify=firewall.pem`. 

Execute one of the available :doc:`firewallapi` methods. 

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

.. note::
   The XML response is converted to a Python dict object to facilitate easier parsing. 


