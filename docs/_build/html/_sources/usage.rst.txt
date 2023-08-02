Usage
=====

Installation
------------

To use sophosfirewall-python, first clone the repository:

.. code-block:: console

   $ git clone https://github.com/sophos-internal/it.netauto.sophos-firewall-api/ sophos-firewall

Then install it using pip:

.. code-block:: console

   $ cd sophos-firewall
   $ pip install dist/sophosfirewall_python-X.X.X-py3-none-any.whl

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
        port=FIREWALL_PORT
        )

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


