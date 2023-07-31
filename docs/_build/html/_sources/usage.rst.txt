Usage
=====

Installation
------------

To use sophosfirewall-python, first install it using pip:

.. code-block:: console

   (.venv) $ pip install [wheel]

Prerequisites
-------------
On the Sophos firewall to be managed, the IP address of the system using this utility must be configured under `Backup & firmware > API`.

Quickstart
-----------

Import the module and create a `SophosFirewall` object:

.. code-block:: python

    from sophosfirewall import SophosFirewall

    fw = SophosFirewall(
        username=FIREWALL_USERNAME,
        password=FIREWALL_PASSWORD,
        hostname=FIREWALL_HOST_OR_IP,
        port=FIREWALL_PORT
        )

Execute one of the available :doc:`sophosfirewall` methods. 

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


