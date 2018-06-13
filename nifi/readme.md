# Automate The Creation of SSL Context, Nifi Bridge, and Nifi Registry Connection

Two scripts
  - **nifi.py:** It creates the SSL context, Nifi Bridge, and Nifi Registry Connection
  - **registry.py:** It creates the user (nifi node) in Nifi Registry to allow the Nifi to authenticate and connect to Nifi Registry

A sample configs file is provided in the repo. Set the specific section to `True` or `False` to enable or the feature

## Options and help for nifi.py:

Usage: nifi.py [options]

Options:

`-h, --help            show this help message and exit`

`-S PROTOCOL, --protocol=PROTOCOL default is http, set to https if required`

`-P PORT, --port=PORT  Set Ranger port default is 9090`

`-u USERNAME, --username=USERNAME default is admin`

`-p PASSWORD, --password=PASSWORD Nifi Password default is admin`

`-H HOST, --host=HOST  Nifi Host default is localhost`

`-c CONFIGS, --configs=CONFIGS Configs file to read default is ./configs`

## Options and help for registry.py:

Usage registry.py [options]

Options:

`-a USER, --usertoadd=USER User name to add, default is the system's hostname`

`-c CONFIGS, --configs=CONFIGS Configs file to read default is ./configs`
