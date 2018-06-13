# Automate Ranger User Creation and Policy Assignments

The script will create the user for the node in Ranger and assign it to the default all resources

Options and help:

Usage: rangernifi.py [options]

Options:

`-h, --help            show this help message and exit`

`-S PROTOCOL, --protocol=PROTOCOL default is http, set to https if required`

`-P PORT, --port=PORT  Set Ranger port default is 6080`

`-u USERNAME, --username=USERNAME default is admin`

`-p PASSWORD, --password=PASSWORD Ranger Password default is admin`

`-H HOST, --host=HOST  Ranger Host default is localhost`

`-a USER, --usertoadd=USER User name to add, default is the system's hostname`

`-n NIFIREPO, --nifi-repo=NIFIREPO Nifi repo to adjust default is nifi`
