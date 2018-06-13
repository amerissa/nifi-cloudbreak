# Automate The Download Of Client Configs From Other Clusters

The script will download the client configs via Ambari API and save them into a specified folder. Define the one or multiple Ambari instances in the configs file. Sample is provided in the repo

## Options and help:

Usage: clientconfigs.py [options]

Options:

`-h, --help            show this help message and exit`

`-c CONFIGS, --configs=CONFIGS Configs file defining ambari default is ./configs`

`-d DIR, --directory=DIR Directory where to extract the tar files`
