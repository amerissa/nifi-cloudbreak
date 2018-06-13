# Nifi Security Automation Helper Scripts
This repo has the code and instructions needed to fully automate the security aspect of spinning Nifi with integration with HDP services. It is ideal with usage with Cloudbreak

It breaks down into four integration points:

  - Automate the creation of users for Nifi nodes and adding them to the basic policy in Ranger
  - Automate the creation of the SSL context and Atlas Bridge
  - Automate the connection to Nifi Registry Service and add Nifi nodes to the services to allow for authentication
  - Automate the download of client configs from other Ambari managed clusters

For integration point specific automation navigate to the specific folder.
