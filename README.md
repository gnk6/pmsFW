# pmsFW
Containerized firewall system

This repository contains the playbooks and the needed files to deploy the containerized firewall system via ansible.
Prerequisites:
- Debian 12 server with two physical ethernet adapters
- Root SSH access on the Debian server with pubkey authentication

Playbooks:
- server_bridge_deploy,yml, is used to create 3 bridge interfaces:
  - br0 is the predefined interface used to communicate with the public network
  - br1 is the predefined interface used to communicate with the local network
  - br2 is the non-editable interface used for the link-local communication between the containers and the server
- firewall_deploy.yml is used to deplpoy the three system contaienrs and the server systemd services:
     - containers:
        - rest-firewall container provides the firewall functionalities (firewall rules, network interfaces management, static routing e.g.) 
        - rest-apache container provides a wgui and the api endpoints that are used for the communication between the three containers and the user interface
        - rest-database container is used to store the configuration for the firewall
     - services:
        - firewall.service, is used to start the system containers
        - firewall_failover.service, is used in order for the Debian server to use the rest-firewall container as its gateway
        - cnetapi.service, provides an api that the rest-firewall container to add,delete and update vlan interfaces

How to use it:
- Modify the inventory file and replace the variables you will find there
- Run server_bridge_deploy.yml to apply the network configuration on the debian server
- Run firewall_deploy.yml to do deploy the system.
- After 5-10 minutes try to connect on https://fw_pnet_ip (fw_pnet_ip is defined on inventory).


