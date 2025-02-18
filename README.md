# proxmox-dynamic-inventory
Dynamic inventory for Proxmox

To use this script it's necessary to have ansible-inventory and the following variables initialized in your environment:
- API_USER: this is the user created on Proxmox for using API
- API_TOKEN: the value of API Token
- API_TOKEN_ID: name of the token
- API_HOST: API endpoint, your Proxmox host/cluster you connect to via browser. Specify even the PORT within this variable, like: API_HOST=127.0.0.1:8006

