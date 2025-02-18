#!/usr/bin/env /usr/bin/python3.11
import requests
import json
import urllib3
import os
import sys

# Libreries
## requests : HTTP library for Python
## json : JSON encoder and decoder
## urllib3 : HTTP library with thread-safe connection pooling, file post, and more
## os : Miscellaneous operating system interfaces, used for getting environment variables
## sys : System-specific parameters and functions, used for printing to stderr

# Suppress only the InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize the inventory dictionary
## _meta : Contains the hostvars dictionary
## hostvars : Contains the IP address and SSH arguments for each VM
## the other keys are the groups of VMs

inventory = {
    "_meta": {
        "hostvars": {}
    },
    "all_vms": {
        "hosts": []
    },
    "running_vms": {
        "hosts": []
    },
    "stopped_vms": {
        "hosts": []
    },
    "all": {
        "children": ["all_vms", "running_vms", "stopped_vms"]  # Include all groups as children
    }
}

def getDataFromEnv():
    # Get the API user, token, and token ID from the environment variables
    api_user = os.getenv("API_USER")
    api_token = os.getenv("API_TOKEN")
    api_token_id = os.getenv("API_TOKEN_ID")
    # Check if the environment variables are set
    if not api_user or not api_token or not api_token_id:
        # Raise a ValueError if the environment variables are not set
        raise ValueError("ENV API value not found!")

    # Combine the API token ID and token to create the full API token
    token_API=f'{api_user}!{api_token_id}={api_token}'
    return token_API

def setHeaders():
    # Get the full API token from the environment variables
    # Create the headers with the full API token and the content type
    pve_api_token_full = getDataFromEnv()
    _headers = {
        'Authorization': 'PVEAPIToken=' + pve_api_token_full,
        'Content-Type': 'application/json'
    }
    return _headers

def getAPIData(url,_headers):
# Get the data from the API
    try:
    # Make the request to the API
    # Verify=False disables SSL verification
    # headers=_headers sets the headers with the API token
    # timeout=10 sets the timeout to 10 seconds

        response = requests.get(url, verify=False, headers=_headers, timeout=10)
        
    # Check if the response is successful

        response.raise_for_status()
        return response.json()

    # Handle exceptions
    # Print the error message and return an empty dictionary
    except requests.exceptions.RequestException as e:
        print(f"Error: {e} for URL: {url}", file=sys.stderr)  # Print to stderr
        return {}  # Return an empty dictionary


def updateHostvars(vm_name, vm_config, inventory):
    if not vm_config:  # Check if vm_config is None or {}
        return

    # Check if the VM has an IP address
    # If the VM has an IP address, add the IP address and SSH arguments to the hostvars dictionary
    if 'ipconfig0' in vm_config["data"] and 'ip=dhcp' not in vm_config["data"]["ipconfig0"]:
        # Get the IP address from the ipconfig0 field
        # Split the ipconfig0 field by 'ip=' and '/' to get the IP address
        ip_address = vm_config["data"]["ipconfig0"].split('ip=')[1].split('/')[0]
        inventory["_meta"]["hostvars"][vm_name] = {
            'ansible_host': ip_address,
            "ansible_ssh_common_args": "-o StrictHostKeyChecking=no",
            "ansible_ssh_extra_args": "-o StrictHostKeyChecking=no"
        }

def createGroupByTag(vm_name, vm_config, inventory):
    if not vm_config:  # Check if vm_config is None or {}
        return
    
    # Check if the VM has tags attribute
    if 'tags' in vm_config["data"]:
        # Get the tags from the tags field
        tags = vm_config["data"]["tags"].split(';')
        for tag in tags:
            # Check if the tag is not empty
            if tag:
                # Check if the tag is not already a group
                if tag not in inventory:
                    inventory[tag] = {"hosts": []}
                # Add the VM to the group
                inventory[tag]["hosts"].append(vm_name)
                inventory["all"]["children"].append(tag)

def __main__():
    # Get the connection headers
    connection_headers = setHeaders()
    # Get the data from the Environment variables
    api_endpoint = os.getenv("API_HOST")
    url_nodes = f'https://{api_endpoint}/api2/json/nodes'
    node_data = getAPIData(url_nodes,connection_headers)
    # Check if the API endpoint is set
    # For each node in the data, get the VMs, thus it gets all vm from all nodes in a cluster
    for pve_node in node_data.get('data', []):
        node_name = pve_node["node"]
        # Set the URL for the Proxmox API
        url_vms_per_endpoit = f'https://{api_endpoint}/api2/json/nodes/{node_name}/qemu'
        
        # Get the VM list from the Proxmox API
        vms_data = getAPIData(url_vms_per_endpoit,connection_headers)

        # Check if the VM list is not empty
        if vms_data:
            # Loop through the VMs in the data
            for vm in vms_data.get('data', []):
                # Get the name of the VM
                vm_name = vm["name"]
                # Add the VM to the all_vms group
                inventory["all_vms"]["hosts"].append(vm_name)

                # Check if the VM is running or stopped
                if vm['status'] == 'running':
                    inventory["running_vms"]["hosts"].append(vm_name)
                    # Get the configuration of the VM
                    url_config = f'{url_vms_per_endpoit}/{vm["vmid"]}/config'
                    vm_config = getAPIData(url_config,connection_headers)
                    # Update the hostvars with the IP address and SSH arguments
                    updateHostvars(vm_name, vm_config, inventory)
                    createGroupByTag(vm_name, vm_config, inventory)
                # Check if the VM is stopped
                elif vm['status'] == 'stopped':
                    inventory["stopped_vms"]["hosts"].append(vm_name)

    # Print the inventory dictionary as JSON
    # Print as last operation due to avoid print errors with ansible-inventory
    print(json.dumps(inventory, indent=4))

if __name__ == "__main__":
    __main__()
