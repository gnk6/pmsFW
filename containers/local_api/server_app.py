#!/firewall/local_api/apienv/bin/python3

from flask import Flask, request, jsonify
import os
import time
import logging
from ipaddress import IPv4Address, IPv4Network, IPv4Interface



servapp = Flask(__name__)

server_int = {'pnet':'br0', 'lnet':'br1', 'cnet':'br2'}
def create_container_net(vlan):
    vlan_id = vlan['interface'].split('_')[1]
    parent = vlan['parent']
    srvint = server_int[parent]+'.'+vlan_id
    dnetname = 'ipvlan'+vlan_id
    dnetwork = IPv4Interface(vlan['ip']).network
    if vlan['action'] == 'create':
        msg = os.popen(f'/usr/local/bin/firewall_manage_vlan create {dnetname} {dnetwork} {srvint}').read().strip()
        if 'Error' in msg:
            raise Exception(f'Could not create vlan. {msg}')
    elif vlan['action'] == 'update':
        msg = os.popen(f'/usr/local/bin/firewall_manage_vlan update {dnetname} {dnetwork} {srvint}').read().strip()
        if 'Error' in msg:
            raise Exception(f'Could not update vlan. {msg}')
    elif vlan['action'] == 'delete':
        msg = os.popen(f'/usr/local/bin/firewall_manage_vlan delete {dnetname}').read().strip()
        if 'Error' in msg:
            raise Exception(f'Could not delete vlan. {msg}')
    return msg

@servapp.route('/vlanconfig', methods=['POST'])
def generate_vlan():
    vlan_dict = request.json
    try:
        msg = create_container_net(vlan_dict)
        return jsonify({'success':msg}), 200
    except Exception as error:
        print(error)
        return jsonify({'error':str(error)}), 400

