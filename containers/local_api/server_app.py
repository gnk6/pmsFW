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
    return msg


@servapp.route('/vlan/<vlanid>', methods=['GET'])
def get_vlan_data(vlanid):
    try:
        vid = vlanid.split('_')[-1]
        vlan_name = 'ipvlan'+vid
        vlan_data = os.popen(f'/usr/bin/docker network inspect {vlan_name}').read().strip()
        print(vlan_data)
        if vlan_data =='[]':
            return jsonify({'error': 'VLAN ID not found'}), 404
        return jsonify({'success':vlan_data}), 200
    except Exception as error:
        print(error)
        return jsonify({'error': 'Could not retrieve VLAN data'}), 500

@servapp.route('/vlan', methods=['POST'])
def create_vlan():
    vlan_dict = request.json
    print(vlan_dict)
    try:
        msg = create_container_net(vlan_dict)
        return jsonify({'success':msg, 'data':vlan_dict}), 200
    except Exception as error:
        print(error)
        return jsonify({'error':str(error)}), 400
    

@servapp.route('/vlan/<vlanid>', methods=['PUT'])
def update_vlan(vlanid):
    vlan_dict = request.json
    print(vlan_dict)
    try:
        msg = create_container_net(vlan_dict)
        return jsonify({'success':msg, 'data':vlan_dict}), 200
    except Exception as error:
        print(error)
        return jsonify({'error':str(error)}), 400


@servapp.route('/vlan/<vlanid>', methods=['DELETE'])
def delete_vlan(vlanid):
    try:
        vid = vlanid.split('_')[-1]
        vlan_name = 'ipvlan'+vid
        vlan_delete = os.popen(f'/usr/local/bin/firewall_manage_vlan delete {vlan_name}').read().strip()
        if 'Error' in vlan_delete:
            return jsonify({'error': vlan_delete}), 400
        return jsonify({'success': vlan_delete}), 200
    except Exception as error:
        return jsonify({'error':str(error)}), 400
    

if __name__ == '__main__':
    servapp.run(host='0.0.0.0',port=6000,debug=True)