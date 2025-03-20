#!/usr/bin/env python3
import json
import requests
from flask import Flask, request
from sqlmodel import SQLModel, Field, create_engine, Session, select
from typing import Optional
import jinja2
import os
import time
import logging
from ipaddress import IPv4Address, IPv4Network, IPv4Interface


logging.basicConfig(filename='/firewall/logs/firewall_app.log', format='%(asctime)s - %(levelname)s - %(message)s',datefmt='%Y-%m-%d %H:%M:%S', level=logging.DEBUG)

app = Flask(__name__)
dburl = "postgresql://{{ psql_user }}:{{ psql_pass }}@169.254.100.3/firewalldb"
engine = create_engine(dburl)

class interfaces(SQLModel,table=True):
    id: int | None = Field(default=None, primary_key=True)
    interface: str = Field(unique=True)
    int_type: str | None
    parent: str | None = None
    ip: str = Field(unique=True)
    gateway: str | None = None
    is_provider: bool | None = Field(default=False)
    priority: int | None
    is_dhcp: bool | None = Field(default=False)
    dhcp_start: str | None = None
    dhcp_end:  str | None = None
    int_delete: bool | None = Field(default=False)
    int_update: bool | None = Field(default=False)



class firewall_rules(SQLModel, table= True):
    id: int | None = Field(default=None, primary_key=True)
    fworder: int
    action: str
    protocol: str
    src_interface: str | None = Field(foreign_key="interfaces.interface")
    dst_interface: str | None = Field(foreign_key="interfaces.interface")
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: str | None = None
    dst_port: str | None = None

class static_routes(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    network: str
    gateway: str
    gateway_int: str | None = Field(foreign_key="interfaces.interface")
    masquerade: bool | None = Field(default=False)


SQLModel.metadata.create_all(engine)

#FLAG
def validate_address(intip=None,gwlist=None,sip=None,route=False,interface=None):
    #Validate interface's ip address format 192.168.0.5/24
    if intip:
        if IPv4Interface(intip):
            if str(IPv4Interface(intip)) == str(IPv4Interface(intip).network) and route==False:
                raise Exception('Interface ip cannot be network')
            return
    #Validate single ip address
    elif sip:
        if IPv4Address(sip):
           return
    #Validate gateway
    elif gwlist:
        if IPv4Address(gwlist[0]):
            gw={}
            gw['ip']=IPv4Address(gwlist[0])
            gw['intip']=str(IPv4Interface(gwlist[1]).ip)
            gw['net']=str(IPv4Interface(gwlist[1]).network).split('/')[0]
            gw['broadcast']=str(IPv4Interface(gwlist[1]).network.broadcast_address)
            logging.debug(gw)
            if str(gw['ip']) == gw['intip']:
                raise Exception('Gateway cannot be the same as interface ip')
            if str(gw['ip'])==gw['net']:
                raise Exception('Gateway cannot be network')
            if not gw['ip'] in IPv4Network(str(IPv4Interface(gwlist[1]).network)):
                raise Exception('Gateway not in defined network')
            if str(gw['ip'])==gw['broadcast']:
                raise Exception('Gateway cannot be broadcast')

    #Validate dhcp
    elif interface:
        if not IPv4Address(interface['dhcp_start']) in IPv4Network(str(IPv4Interface(interface['ip']).network)) or not IPv4Address(interface['dhcp_end']) in IPv4Network(str(IPv4Interface(interface['ip']).network)):
            raise Exception('DHCP range not in defined network')
        #Get dhcp attributes
        interface['mask'] = IPv4Interface(interface['ip']).with_netmask.split('/')[1]
        interface['net'] = str(IPv4Interface(interface['ip']).network).split('/')[0]
        interface['ipaddr'] = str(IPv4Interface(interface['ip']).ip)
        if IPv4Address(interface['ipaddr']) > IPv4Address(interface['dhcp_start']) and IPv4Address(interface['ipaddr']) < IPv4Address(interface['dhcp_end']):
            raise Exception('Interface ip cannot be included in dhcp range')
        if IPv4Address(interface['ipaddr'])==IPv4Address(interface['dhcp_start']) or IPv4Address(interface['ipaddr'])== IPv4Address(interface['dhcp_end']):
            raise Exception('Interface ip cannot be included in dhcp range')
        if interface['net'] == str(IPv4Address(interface['dhcp_start'])) or interface['net'] == str(IPv4Address(interface['dhcp_end'])):
            raise Exception('DHCP range cannot be network')
        if str(IPv4Interface(interface['ip']).network.broadcast_address) == str(IPv4Address(interface['dhcp_start'])) or str(IPv4Interface(interface['ip']).network.broadcast_address) == str(IPv4Address(interface['dhcp_end'])):
            raise Exception('DHCP range cannot be broadcast')
        return



##Get systems current interfaces.
def get_active_interfaces(system_init=None):
    if system_init:
        int_list = os.popen("/firewall/get_container_interfaces iface 2").read().splitlines()
        int_dict = {'pnet': int_list[0],'lnet': int_list[1],'cnet':int_list[2]}
    else:
        int_list = os.popen("/firewall/get_container_interfaces iface").read().splitlines()
        int_dict = {'pnet': int_list[0],'lnet': int_list[1],'cnet':int_list[2]}
        vlan_list = os.popen("/firewall/get_container_interfaces get_vlan").read().splitlines()
        if vlan_list:
            for vlan_int in vlan_list:
                int_dict[vlan_int.split(':')[0]]=vlan_int.split(':')[1]
    logging.debug(int_dict)
    return int_dict

#Get system's provider
def get_providers():
    int_prod=os.popen("/firewall/get_container_interfaces get_provider").read().split()
    return int_prod

##Get system current ip configuration
def get_active_ip(system_init=None):
    if system_init:
        ip_list = os.popen("/firewall/get_container_interfaces ip init").read().splitlines()
    else:
        ip_list = os.popen("/firewall/get_container_interfaces ip").read().splitlines()
    ip_dict = {'pnet': ip_list[0],'lnet': ip_list[1],'cnet':ip_list[2]}
    gway = os.popen("/firewall/get_container_interfaces gw").read().strip()
    ip_dict['gw'] = gway
    return ip_dict

#Vlan on container is represented as physical interface (e.g. eth15) which is dynamic. I retrieve it based on ip config
def get_container_vlan_interface(ip_str,ifconfig):
    cmd = ("ip a | grep %s | grep -v %s | grep -v %s | grep -v %s | awk '{ print $NF }'") %(ip_str,ifconfig['lnet'],ifconfig['pnet'],ifconfig['cnet'])
    vlaniface = os.popen(cmd).read().strip()
    return vlaniface

##Get interface configuration on database
def retrieve_intefaces():
    with Session(engine) as session:
        rinterfaces = session.exec(select(interfaces).order_by(interfaces.id)).all()
        int_list = [int.model_dump() for int in rinterfaces]
        return int_list

def insert_intefaces():
    ipdict = get_active_ip()
    intdata = [{'interface':'pnet', 'ip':ipdict['pnet'],'gateway':ipdict['gw'],'is_provider':True, 'priority':'1'},
               {'interface':'lnet','ip':ipdict['lnet']},
               {'interface':'cnet','ip':ipdict['cnet']}]
    for iface in intdata:
        iface_to_insert = interfaces(**iface)
        with Session(engine) as session:
            session.add(iface_to_insert)
            session.commit()
            session.refresh(iface_to_insert)
    return


##Match cnet, pnet,lnet with the relevant physical inteface eth0, eth1, eth2
def interface_dict(db_int_dict, system_int_dict):
    if not db_int_dict:
        logging.info('No interfaces found in DB, inserting the system config')
        insert_intefaces()
        return None
    for int_info in db_int_dict:
        if int_info['interface'] == 'pnet':
            int_info['sys_int'] = system_int_dict['pnet']
        elif int_info['interface'] == 'lnet':
            int_info['sys_int'] = system_int_dict['lnet']
    return db_int_dict

def overwrite_env_file(ifaces):
    envstring = ''
    for iface in ifaces:
        if iface['int_delete']: ##Do not write interfaces that are going to be deleted
            continue
        if iface['interface'] == 'pnet':
            envstring += f"\nexport WAN=\'{iface['ip']}\'\nexport GW=\'{iface['gateway']}\'"
        elif iface['interface'] == 'lnet':
            envstring += f"\nexport LAN=\'{iface['ip']}\'"
        elif iface['int_type'] == 'vlan':
            vlan_id = iface['interface'].split('_')[1]
            envstring += f"\nexport vlan_{vlan_id}=\'{iface['ip']}\'"
        else:
            envstring += f"\nexport CAN=\'{iface['ip']}\'"
    with open('/firewall/db.env', 'w') as f:
        f.write(envstring)
    return True


def dhcp_config(interfaces,ifconfig):
    for interface in interfaces:
        if interface['int_type']=='vlan':
            interface['sys_int']=get_container_vlan_interface(interface['ip'],ifconfig)
    dhcp_tmpl = jinja2.FileSystemLoader(searchpath='/firewall/')
    dhcp_tmplENV = jinja2.Environment(loader=dhcp_tmpl)
    dhcp_tmplFile = "dhcpd.conf.tmpl"
    tmpl = dhcp_tmplENV.get_template(dhcp_tmplFile)
    dhcp_str = tmpl.render(intfaces=interfaces)
    with open('/etc/dhcp/dhcpd.conf', 'w') as f:
        f.write(dhcp_str)
    logging.debug('Wrote dhcpd config file')
    isc_dhcp_server_tmpl=jinja2.FileSystemLoader(searchpath='/firewall/')
    isc_dhcp_server_tmplENV=jinja2.Environment(loader=isc_dhcp_server_tmpl)
    is_dhcp_server_tmplFile = "isc-dhcp-server.tmpl"
    tmpl2=isc_dhcp_server_tmplENV.get_template(is_dhcp_server_tmplFile)
    is_dhcp_server_str=tmpl2.render(interfaces=interfaces)
    with open('/etc/default/isc-dhcp-server', 'w') as f:
        f.write(is_dhcp_server_str)
    logging.debug('Wrote dhcp server file')
    ##Terminate old dhcp process and start a new one
    os.system('kill -9 $(cat /var/run/dhcpd.pid) > /dev/null 2>&1')
    time.sleep(0.3)
    os.system('rm -f /var/run/dhcp.pid 2> /dev/null')
    time.sleep(0.3)
    os.system('dhcpd -cf /etc/dhcp/dhcpd.conf > /dev/null 2>&1')
    logging.debug('Starting dhcp')
    return

def apply_vlan_config_on_server(interface):
    srvurl = 'http://169.254.100.1:6000/vlanconfig'
    headers = {"Content-type":"Application/json"}
    api_call = requests.post(srvurl, headers=headers, json=interface)
    return api_call

def apply_vlan_ip_on_firewall(interface,ifconfig):
    ip_list = interface['ip'].split('.')
    ip_list.pop(-1)
    ip_str = '.'.join(ip_list)
    vlan_int = get_container_vlan_interface(ip_str,ifconfig)
    os.system(f"ip a flush dev {vlan_int}")
    if interface['int_delete']:
        return
    exit_code = os.system(f"ip a add {interface['ip']} dev {vlan_int}")
    if exit_code == 1:
        raise Exception(f"Could not apply {interface['interface']} on firewall")
    return


def apply_ip_config(interface,ifconfig,system_init=None, action=None):
    match interface['interface']:
        case 'pnet':
            if interface['ip'] != ifconfig['pnet']:
                logging.debug(f"ip a flush dev {interface['sys_int']}")
                os.system(f"ip a flush dev {interface['sys_int']}")
                time.sleep(0.5)
                logging.debug("ip a add {interface['ip']} dev {interface['sys_int']}")
                os.system(f"ip a add {interface['ip']} dev {interface['sys_int']}")
                time.sleep(0.5)
                if interface['is_provider']:
                    os.system(f"/usr/sbin/ip route replace default via {interface['gateway']}")
                return
        case 'lnet':
            if interface['ip'] != ifconfig['lnet']:
                logging.debug(f"ip a flush dev {interface['sys_int']}")
                os.system(f"ip a flush dev {interface['sys_int']}")
                time.sleep(0.5)
                logging.debug("ip a add {interface['ip']} dev {interface['sys_int']}")
                os.system(f"ip a add {interface['ip']} dev {interface['sys_int']}")
                return
        case _ if 'vlan' in interface['interface']:
            if interface['int_delete']:
                interface['action']='delete'
            elif interface['int_update']:
                interface['action']='update'
            else:
                if action =='delete' or action == 'update':
                    return
                else:
                    interface['action']=action
            resp = apply_vlan_config_on_server(interface)
            if resp.status_code != 200:
                err =json.loads(resp.content.decode('utf8'))
                if 'exists' in err['error']: ##Dont break when a vlan exists, continue itteration
                    logging.error(err['error'])
                    return
                raise Exception(err['error'])
            apply_vlan_ip_on_firewall(interface,ifconfig)
            msg = json.loads(resp.content.decode('utf8'))
            logging.debug(msg['success'])
            return


def apply_gw_config(interfaces,ifconfig):
    cur_gw = os.popen("/usr/sbin/ip route | grep -v metric | grep default | awk '{ print $3 }'").read().strip()
    #Clean up old routes with metric
    os.system("for gw in $(/usr/sbin/ip route | grep metric | awk '{ print $3 }'); do echo /usr/sbin/ip route del default via $gw; done")
    gw_dict = {}
    gw_prio = []
    for interface in interfaces:
        if interface['is_provider']:
            #Add all the default routes with their metric
            #logging.debug(f"/usr/sbin/ip route add default via {interface['gateway']} metric {interface['priority']}")
            xcode=os.system(f"/usr/sbin/ip route add default via {interface['gateway']} metric {interface['priority']}")
            gw_prio.append(interface['priority'])
            if interface['int_type']=='vlan':
                interface['sys_int'] = get_container_vlan_interface(interface['ip'],ifconfig)
            gw_dict[interface['priority']]=[interface['sys_int'],interface['gateway']]
    gw_prio.sort()
    logging.debug(gw_dict)
    for prio in gw_prio:
        logging.debug(f'Will try interface {gw_dict[prio][0]} ')
        ping_code = os.system(f"/usr/bin/ping -c2 8.8.8.8 -I {gw_dict[prio][0]} >/dev/null 2>&1")
        if ping_code == 0:
            if gw_dict[prio][1] == cur_gw:
                logging.debug('Gateway already applied, skipping configuration')
                os.system(f"/usr/sbin/ip route del default via {gw_dict[prio][1]} metric {prio}")
                break
            logging.debug(f"/usr/sbin/ip route replace default via {gw_dict[prio][1]}")
            xcode=os.system(f"/usr/sbin/ip route replace default via {gw_dict[prio][1]}")
            if xcode!=0:
                raise Exception(f"code {xcode}")
            os.system(f"/usr/sbin/ip route del default via {gw_dict[prio][1]} metric {prio}")
            break
    return

def apply_system_config(interfaces_dictionaries,system_init=None, action=None):
    if not interfaces_dictionaries:
        logging.info('No config found to apply. Applying default settings.')
        ##Change hardcoded ip
        os.system('/usr/sbin/ip route replace default via {{ server_gw }}')
        return 'OK'
    ifconfig = get_active_ip(system_init)
    dhcp_interfaces=[]
    for dinterface in interfaces_dictionaries:
        try:
            #Validate_ip_addresses
            validate_address(intip=dinterface['ip'])
            if dinterface['is_provider']:
                gateway_list=[dinterface['gateway'],dinterface['ip']]
                validate_address(gwlist=gateway_list)
            if dinterface['is_dhcp']:
                validate_address(interface=dinterface)
                dhcp_interfaces.append(dinterface)
        except Exception as error:
            logging.error('Invalid interface config for \'%s\': %s' %(dinterface['interface'], error))
            return 'Error: Invalid interface config for %s. %s' %(dinterface['interface'],error)
    logging.debug(f'System_config: {ifconfig}')
    logging.debug(f'Complete Data: {interfaces_dictionaries}')
    for interface in interfaces_dictionaries:
        try:
            apply_ip_config(interface,ifconfig,system_init,action)
        except Exception as error:
            logging.error('Error: Could not apply %s. %s' %(interface['interface'],error))
            return 'Error: Could not apply %s. %s' %(interface['interface'],error)
    try:
        apply_gw_config(interfaces_dictionaries,ifconfig)
    except Exception as error:
        logging.error('Could not apply gateway: %s' %error)
        return "Error: could not apply gateway. %s" %error
    try:
        if dhcp_interfaces:
            dhcp_config(dhcp_interfaces,ifconfig)
        logging.info('Applied dhcp config')
    except Exception as error:
        logging.error('Invalid DHCP config: %s' %error)
        return 'Error: Could not generate DHCP. %s' %error
    overwrite_env_file(interfaces_dictionaries)
    return 'OK'




def update_rules_with_the_correct_interfaces(rule_dict,active_int_dict):
    if not rule_dict['src_interface']:
        pass
    else:
        src_int = rule_dict['src_interface']
        rule_dict['src_interface'] = active_int_dict[src_int]
    if not rule_dict['dst_interface']:
        pass
    else:
        dst_int = rule_dict['dst_interface']
        rule_dict['dst_interface'] = active_int_dict[dst_int]
    return rule_dict


##For DNAT destination IPs that are using syntax '192.168.0.5:3389'
def add_extra_value_for_dnat(rule_dict):
    if rule_dict['action'] == 'DNAT':
        rule_dict['dst_ip_port'] = rule_dict['dst_ip']
        rule_dict['dst_ip'] = rule_dict['dst_ip_port'].split(':')[0]
        rule_dict['dst_pub_port'] = rule_dict['dst_port']
        rule_dict['dst_port'] = rule_dict['dst_ip_port'].split(':')[1]
    return rule_dict


def route_update_with_correct_interface(sroute_list,active_int_dict):
    for route_dict in sroute_list:
        route_dict['sys_int']=active_int_dict[route_dict['gateway_int']]
    #logging.debug(sroute_list)
    return sroute_list

def locals_update_with_correct_interfaces(flocals, active_int_dict):
    final_local_ls = []
    for ldata in flocals:
        #create a list that combines local ips with local interfaces
        final_local_ls.append({'iface':active_int_dict[list(ldata.keys())[0]],'ip':list(ldata.values())[0]})
    logging.debug(final_local_ls)
    return final_local_ls

def get_locals_to_listen():
    with Session(engine) as session:
        rlocals = session.exec(select(interfaces.ip, interfaces.interface).where(interfaces.is_provider==False).where(interfaces.ip!='169.254.100.2/29')).all()
        flocals=[]
        #remove prexix from ip e.g. /24 and create a dict for each entry
        for rip in rlocals:
            flocals.append({rip[1]:rip[0].split('/')[0]})
        return flocals

def create_template(rule_list,sroute_list):
    templateLoader = jinja2.FileSystemLoader(searchpath='/firewall/')
    templateENV = jinja2.Environment(loader=templateLoader)
    logging.debug(sroute_list)
    fwtmpl = "iptables_restore.tmpl"
    active_int_dict = get_active_interfaces()
    local_ips = locals_update_with_correct_interfaces(get_locals_to_listen(),active_int_dict)
    for rule in rule_list:
        update_rules_with_the_correct_interfaces(rule,active_int_dict)
        add_extra_value_for_dnat(rule)
    rule_list.append(active_int_dict)
    updated_sroute_list=route_update_with_correct_interface(sroute_list,active_int_dict)
    template = templateENV.get_template(fwtmpl)
    providers_list = get_providers()
    fw_rules = template.render(fw_rules=rule_list,providers=providers_list,routes=updated_sroute_list,llocals=local_ips)
    fw_rules_ls = fw_rules.splitlines()
    fw_rules_ls_with_empty_lines_removed = [ line for line in fw_rules_ls if line.strip() ]
    fw_rules_ls_stipped = '\n'.join([ line.strip() for line in fw_rules_ls_with_empty_lines_removed])
    with open ('/firewall/iptables_save', 'w') as f:
       f.write(fw_rules_ls_stipped)
    return True

def apply_routing_config(sroute_list):
    #Validate_entries:
    for val in sroute_list:
        validate_address(intip=val['network'],route=True)
        validate_address(sip=val['gateway'])
    #Flush previous static routing and insert the new ones
    old_routes = os.popen("/usr/sbin/ip route | grep -v default | grep -v scope").read().splitlines()
    for oroute in old_routes:
        os.system(f"/usr/sbin/ip route del {oroute.strip()}")
    for sroute in sroute_list:
        rcode=os.system(f"/usr/sbin/ip route add {sroute['network']} via {sroute['gateway']}")
        if rcode!=0:
            raise Exception(f"Could not apply routing for {sroute['network']}")
    return

@app.route('/rules',methods=['GET'])
def retrieve_firewall_rules():
    with Session(engine) as session:
        fw_rules = session.exec(select(firewall_rules).order_by(firewall_rules.fworder,firewall_rules.id)).all()
        rule_list = [rule.model_dump() for rule in fw_rules]
        return rule_list

def retrieve_routes():
    with Session(engine) as session:
        sroutes = session.exec(select(static_routes).order_by(static_routes.id)).all()
        sroute_list = [route.model_dump() for route in sroutes]
        return sroute_list


def init_config():
    logging.info('Running initial config')
    system_init = True
    interfaces_dictionaries = interface_dict(retrieve_intefaces(),get_active_interfaces(system_init))
    logging.debug(f'Data: {interfaces_dictionaries}')
    apply_system_config(interfaces_dictionaries,system_init,action='create')
    rule_list = retrieve_firewall_rules()
    sroute_list = retrieve_routes()
    create_template(rule_list,sroute_list)
    fwvalid = int(os.popen('/usr/sbin/iptables-restore --test < /firewall/iptables_save ; echo $?').read().strip())
    if fwvalid == 0:
        os.system('/usr/sbin/iptables-restore < /firewall/iptables_save')
        logging.info('Applying firewall config')
        apply_routing_config(sroute_list)
        return True
    else:
        logging.error('Could not generate firewall config.\nCommand: iptables-restore --test < iptables_save')
        return


def api_gen_firewall():
    try:
        rule_list = retrieve_firewall_rules()
        sroute_list = retrieve_routes()
        create_template(rule_list,sroute_list)
        fwvalid = int(os.popen('iptables-restore --test < /firewall/iptables_save ; echo $?').read().strip())
        if fwvalid == 0:
            os.system('/usr/sbin/iptables-restore < /firewall/iptables_save')
            logging.info('Applying firewall config')
            apply_routing_config(sroute_list)
            return 'OK'
        else:
            raise Exception('Could not generate firewall config.\nCommand: iptables-restore --test < iptables_save')
    except Exception as err:
        logging.error('Invalid entries. %s' %err)
        return 'Error: Invalid entries. %s' %err

def delete_int():
    try:
        with Session(engine) as session:
            vlans_to_delete=session.exec(select(interfaces).where(interfaces.int_delete==True)).all()
            if not vlans_to_delete:
                logging.error('Error could not locate interface on DB')
                return 'Error could not locate interface on DB'
            for vlan_data in vlans_to_delete:
                session.delete(vlan_data)
                session.commit()
        logging.info('entry deleted from DB')
        return 'OK'
    except Exception as err:
        logging.error(str(err))
        if 'firewall' in str(err):
            return 'Error interface is referenced in firewall rules.'
        elif 'static_routes' in str(err):
            return 'Error interface is referenced in static routes'
        return 'Error %s' %err

def api_gen_int(raction,int_name=None):
    int_dict = interface_dict(retrieve_intefaces(),get_active_interfaces())
    logging.debug(f'Data: {int_dict}')
    if raction =='delete':
        msg = delete_int()
        if 'Error' in msg:
            return msg
    cmsg = apply_system_config(int_dict,action=raction)
    if 'Error' in cmsg:
        return cmsg
    logging.info('Applying interfaces')
    return 'OK'



@app.route('/rules', methods=['POST'])
def gen_config():
    command = request.json
    if command['action'] == 'gen_rules':
        return api_gen_firewall()
    elif command['action'] == 'gen_int':
        return api_gen_int('create')
    elif command['action'] == 'update_int' or command['action'] == 'delete_int':
        act=command['action'].split('_')[0]
        imsg=api_gen_int(act)
        if 'Error' in imsg:
            return imsg
        return api_gen_firewall()




if __name__ == '__main__':
    init_config()
    #app.run(host='0.0.0.0',port=6000,debug=True)
