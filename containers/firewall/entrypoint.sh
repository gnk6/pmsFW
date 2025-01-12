#! /usr/bin/env bash
ip route replace default via "{{ server_gw }}" 
ulogd -d 
/firewall/venv/bin/python3 /firewall/iptables_gen.py
/firewall/venv/bin/waitress-serve --host=0.0.0.0 --threads=1 --port=5000 firewall.iptables_gen:app
