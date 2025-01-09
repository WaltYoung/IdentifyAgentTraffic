#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Xiao'

import csv
import ipaddress


def is_ip_in_subnet(ip_address, subnet):
    ip = ipaddress.ip_address(ip_address)
    network = ipaddress.ip_network(subnet, strict=False)
    return ip in network


def searchAS(ip_address):
    for subnet, value in as_dict.items():
        if is_ip_in_subnet(ip_address, subnet):
            return value
    return None


as_dict = {}
with open('as.csv', 'r', encoding='utf-8') as file:
    reader = csv.reader(file)
    for row in reader:
        subnet = row[0]
        autonomous_system_number = row[1]
        nation = row[2][:2]
        autonomous_system = row[3]
        as_dict[subnet] = {
            'autonomous_system_number': autonomous_system_number,
            'nation': nation,
            'autonomous_system': autonomous_system
        }
