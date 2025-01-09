#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Xiao'

import ipaddress


# 构造字典
def read_CNip(filename):
    subnet_list = []
    with open(filename, 'r') as file:
        for line in file:
            subnet = line.strip()
            subnet_list.append(subnet)
    return subnet_list


# 查询函数
def searchCNip(ip_address, subnet_list):
    for subnet in subnet_list:
        if is_ip_in_subnet(ip_address, subnet):
            return True
    return False


# 查询IP地址是否在子网内
def is_ip_in_subnet(ip_address, subnet):
    ip = ipaddress.ip_address(ip_address)
    network = ipaddress.ip_network(subnet, strict=False)
    return ip in network


# 测试
subnet_list = read_CNip('CN-ip-cidr.txt')
print(searchCNip('1.0.32.1', subnet_list))
