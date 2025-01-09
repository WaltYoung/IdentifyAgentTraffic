#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Xiao'

# 构造字典
def read_top_domestic(filename):
    data_dict = {}
    with open(filename, 'r') as file:
        for line in file:
            domain, ip = line.strip().split(',')
            if ip in data_dict:
                data_dict[ip].append(domain)
            else:
                data_dict[ip] = [domain]
    return data_dict

# 查询函数
def query_domain_by_ip(ip, data_dict):
    return data_dict.get(ip, None)
