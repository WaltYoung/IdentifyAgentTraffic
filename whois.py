#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Xiao'

import json
import subprocess


def get_whoenum_data(domain):
    try:
        result = subprocess.run(['whoenum', '-d', domain], capture_output=True, text=True, check=True)
        whoenum_output = result.stdout
        if whoenum_output == '':
            return None
        try:
            data = json.loads(whoenum_output)
            return data
        except json.JSONDecodeError as e:
            print(f"Error: {e}")
            return None
    except subprocess.CalledProcessError as e:
        print(f"Error: {e.stderr}")
        return None


def get_name_servers(whoenum_data):
    if whoenum_data and 'name_servers' in whoenum_data:
        # 提取 name_servers 数组
        name_servers = whoenum_data['name_servers']
        return name_servers
    else:
        print(f"Error: 'name_servers' not found")
        return


def get_registrar(whoenum_data):
    if whoenum_data is None:
        return None
    if whoenum_data and 'registrar' in whoenum_data:
        # 提取 registrar
        registrar = whoenum_data['registrar']
        return registrar
    else:
        print(f"Error: 'registrar' not found")
        return


def search_registrar(filename, registrar):
    with open(filename, 'r', encoding='utf-8') as registrarList:
        for line in registrarList:
            if line.strip() in registrar:
                return True
        return False


def read_known_registrar(filename):
    known_registrar = {}
    with open(filename, 'r', encoding='utf-8') as file:
        for line in file:
            domain, registrar = line.strip().split('|')
            known_registrar[domain] = registrar
    return known_registrar


def append_known_registrar(known_registrar, domain, registrar):
    if domain not in known_registrar:
        known_registrar[domain] = registrar
    return known_registrar


def search_known_registrar(known_registrar, target_domain):
    if target_domain is None:
        return None
    for domain, registrar in known_registrar.items():
        if domain == target_domain:
            return registrar
    return None


def write_known_registrar(filename, known_registrar):
    with open(filename, 'w', encoding='utf-8') as file:
        for domain, registrar in known_registrar.items():
            file.write(f"{domain}|{registrar}\n")