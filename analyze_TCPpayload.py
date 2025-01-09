#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Xiao'

import base64
import time
import os

import ijson
import matplotlib.pyplot as plt
import numpy as np
from progress_bar import progress_bar
from scipy import stats

TCP = 0
TLS = 1
c2s = 0
s2c = 1
strong_exclusion = 0
weak_Matching = 1


class TCPstream:
    def __init__(self, timeStamp, srcIP, dstIP, srcPort, dstPort, type, sni, datas, length, packet_entropy):
        class TimeStamp:
            def __init__(self, timeStamp):
                timeArray = time.localtime(timeStamp)
                self.year = timeArray[0]
                self.month = timeArray[1]
                self.day = timeArray[2]
                self.hour = timeArray[3]
                self.minute = timeArray[4]
                self.second = timeArray[5]
            def __str__(self):
                return f"{self.year}-{self.month}-{self.day} {self.hour}:{self.minute}:{self.second}"
        self.timeStamp = TimeStamp(timeStamp)
        self.srcIP = srcIP
        self.dstIP = dstIP
        self.srcPort = srcPort
        self.dstPort = dstPort
        self.type = type
        self.sni = sni
        self.datas = datas
        self.length = length
        self.packet_entropy = packet_entropy
    def __hash__(self):
        return hash((self.srcIP, self.dstIP))
    def __str__(self):
        datas_str = " ".join(str(data) for data in self.datas)
        return (f"Time: {self.timeStamp}, Source: {self.srcIP}:{self.srcPort}, Destination: {self.dstIP}:{self.dstPort}, Type: {self.type}, SNI: {self.sni}, Datas: {datas_str}, sumLength: {self.length}, Entropy: {self.packet_entropy}, Hash: {self.__hash__()}")


TCPstreams = []


class TCPdatas:
    def __init__(self, side, data, length):
        self.side = side
        self.data = data
        self.length = length
    def __str__(self):
        return (f"Side: {self.side}, Data: {self.data}, Length: {self.length}")


def read_json_lines(file_path):
    with open(file_path, 'rb') as file:
        size = file.seek(0, os.SEEK_END)
        file.seek(0)
        for line in file:
            current_position = file.tell()
            item = next(ijson.items(line, ''))
            file.seek(current_position)
            progress_bar('Reading JSON Lines', file.tell(), size)
            packet_length = 0
            packet_length = 0
            packet_entropy = []
            if item["type"] == TCP:
                TCPDatasList = []
                dataItem = item["datas"]
                for i in dataItem:
                    decoded_data = base64.b64decode(i["data"]).decode('latin1')
                    packet_length += 1 #计算包的数量
                    packet_entropy.append(len(decoded_data))
                    TCPDatasList.append(TCPdatas(i["side"], decoded_data, len(decoded_data)))
                entropy = cul_entropy(packet_entropy)
                # TCPstreams.append(TCPstream(item["timeStamp"], item["srcIP"], item["dstIP"], item["srcPort"], item["dstPort"],item["type"], item["sni"], TCPDatasList, packet_length, entropy))
                TCPstreams = TCPstream(item["timeStamp"], item["srcIP"], item["dstIP"], item["srcPort"], item["dstPort"],item["type"], item["sni"], TCPDatasList, packet_length, entropy)
                arr = [-1 for _ in range(7)]
                feature_vector[TCPstreams.__hash__()] = arr
                if item["srcIP"] not in src2dst:
                    src2dst[item["srcIP"]] = {
                        item["dstIP"]: {
                            item["type"]: []
                        }
                    }
                else:
                    if item["dstIP"] not in src2dst[item["srcIP"]]:
                        src2dst[item["srcIP"]][item["dstIP"]] = {
                            item["type"]: []
                        }
                src2dst[item["srcIP"]][item["dstIP"]][item["type"]].append(TCPstreams)
            elif item["type"] == TLS:
                pass

def cul_entropy(array):
    array = np.array(array)
    try:
        array = array.astype(np.float64)
    except ValueError as e:
        pass
    entropy = stats.entropy(array)
    return entropy


def byte_frequency(byte_stream):
    byte_count = {}
    for byte in byte_stream:
        if byte in byte_count:
            byte_count[byte] += 1
        else:
            byte_count[byte] = 1
    byte_ratio = []
    for byte, count in byte_count.items():
        byte_ratio.append(count / len(byte_stream))
    return byte_ratio


def cul_TCPstream_payload_entropy(payload):
    byte_ratio = byte_frequency(bytes(payload, 'utf-8'))
    payloadLength_entropy = cul_entropy(byte_ratio)
    return payloadLength_entropy

source_ips = []
entropies = []
src2dst = {}
feature_vector = {}
read_json_lines('test.json')
print("Read JSON Lines Done")
for srcIP, dstDict in src2dst.items():
    keys = list(src2dst.keys())
    for dstIP, protocolDict in dstDict.items():
        for protocol, streams in protocolDict.items():
            for stream in streams:
                for payload in stream.datas:
                    source_ips.append(stream.srcIP)
                    entropies.append(cul_TCPstream_payload_entropy(payload.data))
    progress_bar('Calculating Entropy', keys.index(srcIP)+1, len(src2dst))
print("Entropy Calculation Done")

plt.figure(figsize=(100, 60))
plt.scatter(source_ips, entropies, alpha=0.5)
plt.title('Entropy Values')
plt.xlabel('Source IP Addresses')
plt.ylabel('Entropy')
plt.xticks(rotation=45)
plt.grid(True)
plt.tight_layout()
plt.savefig('entropy_plot.png')

output_file = 'entropy_data.txt'
with open(output_file, 'w') as f:
    for ip, entropy in zip(source_ips, entropies):
        f.write(f"{ip}\t{entropy}\n")

print(f"Data saved to {output_file}")
plt.show()