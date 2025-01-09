#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Xiao'

import base64
import time
import os

import ijson
import numpy as np
from enquiry import read_top_domestic, query_domain_by_ip
from scipy import stats
from search import searchAS
from progress_bar import progress_bar
from locate import read_CNip, searchCNip
from whois import get_whoenum_data, get_registrar, search_registrar, read_known_registrar, append_known_registrar, write_known_registrar, search_known_registrar

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


class TLSstream:
    def __init__(self, timeStamp, srcIP, dstIP, srcPort, dstPort, type, domain, commonName, organization, datas, length,packet_entropy):
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
        self.domain = domain
        self.commonName = commonName
        self.organization = organization
        self.datas = datas
        self.length = length
        self.packet_entropy = packet_entropy
    def __hash__(self):
        return hash((self.srcIP, self.dstIP))
    def __str__(self):
        datas_str = " ".join(str(data) for data in self.datas)
        return (f"Time: {self.timeStamp}, Source: {self.srcIP}:{self.srcPort}, Destination: {self.dstIP}:{self.dstPort}, Type: {self.type}, Domain: {self.domain}, CommonName: {self.commonName}, Organization: {self.organization}, Datas: {datas_str}, sumLength: {self.length}, Entropy: {self.packet_entropy}, Hash: {self.__hash__()}")


TLSstreams = []


class TLSdatas:
    def __init__(self, side, messageType, length):
        self.side = side
        self.messageType = messageType
        self.length = length
    def __str__(self):
        return (f"Side: {self.side}, MessageType: {self.messageType}, Length: {self.length}")


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
                    else:
                        if item["type"] not in src2dst[item["srcIP"]][item["dstIP"]]:
                            src2dst[item["srcIP"]][item["dstIP"]][item["type"]] = []
                src2dst[item["srcIP"]][item["dstIP"]][item["type"]].append(TCPstreams)
            elif item["type"] == TLS:
                TLSDatasList = []
                dataItem = item["datas"]
                for i in dataItem:
                    packet_length += 1 #计算包的数量
                    packet_entropy.append(i["length"])
                    TLSDatasList.append(TLSdatas(i["side"], i["messageType"], i["length"]))
                entropy = cul_entropy(packet_entropy)
                # TLSstreams.append(TLSstream(item["timeStamp"], item["srcIP"], item["dstIP"], item["srcPort"], item["dstPort"],item["type"], item["domain"], item["commonName"], item["organization"], TLSDatasList,packet_length, entropy))
                TLSstreams = TLSstream(item["timeStamp"], item["srcIP"], item["dstIP"], item["srcPort"], item["dstPort"],item["type"], item["domain"], item["commonName"], item["organization"], TLSDatasList,packet_length, entropy)
                arr = [-1 for _ in range(7)]
                feature_vector[TLSstreams.__hash__()] = arr
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
                    else:
                        if item["type"] not in src2dst[item["srcIP"]][item["dstIP"]]:
                            src2dst[item["srcIP"]][item["dstIP"]][item["type"]] = []
                src2dst[item["srcIP"]][item["dstIP"]][item["type"]].append(TLSstreams)


def cul_entropy(array):
    array = np.array(array)
    try:
        array = array.astype(np.float64)
    except ValueError as e:
        pass
    entropy = stats.entropy(array)
    return entropy


def cul_streamSumLength_entropy(streams):
    stream_payloadLength = []
    for stream in streams:
        stream_payloadLength.append(stream.length)
    sumLength_entropy = cul_entropy(stream_payloadLength)
    return sumLength_entropy


def cul_stream_entropy(streams, start = 0, end = 0):
    payloadLength = []
    side = []
    for stream in streams:
        for data in stream.datas[start:end]:
            if data.length != 0:
                payloadLength.append(data.length)
                side.append(data.side)
    payloadLength_entropy = cul_entropy(payloadLength)
    side_entropy = cul_entropy(side)
    return payloadLength_entropy, side_entropy


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


def cul_TCPstream_payload_entropy(stream):
    entropies_sequence = []
    if stream.length is not None:
        for payload in stream.datas:
            for i in range(2, len(payload.data) + 1):
                byte_ratio = byte_frequency(bytes(payload.data[:i], 'utf-8'))
                payloadLength_entropy = cul_entropy(byte_ratio)
                entropies_sequence.append(payloadLength_entropy)
    return entropies_sequence


def all_entropies_close_to_one(entropies_sequence, threshold=0.95):
    for entropies in entropies_sequence:
        if type(entropies) is not list:
            entropies = entropies.tolist()
    if not all(entropy_value >= threshold for entropy_value in entropies_sequence):
        return False
    return True


def timeRange(groups, hour = 0, minute = 0, second = 0, limit = 0.9):
    new_timeStamps = [[]]
    num = 0
    for protocols in groups.values():
        num += float(len(protocols))
        for stream in protocols:
            timeStamp = stream.timeStamp
            for seq in new_timeStamps:
                if seq == []:
                    seq.append(timeStamp)
                    break
                else:
                    addFlag = True
                    for seq_timeStamp in seq:
                        if timeStamp.hour - seq_timeStamp.hour <= hour and timeStamp.minute - seq_timeStamp.minute <= max(hour * 60, minute) and timeStamp.second - seq_timeStamp.second <= max(hour * 3600, minute * 60, second):
                            seq.append(timeStamp)
                            addFlag = False
                            break
                    if addFlag:
                        assembly = []
                        assembly.append(timeStamp)
                        new_timeStamps.append(assembly)
    for seque in new_timeStamps:
        if len(seque)/num >= limit:
            return len(seque)


feature_vector = {}
domestic_file = 'AlexaTop10w_domestic_withIP.txt'
data_dict = read_top_domestic(domestic_file)
CNip_file = 'CN-ip-cidr.txt'
subnet_list = read_CNip(CNip_file)
registrarList = 'registrarList.txt'
known_registrarList = 'known_registrar.txt'
known_registrar = read_known_registrar(known_registrarList)
# file_path = 'test.json'
file_path = '2024-07-04-17.json'
src2dst = {}
read_json_lines(file_path)
print("Read JSON Lines Done")
for srcIP, dstDict in src2dst.items():
    keys = list(src2dst.keys())
    # print(f"Source IP: {srcIP}")
    previous_dstIP = None
    for dstIP, protocolDict in dstDict.items():
        if dstIP != previous_dstIP:
            # print(f"  Destination IP: {dstIP}")
            key = hash((srcIP, dstIP))
            # 计算第 0 个流量特征
            domains = query_domain_by_ip(dstIP, data_dict)
            if domains:
                # print(f"IP {dstIP} 对应的域名: {', '.join(domains)}")
                feature_vector[key][0] = strong_exclusion
            else:
                # print(f"IP {dstIP} 不在top10w_domestic数据中")
                feature_vector[key][0] = weak_Matching
            # 计算第 3 个流量特征
            if searchCNip(dstIP, subnet_list):
                # print(f"目的IP {dstIP} 在中国境内")
                feature_vector[key][3] = 'CN'
            else:
                info = searchAS(dstIP)
                if info is not None:
                    # print(f"IP {dstIP} 对应的AS: {info['autonomous_system']}")
                    feature_vector[key][3] = info['nation'] + ';' + info['autonomous_system']
            # 计算第 4 个流量特征
            counts = timeRange(src2dst[srcIP][dstIP], hour=1)
            if counts:
                feature_vector[key][4] = counts
        previous_dstIP = dstIP
        for protocol, streams in protocolDict.items():
            packet_entropy_sequence = []
            for stream in streams:
                if protocol == TCP:
                    # 计算 TCP 流的第 2 个流量特征
                    if stream.sni != '':
                        result = search_known_registrar(known_registrar, stream.sni)
                        if result is None:
                            whoenum_data = get_whoenum_data(stream.sni)
                            registrar = get_registrar(whoenum_data)
                            if registrar is not None:
                                # print(registrar, "registrar is domestic ?", search_registrar(registrarList, registrar))
                                if (search_registrar(registrarList, registrar)):
                                    feature_vector[key][2] = strong_exclusion
                                known_registrar = append_known_registrar(known_registrar, stream.sni, registrar)
                        else:
                            # print(result, "registrar is domestic ?", search_registrar(registrarList, result))
                            if (search_registrar(registrarList, result)):
                                feature_vector[key][2] = strong_exclusion
                    # 计算 TCP 流的第 6 个流量特征
                    entropies_sequence = cul_TCPstream_payload_entropy(stream)
                    # print(f"TCP Stream Payload Length Entropy: {entropies_sequence}")
                    if all_entropies_close_to_one(entropies_sequence):
                        # print("All entropies close to one")
                        feature_vector[key][6] = weak_Matching
                elif protocol == TLS:
                    # 计算 TLS 流的第 2 个流量特征
                    if stream.domain != '':
                        result = search_known_registrar(known_registrar, stream.domain)
                        if result is None:
                            whoenum_data = get_whoenum_data(stream.domain)
                            registrar = get_registrar(whoenum_data)
                            if registrar is not None:
                                # print(registrar, "registrar is domestic ?", search_registrar(registrarList, registrar))
                                if (search_registrar(registrarList, registrar)):
                                    feature_vector[key][2] = strong_exclusion
                                known_registrar = append_known_registrar(known_registrar, stream.domain, registrar)
                        else:
                            # print(result, "registrar is domestic ?", search_registrar(registrarList, result))
                            if (search_registrar(registrarList, result)):
                                feature_vector[key][2] = strong_exclusion
                packet_entropy_sequence.append(stream.packet_entropy) # 第 5 个流量特征第 a 项
            # 计算第 5 个流量特征
            packet_entropy_sequence_np = np.array(packet_entropy_sequence) # 第 a 项
            sumLength_entropy = cul_streamSumLength_entropy(streams) # 第 b 项
            sumLength_entropy_np = np.array([sumLength_entropy])
            payloadLength_entropy, side_entropy = cul_stream_entropy(streams, end=3) # 第 c 项
            flow_before = np.array([payloadLength_entropy, side_entropy])
            payloadLength_entropy, side_entropy = cul_stream_entropy(streams, start=4) # 第 d 项
            flow_after = np.array([payloadLength_entropy, side_entropy])
            payloadLength_entropy, side_entropy = cul_stream_entropy(streams, start=7) # 第 e 项
            flow_afterMore = np.array([payloadLength_entropy, side_entropy])
            entropies_concat = np.concatenate((packet_entropy_sequence_np, sumLength_entropy_np, flow_before, flow_after, flow_afterMore), axis=0)
            feature_vector[key][5] = entropies_concat
    progress_bar('Calculating Entropy', keys.index(srcIP)+1, len(src2dst))
write_known_registrar(known_registrarList, known_registrar)
print("Calculation Done")

# for key, value in feature_vector.items():
#     print(f"Key: {key}, Value: {value}")
