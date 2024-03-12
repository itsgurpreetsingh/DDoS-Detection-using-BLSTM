import pyshark
from sklearn.preprocessing import StandardScaler
import pandas as pd
import numpy as np
import subprocess
# import requests
import pyshark
import csv
from keras.models import load_model
import tensorflow.compat.v2 as tf
from sklearn.preprocessing import StandardScaler
def ConvertData(path):
    cap = pyshark.FileCapture(path)
    xml_list = []
    packet_list = []
    headings = ['frame.len', 'ip.hdr_len',
       'ip.len', 'ip.flags.rb', 'ip.flags.df', 'p.flags.mf', 'ip.frag_offset',
       'ip.ttl', 'ip.proto', 'tcp.srcport', 'tcp.dstport',
       'tcp.len', 'tcp.ack', 'tcp.flags.res', 'tcp.flags.ns', 'tcp.flags.cwr',
       'tcp.flags.ecn', 'tcp.flags.urg', 'tcp.flags.ack', 'tcp.flags.push',
       'tcp.flags.reset', 'tcp.flags.syn', 'tcp.flags.fin', 'tcp.window_size',
       'tcp.time_delta']
    packet_list.append(headings)

    for packet in cap:
        temp = []
        if hasattr(packet,'ip') and hasattr(packet,'tcp'):
            temp.append(str(packet.frame_info._all_fields["frame.len"])) #1
            if hasattr(packet, 'ip'):
                temp.append(str(packet.ip._all_fields['ip.hdr_len']))#3
                temp.append(str(packet.ip._all_fields['ip.len']))#4
                temp.append(str(packet.ip._all_fields['ip.flags.rb']))#5
                temp.append(str(packet.ip._all_fields['ip.flags.df']))#6
                temp.append(str(packet.ip._all_fields['ip.flags.mf']))#7
                temp.append(str(packet.ip._all_fields['ip.frag_offset']))#8
                temp.append(str(packet.ip._all_fields['ip.ttl']))#9
                temp.append(str(packet.ip._all_fields['ip.proto']))#10
            else:
                temp.extend(["0","0","0","0","0","0","0","0","0","0"])
            if hasattr(packet, 'tcp'):
                temp.append(str(packet.tcp._all_fields['tcp.srcport']))#12
                temp.append(str(packet.tcp._all_fields['tcp.dstport']))#13
                temp.append(str(packet.tcp._all_fields['tcp.len']))#14
                temp.append(str(packet.tcp._all_fields['tcp.ack']))#15
                temp.append(str(packet.tcp._all_fields['tcp.flags.res']))#16
                temp.append(str(packet.tcp._all_fields.get('tcp.flags.ns', '0')))#17
                temp.append(str(packet.tcp._all_fields.get('tcp.flags.cwr','0')))#18
                temp.append(str(packet.tcp._all_fields.get('tcp.flags.ecn','0')))#19
                temp.append(str(packet.tcp._all_fields.get('tcp.flags.urg','0')))#20
                temp.append(str(packet.tcp._all_fields.get('tcp.flags.ack','0')))#21
                temp.append(str(packet.tcp._all_fields.get('tcp.flags.push','0')))#22
                temp.append(str(packet.tcp._all_fields.get('tcp.flags.reset','0')))#23
                temp.append(str(packet.tcp._all_fields.get('tcp.flags.syn','0')))#24
                temp.append(str(packet.tcp._all_fields.get('tcp.flags.fin','0')))#25
                temp.append(str(packet.tcp._all_fields['tcp.window_size']))#26
                temp.append(str(packet.tcp._all_fields['tcp.time_delta']))#27
            else:
                temp.extend(["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"])
            packet_list.append(temp)
        else:
            temp.extend(["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"])
            packet_list.append(temp)

    dataf=pd.DataFrame(packet_list[1:])
    dataf.columns=['frame.len', 'ip.hdr_len',
       'ip.len', 'ip.flags.rb', 'ip.flags.df', 'p.flags.mf', 'ip.frag_offset',
       'ip.ttl', 'ip.proto', 'tcp.srcport', 'tcp.dstport',
       'tcp.len', 'tcp.ack', 'tcp.flags.res', 'tcp.flags.ns', 'tcp.flags.cwr',
       'tcp.flags.ecn', 'tcp.flags.urg', 'tcp.flags.ack', 'tcp.flags.push',
       'tcp.flags.reset', 'tcp.flags.syn', 'tcp.flags.fin', 'tcp.window_size',
       'tcp.time_delta']
    
    features=[ 'frame.len', 'ip.hdr_len',
       'ip.len', 'ip.flags.rb', 'ip.flags.df', 'p.flags.mf', 'ip.frag_offset',
       'ip.ttl', 'ip.proto', 'tcp.srcport', 'tcp.dstport',
       'tcp.len', 'tcp.ack', 'tcp.flags.res', 'tcp.flags.ns', 'tcp.flags.cwr',
       'tcp.flags.ecn', 'tcp.flags.urg', 'tcp.flags.ack', 'tcp.flags.push',
       'tcp.flags.reset', 'tcp.flags.syn', 'tcp.flags.fin', 'tcp.window_size',
       'tcp.time_delta']
    
    X= dataf[features].values
    scalar = StandardScaler(copy=True, with_mean=True, with_std=True)
    scalar.fit(X)
    X = scalar.transform(X)
    features = len(X[0])
    samples = X.shape[0]
    train_len = 25
    input_len = samples - train_len
    I = np.zeros((samples - train_len, train_len, features))
    for i in range(input_len):
        temp = np.zeros((train_len, features))
        for j in range(i, i + train_len - 1):
            temp[j-i] = X[j]
        I[i] = temp

    return I
