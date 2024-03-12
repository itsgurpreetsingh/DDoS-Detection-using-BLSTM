import subprocess
# import requests
import pyshark
import csv
import numpy as np
import pandas as pd
from keras.models import load_model
import tensorflow.compat.v2 as tf
from GetData import ConvertData
from sklearn.preprocessing import StandardScaler
import time
from scapy.all import *

PACKET_THRESHOLD = 150

# Function to capture packets and write them to a pcap file
def capture_packets(packet_count):
    # Capture packets
    packets = sniff(count=packet_count)
    
    # Generate a unique file name for the pcap file based on the current timestamp
    file_name = "capture.pcap"
    
    # Write packets to a pcap file
    wrpcap(file_name, packets)

def __main__():
	while(1):
		# Define the sudo password
		# sudo_password = ""
		# # Define the tcpdump command
		# command = "sudo -s tcpdump -c 50 -w capture.pcap"

		# Run the command using subprocess
		# process = subprocess.Popen(command, shell=True, stdin=subprocess.PIPE, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
		# stdout, stderr = process.communicate(input=(sudo_password + '\n').encode())
		capture_packets(PACKET_THRESHOLD)
		# Check for any errors
		# if stderr:
		# 	print("Error:", stderr.decode())
		# else:
		# 	print("Command executed successfully.")	
		print("Command executed successfully.")	
		model_file_path = './Netprobe.h5'
		model = load_model(model_file_path)
		I=ConvertData('./capture.pcap')
		I = I.astype('float32')
	
		predict = model.predict(I, verbose=1)
		predictn = predict.flatten().round()
		predictn = predictn.tolist()
		prediction_labels = ['Attack' if value == 0 else 'Normal' for value in predictn]
		print(len(prediction_labels))
		num_attacks = prediction_labels.count('Attack')
		num_normal=prediction_labels.count('Normal')
		print("Number of attacks:", num_attacks)
		print("Number of Normal:", num_normal)

		if num_normal>num_attacks:
			print("Normal")
		else:
			print("Attack")
		
		time.sleep(4)

if __name__=="__main__":
	__main__()
