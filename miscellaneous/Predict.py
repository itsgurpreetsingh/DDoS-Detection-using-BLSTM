import pandas as pd
import numpy as np
from scapy.all import *
from keras.utils import to_categorical
from tensorflow.keras.models import load_model
from sklearn.preprocessing import OneHotEncoder
import matplotlib.pyplot as plt

# Function to capture live traffic from pcap file
def capture_live_traffic(pcap_file):
    packets = rdpcap(pcap_file)  # Read packets from pcap file
    return packets

# Function to preprocess live traffic data
def preprocess_packets_to_dataframe(packets):
    data = []

    for packet in packets:
        # Extract relevant features from each packet
        row = {
            'Src_Port': packet[TCP].sport,                    # Source port
            'Dst_Port': packet[TCP].dport,                    # Destination port
            'Protocol': packet[IP].proto,                     # Protocol
            'Flow_Duration': packet.time,                     # Flow duration
            'Tot_Fwd_Pkts': packet[IP].len,                  # Total forward packets
            'Tot_Bwd_Pkts': packet[TCP].seq,                 # Total backward packets
            'TotLen_Fwd_Pkts': packet[IP].len,               # Total length of forward packets
            'TotLen_Bwd_Pkts': packet[TCP].seq,               # Total length of backward packets
            'Fwd_Pkt_Len_Max': packet[IP].len,               # Maximum length of forward packets
            'Fwd_Pkt_Len_Min': packet[TCP].seq,               # Minimum length of forward packets
            # Add more features as needed
        }
        data.append(row)

    # Convert the list of dictionaries into a DataFrame
    df = pd.DataFrame(data)
    
    # Perform additional preprocessing steps
    # One-hot encode categorical variables (if any)
    encoder = OneHotEncoder(sparse=False, drop='first')
    categorical_cols = ['Protocol']  # Adjust this based on your categorical columns
    encoded_categorical = encoder.fit_transform(df[categorical_cols])
    encoded_categorical_df = pd.DataFrame(encoded_categorical, columns=encoder.get_feature_names(categorical_cols))
    
    # Concatenate the encoded categorical variables with the original dataframe
    df = pd.concat([df, encoded_categorical_df], axis=1)
    
    # Drop the original categorical columns
    df.drop(columns=categorical_cols, inplace=True)
    
    # Perform any other preprocessing steps (e.g., handling missing values, scaling features, etc.)
    
    return df

# Function to make predictions on live traffic using a pre-trained model
def predict_live_traffic(model, live_data):
    # Reshape live data as per the model input shape
    live_data = np.reshape(live_data, (1, live_data.shape[0], live_data.shape[1]))
    # Make predictions using the loaded model
    predictions = model.predict(live_data)
    return predictions

# Load the pre-trained model
pretrained_model = load_model('pretrained_model.h5')  # Provide the path to your pre-trained model

# Capture and preprocess live traffic
live_pcap_file = "live_traffic.pcap"  # Provide the path to the live pcap file
live_packets = capture_live_traffic(live_pcap_file)
live_traffic_data = preprocess_packets_to_dataframe(live_packets)

# Make predictions on live traffic using the pre-trained model
live_traffic_predictions = predict_live_traffic(pretrained_model, live_traffic_data)

# Process the predictions as per your requirements (e.g., display, store, etc.)
print("Live Traffic Predictions:", live_traffic_predictions)
