import os
import socket
import threading
import json
import hashlib
import random
import subprocess
import pickle
import numpy as np
from sklearn.preprocessing import StandardScaler
import signal
import time
import json
import pandas as pd
import ipaddress
# Constants
HOST = "0.0.0.0"
PORT = 5001
MODEL_FILE = "birch_model_ntl.pkl"
REPUTATION_FILE = "reputation.json"
PCAP_FILE = "captured_traffic.pcap"
CSV_FILE = "captured_traffic.csv"
DEFAULT_REPUTATION = 50
DIFFICULTY_BASE = 0  # Base difficulty, can be adjusted


tcpdump_process = None

# Load pre-trained model
def load_model():
    if not os.path.exists(MODEL_FILE):
        print(f"Model file {MODEL_FILE} not found. Exiting.")
        exit(1)
    with open(MODEL_FILE, "rb") as file:
        return pickle.load(file)

# Load reputation data from the JSON file
def load_reputation(client_ip):
    if os.path.exists(REPUTATION_FILE):
        with open(REPUTATION_FILE, 'r') as f:
            return json.load(f)
    else:
        # Initialize reputation if the file does not exist
        reputation_data={client_ip:[DEFAULT_REPUTATION,0,0]}
        with open(REPUTATION_FILE, 'w') as f:
            json.dump(reputation_data, f, indent=4)
        return reputation_data

# Update reputation in the JSON file
def update_reputation(client_ip,reputation_array):
    """Update the reputation data for a specific client IP."""
    reputation_data = load_reputation(client_ip)
    reputation_data[client_ip] = reputation_array
    
    with open(REPUTATION_FILE, 'w') as f:
        json.dump(reputation_data, f, indent=4)

# Start tcpdump to capture traffic
def start_tcpdump():
    global tcpdump_process
    try:
        tcpdump_process = subprocess.Popen(
            f"tcpdump -i ens34 -w {PCAP_FILE}",
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        print("tcpdump started...")
    except Exception as e:
        print(f"Failed to start tcpdump: {e}")

# Stop tcpdump
def stop_tcpdump():
    global tcpdump_process
    if tcpdump_process and tcpdump_process.poll() is None:
        print("Gracefully stopping tcpdump.")
        tcpdump_process.send_signal(signal.SIGTERM)  # Graceful stop
        tcpdump_process.wait()
        print("tcpdump stopped.")

# Extract features from pcap using tshark
def extract_features():
    if not os.path.exists(PCAP_FILE) or os.path.getsize(PCAP_FILE) == 0:
        print("No valid PCAP file found.")
        return False
    try:
        command = (
            f"ntlflowlyzer -c ntl_config.json "
        )
        subprocess.run(command, shell=True, capture_output=True, text=True)
        time.sleep(4)
        print("ntlflowlyzer finished")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error during feature extraction: {e}")
        return False
def convert_ip_to_int(ip_str):
    """Convert IP address string to an integer."""
    try:
        return int(ipaddress.IPv4Address(ip_str))
    except ValueError:
        return np.nan
# PreprocesAs extracted features
def preprocess_data():
    if not os.path.exists(CSV_FILE) or os.path.getsize(CSV_FILE) == 0:
        print("No valid CSV file found.")
        return None

    try:
        selected_features = [
        'src_ip', 'dst_ip', 'bwd_packets_count', 'bwd_payload_bytes_skewness',
        'bwd_payload_bytes_cov', 'fwd_total_header_bytes', 'bwd_total_header_bytes',
        'bwd_skewness_header_bytes', 'bwd_mode_header_bytes', 'bwd_segment_size_max',
        'bwd_segment_size_min', 'bwd_segment_size_skewness', 'packets_rate',
        'bwd_packets_rate', 'fwd_packets_rate', 'ack_flag_counts', 'rst_flag_counts',
        'fwd_ack_flag_counts', 'bwd_rst_flag_counts', 'syn_flag_percentage_in_total',
        'ack_flag_percentage_in_total', 'rst_flag_percentage_in_total',
        'fwd_syn_flag_percentage_in_total', 'fwd_ack_flag_percentage_in_total',
        'bwd_rst_flag_percentage_in_total', 'fwd_syn_flag_percentage_in_fwd_packets',
        'fwd_ack_flag_percentage_in_fwd_packets', 'bwd_rst_flag_percentage_in_bwd_packets',
        'packets_IAT_mean', 'packet_IAT_max', 'packet_IAT_min', 'packet_IAT_total',
        'packets_IAT_median', 'packets_IAT_mode', 'fwd_packets_IAT_mean',
        'fwd_packets_IAT_max', 'fwd_packets_IAT_min', 'fwd_packets_IAT_total',
        'fwd_packets_IAT_median', 'fwd_packets_IAT_mode', 'bwd_packets_IAT_mean',
        'bwd_packets_IAT_min', 'bwd_packets_IAT_total', 'bwd_packets_IAT_cov',
        'bwd_packets_IAT_mode', 'timestamp_hour', 'timestamp_day'
        ]

        # Load dataset
        data = pd.read_csv(CSV_FILE)
        client_ip = data['src_ip'].iloc[0]
        data['timestamp'] = pd.to_datetime(data['timestamp'], errors='coerce')
        data[f'timestamp_hour'] = data['timestamp'].dt.hour
        data[f'timestamp_day'] = data['timestamp'].dt.day
        data = data.drop(columns=['timestamp'])

        # Ensure all selected features are present in the dataset
        missing_features = [feature for feature in selected_features if feature not in data.columns]
        if missing_features:
            raise ValueError(f"Missing features in the dataset: {missing_features}")

        # Select relevant features
        data = data[selected_features]

        # Convert IP addresses to numeric values

        for ip_feature in ['src_ip', 'dst_ip']:
            if ip_feature in data.columns:
                data[ip_feature] = data[ip_feature].apply(convert_ip_to_int).fillna(0)
        
        
        

        # Convert all features to numeric and handle NaN values
        for col in data.columns:
            data[col] = pd.to_numeric(data[col], errors='coerce').fillna(0)

        # Handle infinite values
        data.replace([np.inf, -np.inf], np.nan, inplace=True)
        data.fillna(0, inplace=True)

        # # Standardize the data using StandardScaler
        # scaler = StandardScaler()
        # data = scaler.fit_transform(data)

        print("Preprocessing complete.")
        return data,client_ip
    except Exception as e:
        print(f"Error during data preprocessing: {e}")
        return None

# Generate PoW challenge based on reputation
def generate_challenge(reputation):
    # difficulty = DIFFICULTY_BASE + (100 - reputation) // 10  # Calculate difficulty based on reputation
    if(reputation>=0 and reputation<=20):
        difficulty=5
    elif(reputation>=21 and reputation<=40):
        difficulty=4
    elif(reputation>=41 and reputation<=60):
        difficulty=3
    elif(reputation>=61 and reputation<=80):
        difficulty=2
    elif(reputation>=81 and reputation<=100):
        difficulty=1
    challenge = hashlib.sha256(os.urandom(16)).hexdigest()  # Generate challenge using SHA-256 of random data
    return challenge, difficulty

# Validate PoW solution
def validate_pow(challenge, nonce, expected_difficulty):
    target = "0" * expected_difficulty  # Define the target based on difficulty
    message = f"{challenge}{nonce}"  # Concatenate challenge and nonce
    hash_result = hashlib.sha256(message.encode()).hexdigest()  # Generate SHA-256 hash
    
    # Check if the hash starts with the target number of zeros
    if hash_result.startswith(target):
        return True, hash_result  # PoW solution is valid
    return False, hash_result  # PoW solution is invalid

# Handle client connection
def handle_client(conn, addr):
    print(f"Connection established with {addr}")

    try:
        # Initialize reputation at the start
        
        
        

        cleanup_files()
        start_tcpdump()

        # Wait for termination signal from client
        while True:
            client_signal = conn.recv(1024).decode()
            # client_ip = conn.recv(1024).decode()
            
            if client_signal.lower() == "terminate":
                print("Received termination signal from client.")
                time.sleep(2)  # Wait to ensure traffic capture completes
                stop_tcpdump()
                print("tcpdump stopped.")
                
                break

        # Process captured traffic
        if not extract_features():
            conn.send(json.dumps({"error": "Feature extraction failed"}).encode())
            return

        traffic_data,client_ip = preprocess_data()
        if traffic_data is None:
            conn.send(json.dumps({"error": "No valid traffic data"}).encode())
            return

        # Perform clustering and respond
        no_of_rows=len(traffic_data)
        print(f"no of row is {no_of_rows}")
        features = traffic_data.iloc[0].tolist()
        print(f"feuatres is {features}")
        sus=0
        nonsus=0
        for i in range(0,no_of_rows):
            features = traffic_data.iloc[i].tolist()
            prediction = model.predict([features])[0]
            if prediction == 0:
                sus += 1
            else:
                nonsus += 1

        classification = "suspicious" if sus >= nonsus else "non-suspicious"
        if len(traffic_data)>5000:
            classification = "suspicious"
        
        # Add challenge based on reputation
        
        print("client ip:",client_ip)
        reputation_data = load_reputation(client_ip)
        reputation_array = reputation_data.get(client_ip, [DEFAULT_REPUTATION,0,0])

        # Update reputation after classification
        if classification == "suspicious":
            print("Classified as suspicious")
            reputation=reputation_array[0]
            attack_count=reputation_array[1]
            normal_count=reputation_array[2]
            challenge, difficulty = generate_challenge(reputation)
            response = {
                "classification": classification,
                "challenge": challenge,
                "difficulty": difficulty,
            }
        
            # Update reputation file
            

            conn.send(json.dumps(response).encode())

            # Receive PoW solution from the client
            solution = conn.recv(1024).decode()
            solution_data = json.loads(solution)
        
            if "nonce" in solution_data:
                nonce = solution_data["nonce"]
                is_valid, hash_result = validate_pow(challenge, nonce, difficulty)
                
            
                if is_valid:
                    print(f"PoW solution valid: {hash_result}")
                    conn.send(json.dumps({"result": "valid", "hash": hash_result,"access":"granted"}).encode())
                    normal_count+=1
                    
                    attack_per=(attack_count)/(attack_count+normal_count)
                    normal_per=1-attack_per
                    reputation += ((attack_per*attack_count)+(normal_per*normal_count))*10  
                    reputation=min(100,reputation)
                    reputation_array=[reputation,attack_count,normal_count]
                    update_reputation(client_ip,reputation_array)
                    print(f"Updated reputation for {client_ip}: {reputation_array}")
                else:
                    print(f"PoW solution invalid: {hash_result}")
                    conn.send(json.dumps({"result": "invalid", "hash": hash_result,"access":"denied"}).encode())
                    
                    attack_count+=1
                    
                    attack_per=(attack_count)/(attack_count+normal_count)
                    normal_per=1-attack_per
                    reputation -= ((attack_per*attack_count)+(normal_per*normal_count))*10  
                    reputation=max(10,reputation)
                    reputation_array=[reputation,attack_count,normal_count]
                    update_reputation(client_ip,reputation_array)
                    print(f"Updated reputation for {client_ip}: {reputation_array}")
                
            else:
                conn.send(json.dumps({"error": "No nonce received"}).encode())
        else:
            response = {
                "classification": classification,
            }
            conn.send(json.dumps(response).encode())
            print("Classified as Non-suspicious")

        # Send challenge and classification to the client
        

    except Exception as e:
        print(f"Error during client handling: {e}")
        conn.send(json.dumps({"error": "Internal server error"}).encode())
    finally:
        conn.close()
        print(f"Connection with {addr} closed")

# Clean up old files
def cleanup_files():
    for file in [PCAP_FILE, CSV_FILE]:
        if os.path.exists(file):
            os.remove(file)

# Start server
def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    print(f"Server started on {HOST}:{PORT}")

    while True:
        try:
            conn, addr = server_socket.accept()
            client_thread = threading.Thread(target=handle_client, args=(conn, addr))
            client_thread.start()
        except KeyboardInterrupt:
            print("\nServer shutting down...")
            break
        except Exception as e:
            print(f"Error: {e}")
    server_socket.close()

if __name__ == "__main__":
    model = load_model()  # Load pre-trained model
    start_server()  # Start the server


