import socket
import hashlib
import json
import random
import time
import subprocess

# Server details
SERVER_HOST = "192.168.54.12"  # Replace with your server's IP address
SERVER_PORT = 5001
TARGET_IP="10.10.10.113"

# Function to solve the PoW challenge
def solve_pow(challenge, difficulty):
    target = "0" * difficulty  # Define the target based on difficulty
    nonce = 0
    while True:
        message = f"{challenge}{nonce}"
        hash_result = hashlib.sha256(message.encode()).hexdigest()
        if hash_result.startswith(target):
            return nonce, hash_result
        nonce += 1

# Function to send traffic to server (simulated here with random data)
def generate_traffic(target_ip):
    print(f"Sending traffic to {target_ip}")
    try:
        subprocess.run(["hping3", "--syn", "-p", "80", target_ip, "-c", "10000", "-i", "u333"], check=True)
        print("Traffic generation successful.")
    except subprocess.CalledProcessError as e:
        print(f"Traffic generation failed: {e}")

# Connect to the server and interact
def connect_to_server():
    # Create a socket to connect to the server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((SERVER_HOST, SERVER_PORT))
        print(f"Connected to server {SERVER_HOST}:{SERVER_PORT}")

        # Step 1: Generate traffic (this is simulated)
        generate_traffic(TARGET_IP)

        # Step 2: Send a signal to terminate tcpdump (as per server protocol)
        client_socket.send("terminate".encode())
        # client_socket.send("39.40.195.173".encode())

        # Step 3: Wait for server response
        server_response = client_socket.recv(1024).decode()
        print(f"Server response: {server_response}")

        # Parse the response
        response_data = json.loads(server_response)
        classification=response_data['classification']
        
        if "classification" in response_data:
            print(f"Classification result: {response_data['classification']}")
            if classification=="suspicious":
                if "challenge" in response_data and "difficulty" in response_data:
                    challenge = response_data["challenge"]
                    difficulty = response_data["difficulty"]
                    difficulty=int(difficulty)
                    print(f"Received challenge: {challenge} with difficulty: {difficulty}")

                    # Solve the PoW challenge
                    nonce, hash_result = solve_pow(challenge, difficulty)
                    print(f"Solved PoW challenge with nonce: {nonce}")

                    # Step 5: Send PoW solution to server
                    solution = {
                        "nonce": nonce,
                        "hash": hash_result
                    }
                    client_socket.send(json.dumps(solution).encode())

                    # Step 6: Receive final classification response
                    final_response = client_socket.recv(1024).decode()
                    
                    isvald = json.loads(final_response)
                    print(f"Final server response: {final_response}")
                    

                    # Parse and print classification result
            
           
                else:
                    print("No challenge received from server.")
            else:
                print(" access grantedd without pow")
        else:
            print("Error or invalid response from server.")
        # Step 4: If challenge exists, solve it
        
    except Exception as e:
        print(f"Error during connection or communication: {e}")
    finally:
        client_socket.close()
        print("Connection closed.")

if __name__ == "__main__":
    while 1:
        connect_to_server()



