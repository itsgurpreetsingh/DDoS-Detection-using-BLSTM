import subprocess

# Define the sudo password
sudo_password = "ubuntu"

# Define the tcpdump command
command = "sudo -s tcpdump -c  -w capture.pcap"

# Run the command using subprocess
process = subprocess.Popen(command, shell=True, stdin=subprocess.PIPE, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
stdout, stderr = process.communicate(input=(sudo_password + '\n').encode())

# Check for any errors
if stderr:
    print("Error:", stderr.decode())
else:
    print("Command executed successfully.")
