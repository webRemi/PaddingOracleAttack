'''
Padding Oracle Attack
by ASX
'''

from Crypto.Util.strxor import strxor
import base64
from pwn import *
context.log_level = "error"

def get_block_and_data(ciphertext, block_number):
  block_start = block_number * 16
  block_end = block_start + 16
  next_block_start = block_end
  next_block_end = next_block_start + 16
  return ciphertext[block_start:block_end], ciphertext[next_block_start:next_block_end]

def decrypt_block(program, block, data, key, flag, padding_value, text):
  for j in range(15, -1, -1):
    for i in range(256):
      p = process(program)

      expected = bytes.fromhex(''.join([hex(x ^ padding_value)[2:].zfill(2) for x in key[::-1]]))

      zero_out_iv = text * j
      new_iv = zero_out_iv+bytes([int(hex(text[0])[-1:], 16) + i])+expected

      # Craft the payload to send to the process
      end_payload = base64.b64encode(new_iv+data).decode()
      start_payload = "TASK: "
      payload = start_payload + end_payload
      p.sendline(payload.encode())

      if not "Traceback" in p.recvline().decode():
        discovered_key = new_iv[j] ^ padding_value
        key.append(discovered_key)
        flag.append(hex(discovered_key ^ block[j])[2:].zfill(2))
        break
      p.close()
    padding_value += 1

def main():
  flags = []
  program = input("Enter the name of the program: ")
  ciphertext = base64.b64decode(input("Enter base64 ciphertext: "))

  for k in range(4):
    # Setting values
    plaintext = ""
    expected = b""
    text = b"\x00"
    key = []
    flag = []
    padding_value = 1

    print(f"Cracking block{k}...")

    block, data = get_block_and_data(ciphertext, k)
    print("Block: ", block)
    decrypt_block(program, block, data, key, flag, padding_value, text)
    print(f"Block{k} cracked!")
    flags.append(bytes.fromhex(''.join(flag[::-1])).decode())
    print("Decrypted block: ", flags[k])

  print("Decrypted ciphertext: ", ''.join(flags))

if __name__ == "__main__":
  main()
