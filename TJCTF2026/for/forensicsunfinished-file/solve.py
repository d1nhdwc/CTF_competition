hex_data = "36 28 21 36 24 39 2C 71 34 71 30 1D 2E 71 36 1D 72 36 2A 27 30 1D 32 71 72 32 2E 27 1D 36 72 37 21 2A 1D 37 30 1D 21 72 2F 32 37 36 27 30 3F 50 4B 01 02 14 00 14 00 00 00 00 00 00 00 00 00 CE 9E B0 6E 29 00 00 00 29 00 00 00 0A 00 00 00 00"

data_bytes = bytes.fromhex(hex_data)

key_bytes = 0x42

result = bytearray()
for byte in data_bytes: 
    decrypted_byte = byte ^ key_bytes
    result.append(decrypted_byte)
    
print(result.decode('utf-8', errors='replace')) 