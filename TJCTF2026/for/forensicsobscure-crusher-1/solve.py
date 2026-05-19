def xor_decrypt():
    hex_data = "1D 09 0D 07 67 0F 44 04 71 1B 0C 1E 49 32 02 39 1C 10 06 40 73 2B 45 05 6C 0B 26 18 0E 0B 3E 27 13 0E 5D 0E 00 00 00 00"
        
    data_bytes = bytes.fromhex(hex_data)

    key_bytes = b"icns\x01ttf\x02xylzmaK"
    
    result = bytearray()
    for i in range(len(data_bytes)):
        decrypted_byte = data_bytes[i] ^ key_bytes[i % len(key_bytes)]
        result.append(decrypted_byte)
    
    print(result.decode('utf-8', errors='replace'))

if __name__ == "__main__":
    xor_decrypt()