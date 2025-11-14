with open('TestDll.dll', 'rb') as f:
    data = f.read()

# XOR each byte with 0xFF
encrypted = bytes(b ^ 0xFF for b in data)

# Write to data.bin
with open('data.bin', 'wb') as f:
    f.write(encrypted)

print(f"Encrypted {len(encrypted)} bytes to data.bin")