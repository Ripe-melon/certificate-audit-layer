# Your SHA-256 example in Python
sha256_key = "24:90:D7:6C:81:72:94:C0:46:68:BC:D1:88:09:F3:B4:31:75:A3:7E:56:B8:23:E6:10:CB:57:66:7E:DF:82:11"

# Replace all colons with an empty string
clean_hex = sha256_key.replace(":", "")

print(f"Original: {sha256_key}")
print(f"Cleaned:  {clean_hex}")
# Output: 6AA87B3FD1E49C2B