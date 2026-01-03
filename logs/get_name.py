from scapy.arch.windows import get_windows_if_list
print("\n--- COPY THE NAME BELOW ---")
for i in get_windows_if_list():
    if "Wi-Fi" in i['name'] or "Ethernet" in i['name']:
        print(f"Name: {i['name']}")
        print(f"Description: {i['description']}")