from scapy.arch.windows import get_windows_if_list

for iface in get_windows_if_list():
    print(f"Interface info keys: {list(iface.keys())}")
    for key, value in iface.items():
        print(f"{key}: {value}")
    print('-' * 60)
