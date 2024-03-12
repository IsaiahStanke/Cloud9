import os

def list_interfaces():
    interfaces = []
    ipconfig_output = os.popen("ipconfig /all").read()
    lines = ipconfig_output.split('\n')
    for line in lines:
        if "Ethernet adapter" in line or "Wireless LAN adapter" in line:
            interface_name = line.split(":")[0].strip()
            interfaces.append(interface_name)
    return interfaces

if __name__ == "__main__":
    interfaces = list_interfaces()
    print("Available network interfaces:")
    for interface in interfaces:
        print(f"- {interface}")