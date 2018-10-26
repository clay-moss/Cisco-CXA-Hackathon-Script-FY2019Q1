import ipaddress, nmap, requests, sys
from multiping import MultiPing
from getmac import get_mac_address
from pprint import pprint


def getvendor(mac):
    if mac == "Unknown":
        return "Unknown"
    else:
        MAC_URL = 'https://macvendors.co/api/vendorname/%s'
        r = requests.get(MAC_URL % mac)
        return r.text


def display_info(all_subnets):

    nm = nmap.PortScanner()
    while 1:
        print(" \n\n\nSubnets\n------------")
        [print(str(network) + " - " + all_subnets[network]['subnet util']) for network in all_subnets],
        subnet_selection = input("\nSelect subnet (must match above output): ").lower()

        if subnet_selection in str(all_subnets):
            info_select = int(input(f"""\n
                     1) Display all alive hosts in subnet {subnet_selection}
                     2) Display info for single host in subnet {subnet_selection}
                     3) Display info for multiple hosts in subnet {subnet_selection}
                     4) Display info for all hosts in subnet {subnet_selection}
                     5) exit program
                     >> """))
        else:
            print("ERROR: Invalid subnet...")
            continue
        subnet = ipaddress.ip_network(subnet_selection)
        if info_select == 1:
            print("\nAlive Hosts Below\n------------------")
            pprint(sorted(list(all_subnets[subnet]['alive hosts'].keys())))
        elif info_select == 2:
            host_selection = input(f"Enter host IP: ").lower()
            try:
                if ipaddress.ip_address(host_selection) in subnet and list(all_subnets[subnet]['alive hosts'].keys()):
                    print(f"Scanning host {host_selection}...")
                    nm.scan(host_selection)
                    try:
                        print(f"\nHost Info: {host_selection}\n-----------------------------")
                        print(f"IP Address: {host_selection} ({nm[host_selection].hostname()})")
                        print(f"MAC Address:  {all_subnets[subnet]['alive hosts'][host_selection]}")
                        print(f"Hardware: {getvendor(all_subnets[subnet]['alive hosts'][host_selection])}")
                        for protocol in nm[host_selection].all_protocols():
                            print("-----------------------------")
                            print(f"Protocol : {protocol}\n")
                            port_list = nm[host_selection][protocol].keys()
                            sorted(port_list)
                            for port in port_list:
                                print(f"port # : {port}\tstate : {nm[host_selection][protocol][port]['state']}\tservice : {nm[host_selection][protocol][port]['name']}")
                    except Exception as err:
                        print(f"ERROR: Could not scan host {host_selection}")
                else:
                    print(f"ERROR: Host Address {host_selection} not found...")
            except ValueError as err:
                print(f"ERROR: Invalid IPv4 Address {err}")
                continue
        elif info_select == 3:
            hosts = []
            while True:
                host_selection = input(f"Enter multiple hosts (enter 'exit' to exit input): ").lower()
                if host_selection == "exit":
                    break
                try:
                    if ipaddress.ip_address(host_selection) in subnet and list(all_subnets[subnet]['alive hosts'].keys()):
                        hosts.append(str(ipaddress.ip_address(host_selection)))
                    else:
                        print(f"ERROR: Host Address {host_selection} not found...")
                        continue
                except ValueError as err:
                    print(f"ERROR: Invalid IPv4 Address {err}")
                    continue
            print(f"Starting port scan of hosts - {hosts}...")
            for host in hosts:
                nm.scan(host)
                try:
                    print(f"\nHost Info: {host}\n-----------------------------")
                    print(f"IP Address: {host} ({nm[host].hostname()})")
                    print(f"MAC Address:  {all_subnets[subnet]['alive hosts'][host]}")
                    print(f"Hardware: {getvendor(all_subnets[subnet]['alive hosts'][host])}")
                    for protocol in nm[host].all_protocols():
                        print("-----------------------------")
                        print(f"Protocol : {protocol}\n")

                        port_list = nm[host][protocol].keys()
                        sorted(port_list)
                        for port in port_list:
                            print(f"port # : {port}\tstate : {nm[host][protocol][port]['state']}\tservice : {nm[host][protocol][port]['name']}")
                except Exception as err:
                    print(f"ERROR: Could not scan host {host_selection}\n\n")
                    continue
                print("\n\n\n")
        elif info_select == 4:
            print(f"Starting port scan of subnet {subnet_selection}")
            for host in list(all_subnets[subnet]['alive hosts'].keys()):
                nm.scan(host)
                try:
                    print(f"\nHost Info: {host}\n-----------------------------")
                    print(f"IP Address: {host} ({nm[host].hostname()})")
                    print(f"MAC Address:  {all_subnets[subnet]['alive hosts'][host]}")
                    print(f"Hardware: {getvendor(all_subnets[subnet]['alive hosts'][host])}")
                    for protocol in nm[host].all_protocols():
                        print("-----------------------------")
                        print(f"Protocol : {protocol}\n")

                        port_list = nm[host][protocol].keys()
                        sorted(port_list)
                        for port in port_list:
                            print(f"port # : {port}\tstate : {nm[host][protocol][port]['state']}\tservice : {nm[host][protocol][port]['name']}")
                except Exception as err:
                    print(f"ERROR: Could not scan host {host_selection}\n\n")
                    continue
        elif info_select == 5:
            sys.exit()
        else:
            print("ERROR: Invalid selection!")
            continue


def main():

    subnets = {}
    while 1:
        user_input = input("\nEnter 'exit' to quit subnet entry.\n\nEnter subnet(s) to scan (i.e 192.168.1.0/24): ").lower()

        if user_input == "exit":
            break
        try:
            network = ipaddress.ip_network(user_input)
        except ValueError or Exception as err:
            print(f"ERROR: Invalid IPv4 Network, {err}")
            continue
        print(f"\nGathering subnet {user_input} information...")
        subnets[network] = {}
        all_hosts = [str(host) for host in network.hosts()]
        mp = MultiPing(all_hosts)
        mp.send()
        alive, not_alive = mp.receive(1)
        subnet_utilization = ((len(alive)/len(all_hosts)*100)//1)
        subnet_utilization_string = f"Subnet Utilization: {subnet_utilization}% \tHosts Alive: {len(alive)}"
        all_alive_hosts = [list(alive.keys())[i] for i in range(0, len(alive))]
        subnets[network]['subnet util'] = subnet_utilization_string
        subnets[network]['alive hosts'] = {}
        for host in all_alive_hosts:
            subnets[network]['alive hosts'][str(host)] = get_mac_address(ip=str(host))
            if subnets[network]['alive hosts'][str(host)] is None:
                print("WARNING: Remote network detected, cannot gather MAC Addresses...")
                for remote_host in all_alive_hosts:
                    subnets[network]['alive hosts'][str(remote_host)] = "Unknown"
                break
        print(f"Successfully scanned subnet {user_input}...")
    return display_info(subnets)


if __name__ == "__main__":
    main()
