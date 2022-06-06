from async_timeout import timeout
import scapy.all as scapy
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t","--target",dest="target")
    val = parser.parse_args()
    return val
def scan(ip):
    arp_request = scapy.ARP(pdst=ip)

    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    arp_request_broadcast = broadcast/arp_request


    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return answered_list

def print_result(ans):
    print("----------------------------------------------")
    print("IP \t\t\t MAC")
    print("----------------------------------------------")
    counter=0
    for element in ans:
        print(element[1].psrc + "\t\t" + element[1].hwsrc )
        counter +=1
    print(f"-------------------------------------------\n\t\t {counter} Host alive")

val = get_arguments()
if val.target==None:
    print("Type -h or --help")
    exit()
scan_result = scan(val.target)
print_result(scan_result)