import socket
import struct
import sys
import os
import subprocess
from netaddr import IPNetwork

pkt = b'\x00\x00\x00\xc0\xfeSMB@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00$\x00\x08\x00\x01\x00\x00\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00x\x00\x00\x00\x02\x00\x00\x00\x02\x02\x10\x02"\x02$\x02\x00\x03\x02\x03\x10\x03\x11\x03\x00\x00\x00\x00\x01\x00&\x00\x00\x00\x00\x00\x01\x00 \x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\n\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00'

fichierDip = sys.argv[1]


listIp = []


with open(fichierDip) as fichier:
        ipAExtraire = fichier.read();
        files = ipAExtraire.split('\n')


for ip in files:
        if len(ip) == 0:
            files.remove(ip)
        
# Option PING
#for ip2 in files:
#        fifi = os.system("ping -c 2 " + ip2 +"> /dev/null" )

#        if fifi == 0:
#           print("[+] " +ip2+ " is up !")
#        else:
#            print("[-] "+ip2+ " is down !") 



for f in files:
    for ip in IPNetwork(f):
        print("[?] IP tested:"+str(ip))
        sock = socket.socket(socket.AF_INET)
        sock.settimeout(3)

        try:
            sock.connect(( str(ip), 445))
        except:
            sock.close()
            continue

        sock.send(pkt)

        nb, = struct.unpack(">I", sock.recv(4))
        res = sock.recv(nb)

        if res[68:70] != b"\x11\x03" or res[70:72] != b"\x02\x00":
                print(f"     [+] {ip} uses SMBv3 and is Not Vulnerable.")
        else:
            print(f"     [-] {ip} uses SMBv3 and is vulnerable !")
