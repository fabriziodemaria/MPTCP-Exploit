import inspect
from subprocess import check_output as execCommand
from scapy.all import rdpcap
import tempfile
import time


THREAD_SYNC_TIME = 1

def get_MPTCP_syn(i):
    try:
        tf = tempfile.NamedTemporaryFile()
        execCommand("sudo tcpdump -c 1 -w " + tf.name + ".cap -i " + i + " \"tcp[tcpflags] & tcp-syn != 0\" 2>/dev/null", shell = True)
        scan = rdpcap("" + tf.name + ".cap")
    finally:
        execCommand("rm -f " + tf.name + ".cap", shell = True)
    return scan[0]


def get_MPTCP_synack(i, srcIP):
    try:
        tf = tempfile.NamedTemporaryFile()
        execCommand("sudo tcpdump -c 1 -w " + tf.name + ".cap -i " + i + " \"tcp[tcpflags] & (tcp-syn) != 0 and src net " + srcIP + "\" 2>/dev/null", shell = True)
        scan = rdpcap("" + tf.name + ".cap")
    finally:
        execCommand("rm -f " + tf.name + ".cap", shell = True)
    return scan[0]


def get_MPTCP_ack(i, dstIP):
    try:
        tf = tempfile.NamedTemporaryFile()
        execCommand("sudo tcpdump -c 1 -w " + tf.name + ".cap -i " + i + " \"tcp[tcpflags] & (tcp-ack) != 0 and tcp[tcpflags] & (tcp-syn) == 0 and dst net " + dstIP + "\" 2>/dev/null", shell = True)
        scan = rdpcap("" + tf.name + ".cap")
    finally:
        execCommand("rm -f " + tf.name + ".cap", shell = True)
    return scan[0]


def disable_RST():
    execCommand("sudo iptables -I OUTPUT -p tcp --tcp-flags ALL RST,ACK -j DROP", shell = True)
    execCommand("sudo iptables -I OUTPUT -p tcp --tcp-flags ALL RST -j DROP", shell = True)
    time.sleep(THREAD_SYNC_TIME)


def enable_RST():
    execCommand("sudo iptables -I OUTPUT -p tcp --tcp-flags ALL RST -j ACCEPT", shell = True)
    execCommand("sudo iptables -I OUTPUT -p tcp --tcp-flags ALL RST,ACK -j ACCEPT", shell = True)
    time.sleep(THREAD_SYNC_TIME)
