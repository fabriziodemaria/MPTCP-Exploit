from subprocess import check_output as execCommand
import tempfile

def graph_bw(a1, a2, f):
    try:
        tf1 = tempfile.NamedTemporaryFile()
    	tf2 = tempfile.NamedTemporaryFile()
    	tf3 = tempfile.NamedTemporaryFile()
    	execCommand("echo set terminal png > " + tf3.name, shell = True)
    	execCommand("echo set grid >> " + tf3.name, shell = True)
    	execCommand("echo set yrange [ -10 :  ] >> " + tf3.name, shell = True)
    	execCommand("echo set title \\\"Protocol breakdown in the last hour\\\" >> " + tf3.name, shell = True)
    	execCommand("echo set xlabel \\\"seconds\\\" >> " + tf3.name, shell = True)
    	execCommand("echo set ylabel \\\"packets/s\\\" >> " + tf3.name, shell = True)
    	execCommand("echo plot	\\\"" + tf1.name + "\\\" using 1:\\(\\$2/60\\) smooth csplines title \\\"TCP1\\\" \\\ >> " + tf3.name, shell = True)
        execCommand("echo ,\\\"" + tf2.name + "\\\" using 1:\\(\\$2/60\\) smooth csplines title \\\"TCP2\\\" >> " + tf3.name, shell = True)

        execCommand("tcpstat -r " + f + " -f \"net " + a1 + "\" -o \"%R\\t%T\\n\" 0.1 > " + tf1.name + " && tcpstat -r " + f + " -f \"net " + a2 + "\" -o \"%R\\t%T\\n\" 0.1 > " + tf2.name + " && gnuplot " + tf3.name + " > bw.png", shell = True)
        # execCommand("cat " + tf1.name + " > out", shell = True)
        # execCommand("cat " + tf2.name + " >> out", shell = True)
    finally:
        return

def parse_args():
    import argparse
    import itertools
    import sys

    parser = argparse.ArgumentParser(description='Graph generator for MPTCP connections')
    parser.add_argument('IP1', action='store', help='IP address 1')
    parser.add_argument('IP2', action='store', help='IP address 2')
    parser.add_argument('CAP', action='store', help='CAP file location')

    if len(sys.argv)!=4:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()
    return args

if __name__ == "__main__":
    args = parse_args()
    graph_bw(args.IP1, args.IP2, args.CAP)
