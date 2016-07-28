#!/usr/bin/env python

##
#   BSD LICENSE
#
#   Copyright (c) 2016, 6WIND S.A.
#   All rights reserved.
#
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions
#   are met:
#
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in
#       the documentation and/or other materials provided with the
#       distribution.
#     * Neither the name of 6WIND S.A. nor the names of its
#       contributors may be used to endorse or promote products derived
#       from this software without specific prior written permission.
#
#   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
##

from bcc import BPF
from pyroute2 import IPRoute, IPDB
from simulation import Simulation
import sys
from time import sleep

# In case we need to kill remaining netcats
#from subprocess import call

"""
OpenState port knocking in BPF.
Runs with file portknocking.c.

Launch it with:
    # python pk_launcher.py portknocking ebpf_filter

Scenario: two network namespaces for the simulation of two hosts, "client" and
"server". Client wants to reach UDP port 9922 of server, but a port knocking
application has been installed on its interface (as a tc filter).
To access to this port the client must first send UDP packets on ports 1111,
2222 and 3333. (Of course in a real case the filter would run on an
intermediary switch instead of on client).

Client                                               Server
+-----------------+                     +-----------------+
|            +----+-----+         +-----+----+            |
| 10.0.2.100 | BPF prog +---------+    NIC   | 10.0.2.101 |
|            +----+-----+    ?    +-----+----+            |
+-----------------+        ---->        +-----------------+
"""

ipr = IPRoute()
ipdb = IPDB(nl=ipr)

IPv4 = 0x0800
IPv6 = 0x86DD
ARP  = 0x0806
TCP  = 0x06
UDP  = 0x11

# Do not modify these, unless you also edit openstate.h
DROP    = 0
FORWARD = 1

# Load BPF

b = BPF(src_file=sys.argv[1], debug=0)
# print b.dump_func("ebpf_filter") # For debug. Dump is in binary form.

fn = b.load_func(sys.argv[2], BPF.SCHED_CLS)

# BPF maps handles

stateTable = b.get_table("state_table")
XFSMTable  = b.get_table("xfsm_table")

class SimpleSimulation(Simulation):

    def __init__(self, ipdb):
        super(SimpleSimulation, self).__init__(ipdb)

    def start(self):

        # OpenState tables
        #
        # This is where we set up all the "magic" for stateful processing. The
        # BPF program we use is nearly generic, the behavior depends on the
        # initial configuration of the two OpenState tables.
        #
        # One exception, though: the default action, performed when no match is
        # found in the XFSM table, is application-dependant but is implemented
        # in the BPF code for now.

        # Port knocking states
        DEFAULT = 0
        STEP_1  = 1
        STEP_2  = 2
        OPEN    = 3

        # Here we want to initialize the state table for our single flow: it
        # starts at state DEFAULT. Let's build the index and update the table.
        # Key:  | ether_type | padding | src_ip | dst_ip |
        # Leaf: | current state |
        src_ip = (10 << 24) + (0 << 16) + (2 << 8) + 100
        dst_ip = (10 << 24) + (0 << 16) + (2 << 8) + 101
        stateTable[stateTable.Key(IPv4, 0, src_ip, dst_ip)] = stateTable.Leaf(DEFAULT)

        # Now we want to build the XFSM table: this describes the different
        # states transitions that we want for port knocking.
        # UDP source port is left at 0, because we don't care about it.
        # Key:  | current state | padding 1 | padding 2 | L4 protocol nb | src port | dst port |
        # Leaf: | action | next state |
        XFSMTable[XFSMTable.Key(DEFAULT, UDP, 0, 0, 0, 1111)] = XFSMTable.Leaf(DROP,    STEP_1)
        XFSMTable[XFSMTable.Key(STEP_1,  UDP, 0, 0, 0, 2222)] = XFSMTable.Leaf(DROP,    STEP_2)
        XFSMTable[XFSMTable.Key(STEP_2,  UDP, 0, 0, 0, 3333)] = XFSMTable.Leaf(DROP,    OPEN)
        XFSMTable[XFSMTable.Key(OPEN,    UDP, 0, 0, 0, 9922)] = XFSMTable.Leaf(FORWARD, OPEN)

        # Client

        # Sleep a while until setup is done. 0.5s is enough, 2.5s enables us to
        # launch tcpdump in another terminal after the namespaces creation and
        # before the actual experiment.
        # After that, send correct sequence, then packets on port 9922.
        cmd = ["bash", "-c", """sleep 2.5 && \
                echo "[Client] Sending p1..."
                printf -- '[p1]' | nc -q 1 -u 10.0.2.101 1111
                echo "[Client] Sending p2..."
                printf -- '[p2]' | nc -q 1 -u 10.0.2.101 2222
                echo "[Client] Sending p3..."
                printf -- '[p3]' | nc -q 1 -u 10.0.2.101 3333
                echo "[Client] Sending p4..."
                printf -- '[p4]' | nc -q 1 -u 10.0.2.101 9922
                echo "[Client] Sending p5..."
                printf -- '[p5]' | nc -q 1 -u 10.0.2.101 9922
                echo "[Client] Sending p6..."
                printf -- '[p6]' | nc -q 1 -u 10.0.2.101 9922
                """]
        ipaddr = "10.0.2.100/24"
        client = self._create_ns("client", ipaddr=ipaddr,
                               cmd=cmd)

        # Server

        # Make it execute a simple Python script that dumps everything it
        # receives on port 9922.
        cmd = ["python", "-c", """
import socket

UDP_IP = "10.0.2.101"
UDP_PORT = 9922

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))

while True:
    data, addr = sock.recvfrom(1024)
    print "[Server] Received message: ", data"""]

        ipaddr = "10.0.2.101/24"
        server = self._create_ns("server", ipaddr=ipaddr,
                              cmd=cmd)

        with ipdb.create(ifname="bridge", kind="bridge") as bridge:
            bridge.add_port(client[1])
            bridge.add_port(server[1])
            bridge.up()

        # Attach BPF program to client tc hook.
        ipr.tc("add", "ingress", client[1]["index"], "ffff:")
        ipr.tc("add-filter", "bpf", client[1]["index"], ":1", fd=fn.fd,
               name=fn.name, parent="ffff:", action="drop", classid=1)

try:
    sim = SimpleSimulation(ipdb)
    sim.start()
    sleep(8)
    print("Finished.")
finally:
    if "client" in ipdb.interfaces: ipdb.interfaces.client.remove().commit()
    if "server" in ipdb.interfaces: ipdb.interfaces.server.remove().commit()
    if "bridge" in ipdb.interfaces: ipdb.interfaces.bridge.remove().commit()
    if "sim" in locals(): sim.release()
    ipdb.release()
