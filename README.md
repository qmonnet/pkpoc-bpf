# Port knocking in eBPF

This is a proof of concept of stateful packet processing with eBPF on Linux. It
implements the basics of OpenState abstraction layer for stateful processing,
that have been designed as part of the [BEBA research
project](http://www.beba-project.eu/).

## Description

Port knocking is a port obfuscation measure that consists in a secret sequence
of “knocks” which have to be transmitted to a server before the latter opens a
given port, usually SSH, for the client.

Here the experiment creates two network namespaces, a `client` and a `server`.
The client wants to reach a given server port, here TCP port 9922. It sends the
packets of the secret sequence but, before those packets reach the network,
they are caught by an eBPF filter installed on the tc (Linux traffic control)
hook of the interface. The port knocking occurs at this level: thanks to
tables, eBPF can implement the OpenState layer and provide stateful processing
for the flow. So if the client sends the correct sequence of packets, the state
is set to `OPEN` and the server sees traffic on its port 9922. Otherwise, all
packets are dropped at the client's interface.

The idea behind this PoC is to explore eBPF's stateful capabilities, and to
integrate it, at a later stage, in a BPF version of a full BEBA switch.

## Requirements

This works only on a Linux system, with a recent kernel. To run this proof of
concept, one first needs to install the [bcc set of
tools](https://github.com/iovisor/bcc). Detailed instructions are available
[from here](https://github.com/iovisor/bcc/blob/master/INSTALL.md).

## Running the proof of concept

Get the code:

    git clone https://github.com/qmonnet/pkpoc-bpf.git

Launch the experiment:

    root# cd ./pkpoc-bpf
    root# python pk_launcher.py portknocking.c ebpf_filter
    [Client] Sending p1...
    [Client] Sending p2...
    [Client] Sending p3...
    [Client] Sending p4...
    [Server] Received message:  [p4]
    [Client] Sending p5...
    [Server] Received message:  [p5]
    [Client] Sending p6...
    [Server] Received message:  [p6]
    Finished.

While the experiment is running, you can launch a packet capture with `tcpdump`
in another terminal with the command below. Note that you must wait for the
`server` namespace to be created by the Python script before launching the
command, or it will fail.

    root# ip netns exec server tcpdump -vvv -e -XX -i eth0 src 10.0.2.100

Captured packets seem to appear only on termination (through `CTRL`-`C`) of the
command.

## License

File `simulation.py` comes from the bcc set of tools. As such, it is Copyright
2015 PLUMgrid, and is released under [the Apache License, version
2.0](http://www.apache.org/licenses/LICENSE-2.0).

The other files in this repository are Copyright 6WIND S.A., and are released
under [the 3-clause BSD
license](https://raw.githubusercontent.com/qmonnet/pkpoc-bpf/master/LICENSE).

## Resources

* [Port knocking on Wikipedia](https://en.wikipedia.org/wiki/Port_knocking).
* [BEBA's list of public
  deliverables](http://www.beba-project.eu/dissemination/public-deliverables).
  In particular, deliverables D2.1 and D2.2 relate to the design and basic
  implementation of the OpenState layer.
* [A blog
  article](https://qmonnet.github.io/whirl-offload/2016/07/17/openstate-stateful-packet-processing/)
  about OpenState, with port knocking taken as an example.
* [tc-bpf Linux manual
  page](http://man7.org/linux/man-pages/man8/tc-bpf.8.html).
* [bcc's resources](https://github.com/iovisor/bpf-docs) about (e)BPF.
