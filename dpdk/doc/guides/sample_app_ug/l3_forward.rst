..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2010-2014 Intel Corporation.

L3 Forwarding Sample Application
================================

The L3 Forwarding application is a simple example of packet processing using
DPDK to demonstrate usage of poll and event mode packet I/O mechanism.
The application performs L3 forwarding.

Overview
--------

The application demonstrates the use of the hash, LPM, FIB and ACL libraries in DPDK
to implement packet forwarding using poll or event mode PMDs for packet I/O.
The initialization and run-time paths are very similar to those of the
:doc:`l2_forward_real_virtual` and :doc:`l2_forward_event`.
The main difference from the L2 Forwarding sample application is that optionally
packet can be Rx/Tx from/to eventdev instead of port directly and forwarding
decision is made based on information read from the input packet.

Eventdev can optionally use S/W or H/W (if supported by platform) scheduler
implementation for packet I/O based on run time parameters.

The lookup method is hash-based, LPM-based, FIB-based or ACL-based
and is selected at run time.
When the selected lookup method is hash-based,
a hash object is used to emulate the flow classification stage.
The hash object is used in correlation with a flow table to map each input packet to its flow at runtime.

The hash lookup key is represented by a DiffServ 5-tuple composed of the following fields read from the input packet:
Source IP Address, Destination IP Address, Protocol, Source Port and Destination Port.
The ID of the output interface for the input packet is read from the identified flow table entry.
The set of flows used by the application is statically configured and loaded into the hash at initialization time.
When the selected lookup method is LPM or FIB based,
an LPM or FIB object is used to emulate the forwarding stage for IPv4 packets.
The LPM or FIB object is used as the routing table
to identify the next hop for each input packet at runtime.

The LPM and FIB lookup keys are represented by the destination IP address field
read from the input packet.
The ID of the output interface for the input packet is the next hop
returned by the LPM or FIB lookup.
The set of LPM and FIB rules used by the application is statically configured
and loaded into the LPM or FIB object at initialization time.

For ACL, the ACL library is used to perform both ACL and route entry lookup.
When packets are received from a port,
the application extracts the necessary information
from the TCP/IP header of the received packet
and performs a lookup in the rule database to figure out
whether the packets should be dropped (in the ACL range)
or forwarded to desired ports.
For ACL, the application implements packet classification
for the IPv4/IPv6 5-tuple syntax specifically.
The 5-tuple syntax consists of a source IP address, a destination IP address,
a source port, a destination port and a protocol identifier.

In the sample application, hash-based, LPM-based, FIB-based and ACL-based forwarding supports
both IPv4 and IPv6.
During the initialization phase route rules for IPv4 and IPv6 are read from rule files.

Compiling the Application
-------------------------

To compile the sample application see :doc:`compiling`.

The application is located in the ``l3fwd`` sub-directory.

Running the Application
-----------------------

The application has a number of command line options::

    ./dpdk-l3fwd [EAL options] -- -p PORTMASK
                             --rule_ipv4=FILE
                             --rule_ipv6=FILE
                             [-P]
                             [--lookup LOOKUP_METHOD]
                             --config(port,queue,lcore)[,(port,queue,lcore)]
                             [--eth-dest=X,MM:MM:MM:MM:MM:MM]
                             [--max-pkt-len PKTLEN]
                             [--no-numa]
                             [--hash-entry-num]
                             [--ipv6]
                             [--parse-ptype]
                             [--per-port-pool]
                             [--mode]
                             [--eventq-sched]
                             [--event-eth-rxqs]
                             [--event-vector [--event-vector-size SIZE] [--event-vector-tmo NS]]
                             [-E]
                             [-L]

Where,

* ``-p PORTMASK:`` Hexadecimal bitmask of ports to configure

* ``--rule_ipv4=FILE:`` specify the ipv4 rules entries file.
  Each rule occupies one line.

* ``--rule_ipv6=FILE:`` specify the ipv6 rules entries file.

* ``-P:`` Optional, sets all ports to promiscuous mode so that packets are accepted regardless of the packet's Ethernet MAC destination address.
  Without this option, only packets with the Ethernet MAC destination address set to the Ethernet address of the port are accepted.

* ``--lookup:`` Optional, select the lookup method.
  Accepted options:
  ``em`` (Exact Match),
  ``lpm`` (Longest Prefix Match),
  ``fib`` (Forwarding Information Base),
  ``acl`` (Access Control List).
  Default is ``lpm``.

* ``--config (port,queue,lcore)[,(port,queue,lcore)]:`` Determines which queues from which ports are mapped to which cores.

* ``--eth-dest=X,MM:MM:MM:MM:MM:MM:`` Optional, ethernet destination for port X.

* ``--max-pkt-len:`` Optional, maximum packet length in decimal (64-9600).

* ``--no-numa:`` Optional, disables numa awareness.

* ``--hash-entry-num:`` Optional, specifies the hash entry number in hexadecimal to be setup.

* ``--ipv6:`` Optional, set if running ipv6 packets.

* ``--parse-ptype:`` Optional, set to use software to analyze packet type. Without this option, hardware will check the packet type.

* ``--per-port-pool:`` Optional, set to use independent buffer pools per port. Without this option, single buffer pool is used for all ports.

* ``--mode:`` Optional, Packet transfer mode for I/O, poll or eventdev.

* ``--eventq-sched:`` Optional, Event queue synchronization method, Ordered, Atomic or Parallel. Only valid if --mode=eventdev.

* ``--event-eth-rxqs:`` Optional, Number of ethernet RX queues per device. Only valid if --mode=eventdev.

* ``--event-vector:`` Optional, Enable event vectorization. Only valid if --mode=eventdev.

* ``--event-vector-size:`` Optional, Max vector size if event vectorization is enabled.

* ``--event-vector-tmo:`` Optional, Max timeout to form vector in nanoseconds if event vectorization is enabled.

* ``--alg=<val>:`` optional, ACL classify method to use, one of:
  ``scalar|sse|avx2|neon|altivec|avx512x16|avx512x32``

* ``-E:`` Optional, enable exact match,
  legacy flag, please use ``--lookup=em`` instead.

* ``-L:`` Optional, enable longest prefix match,
  legacy flag, please use ``--lookup=lpm`` instead.


For example, consider a dual processor socket platform with 8 physical cores, where cores 0-7 and 16-23 appear on socket 0,
while cores 8-15 and 24-31 appear on socket 1.

To enable L3 forwarding between two ports, assuming that both ports are in the same socket, using two cores, cores 1 and 2,
(which are in the same socket too), use the following command:

.. code-block:: console

    ./<build_dir>/examples/dpdk-l3fwd -l 1,2 -n 4 -- -p 0x3 --config="(0,0,1),(1,0,2)" --rule_ipv4="rule_ipv4.cfg" --rule_ipv6="rule_ipv6.cfg"

In this command:

*   The -l option enables cores 1, 2

*   The -p option enables ports 0 and 1

*   The --config option enables one queue on each port and maps each (port,queue) pair to a specific core.
    The following table shows the mapping in this example:

+----------+-----------+-----------+-------------------------------------+
| **Port** | **Queue** | **lcore** | **Description**                     |
|          |           |           |                                     |
+----------+-----------+-----------+-------------------------------------+
| 0        | 0         | 1         | Map queue 0 from port 0 to lcore 1. |
|          |           |           |                                     |
+----------+-----------+-----------+-------------------------------------+
| 1        | 0         | 2         | Map queue 0 from port 1 to lcore 2. |
|          |           |           |                                     |
+----------+-----------+-----------+-------------------------------------+

*   The -rule_ipv4 option specifies the reading of IPv4 rules sets from the rule_ipv4.cfg file

*   The -rule_ipv6 option specifies the reading of IPv6 rules sets from the rule_ipv6.cfg file.

To use eventdev mode with sync method **ordered** on above mentioned environment,
Following is the sample command:

.. code-block:: console

    ./<build_dir>/examples/dpdk-l3fwd -l 0-3 -n 4 -a <event device> -- -p 0x3 --eventq-sched=ordered --rule_ipv4="rule_ipv4.cfg" --rule_ipv6="rule_ipv6.cfg"

or

.. code-block:: console

    ./<build_dir>/examples/dpdk-l3fwd -l 0-3 -n 4 -a <event device> \
		-- -p 0x03 --mode=eventdev --eventq-sched=ordered --rule_ipv4="rule_ipv4.cfg" --rule_ipv6="rule_ipv6.cfg"

In this command:

*   -a option allows the event device supported by platform.
    The syntax used to indicate this device may vary based on platform.

*   The --mode option defines PMD to be used for packet I/O.

*   The --eventq-sched option enables synchronization menthod of event queue so that packets will be scheduled accordingly.

If application uses S/W scheduler, it uses following DPDK services:

*   Software scheduler
*   Rx adapter service function
*   Tx adapter service function

Application needs service cores to run above mentioned services. Service cores
must be provided as EAL parameters along with the --vdev=event_sw0 to enable S/W
scheduler. Following is the sample command:

.. code-block:: console

    ./<build_dir>/examples/dpdk-l3fwd -l 0-7 -s 0xf0000 -n 4 --vdev event_sw0 -- -p 0x3 --mode=eventdev --eventq-sched=ordered --rule_ipv4="rule_ipv4.cfg" --rule_ipv6="rule_ipv6.cfg"

In case of eventdev mode, *--config* option is not used for ethernet port
configuration. Instead each ethernet port will be configured with mentioned
setup:

*   Single Rx/Tx queue

*   Each Rx queue will be connected to event queue via Rx adapter.

*   Each Tx queue will be connected via Tx adapter.

Refer to the *DPDK Getting Started Guide* for general information on running applications and
the Environment Abstraction Layer (EAL) options.

.. _l3_fwd_explanation:

Explanation
-----------

The following sections provide some explanation of the sample application code. As mentioned in the overview section,
the initialization and run-time paths are very similar to those of the :doc:`l2_forward_real_virtual` and :doc:`l2_forward_event`.
The following sections describe aspects that are specific to the L3 Forwarding sample application.

Parse Rules from File
~~~~~~~~~~~~~~~~~~~~~

The application parses the rules from the file and adds them to the appropriate route table by calling the appropriate function.
It ignores empty and comment lines, and parses and validates the rules it reads.
If errors are detected, the application exits with messages to identify the errors encountered.

The format of the route rules differs based on which lookup method is being used.
Therefore, the code only decreases the priority number with each rule it parses.
Route rules are mandatory.
To read data from the specified file successfully, the application assumes the following:

*   Each rule occupies a single line.

*   Only the following four rule line types are valid in this application:

*   Route rule line, which starts with a leading character 'R'

*   Comment line, which starts with a leading character '#'

*   ACL rule line, which starts with a leading character ‘@’

*   Empty line, which consists of a space, form-feed ('\f'), newline ('\n'),
    carriage return ('\r'), horizontal tab ('\t'), or vertical tab ('\v').

Other lines types are considered invalid.

*   Rules are organized in descending order of priority,
    which means rules at the head of the file always have a higher priority than those further down in the file.

*   A typical IPv4 LPM/FIB rule line should have a format as shown below:

R<destination_ip>/<ip_mask_length><output_port_number>

*   A typical IPv4 EM rule line should have a format as shown below:

R<destination_ip><source_ip><destination_port><source_port><protocol><output_port_number>

*   A typical IPv4 ACL rule line should have a format as shown below:

.. _figure_ipv4_acl_rule:

.. figure:: img/ipv4_acl_rule.*

   A typical IPv4 ACL rule

IPv4 addresses are specified in CIDR format as specified in RFC 4632.
For LPM/FIB/ACL they consist of the dot notation for the address
and a prefix length separated by '/'.
For example, 192.168.0.34/32, where the address is 192.168.0.34 and the prefix length is 32.
For EM they consist of just the dot notation for the address and no prefix length.
For example, 192.168.0.34, where the Address is 192.168.0.34.
EM also includes ports which are specified as a single number which represents a single port.

The application parses the rules from the file,
it ignores empty and comment lines,
and parses and validates the rules it reads.
If errors are detected, the application exits
with messages to identify the errors encountered.
The ACL rules save the index to the specific rules in the userdata field,
while route rules save the forwarding port number.

Hash Initialization
~~~~~~~~~~~~~~~~~~~

The hash object is created and loaded with the pre-configured entries read from a global array,
and then generate the expected 5-tuple as key to keep consistence with those of real flow
for the convenience to execute hash performance test on 4M/8M/16M flows.

.. note::

    The Hash initialization will setup both ipv4 and ipv6 hash table,
    and populate the either table depending on the value of variable ipv6.

.. note::

    Value of global variable ipv6 can be specified with --ipv6 in the command line.
    Value of global variable hash_entry_number,
    which is used to specify the total hash entry number for all used ports in hash performance test,
    can be specified with --hash-entry-num VALUE in command line, being its default value 4.

.. code-block:: c

    #if (APP_LOOKUP_METHOD == APP_LOOKUP_EXACT_MATCH)

        static void
        setup_hash(int socketid)
        {
            // ...

            if (ipv6 == 0) {
                /* populate the ipv4 hash */
                populate_ipv4_flow_into_table(
                    ipv4_l3fwd_em_lookup_struct[socketid]);
            } else {
                /* populate the ipv6 hash */
                populate_ipv6_flow_into_table(
                    ipv6_l3fwd_em_lookup_struct[socketid]);
            }
        }
    #endif

LPM Initialization
~~~~~~~~~~~~~~~~~~

The LPM object is created and loaded with the pre-configured entries read from a global array.

.. literalinclude:: ../../../examples/l3fwd/l3fwd_em.c
    :language: c
    :start-after: Initialize exact match (hash) parameters. 8<
    :end-before: >8 End of initialization of hash parameters.

FIB Initialization
~~~~~~~~~~~~~~~~~~

The FIB object is created and loaded with the pre-configured entries
read from a global array.
The abridged code snippet below shows the FIB initialization for IPv4,
the full setup function including the IPv6 setup can be seen in the app code.

.. literalinclude:: ../../../examples/l3fwd/l3fwd_fib.c
   :language: c
   :start-after: Function to setup fib. 8<
   :end-before: >8 End of setup fib.

ACL Initialization
~~~~~~~~~~~~~~~~~~

For each supported ACL rule format (IPv4 5-tuple, IPv6 6-tuple),
the application creates a separate context handler
from the ACL library for each CPU socket on the board
and adds parsed rules into that context.

Note, that for each supported rule type,
the application needs to calculate the expected offset of the fields
from the start of the packet.
That's why only packets with fixed IPv4/ IPv6 header are supported.
That allows to perform ACL classify straight over incoming packet buffer -
no extra protocol field retrieval need to be performed.

Subsequently, the application checks whether NUMA is enabled.
If it is, the application records the socket IDs of the CPU cores involved in the task.

Finally, the application creates contexts handler from the ACL library,
adds rules parsed from the file into the database and build an ACL trie.
It is important to note that the application creates an independent copy
of each database for each socket CPU involved in the task
to reduce the time for remote memory access.

.. literalinclude:: ../../../examples/l3fwd/l3fwd_acl.c
   :language: c
   :start-after: Setup ACL context. 8<
   :end-before: >8 End of ACL context setup.

Packet Forwarding for Hash-based Lookups
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For each input packet, the packet forwarding operation is done by the l3fwd_simple_forward()
or simple_ipv4_fwd_4pkts() function for IPv4 packets or the simple_ipv6_fwd_4pkts() function for IPv6 packets.
The l3fwd_simple_forward() function provides the basic functionality for both IPv4 and IPv6 packet forwarding
for any number of burst packets received,
and the packet forwarding decision (that is, the identification of the output interface for the packet)
for hash-based lookups is done by the  get_ipv4_dst_port() or get_ipv6_dst_port() function.
The get_ipv4_dst_port() function is shown below:

.. literalinclude:: ../../../examples/l3fwd/l3fwd_em.c
   :language: c
   :start-after: Performing hash-based lookups. 8<
   :end-before: >8 End of performing hash-based lookups.

The get_ipv6_dst_port() function is similar to the get_ipv4_dst_port() function.

The simple_ipv4_fwd_4pkts() and simple_ipv6_fwd_4pkts() function are optimized for continuous 4 valid ipv4 and ipv6 packets,
they leverage the multiple buffer optimization to boost the performance of forwarding packets with the exact match on hash table.
The key code snippet of simple_ipv4_fwd_4pkts() is shown below:

.. code-block:: c

    static inline void
    simple_ipv4_fwd_4pkts(struct rte_mbuf* m[4], uint16_t portid, struct lcore_conf *qconf)
    {
        // ...

        data[0] = _mm_loadu_si128(( m128i*)(rte_pktmbuf_mtod(m[0], unsigned char *) + sizeof(struct rte_ether_hdr) + offsetof(struct rte_ipv4_hdr, time_to_live)));
        data[1] = _mm_loadu_si128(( m128i*)(rte_pktmbuf_mtod(m[1], unsigned char *) + sizeof(struct rte_ether_hdr) + offsetof(struct rte_ipv4_hdr, time_to_live)));
        data[2] = _mm_loadu_si128(( m128i*)(rte_pktmbuf_mtod(m[2], unsigned char *) + sizeof(struct rte_ether_hdr) + offsetof(struct rte_ipv4_hdr, time_to_live)));
        data[3] = _mm_loadu_si128(( m128i*)(rte_pktmbuf_mtod(m[3], unsigned char *) + sizeof(struct rte_ether_hdr) + offsetof(struct rte_ipv4_hdr, time_to_live)));

        key[0].xmm = _mm_and_si128(data[0], mask0);
        key[1].xmm = _mm_and_si128(data[1], mask0);
        key[2].xmm = _mm_and_si128(data[2], mask0);
        key[3].xmm = _mm_and_si128(data[3], mask0);

        const void *key_array[4] = {&key[0], &key[1], &key[2],&key[3]};

        rte_hash_lookup_bulk(qconf->ipv4_lookup_struct, &key_array[0], 4, ret);

        dst_port[0] = (ret[0] < 0)? portid:ipv4_l3fwd_out_if[ret[0]];
        dst_port[1] = (ret[1] < 0)? portid:ipv4_l3fwd_out_if[ret[1]];
        dst_port[2] = (ret[2] < 0)? portid:ipv4_l3fwd_out_if[ret[2]];
        dst_port[3] = (ret[3] < 0)? portid:ipv4_l3fwd_out_if[ret[3]];

        // ...
    }

The simple_ipv6_fwd_4pkts() function is similar to the simple_ipv4_fwd_4pkts() function.

Known issue: IP packets with extensions or IP packets which are not TCP/UDP cannot work well at this mode.

Packet Forwarding for LPM-based Lookups
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For each input packet, the packet forwarding operation is done by the l3fwd_simple_forward() function,
but the packet forwarding decision (that is, the identification of the output interface for the packet)
for LPM-based lookups is done by the get_ipv4_dst_port() function below:

.. literalinclude:: ../../../examples/l3fwd/l3fwd_lpm.c
   :language: c
   :start-after: Performing LPM-based lookups. 8<
   :end-before: >8 End of performing LPM-based lookups.

Packet Forwarding for FIB-based Lookups
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The FIB library was designed to process multiple packets at once,
it does not have separate functions for single and bulk lookups.
``rte_fib_lookup_bulk`` is used for IPv4 lookups
and ``rte_fib6_lookup_bulk`` for IPv6.
Various examples of these functions being used
can be found in the sample app code.

Eventdev Driver Initialization
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Eventdev driver initialization is same as L2 forwarding eventdev application.
Refer :doc:`l2_forward_event` for more details.
