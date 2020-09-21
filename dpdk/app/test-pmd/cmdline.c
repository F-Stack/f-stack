/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2016 Intel Corporation.
 * Copyright(c) 2014 6WIND S.A.
 */

#include <stdarg.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <inttypes.h>
#ifndef __linux__
#ifndef __FreeBSD__
#include <net/socket.h>
#else
#include <sys/socket.h>
#endif
#endif
#include <netinet/in.h>

#include <sys/queue.h>

#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_cycles.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_malloc.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_string_fns.h>
#include <rte_devargs.h>
#include <rte_eth_ctrl.h>
#include <rte_flow.h>
#include <rte_gro.h>

#include <cmdline_rdline.h>
#include <cmdline_parse.h>
#include <cmdline_parse_num.h>
#include <cmdline_parse_string.h>
#include <cmdline_parse_ipaddr.h>
#include <cmdline_parse_etheraddr.h>
#include <cmdline_socket.h>
#include <cmdline.h>
#ifdef RTE_LIBRTE_PMD_BOND
#include <rte_eth_bond.h>
#include <rte_eth_bond_8023ad.h>
#endif
#if defined RTE_LIBRTE_DPAA_BUS && defined RTE_LIBRTE_DPAA_PMD
#include <rte_pmd_dpaa.h>
#endif
#ifdef RTE_LIBRTE_IXGBE_PMD
#include <rte_pmd_ixgbe.h>
#endif
#ifdef RTE_LIBRTE_I40E_PMD
#include <rte_pmd_i40e.h>
#endif
#ifdef RTE_LIBRTE_BNXT_PMD
#include <rte_pmd_bnxt.h>
#endif
#include "testpmd.h"
#include "cmdline_mtr.h"
#include "cmdline_tm.h"
#include "bpf_cmd.h"

static struct cmdline *testpmd_cl;

static void cmd_reconfig_device_queue(portid_t id, uint8_t dev, uint8_t queue);

/* *** Help command with introduction. *** */
struct cmd_help_brief_result {
	cmdline_fixed_string_t help;
};

static void cmd_help_brief_parsed(__attribute__((unused)) void *parsed_result,
                                  struct cmdline *cl,
                                  __attribute__((unused)) void *data)
{
	cmdline_printf(
		cl,
		"\n"
		"Help is available for the following sections:\n\n"
		"    help control                    : Start and stop forwarding.\n"
		"    help display                    : Displaying port, stats and config "
		"information.\n"
		"    help config                     : Configuration information.\n"
		"    help ports                      : Configuring ports.\n"
		"    help registers                  : Reading and setting port registers.\n"
		"    help filters                    : Filters configuration help.\n"
		"    help traffic_management         : Traffic Management commmands.\n"
		"    help all                        : All of the above sections.\n\n"
	);

}

cmdline_parse_token_string_t cmd_help_brief_help =
	TOKEN_STRING_INITIALIZER(struct cmd_help_brief_result, help, "help");

cmdline_parse_inst_t cmd_help_brief = {
	.f = cmd_help_brief_parsed,
	.data = NULL,
	.help_str = "help: Show help",
	.tokens = {
		(void *)&cmd_help_brief_help,
		NULL,
	},
};

/* *** Help command with help sections. *** */
struct cmd_help_long_result {
	cmdline_fixed_string_t help;
	cmdline_fixed_string_t section;
};

static void cmd_help_long_parsed(void *parsed_result,
                                 struct cmdline *cl,
                                 __attribute__((unused)) void *data)
{
	int show_all = 0;
	struct cmd_help_long_result *res = parsed_result;

	if (!strcmp(res->section, "all"))
		show_all = 1;

	if (show_all || !strcmp(res->section, "control")) {

		cmdline_printf(
			cl,
			"\n"
			"Control forwarding:\n"
			"-------------------\n\n"

			"start\n"
			"    Start packet forwarding with current configuration.\n\n"

			"start tx_first\n"
			"    Start packet forwarding with current config"
			" after sending one burst of packets.\n\n"

			"stop\n"
			"    Stop packet forwarding, and display accumulated"
			" statistics.\n\n"

			"quit\n"
			"    Quit to prompt.\n\n"
		);
	}

	if (show_all || !strcmp(res->section, "display")) {

		cmdline_printf(
			cl,
			"\n"
			"Display:\n"
			"--------\n\n"

			"show port (info|stats|summary|xstats|fdir|stat_qmap|dcb_tc|cap) (port_id|all)\n"
			"    Display information for port_id, or all.\n\n"

			"show port X rss reta (size) (mask0,mask1,...)\n"
			"    Display the rss redirection table entry indicated"
			" by masks on port X. size is used to indicate the"
			" hardware supported reta size\n\n"

			"show port (port_id) rss-hash [key]\n"
			"    Display the RSS hash functions and RSS hash key of port\n\n"

			"clear port (info|stats|xstats|fdir|stat_qmap) (port_id|all)\n"
			"    Clear information for port_id, or all.\n\n"

			"show (rxq|txq) info (port_id) (queue_id)\n"
			"    Display information for configured RX/TX queue.\n\n"

			"show config (rxtx|cores|fwd|txpkts)\n"
			"    Display the given configuration.\n\n"

			"read rxd (port_id) (queue_id) (rxd_id)\n"
			"    Display an RX descriptor of a port RX queue.\n\n"

			"read txd (port_id) (queue_id) (txd_id)\n"
			"    Display a TX descriptor of a port TX queue.\n\n"

			"ddp get list (port_id)\n"
			"    Get ddp profile info list\n\n"

			"ddp get info (profile_path)\n"
			"    Get ddp profile information.\n\n"

			"show vf stats (port_id) (vf_id)\n"
			"    Display a VF's statistics.\n\n"

			"clear vf stats (port_id) (vf_id)\n"
			"    Reset a VF's statistics.\n\n"

			"show port (port_id) pctype mapping\n"
			"    Get flow ptype to pctype mapping on a port\n\n"

			"show port meter stats (port_id) (meter_id) (clear)\n"
			"    Get meter stats on a port\n\n"

			"show fwd stats all\n"
			"    Display statistics for all fwd engines.\n\n"

			"clear fwd stats all\n"
			"    Clear statistics for all fwd engines.\n\n"

			"show port (port_id) rx_offload capabilities\n"
			"    List all per queue and per port Rx offloading"
			" capabilities of a port\n\n"

			"show port (port_id) rx_offload configuration\n"
			"    List port level and all queue level"
			" Rx offloading configuration\n\n"

			"show port (port_id) tx_offload capabilities\n"
			"    List all per queue and per port"
			" Tx offloading capabilities of a port\n\n"

			"show port (port_id) tx_offload configuration\n"
			"    List port level and all queue level"
			" Tx offloading configuration\n\n"

			"show port (port_id) tx_metadata\n"
			"    Show Tx metadata value set"
			" for a specific port\n\n"
		);
	}

	if (show_all || !strcmp(res->section, "config")) {
		cmdline_printf(
			cl,
			"\n"
			"Configuration:\n"
			"--------------\n"
			"Configuration changes only become active when"
			" forwarding is started/restarted.\n\n"

			"set default\n"
			"    Reset forwarding to the default configuration.\n\n"

			"set verbose (level)\n"
			"    Set the debug verbosity level X.\n\n"

			"set log global|(type) (level)\n"
			"    Set the log level.\n\n"

			"set nbport (num)\n"
			"    Set number of ports.\n\n"

			"set nbcore (num)\n"
			"    Set number of cores.\n\n"

			"set coremask (mask)\n"
			"    Set the forwarding cores hexadecimal mask.\n\n"

			"set portmask (mask)\n"
			"    Set the forwarding ports hexadecimal mask.\n\n"

			"set burst (num)\n"
			"    Set number of packets per burst.\n\n"

			"set burst tx delay (microseconds) retry (num)\n"
			"    Set the transmit delay time and number of retries,"
			" effective when retry is enabled.\n\n"

			"set txpkts (x[,y]*)\n"
			"    Set the length of each segment of TXONLY"
			" and optionally CSUM packets.\n\n"

			"set txsplit (off|on|rand)\n"
			"    Set the split policy for the TX packets."
			" Right now only applicable for CSUM and TXONLY"
			" modes\n\n"

			"set corelist (x[,y]*)\n"
			"    Set the list of forwarding cores.\n\n"

			"set portlist (x[,y]*)\n"
			"    Set the list of forwarding ports.\n\n"

			"set port setup on (iterator|event)\n"
			"    Select how attached port is retrieved for setup.\n\n"

			"set tx loopback (port_id) (on|off)\n"
			"    Enable or disable tx loopback.\n\n"

			"set all queues drop (port_id) (on|off)\n"
			"    Set drop enable bit for all queues.\n\n"

			"set vf split drop (port_id) (vf_id) (on|off)\n"
			"    Set split drop enable bit for a VF from the PF.\n\n"

			"set vf mac antispoof (port_id) (vf_id) (on|off).\n"
			"    Set MAC antispoof for a VF from the PF.\n\n"

			"set macsec offload (port_id) on encrypt (on|off) replay-protect (on|off)\n"
			"    Enable MACsec offload.\n\n"

			"set macsec offload (port_id) off\n"
			"    Disable MACsec offload.\n\n"

			"set macsec sc (tx|rx) (port_id) (mac) (pi)\n"
			"    Configure MACsec secure connection (SC).\n\n"

			"set macsec sa (tx|rx) (port_id) (idx) (an) (pn) (key)\n"
			"    Configure MACsec secure association (SA).\n\n"

			"set vf broadcast (port_id) (vf_id) (on|off)\n"
			"    Set VF broadcast for a VF from the PF.\n\n"

			"vlan set strip (on|off) (port_id)\n"
			"    Set the VLAN strip on a port.\n\n"

			"vlan set stripq (on|off) (port_id,queue_id)\n"
			"    Set the VLAN strip for a queue on a port.\n\n"

			"set vf vlan stripq (port_id) (vf_id) (on|off)\n"
			"    Set the VLAN strip for all queues in a pool for a VF from the PF.\n\n"

			"set vf vlan insert (port_id) (vf_id) (vlan_id)\n"
			"    Set VLAN insert for a VF from the PF.\n\n"

			"set vf vlan antispoof (port_id) (vf_id) (on|off)\n"
			"    Set VLAN antispoof for a VF from the PF.\n\n"

			"set vf vlan tag (port_id) (vf_id) (on|off)\n"
			"    Set VLAN tag for a VF from the PF.\n\n"

			"set vf tx max-bandwidth (port_id) (vf_id) (bandwidth)\n"
			"    Set a VF's max bandwidth(Mbps).\n\n"

			"set vf tc tx min-bandwidth (port_id) (vf_id) (bw1, bw2, ...)\n"
			"    Set all TCs' min bandwidth(%%) on a VF.\n\n"

			"set vf tc tx max-bandwidth (port_id) (vf_id) (tc_no) (bandwidth)\n"
			"    Set a TC's max bandwidth(Mbps) on a VF.\n\n"

			"set tx strict-link-priority (port_id) (tc_bitmap)\n"
			"    Set some TCs' strict link priority mode on a physical port.\n\n"

			"set tc tx min-bandwidth (port_id) (bw1, bw2, ...)\n"
			"    Set all TCs' min bandwidth(%%) for all PF and VFs.\n\n"

			"vlan set filter (on|off) (port_id)\n"
			"    Set the VLAN filter on a port.\n\n"

			"vlan set qinq (on|off) (port_id)\n"
			"    Set the VLAN QinQ (extended queue in queue)"
			" on a port.\n\n"

			"vlan set (inner|outer) tpid (value) (port_id)\n"
			"    Set the VLAN TPID for Packet Filtering on"
			" a port\n\n"

			"rx_vlan add (vlan_id|all) (port_id)\n"
			"    Add a vlan_id, or all identifiers, to the set"
			" of VLAN identifiers filtered by port_id.\n\n"

			"rx_vlan rm (vlan_id|all) (port_id)\n"
			"    Remove a vlan_id, or all identifiers, from the set"
			" of VLAN identifiers filtered by port_id.\n\n"

			"rx_vlan add (vlan_id) port (port_id) vf (vf_mask)\n"
			"    Add a vlan_id, to the set of VLAN identifiers"
			"filtered for VF(s) from port_id.\n\n"

			"rx_vlan rm (vlan_id) port (port_id) vf (vf_mask)\n"
			"    Remove a vlan_id, to the set of VLAN identifiers"
			"filtered for VF(s) from port_id.\n\n"

			"tunnel_filter add (port_id) (outer_mac) (inner_mac) (ip_addr) "
			"(inner_vlan) (vxlan|nvgre|ipingre) (imac-ivlan|imac-ivlan-tenid|"
			"imac-tenid|imac|omac-imac-tenid|oip|iip) (tenant_id) (queue_id)\n"
			"   add a tunnel filter of a port.\n\n"

			"tunnel_filter rm (port_id) (outer_mac) (inner_mac) (ip_addr) "
			"(inner_vlan) (vxlan|nvgre|ipingre) (imac-ivlan|imac-ivlan-tenid|"
			"imac-tenid|imac|omac-imac-tenid|oip|iip) (tenant_id) (queue_id)\n"
			"   remove a tunnel filter of a port.\n\n"

			"rx_vxlan_port add (udp_port) (port_id)\n"
			"    Add an UDP port for VXLAN packet filter on a port\n\n"

			"rx_vxlan_port rm (udp_port) (port_id)\n"
			"    Remove an UDP port for VXLAN packet filter on a port\n\n"

			"tx_vlan set (port_id) vlan_id[, vlan_id_outer]\n"
			"    Set hardware insertion of VLAN IDs (single or double VLAN "
			"depends on the number of VLAN IDs) in packets sent on a port.\n\n"

			"tx_vlan set pvid port_id vlan_id (on|off)\n"
			"    Set port based TX VLAN insertion.\n\n"

			"tx_vlan reset (port_id)\n"
			"    Disable hardware insertion of a VLAN header in"
			" packets sent on a port.\n\n"

			"csum set (ip|udp|tcp|sctp|outer-ip|outer-udp) (hw|sw) (port_id)\n"
			"    Select hardware or software calculation of the"
			" checksum when transmitting a packet using the"
			" csum forward engine.\n"
			"    ip|udp|tcp|sctp always concern the inner layer.\n"
			"    outer-ip concerns the outer IP layer in"
			"    outer-udp concerns the outer UDP layer in"
			" case the packet is recognized as a tunnel packet by"
			" the forward engine (vxlan, gre and ipip are supported)\n"
			"    Please check the NIC datasheet for HW limits.\n\n"

			"csum parse-tunnel (on|off) (tx_port_id)\n"
			"    If disabled, treat tunnel packets as non-tunneled"
			" packets (treat inner headers as payload). The port\n"
			"    argument is the port used for TX in csum forward"
			" engine.\n\n"

			"csum show (port_id)\n"
			"    Display tx checksum offload configuration\n\n"

			"tso set (segsize) (portid)\n"
			"    Enable TCP Segmentation Offload in csum forward"
			" engine.\n"
			"    Please check the NIC datasheet for HW limits.\n\n"

			"tso show (portid)"
			"    Display the status of TCP Segmentation Offload.\n\n"

			"set port (port_id) gro on|off\n"
			"    Enable or disable Generic Receive Offload in"
			" csum forwarding engine.\n\n"

			"show port (port_id) gro\n"
			"    Display GRO configuration.\n\n"

			"set gro flush (cycles)\n"
			"    Set the cycle to flush GROed packets from"
			" reassembly tables.\n\n"

			"set port (port_id) gso (on|off)"
			"    Enable or disable Generic Segmentation Offload in"
			" csum forwarding engine.\n\n"

			"set gso segsz (length)\n"
			"    Set max packet length for output GSO segments,"
			" including packet header and payload.\n\n"

			"show port (port_id) gso\n"
			"    Show GSO configuration.\n\n"

			"set fwd (%s)\n"
			"    Set packet forwarding mode.\n\n"

			"mac_addr add (port_id) (XX:XX:XX:XX:XX:XX)\n"
			"    Add a MAC address on port_id.\n\n"

			"mac_addr remove (port_id) (XX:XX:XX:XX:XX:XX)\n"
			"    Remove a MAC address from port_id.\n\n"

			"mac_addr set (port_id) (XX:XX:XX:XX:XX:XX)\n"
			"    Set the default MAC address for port_id.\n\n"

			"mac_addr add port (port_id) vf (vf_id) (mac_address)\n"
			"    Add a MAC address for a VF on the port.\n\n"

			"set vf mac addr (port_id) (vf_id) (XX:XX:XX:XX:XX:XX)\n"
			"    Set the MAC address for a VF from the PF.\n\n"

			"set eth-peer (port_id) (peer_addr)\n"
			"    set the peer address for certain port.\n\n"

			"set port (port_id) uta (mac_address|all) (on|off)\n"
			"    Add/Remove a or all unicast hash filter(s)"
			"from port X.\n\n"

			"set promisc (port_id|all) (on|off)\n"
			"    Set the promiscuous mode on port_id, or all.\n\n"

			"set allmulti (port_id|all) (on|off)\n"
			"    Set the allmulti mode on port_id, or all.\n\n"

			"set vf promisc (port_id) (vf_id) (on|off)\n"
			"    Set unicast promiscuous mode for a VF from the PF.\n\n"

			"set vf allmulti (port_id) (vf_id) (on|off)\n"
			"    Set multicast promiscuous mode for a VF from the PF.\n\n"

			"set flow_ctrl rx (on|off) tx (on|off) (high_water)"
			" (low_water) (pause_time) (send_xon) mac_ctrl_frame_fwd"
			" (on|off) autoneg (on|off) (port_id)\n"
			"set flow_ctrl rx (on|off) (portid)\n"
			"set flow_ctrl tx (on|off) (portid)\n"
			"set flow_ctrl high_water (high_water) (portid)\n"
			"set flow_ctrl low_water (low_water) (portid)\n"
			"set flow_ctrl pause_time (pause_time) (portid)\n"
			"set flow_ctrl send_xon (send_xon) (portid)\n"
			"set flow_ctrl mac_ctrl_frame_fwd (on|off) (portid)\n"
			"set flow_ctrl autoneg (on|off) (port_id)\n"
			"    Set the link flow control parameter on a port.\n\n"

			"set pfc_ctrl rx (on|off) tx (on|off) (high_water)"
			" (low_water) (pause_time) (priority) (port_id)\n"
			"    Set the priority flow control parameter on a"
			" port.\n\n"

			"set stat_qmap (tx|rx) (port_id) (queue_id) (qmapping)\n"
			"    Set statistics mapping (qmapping 0..15) for RX/TX"
			" queue on port.\n"
			"    e.g., 'set stat_qmap rx 0 2 5' sets rx queue 2"
			" on port 0 to mapping 5.\n\n"

			"set xstats-hide-zero on|off\n"
			"    Set the option to hide the zero values"
			" for xstats display.\n"

			"set port (port_id) vf (vf_id) rx|tx on|off\n"
			"    Enable/Disable a VF receive/tranmit from a port\n\n"

			"set port (port_id) vf (vf_id) (mac_addr)"
			" (exact-mac#exact-mac-vlan#hashmac|hashmac-vlan) on|off\n"
			"   Add/Remove unicast or multicast MAC addr filter"
			" for a VF.\n\n"

			"set port (port_id) vf (vf_id) rxmode (AUPE|ROPE|BAM"
			"|MPE) (on|off)\n"
			"    AUPE:accepts untagged VLAN;"
			"ROPE:accept unicast hash\n\n"
			"    BAM:accepts broadcast packets;"
			"MPE:accepts all multicast packets\n\n"
			"    Enable/Disable a VF receive mode of a port\n\n"

			"set port (port_id) queue (queue_id) rate (rate_num)\n"
			"    Set rate limit for a queue of a port\n\n"

			"set port (port_id) vf (vf_id) rate (rate_num) "
			"queue_mask (queue_mask_value)\n"
			"    Set rate limit for queues in VF of a port\n\n"

			"set port (port_id) mirror-rule (rule_id)"
			" (pool-mirror-up|pool-mirror-down|vlan-mirror)"
			" (poolmask|vlanid[,vlanid]*) dst-pool (pool_id) (on|off)\n"
			"   Set pool or vlan type mirror rule on a port.\n"
			"   e.g., 'set port 0 mirror-rule 0 vlan-mirror 0,1"
			" dst-pool 0 on' enable mirror traffic with vlan 0,1"
			" to pool 0.\n\n"

			"set port (port_id) mirror-rule (rule_id)"
			" (uplink-mirror|downlink-mirror) dst-pool"
			" (pool_id) (on|off)\n"
			"   Set uplink or downlink type mirror rule on a port.\n"
			"   e.g., 'set port 0 mirror-rule 0 uplink-mirror dst-pool"
			" 0 on' enable mirror income traffic to pool 0.\n\n"

			"reset port (port_id) mirror-rule (rule_id)\n"
			"   Reset a mirror rule.\n\n"

			"set flush_rx (on|off)\n"
			"   Flush (default) or don't flush RX streams before"
			" forwarding. Mainly used with PCAP drivers.\n\n"

			"set bypass mode (normal|bypass|isolate) (port_id)\n"
			"   Set the bypass mode for the lowest port on bypass enabled"
			" NIC.\n\n"

			"set bypass event (timeout|os_on|os_off|power_on|power_off) "
			"mode (normal|bypass|isolate) (port_id)\n"
			"   Set the event required to initiate specified bypass mode for"
			" the lowest port on a bypass enabled NIC where:\n"
			"       timeout   = enable bypass after watchdog timeout.\n"
			"       os_on     = enable bypass when OS/board is powered on.\n"
			"       os_off    = enable bypass when OS/board is powered off.\n"
			"       power_on  = enable bypass when power supply is turned on.\n"
			"       power_off = enable bypass when power supply is turned off."
			"\n\n"

			"set bypass timeout (0|1.5|2|3|4|8|16|32)\n"
			"   Set the bypass watchdog timeout to 'n' seconds"
			" where 0 = instant.\n\n"

			"show bypass config (port_id)\n"
			"   Show the bypass configuration for a bypass enabled NIC"
			" using the lowest port on the NIC.\n\n"

#ifdef RTE_LIBRTE_PMD_BOND
			"create bonded device (mode) (socket)\n"
			"	Create a new bonded device with specific bonding mode and socket.\n\n"

			"add bonding slave (slave_id) (port_id)\n"
			"	Add a slave device to a bonded device.\n\n"

			"remove bonding slave (slave_id) (port_id)\n"
			"	Remove a slave device from a bonded device.\n\n"

			"set bonding mode (value) (port_id)\n"
			"	Set the bonding mode on a bonded device.\n\n"

			"set bonding primary (slave_id) (port_id)\n"
			"	Set the primary slave for a bonded device.\n\n"

			"show bonding config (port_id)\n"
			"	Show the bonding config for port_id.\n\n"

			"set bonding mac_addr (port_id) (address)\n"
			"	Set the MAC address of a bonded device.\n\n"

			"set bonding mode IEEE802.3AD aggregator policy (port_id) (agg_name)"
			"	Set Aggregation mode for IEEE802.3AD (mode 4)"

			"set bonding xmit_balance_policy (port_id) (l2|l23|l34)\n"
			"	Set the transmit balance policy for bonded device running in balance mode.\n\n"

			"set bonding mon_period (port_id) (value)\n"
			"	Set the bonding link status monitoring polling period in ms.\n\n"

			"set bonding lacp dedicated_queues <port_id> (enable|disable)\n"
			"	Enable/disable dedicated queues for LACP control traffic.\n\n"

#endif
			"set link-up port (port_id)\n"
			"	Set link up for a port.\n\n"

			"set link-down port (port_id)\n"
			"	Set link down for a port.\n\n"

			"E-tag set insertion on port-tag-id (value)"
			" port (port_id) vf (vf_id)\n"
			"    Enable E-tag insertion for a VF on a port\n\n"

			"E-tag set insertion off port (port_id) vf (vf_id)\n"
			"    Disable E-tag insertion for a VF on a port\n\n"

			"E-tag set stripping (on|off) port (port_id)\n"
			"    Enable/disable E-tag stripping on a port\n\n"

			"E-tag set forwarding (on|off) port (port_id)\n"
			"    Enable/disable E-tag based forwarding"
			" on a port\n\n"

			"E-tag set filter add e-tag-id (value) dst-pool"
			" (pool_id) port (port_id)\n"
			"    Add an E-tag forwarding filter on a port\n\n"

			"E-tag set filter del e-tag-id (value) port (port_id)\n"
			"    Delete an E-tag forwarding filter on a port\n\n"

			"ddp add (port_id) (profile_path[,backup_profile_path])\n"
			"    Load a profile package on a port\n\n"

			"ddp del (port_id) (backup_profile_path)\n"
			"    Delete a profile package from a port\n\n"

			"ptype mapping get (port_id) (valid_only)\n"
			"    Get ptype mapping on a port\n\n"

			"ptype mapping replace (port_id) (target) (mask) (pky_type)\n"
			"    Replace target with the pkt_type in ptype mapping\n\n"

			"ptype mapping reset (port_id)\n"
			"    Reset ptype mapping on a port\n\n"

			"ptype mapping update (port_id) (hw_ptype) (sw_ptype)\n"
			"    Update a ptype mapping item on a port\n\n"

			"set port (port_id) queue-region region_id (value) "
			"queue_start_index (value) queue_num (value)\n"
			"    Set a queue region on a port\n\n"

			"set port (port_id) queue-region region_id (value) "
			"flowtype (value)\n"
			"    Set a flowtype region index on a port\n\n"

			"set port (port_id) queue-region UP (value) region_id (value)\n"
			"    Set the mapping of User Priority to "
			"queue region on a port\n\n"

			"set port (port_id) queue-region flush (on|off)\n"
			"    flush all queue region related configuration\n\n"

			"show port meter cap (port_id)\n"
			"    Show port meter capability information\n\n"

			"add port meter profile srtcm_rfc2697 (port_id) (profile_id) (cir) (cbs) (ebs)\n"
			"    meter profile add - srtcm rfc 2697\n\n"

			"add port meter profile trtcm_rfc2698 (port_id) (profile_id) (cir) (pir) (cbs) (pbs)\n"
			"    meter profile add - trtcm rfc 2698\n\n"

			"add port meter profile trtcm_rfc4115 (port_id) (profile_id) (cir) (eir) (cbs) (ebs)\n"
			"    meter profile add - trtcm rfc 4115\n\n"

			"del port meter profile (port_id) (profile_id)\n"
			"    meter profile delete\n\n"

			"create port meter (port_id) (mtr_id) (profile_id) (meter_enable)\n"
			"(g_action) (y_action) (r_action) (stats_mask) (shared)\n"
			"(use_pre_meter_color) [(dscp_tbl_entry0) (dscp_tbl_entry1)...\n"
			"(dscp_tbl_entry63)]\n"
			"    meter create\n\n"

			"enable port meter (port_id) (mtr_id)\n"
			"    meter enable\n\n"

			"disable port meter (port_id) (mtr_id)\n"
			"    meter disable\n\n"

			"del port meter (port_id) (mtr_id)\n"
			"    meter delete\n\n"

			"set port meter profile (port_id) (mtr_id) (profile_id)\n"
			"    meter update meter profile\n\n"

			"set port meter dscp table (port_id) (mtr_id) [(dscp_tbl_entry0)\n"
			"(dscp_tbl_entry1)...(dscp_tbl_entry63)]\n"
			"    update meter dscp table entries\n\n"

			"set port meter policer action (port_id) (mtr_id) (action_mask)\n"
			"(action0) [(action1) (action2)]\n"
			"    meter update policer action\n\n"

			"set port meter stats mask (port_id) (mtr_id) (stats_mask)\n"
			"    meter update stats\n\n"

			"show port (port_id) queue-region\n"
			"    show all queue region related configuration info\n\n"

			"vxlan ip-version (ipv4|ipv6) vni (vni) udp-src"
			" (udp-src) udp-dst (udp-dst) ip-src (ip-src) ip-dst"
			" (ip-dst) eth-src (eth-src) eth-dst (eth-dst)\n"
			"       Configure the VXLAN encapsulation for flows.\n\n"

			"vxlan-with-vlan ip-version (ipv4|ipv6) vni (vni)"
			" udp-src (udp-src) udp-dst (udp-dst) ip-src (ip-src)"
			" ip-dst (ip-dst) vlan-tci (vlan-tci) eth-src (eth-src)"
			" eth-dst (eth-dst)\n"
			"       Configure the VXLAN encapsulation for flows.\n\n"

			"nvgre ip-version (ipv4|ipv6) tni (tni) ip-src"
			" (ip-src) ip-dst (ip-dst) eth-src (eth-src) eth-dst"
			" (eth-dst)\n"
			"       Configure the NVGRE encapsulation for flows.\n\n"

			"nvgre-with-vlan ip-version (ipv4|ipv6) tni (tni)"
			" ip-src (ip-src) ip-dst (ip-dst) vlan-tci (vlan-tci)"
			" eth-src (eth-src) eth-dst (eth-dst)\n"
			"       Configure the NVGRE encapsulation for flows.\n\n"

			, list_pkt_forwarding_modes()
		);
	}

	if (show_all || !strcmp(res->section, "ports")) {

		cmdline_printf(
			cl,
			"\n"
			"Port Operations:\n"
			"----------------\n\n"

			"port start (port_id|all)\n"
			"    Start all ports or port_id.\n\n"

			"port stop (port_id|all)\n"
			"    Stop all ports or port_id.\n\n"

			"port close (port_id|all)\n"
			"    Close all ports or port_id.\n\n"

			"port attach (ident)\n"
			"    Attach physical or virtual dev by pci address or virtual device name\n\n"

			"port detach (port_id)\n"
			"    Detach physical or virtual dev by port_id\n\n"

			"port config (port_id|all)"
			" speed (10|100|1000|10000|25000|40000|50000|100000|auto)"
			" duplex (half|full|auto)\n"
			"    Set speed and duplex for all ports or port_id\n\n"

			"port config (port_id|all) loopback (mode)\n"
			"    Set loopback mode for all ports or port_id\n\n"

			"port config all (rxq|txq|rxd|txd) (value)\n"
			"    Set number for rxq/txq/rxd/txd.\n\n"

			"port config all max-pkt-len (value)\n"
			"    Set the max packet length.\n\n"

			"port config all (crc-strip|scatter|rx-cksum|rx-timestamp|hw-vlan|hw-vlan-filter|"
			"hw-vlan-strip|hw-vlan-extend|drop-en)"
			" (on|off)\n"
			"    Set crc-strip/scatter/rx-checksum/hardware-vlan/drop_en"
			" for ports.\n\n"

			"port config all rss (all|default|ip|tcp|udp|sctp|"
			"ether|port|vxlan|geneve|nvgre|none|<flowtype_id>)\n"
			"    Set the RSS mode.\n\n"

			"port config port-id rss reta (hash,queue)[,(hash,queue)]\n"
			"    Set the RSS redirection table.\n\n"

			"port config (port_id) dcb vt (on|off) (traffic_class)"
			" pfc (on|off)\n"
			"    Set the DCB mode.\n\n"

			"port config all burst (value)\n"
			"    Set the number of packets per burst.\n\n"

			"port config all (txpt|txht|txwt|rxpt|rxht|rxwt)"
			" (value)\n"
			"    Set the ring prefetch/host/writeback threshold"
			" for tx/rx queue.\n\n"

			"port config all (txfreet|txrst|rxfreet) (value)\n"
			"    Set free threshold for rx/tx, or set"
			" tx rs bit threshold.\n\n"
			"port config mtu X value\n"
			"    Set the MTU of port X to a given value\n\n"

			"port config (port_id) (rxq|txq) (queue_id) ring_size (value)\n"
			"    Set a rx/tx queue's ring size configuration, the new"
			" value will take effect after command that (re-)start the port"
			" or command that setup the specific queue\n\n"

			"port (port_id) (rxq|txq) (queue_id) (start|stop)\n"
			"    Start/stop a rx/tx queue of port X. Only take effect"
			" when port X is started\n\n"

			"port (port_id) (rxq|txq) (queue_id) deferred_start (on|off)\n"
			"    Switch on/off a deferred start of port X rx/tx queue. Only"
			" take effect when port X is stopped.\n\n"

			"port (port_id) (rxq|txq) (queue_id) setup\n"
			"    Setup a rx/tx queue of port X.\n\n"

			"port config (port_id|all) l2-tunnel E-tag ether-type"
			" (value)\n"
			"    Set the value of E-tag ether-type.\n\n"

			"port config (port_id|all) l2-tunnel E-tag"
			" (enable|disable)\n"
			"    Enable/disable the E-tag support.\n\n"

			"port config (port_id) pctype mapping reset\n"
			"    Reset flow type to pctype mapping on a port\n\n"

			"port config (port_id) pctype mapping update"
			" (pctype_id_0[,pctype_id_1]*) (flow_type_id)\n"
			"    Update a flow type to pctype mapping item on a port\n\n"

			"port config (port_id) pctype (pctype_id) hash_inset|"
			"fdir_inset|fdir_flx_inset get|set|clear field\n"
			" (field_idx)\n"
			"    Configure RSS|FDIR|FDIR_FLX input set for some pctype\n\n"

			"port config (port_id) pctype (pctype_id) hash_inset|"
			"fdir_inset|fdir_flx_inset clear all"
			"    Clear RSS|FDIR|FDIR_FLX input set completely for some pctype\n\n"

			"port config (port_id) udp_tunnel_port add|rm vxlan|geneve (udp_port)\n\n"
			"    Add/remove UDP tunnel port for tunneling offload\n\n"

			"port config <port_id> rx_offload vlan_strip|"
			"ipv4_cksum|udp_cksum|tcp_cksum|tcp_lro|qinq_strip|"
			"outer_ipv4_cksum|macsec_strip|header_split|"
			"vlan_filter|vlan_extend|jumbo_frame|crc_strip|"
			"scatter|timestamp|security|keep_crc on|off\n"
			"     Enable or disable a per port Rx offloading"
			" on all Rx queues of a port\n\n"

			"port (port_id) rxq (queue_id) rx_offload vlan_strip|"
			"ipv4_cksum|udp_cksum|tcp_cksum|tcp_lro|qinq_strip|"
			"outer_ipv4_cksum|macsec_strip|header_split|"
			"vlan_filter|vlan_extend|jumbo_frame|crc_strip|"
			"scatter|timestamp|security|keep_crc on|off\n"
			"    Enable or disable a per queue Rx offloading"
			" only on a specific Rx queue\n\n"

			"port config (port_id) tx_offload vlan_insert|"
			"ipv4_cksum|udp_cksum|tcp_cksum|sctp_cksum|tcp_tso|"
			"udp_tso|outer_ipv4_cksum|qinq_insert|vxlan_tnl_tso|"
			"gre_tnl_tso|ipip_tnl_tso|geneve_tnl_tso|"
			"macsec_insert|mt_lockfree|multi_segs|mbuf_fast_free|"
			"security|match_metadata on|off\n"
			"    Enable or disable a per port Tx offloading"
			" on all Tx queues of a port\n\n"

			"port (port_id) txq (queue_id) tx_offload vlan_insert|"
			"ipv4_cksum|udp_cksum|tcp_cksum|sctp_cksum|tcp_tso|"
			"udp_tso|outer_ipv4_cksum|qinq_insert|vxlan_tnl_tso|"
			"gre_tnl_tso|ipip_tnl_tso|geneve_tnl_tso|macsec_insert"
			"|mt_lockfree|multi_segs|mbuf_fast_free|security"
			" on|off\n"
			"    Enable or disable a per queue Tx offloading"
			" only on a specific Tx queue\n\n"

			"bpf-load rx|tx (port) (queue) (J|M|B) (file_name)\n"
			"    Load an eBPF program as a callback"
			" for particular RX/TX queue\n\n"

			"bpf-unload rx|tx (port) (queue)\n"
			"    Unload previously loaded eBPF program"
			" for particular RX/TX queue\n\n"

			"port config (port_id) tx_metadata (value)\n"
			"    Set Tx metadata value per port. Testpmd will add this value"
			" to any Tx packet sent from this port\n\n"
		);
	}

	if (show_all || !strcmp(res->section, "registers")) {

		cmdline_printf(
			cl,
			"\n"
			"Registers:\n"
			"----------\n\n"

			"read reg (port_id) (address)\n"
			"    Display value of a port register.\n\n"

			"read regfield (port_id) (address) (bit_x) (bit_y)\n"
			"    Display a port register bit field.\n\n"

			"read regbit (port_id) (address) (bit_x)\n"
			"    Display a single port register bit.\n\n"

			"write reg (port_id) (address) (value)\n"
			"    Set value of a port register.\n\n"

			"write regfield (port_id) (address) (bit_x) (bit_y)"
			" (value)\n"
			"    Set bit field of a port register.\n\n"

			"write regbit (port_id) (address) (bit_x) (value)\n"
			"    Set single bit value of a port register.\n\n"
		);
	}
	if (show_all || !strcmp(res->section, "filters")) {

		cmdline_printf(
			cl,
			"\n"
			"filters:\n"
			"--------\n\n"

			"ethertype_filter (port_id) (add|del)"
			" (mac_addr|mac_ignr) (mac_address) ethertype"
			" (ether_type) (drop|fwd) queue (queue_id)\n"
			"    Add/Del an ethertype filter.\n\n"

			"2tuple_filter (port_id) (add|del)"
			" dst_port (dst_port_value) protocol (protocol_value)"
			" mask (mask_value) tcp_flags (tcp_flags_value)"
			" priority (prio_value) queue (queue_id)\n"
			"    Add/Del a 2tuple filter.\n\n"

			"5tuple_filter (port_id) (add|del)"
			" dst_ip (dst_address) src_ip (src_address)"
			" dst_port (dst_port_value) src_port (src_port_value)"
			" protocol (protocol_value)"
			" mask (mask_value) tcp_flags (tcp_flags_value)"
			" priority (prio_value) queue (queue_id)\n"
			"    Add/Del a 5tuple filter.\n\n"

			"syn_filter (port_id) (add|del) priority (high|low) queue (queue_id)"
			"    Add/Del syn filter.\n\n"

			"flex_filter (port_id) (add|del) len (len_value)"
			" bytes (bytes_value) mask (mask_value)"
			" priority (prio_value) queue (queue_id)\n"
			"    Add/Del a flex filter.\n\n"

			"flow_director_filter (port_id) mode IP (add|del|update)"
			" flow (ipv4-other|ipv4-frag|ipv6-other|ipv6-frag)"
			" src (src_ip_address) dst (dst_ip_address)"
			" tos (tos_value) proto (proto_value) ttl (ttl_value)"
			" vlan (vlan_value) flexbytes (flexbytes_value)"
			" (drop|fwd) pf|vf(vf_id) queue (queue_id)"
			" fd_id (fd_id_value)\n"
			"    Add/Del an IP type flow director filter.\n\n"

			"flow_director_filter (port_id) mode IP (add|del|update)"
			" flow (ipv4-tcp|ipv4-udp|ipv6-tcp|ipv6-udp)"
			" src (src_ip_address) (src_port)"
			" dst (dst_ip_address) (dst_port)"
			" tos (tos_value) ttl (ttl_value)"
			" vlan (vlan_value) flexbytes (flexbytes_value)"
			" (drop|fwd) pf|vf(vf_id) queue (queue_id)"
			" fd_id (fd_id_value)\n"
			"    Add/Del an UDP/TCP type flow director filter.\n\n"

			"flow_director_filter (port_id) mode IP (add|del|update)"
			" flow (ipv4-sctp|ipv6-sctp)"
			" src (src_ip_address) (src_port)"
			" dst (dst_ip_address) (dst_port)"
			" tag (verification_tag) "
			" tos (tos_value) ttl (ttl_value)"
			" vlan (vlan_value)"
			" flexbytes (flexbytes_value) (drop|fwd)"
			" pf|vf(vf_id) queue (queue_id) fd_id (fd_id_value)\n"
			"    Add/Del a SCTP type flow director filter.\n\n"

			"flow_director_filter (port_id) mode IP (add|del|update)"
			" flow l2_payload ether (ethertype)"
			" flexbytes (flexbytes_value) (drop|fwd)"
			" pf|vf(vf_id) queue (queue_id) fd_id (fd_id_value)\n"
			"    Add/Del a l2 payload type flow director filter.\n\n"

			"flow_director_filter (port_id) mode MAC-VLAN (add|del|update)"
			" mac (mac_address) vlan (vlan_value)"
			" flexbytes (flexbytes_value) (drop|fwd)"
			" queue (queue_id) fd_id (fd_id_value)\n"
			"    Add/Del a MAC-VLAN flow director filter.\n\n"

			"flow_director_filter (port_id) mode Tunnel (add|del|update)"
			" mac (mac_address) vlan (vlan_value)"
			" tunnel (NVGRE|VxLAN) tunnel-id (tunnel_id_value)"
			" flexbytes (flexbytes_value) (drop|fwd)"
			" queue (queue_id) fd_id (fd_id_value)\n"
			"    Add/Del a Tunnel flow director filter.\n\n"

			"flow_director_filter (port_id) mode raw (add|del|update)"
			" flow (flow_id) (drop|fwd) queue (queue_id)"
			" fd_id (fd_id_value) packet (packet file name)\n"
			"    Add/Del a raw type flow director filter.\n\n"

			"flush_flow_director (port_id)\n"
			"    Flush all flow director entries of a device.\n\n"

			"flow_director_mask (port_id) mode IP vlan (vlan_value)"
			" src_mask (ipv4_src) (ipv6_src) (src_port)"
			" dst_mask (ipv4_dst) (ipv6_dst) (dst_port)\n"
			"    Set flow director IP mask.\n\n"

			"flow_director_mask (port_id) mode MAC-VLAN"
			" vlan (vlan_value)\n"
			"    Set flow director MAC-VLAN mask.\n\n"

			"flow_director_mask (port_id) mode Tunnel"
			" vlan (vlan_value) mac (mac_value)"
			" tunnel-type (tunnel_type_value)"
			" tunnel-id (tunnel_id_value)\n"
			"    Set flow director Tunnel mask.\n\n"

			"flow_director_flex_mask (port_id)"
			" flow (none|ipv4-other|ipv4-frag|ipv4-tcp|ipv4-udp|ipv4-sctp|"
			"ipv6-other|ipv6-frag|ipv6-tcp|ipv6-udp|ipv6-sctp|l2_payload|all)"
			" (mask)\n"
			"    Configure mask of flex payload.\n\n"

			"flow_director_flex_payload (port_id)"
			" (raw|l2|l3|l4) (config)\n"
			"    Configure flex payload selection.\n\n"

			"get_sym_hash_ena_per_port (port_id)\n"
			"    get symmetric hash enable configuration per port.\n\n"

			"set_sym_hash_ena_per_port (port_id) (enable|disable)\n"
			"    set symmetric hash enable configuration per port"
			" to enable or disable.\n\n"

			"get_hash_global_config (port_id)\n"
			"    Get the global configurations of hash filters.\n\n"

			"set_hash_global_config (port_id) (toeplitz|simple_xor|default)"
			" (ipv4|ipv4-frag|ipv4-tcp|ipv4-udp|ipv4-sctp|ipv4-other|ipv6|"
			"ipv6-frag|ipv6-tcp|ipv6-udp|ipv6-sctp|ipv6-other|l2_payload)"
			" (enable|disable)\n"
			"    Set the global configurations of hash filters.\n\n"

			"set_hash_input_set (port_id) (ipv4|ipv4-frag|"
			"ipv4-tcp|ipv4-udp|ipv4-sctp|ipv4-other|ipv6|"
			"ipv6-frag|ipv6-tcp|ipv6-udp|ipv6-sctp|ipv6-other|"
			"l2_payload|<flowtype_id>) (ovlan|ivlan|src-ipv4|dst-ipv4|"
			"src-ipv6|dst-ipv6|ipv4-tos|ipv4-proto|ipv6-tc|"
			"ipv6-next-header|udp-src-port|udp-dst-port|"
			"tcp-src-port|tcp-dst-port|sctp-src-port|"
			"sctp-dst-port|sctp-veri-tag|udp-key|gre-key|fld-1st|"
			"fld-2nd|fld-3rd|fld-4th|fld-5th|fld-6th|fld-7th|"
			"fld-8th|none) (select|add)\n"
			"    Set the input set for hash.\n\n"

			"set_fdir_input_set (port_id) "
			"(ipv4-frag|ipv4-tcp|ipv4-udp|ipv4-sctp|ipv4-other|"
			"ipv6-frag|ipv6-tcp|ipv6-udp|ipv6-sctp|ipv6-other|"
			"l2_payload) (ivlan|ethertype|src-ipv4|dst-ipv4|src-ipv6|"
			"dst-ipv6|ipv4-tos|ipv4-proto|ipv4-ttl|ipv6-tc|"
			"ipv6-next-header|ipv6-hop-limits|udp-src-port|"
			"udp-dst-port|tcp-src-port|tcp-dst-port|"
			"sctp-src-port|sctp-dst-port|sctp-veri-tag|none)"
			" (select|add)\n"
			"    Set the input set for FDir.\n\n"

			"flow validate {port_id}"
			" [group {group_id}] [priority {level}]"
			" [ingress] [egress]"
			" pattern {item} [/ {item} [...]] / end"
			" actions {action} [/ {action} [...]] / end\n"
			"    Check whether a flow rule can be created.\n\n"

			"flow create {port_id}"
			" [group {group_id}] [priority {level}]"
			" [ingress] [egress]"
			" pattern {item} [/ {item} [...]] / end"
			" actions {action} [/ {action} [...]] / end\n"
			"    Create a flow rule.\n\n"

			"flow destroy {port_id} rule {rule_id} [...]\n"
			"    Destroy specific flow rules.\n\n"

			"flow flush {port_id}\n"
			"    Destroy all flow rules.\n\n"

			"flow query {port_id} {rule_id} {action}\n"
			"    Query an existing flow rule.\n\n"

			"flow list {port_id} [group {group_id}] [...]\n"
			"    List existing flow rules sorted by priority,"
			" filtered by group identifiers.\n\n"

			"flow isolate {port_id} {boolean}\n"
			"    Restrict ingress traffic to the defined"
			" flow rules\n\n"
		);
	}

	if (show_all || !strcmp(res->section, "traffic_management")) {
		cmdline_printf(
			cl,
			"\n"
			"Traffic Management:\n"
			"--------------\n"
			"show port tm cap (port_id)\n"
			"       Display the port TM capability.\n\n"

			"show port tm level cap (port_id) (level_id)\n"
			"       Display the port TM hierarchical level capability.\n\n"

			"show port tm node cap (port_id) (node_id)\n"
			"       Display the port TM node capability.\n\n"

			"show port tm node type (port_id) (node_id)\n"
			"       Display the port TM node type.\n\n"

			"show port tm node stats (port_id) (node_id) (clear)\n"
			"       Display the port TM node stats.\n\n"

#if defined RTE_LIBRTE_PMD_SOFTNIC && defined RTE_LIBRTE_SCHED
			"set port tm hierarchy default (port_id)\n"
			"       Set default traffic Management hierarchy on a port\n\n"
#endif

			"add port tm node shaper profile (port_id) (shaper_profile_id)"
			" (cmit_tb_rate) (cmit_tb_size) (peak_tb_rate) (peak_tb_size)"
			" (packet_length_adjust)\n"
			"       Add port tm node private shaper profile.\n\n"

			"del port tm node shaper profile (port_id) (shaper_profile_id)\n"
			"       Delete port tm node private shaper profile.\n\n"

			"add port tm node shared shaper (port_id) (shared_shaper_id)"
			" (shaper_profile_id)\n"
			"       Add/update port tm node shared shaper.\n\n"

			"del port tm node shared shaper (port_id) (shared_shaper_id)\n"
			"       Delete port tm node shared shaper.\n\n"

			"set port tm node shaper profile (port_id) (node_id)"
			" (shaper_profile_id)\n"
			"       Set port tm node shaper profile.\n\n"

			"add port tm node wred profile (port_id) (wred_profile_id)"
			" (color_g) (min_th_g) (max_th_g) (maxp_inv_g) (wq_log2_g)"
			" (color_y) (min_th_y) (max_th_y) (maxp_inv_y) (wq_log2_y)"
			" (color_r) (min_th_r) (max_th_r) (maxp_inv_r) (wq_log2_r)\n"
			"       Add port tm node wred profile.\n\n"

			"del port tm node wred profile (port_id) (wred_profile_id)\n"
			"       Delete port tm node wred profile.\n\n"

			"add port tm nonleaf node (port_id) (node_id) (parent_node_id)"
			" (priority) (weight) (level_id) (shaper_profile_id)"
			" (n_sp_priorities) (stats_mask) (n_shared_shapers)"
			" [(shared_shaper_id_0) (shared_shaper_id_1)...]\n"
			"       Add port tm nonleaf node.\n\n"

			"add port tm leaf node (port_id) (node_id) (parent_node_id)"
			" (priority) (weight) (level_id) (shaper_profile_id)"
			" (cman_mode) (wred_profile_id) (stats_mask) (n_shared_shapers)"
			" [(shared_shaper_id_0) (shared_shaper_id_1)...]\n"
			"       Add port tm leaf node.\n\n"

			"del port tm node (port_id) (node_id)\n"
			"       Delete port tm node.\n\n"

			"set port tm node parent (port_id) (node_id) (parent_node_id)"
			" (priority) (weight)\n"
			"       Set port tm node parent.\n\n"

			"suspend port tm node (port_id) (node_id)"
			"       Suspend tm node.\n\n"

			"resume port tm node (port_id) (node_id)"
			"       Resume tm node.\n\n"

			"port tm hierarchy commit (port_id) (clean_on_fail)\n"
			"       Commit tm hierarchy.\n\n"

			"set port tm mark ip_ecn (port) (green) (yellow)"
			" (red)\n"
			"    Enables/Disables the traffic management marking"
			" for IP ECN (Explicit Congestion Notification)"
			" packets on a given port\n\n"

			"set port tm mark ip_dscp (port) (green) (yellow)"
			" (red)\n"
			"    Enables/Disables the traffic management marking"
			" on the port for IP dscp packets\n\n"

			"set port tm mark vlan_dei (port) (green) (yellow)"
			" (red)\n"
			"    Enables/Disables the traffic management marking"
			" on the port for VLAN packets with DEI enabled\n\n"
		);
	}

}

cmdline_parse_token_string_t cmd_help_long_help =
	TOKEN_STRING_INITIALIZER(struct cmd_help_long_result, help, "help");

cmdline_parse_token_string_t cmd_help_long_section =
	TOKEN_STRING_INITIALIZER(struct cmd_help_long_result, section,
			"all#control#display#config#"
			"ports#registers#filters#traffic_management");

cmdline_parse_inst_t cmd_help_long = {
	.f = cmd_help_long_parsed,
	.data = NULL,
	.help_str = "help all|control|display|config|ports|register|"
		"filters|traffic_management: "
		"Show help",
	.tokens = {
		(void *)&cmd_help_long_help,
		(void *)&cmd_help_long_section,
		NULL,
	},
};


/* *** start/stop/close all ports *** */
struct cmd_operate_port_result {
	cmdline_fixed_string_t keyword;
	cmdline_fixed_string_t name;
	cmdline_fixed_string_t value;
};

static void cmd_operate_port_parsed(void *parsed_result,
				__attribute__((unused)) struct cmdline *cl,
				__attribute__((unused)) void *data)
{
	struct cmd_operate_port_result *res = parsed_result;

	if (!strcmp(res->name, "start"))
		start_port(RTE_PORT_ALL);
	else if (!strcmp(res->name, "stop"))
		stop_port(RTE_PORT_ALL);
	else if (!strcmp(res->name, "close"))
		close_port(RTE_PORT_ALL);
	else if (!strcmp(res->name, "reset"))
		reset_port(RTE_PORT_ALL);
	else
		printf("Unknown parameter\n");
}

cmdline_parse_token_string_t cmd_operate_port_all_cmd =
	TOKEN_STRING_INITIALIZER(struct cmd_operate_port_result, keyword,
								"port");
cmdline_parse_token_string_t cmd_operate_port_all_port =
	TOKEN_STRING_INITIALIZER(struct cmd_operate_port_result, name,
						"start#stop#close#reset");
cmdline_parse_token_string_t cmd_operate_port_all_all =
	TOKEN_STRING_INITIALIZER(struct cmd_operate_port_result, value, "all");

cmdline_parse_inst_t cmd_operate_port = {
	.f = cmd_operate_port_parsed,
	.data = NULL,
	.help_str = "port start|stop|close all: Start/Stop/Close/Reset all ports",
	.tokens = {
		(void *)&cmd_operate_port_all_cmd,
		(void *)&cmd_operate_port_all_port,
		(void *)&cmd_operate_port_all_all,
		NULL,
	},
};

/* *** start/stop/close specific port *** */
struct cmd_operate_specific_port_result {
	cmdline_fixed_string_t keyword;
	cmdline_fixed_string_t name;
	uint8_t value;
};

static void cmd_operate_specific_port_parsed(void *parsed_result,
			__attribute__((unused)) struct cmdline *cl,
				__attribute__((unused)) void *data)
{
	struct cmd_operate_specific_port_result *res = parsed_result;

	if (!strcmp(res->name, "start"))
		start_port(res->value);
	else if (!strcmp(res->name, "stop"))
		stop_port(res->value);
	else if (!strcmp(res->name, "close"))
		close_port(res->value);
	else if (!strcmp(res->name, "reset"))
		reset_port(res->value);
	else
		printf("Unknown parameter\n");
}

cmdline_parse_token_string_t cmd_operate_specific_port_cmd =
	TOKEN_STRING_INITIALIZER(struct cmd_operate_specific_port_result,
							keyword, "port");
cmdline_parse_token_string_t cmd_operate_specific_port_port =
	TOKEN_STRING_INITIALIZER(struct cmd_operate_specific_port_result,
						name, "start#stop#close#reset");
cmdline_parse_token_num_t cmd_operate_specific_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_operate_specific_port_result,
							value, UINT8);

cmdline_parse_inst_t cmd_operate_specific_port = {
	.f = cmd_operate_specific_port_parsed,
	.data = NULL,
	.help_str = "port start|stop|close <port_id>: Start/Stop/Close/Reset port_id",
	.tokens = {
		(void *)&cmd_operate_specific_port_cmd,
		(void *)&cmd_operate_specific_port_port,
		(void *)&cmd_operate_specific_port_id,
		NULL,
	},
};

/* *** enable port setup (after attach) via iterator or event *** */
struct cmd_set_port_setup_on_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t setup;
	cmdline_fixed_string_t on;
	cmdline_fixed_string_t mode;
};

static void cmd_set_port_setup_on_parsed(void *parsed_result,
				__attribute__((unused)) struct cmdline *cl,
				__attribute__((unused)) void *data)
{
	struct cmd_set_port_setup_on_result *res = parsed_result;

	if (strcmp(res->mode, "event") == 0)
		setup_on_probe_event = true;
	else if (strcmp(res->mode, "iterator") == 0)
		setup_on_probe_event = false;
	else
		printf("Unknown mode\n");
}

cmdline_parse_token_string_t cmd_set_port_setup_on_set =
	TOKEN_STRING_INITIALIZER(struct cmd_set_port_setup_on_result,
			set, "set");
cmdline_parse_token_string_t cmd_set_port_setup_on_port =
	TOKEN_STRING_INITIALIZER(struct cmd_set_port_setup_on_result,
			port, "port");
cmdline_parse_token_string_t cmd_set_port_setup_on_setup =
	TOKEN_STRING_INITIALIZER(struct cmd_set_port_setup_on_result,
			setup, "setup");
cmdline_parse_token_string_t cmd_set_port_setup_on_on =
	TOKEN_STRING_INITIALIZER(struct cmd_set_port_setup_on_result,
			on, "on");
cmdline_parse_token_string_t cmd_set_port_setup_on_mode =
	TOKEN_STRING_INITIALIZER(struct cmd_set_port_setup_on_result,
			mode, "iterator#event");

cmdline_parse_inst_t cmd_set_port_setup_on = {
	.f = cmd_set_port_setup_on_parsed,
	.data = NULL,
	.help_str = "set port setup on iterator|event",
	.tokens = {
		(void *)&cmd_set_port_setup_on_set,
		(void *)&cmd_set_port_setup_on_port,
		(void *)&cmd_set_port_setup_on_setup,
		(void *)&cmd_set_port_setup_on_on,
		(void *)&cmd_set_port_setup_on_mode,
		NULL,
	},
};

/* *** attach a specified port *** */
struct cmd_operate_attach_port_result {
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t keyword;
	cmdline_fixed_string_t identifier;
};

static void cmd_operate_attach_port_parsed(void *parsed_result,
				__attribute__((unused)) struct cmdline *cl,
				__attribute__((unused)) void *data)
{
	struct cmd_operate_attach_port_result *res = parsed_result;

	if (!strcmp(res->keyword, "attach"))
		attach_port(res->identifier);
	else
		printf("Unknown parameter\n");
}

cmdline_parse_token_string_t cmd_operate_attach_port_port =
	TOKEN_STRING_INITIALIZER(struct cmd_operate_attach_port_result,
			port, "port");
cmdline_parse_token_string_t cmd_operate_attach_port_keyword =
	TOKEN_STRING_INITIALIZER(struct cmd_operate_attach_port_result,
			keyword, "attach");
cmdline_parse_token_string_t cmd_operate_attach_port_identifier =
	TOKEN_STRING_INITIALIZER(struct cmd_operate_attach_port_result,
			identifier, NULL);

cmdline_parse_inst_t cmd_operate_attach_port = {
	.f = cmd_operate_attach_port_parsed,
	.data = NULL,
	.help_str = "port attach <identifier>: "
		"(identifier: pci address or virtual dev name)",
	.tokens = {
		(void *)&cmd_operate_attach_port_port,
		(void *)&cmd_operate_attach_port_keyword,
		(void *)&cmd_operate_attach_port_identifier,
		NULL,
	},
};

/* *** detach a specified port *** */
struct cmd_operate_detach_port_result {
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t keyword;
	portid_t port_id;
};

static void cmd_operate_detach_port_parsed(void *parsed_result,
				__attribute__((unused)) struct cmdline *cl,
				__attribute__((unused)) void *data)
{
	struct cmd_operate_detach_port_result *res = parsed_result;

	if (!strcmp(res->keyword, "detach"))
		detach_port_device(res->port_id);
	else
		printf("Unknown parameter\n");
}

cmdline_parse_token_string_t cmd_operate_detach_port_port =
	TOKEN_STRING_INITIALIZER(struct cmd_operate_detach_port_result,
			port, "port");
cmdline_parse_token_string_t cmd_operate_detach_port_keyword =
	TOKEN_STRING_INITIALIZER(struct cmd_operate_detach_port_result,
			keyword, "detach");
cmdline_parse_token_num_t cmd_operate_detach_port_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_operate_detach_port_result,
			port_id, UINT16);

cmdline_parse_inst_t cmd_operate_detach_port = {
	.f = cmd_operate_detach_port_parsed,
	.data = NULL,
	.help_str = "port detach <port_id>",
	.tokens = {
		(void *)&cmd_operate_detach_port_port,
		(void *)&cmd_operate_detach_port_keyword,
		(void *)&cmd_operate_detach_port_port_id,
		NULL,
	},
};

/* *** configure speed for all ports *** */
struct cmd_config_speed_all {
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t keyword;
	cmdline_fixed_string_t all;
	cmdline_fixed_string_t item1;
	cmdline_fixed_string_t item2;
	cmdline_fixed_string_t value1;
	cmdline_fixed_string_t value2;
};

static int
parse_and_check_speed_duplex(char *speedstr, char *duplexstr, uint32_t *speed)
{

	int duplex;

	if (!strcmp(duplexstr, "half")) {
		duplex = ETH_LINK_HALF_DUPLEX;
	} else if (!strcmp(duplexstr, "full")) {
		duplex = ETH_LINK_FULL_DUPLEX;
	} else if (!strcmp(duplexstr, "auto")) {
		duplex = ETH_LINK_FULL_DUPLEX;
	} else {
		printf("Unknown duplex parameter\n");
		return -1;
	}

	if (!strcmp(speedstr, "10")) {
		*speed = (duplex == ETH_LINK_HALF_DUPLEX) ?
				ETH_LINK_SPEED_10M_HD : ETH_LINK_SPEED_10M;
	} else if (!strcmp(speedstr, "100")) {
		*speed = (duplex == ETH_LINK_HALF_DUPLEX) ?
				ETH_LINK_SPEED_100M_HD : ETH_LINK_SPEED_100M;
	} else {
		if (duplex != ETH_LINK_FULL_DUPLEX) {
			printf("Invalid speed/duplex parameters\n");
			return -1;
		}
		if (!strcmp(speedstr, "1000")) {
			*speed = ETH_LINK_SPEED_1G;
		} else if (!strcmp(speedstr, "10000")) {
			*speed = ETH_LINK_SPEED_10G;
		} else if (!strcmp(speedstr, "25000")) {
			*speed = ETH_LINK_SPEED_25G;
		} else if (!strcmp(speedstr, "40000")) {
			*speed = ETH_LINK_SPEED_40G;
		} else if (!strcmp(speedstr, "50000")) {
			*speed = ETH_LINK_SPEED_50G;
		} else if (!strcmp(speedstr, "100000")) {
			*speed = ETH_LINK_SPEED_100G;
		} else if (!strcmp(speedstr, "auto")) {
			*speed = ETH_LINK_SPEED_AUTONEG;
		} else {
			printf("Unknown speed parameter\n");
			return -1;
		}
	}

	return 0;
}

static void
cmd_config_speed_all_parsed(void *parsed_result,
			__attribute__((unused)) struct cmdline *cl,
			__attribute__((unused)) void *data)
{
	struct cmd_config_speed_all *res = parsed_result;
	uint32_t link_speed;
	portid_t pid;

	if (!all_ports_stopped()) {
		printf("Please stop all ports first\n");
		return;
	}

	if (parse_and_check_speed_duplex(res->value1, res->value2,
			&link_speed) < 0)
		return;

	RTE_ETH_FOREACH_DEV(pid) {
		ports[pid].dev_conf.link_speeds = link_speed;
	}

	cmd_reconfig_device_queue(RTE_PORT_ALL, 1, 1);
}

cmdline_parse_token_string_t cmd_config_speed_all_port =
	TOKEN_STRING_INITIALIZER(struct cmd_config_speed_all, port, "port");
cmdline_parse_token_string_t cmd_config_speed_all_keyword =
	TOKEN_STRING_INITIALIZER(struct cmd_config_speed_all, keyword,
							"config");
cmdline_parse_token_string_t cmd_config_speed_all_all =
	TOKEN_STRING_INITIALIZER(struct cmd_config_speed_all, all, "all");
cmdline_parse_token_string_t cmd_config_speed_all_item1 =
	TOKEN_STRING_INITIALIZER(struct cmd_config_speed_all, item1, "speed");
cmdline_parse_token_string_t cmd_config_speed_all_value1 =
	TOKEN_STRING_INITIALIZER(struct cmd_config_speed_all, value1,
				"10#100#1000#10000#25000#40000#50000#100000#auto");
cmdline_parse_token_string_t cmd_config_speed_all_item2 =
	TOKEN_STRING_INITIALIZER(struct cmd_config_speed_all, item2, "duplex");
cmdline_parse_token_string_t cmd_config_speed_all_value2 =
	TOKEN_STRING_INITIALIZER(struct cmd_config_speed_all, value2,
						"half#full#auto");

cmdline_parse_inst_t cmd_config_speed_all = {
	.f = cmd_config_speed_all_parsed,
	.data = NULL,
	.help_str = "port config all speed "
		"10|100|1000|10000|25000|40000|50000|100000|auto duplex "
							"half|full|auto",
	.tokens = {
		(void *)&cmd_config_speed_all_port,
		(void *)&cmd_config_speed_all_keyword,
		(void *)&cmd_config_speed_all_all,
		(void *)&cmd_config_speed_all_item1,
		(void *)&cmd_config_speed_all_value1,
		(void *)&cmd_config_speed_all_item2,
		(void *)&cmd_config_speed_all_value2,
		NULL,
	},
};

/* *** configure speed for specific port *** */
struct cmd_config_speed_specific {
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t keyword;
	portid_t id;
	cmdline_fixed_string_t item1;
	cmdline_fixed_string_t item2;
	cmdline_fixed_string_t value1;
	cmdline_fixed_string_t value2;
};

static void
cmd_config_speed_specific_parsed(void *parsed_result,
				__attribute__((unused)) struct cmdline *cl,
				__attribute__((unused)) void *data)
{
	struct cmd_config_speed_specific *res = parsed_result;
	uint32_t link_speed;

	if (!all_ports_stopped()) {
		printf("Please stop all ports first\n");
		return;
	}

	if (port_id_is_invalid(res->id, ENABLED_WARN))
		return;

	if (parse_and_check_speed_duplex(res->value1, res->value2,
			&link_speed) < 0)
		return;

	ports[res->id].dev_conf.link_speeds = link_speed;

	cmd_reconfig_device_queue(RTE_PORT_ALL, 1, 1);
}


cmdline_parse_token_string_t cmd_config_speed_specific_port =
	TOKEN_STRING_INITIALIZER(struct cmd_config_speed_specific, port,
								"port");
cmdline_parse_token_string_t cmd_config_speed_specific_keyword =
	TOKEN_STRING_INITIALIZER(struct cmd_config_speed_specific, keyword,
								"config");
cmdline_parse_token_num_t cmd_config_speed_specific_id =
	TOKEN_NUM_INITIALIZER(struct cmd_config_speed_specific, id, UINT16);
cmdline_parse_token_string_t cmd_config_speed_specific_item1 =
	TOKEN_STRING_INITIALIZER(struct cmd_config_speed_specific, item1,
								"speed");
cmdline_parse_token_string_t cmd_config_speed_specific_value1 =
	TOKEN_STRING_INITIALIZER(struct cmd_config_speed_specific, value1,
				"10#100#1000#10000#25000#40000#50000#100000#auto");
cmdline_parse_token_string_t cmd_config_speed_specific_item2 =
	TOKEN_STRING_INITIALIZER(struct cmd_config_speed_specific, item2,
								"duplex");
cmdline_parse_token_string_t cmd_config_speed_specific_value2 =
	TOKEN_STRING_INITIALIZER(struct cmd_config_speed_specific, value2,
							"half#full#auto");

cmdline_parse_inst_t cmd_config_speed_specific = {
	.f = cmd_config_speed_specific_parsed,
	.data = NULL,
	.help_str = "port config <port_id> speed "
		"10|100|1000|10000|25000|40000|50000|100000|auto duplex "
							"half|full|auto",
	.tokens = {
		(void *)&cmd_config_speed_specific_port,
		(void *)&cmd_config_speed_specific_keyword,
		(void *)&cmd_config_speed_specific_id,
		(void *)&cmd_config_speed_specific_item1,
		(void *)&cmd_config_speed_specific_value1,
		(void *)&cmd_config_speed_specific_item2,
		(void *)&cmd_config_speed_specific_value2,
		NULL,
	},
};

/* *** configure loopback for all ports *** */
struct cmd_config_loopback_all {
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t keyword;
	cmdline_fixed_string_t all;
	cmdline_fixed_string_t item;
	uint32_t mode;
};

static void
cmd_config_loopback_all_parsed(void *parsed_result,
			__attribute__((unused)) struct cmdline *cl,
			__attribute__((unused)) void *data)
{
	struct cmd_config_loopback_all *res = parsed_result;
	portid_t pid;

	if (!all_ports_stopped()) {
		printf("Please stop all ports first\n");
		return;
	}

	RTE_ETH_FOREACH_DEV(pid) {
		ports[pid].dev_conf.lpbk_mode = res->mode;
	}

	cmd_reconfig_device_queue(RTE_PORT_ALL, 1, 1);
}

cmdline_parse_token_string_t cmd_config_loopback_all_port =
	TOKEN_STRING_INITIALIZER(struct cmd_config_loopback_all, port, "port");
cmdline_parse_token_string_t cmd_config_loopback_all_keyword =
	TOKEN_STRING_INITIALIZER(struct cmd_config_loopback_all, keyword,
							"config");
cmdline_parse_token_string_t cmd_config_loopback_all_all =
	TOKEN_STRING_INITIALIZER(struct cmd_config_loopback_all, all, "all");
cmdline_parse_token_string_t cmd_config_loopback_all_item =
	TOKEN_STRING_INITIALIZER(struct cmd_config_loopback_all, item,
							"loopback");
cmdline_parse_token_num_t cmd_config_loopback_all_mode =
	TOKEN_NUM_INITIALIZER(struct cmd_config_loopback_all, mode, UINT32);

cmdline_parse_inst_t cmd_config_loopback_all = {
	.f = cmd_config_loopback_all_parsed,
	.data = NULL,
	.help_str = "port config all loopback <mode>",
	.tokens = {
		(void *)&cmd_config_loopback_all_port,
		(void *)&cmd_config_loopback_all_keyword,
		(void *)&cmd_config_loopback_all_all,
		(void *)&cmd_config_loopback_all_item,
		(void *)&cmd_config_loopback_all_mode,
		NULL,
	},
};

/* *** configure loopback for specific port *** */
struct cmd_config_loopback_specific {
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t keyword;
	uint16_t port_id;
	cmdline_fixed_string_t item;
	uint32_t mode;
};

static void
cmd_config_loopback_specific_parsed(void *parsed_result,
				__attribute__((unused)) struct cmdline *cl,
				__attribute__((unused)) void *data)
{
	struct cmd_config_loopback_specific *res = parsed_result;

	if (port_id_is_invalid(res->port_id, ENABLED_WARN))
		return;

	if (!port_is_stopped(res->port_id)) {
		printf("Please stop port %u first\n", res->port_id);
		return;
	}

	ports[res->port_id].dev_conf.lpbk_mode = res->mode;

	cmd_reconfig_device_queue(res->port_id, 1, 1);
}


cmdline_parse_token_string_t cmd_config_loopback_specific_port =
	TOKEN_STRING_INITIALIZER(struct cmd_config_loopback_specific, port,
								"port");
cmdline_parse_token_string_t cmd_config_loopback_specific_keyword =
	TOKEN_STRING_INITIALIZER(struct cmd_config_loopback_specific, keyword,
								"config");
cmdline_parse_token_num_t cmd_config_loopback_specific_id =
	TOKEN_NUM_INITIALIZER(struct cmd_config_loopback_specific, port_id,
								UINT16);
cmdline_parse_token_string_t cmd_config_loopback_specific_item =
	TOKEN_STRING_INITIALIZER(struct cmd_config_loopback_specific, item,
								"loopback");
cmdline_parse_token_num_t cmd_config_loopback_specific_mode =
	TOKEN_NUM_INITIALIZER(struct cmd_config_loopback_specific, mode,
			      UINT32);

cmdline_parse_inst_t cmd_config_loopback_specific = {
	.f = cmd_config_loopback_specific_parsed,
	.data = NULL,
	.help_str = "port config <port_id> loopback <mode>",
	.tokens = {
		(void *)&cmd_config_loopback_specific_port,
		(void *)&cmd_config_loopback_specific_keyword,
		(void *)&cmd_config_loopback_specific_id,
		(void *)&cmd_config_loopback_specific_item,
		(void *)&cmd_config_loopback_specific_mode,
		NULL,
	},
};

/* *** configure txq/rxq, txd/rxd *** */
struct cmd_config_rx_tx {
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t keyword;
	cmdline_fixed_string_t all;
	cmdline_fixed_string_t name;
	uint16_t value;
};

static void
cmd_config_rx_tx_parsed(void *parsed_result,
			__attribute__((unused)) struct cmdline *cl,
			__attribute__((unused)) void *data)
{
	struct cmd_config_rx_tx *res = parsed_result;

	if (!all_ports_stopped()) {
		printf("Please stop all ports first\n");
		return;
	}
	if (!strcmp(res->name, "rxq")) {
		if (!res->value && !nb_txq) {
			printf("Warning: Either rx or tx queues should be non zero\n");
			return;
		}
		if (check_nb_rxq(res->value) != 0)
			return;
		nb_rxq = res->value;
	}
	else if (!strcmp(res->name, "txq")) {
		if (!res->value && !nb_rxq) {
			printf("Warning: Either rx or tx queues should be non zero\n");
			return;
		}
		if (check_nb_txq(res->value) != 0)
			return;
		nb_txq = res->value;
	}
	else if (!strcmp(res->name, "rxd")) {
		if (res->value <= 0 || res->value > RTE_TEST_RX_DESC_MAX) {
			printf("rxd %d invalid - must be > 0 && <= %d\n",
					res->value, RTE_TEST_RX_DESC_MAX);
			return;
		}
		nb_rxd = res->value;
	} else if (!strcmp(res->name, "txd")) {
		if (res->value <= 0 || res->value > RTE_TEST_TX_DESC_MAX) {
			printf("txd %d invalid - must be > 0 && <= %d\n",
					res->value, RTE_TEST_TX_DESC_MAX);
			return;
		}
		nb_txd = res->value;
	} else {
		printf("Unknown parameter\n");
		return;
	}

	fwd_config_setup();

	init_port_config();

	cmd_reconfig_device_queue(RTE_PORT_ALL, 1, 1);
}

cmdline_parse_token_string_t cmd_config_rx_tx_port =
	TOKEN_STRING_INITIALIZER(struct cmd_config_rx_tx, port, "port");
cmdline_parse_token_string_t cmd_config_rx_tx_keyword =
	TOKEN_STRING_INITIALIZER(struct cmd_config_rx_tx, keyword, "config");
cmdline_parse_token_string_t cmd_config_rx_tx_all =
	TOKEN_STRING_INITIALIZER(struct cmd_config_rx_tx, all, "all");
cmdline_parse_token_string_t cmd_config_rx_tx_name =
	TOKEN_STRING_INITIALIZER(struct cmd_config_rx_tx, name,
						"rxq#txq#rxd#txd");
cmdline_parse_token_num_t cmd_config_rx_tx_value =
	TOKEN_NUM_INITIALIZER(struct cmd_config_rx_tx, value, UINT16);

cmdline_parse_inst_t cmd_config_rx_tx = {
	.f = cmd_config_rx_tx_parsed,
	.data = NULL,
	.help_str = "port config all rxq|txq|rxd|txd <value>",
	.tokens = {
		(void *)&cmd_config_rx_tx_port,
		(void *)&cmd_config_rx_tx_keyword,
		(void *)&cmd_config_rx_tx_all,
		(void *)&cmd_config_rx_tx_name,
		(void *)&cmd_config_rx_tx_value,
		NULL,
	},
};

/* *** config max packet length *** */
struct cmd_config_max_pkt_len_result {
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t keyword;
	cmdline_fixed_string_t all;
	cmdline_fixed_string_t name;
	uint32_t value;
};

static void
cmd_config_max_pkt_len_parsed(void *parsed_result,
				__attribute__((unused)) struct cmdline *cl,
				__attribute__((unused)) void *data)
{
	struct cmd_config_max_pkt_len_result *res = parsed_result;
	portid_t pid;

	if (!all_ports_stopped()) {
		printf("Please stop all ports first\n");
		return;
	}

	RTE_ETH_FOREACH_DEV(pid) {
		struct rte_port *port = &ports[pid];
		uint64_t rx_offloads = port->dev_conf.rxmode.offloads;

		if (!strcmp(res->name, "max-pkt-len")) {
			if (res->value < ETHER_MIN_LEN) {
				printf("max-pkt-len can not be less than %d\n",
						ETHER_MIN_LEN);
				return;
			}
			if (res->value == port->dev_conf.rxmode.max_rx_pkt_len)
				return;

			port->dev_conf.rxmode.max_rx_pkt_len = res->value;
			if (res->value > ETHER_MAX_LEN)
				rx_offloads |= DEV_RX_OFFLOAD_JUMBO_FRAME;
			else
				rx_offloads &= ~DEV_RX_OFFLOAD_JUMBO_FRAME;
			port->dev_conf.rxmode.offloads = rx_offloads;
		} else {
			printf("Unknown parameter\n");
			return;
		}
	}

	init_port_config();

	cmd_reconfig_device_queue(RTE_PORT_ALL, 1, 1);
}

cmdline_parse_token_string_t cmd_config_max_pkt_len_port =
	TOKEN_STRING_INITIALIZER(struct cmd_config_max_pkt_len_result, port,
								"port");
cmdline_parse_token_string_t cmd_config_max_pkt_len_keyword =
	TOKEN_STRING_INITIALIZER(struct cmd_config_max_pkt_len_result, keyword,
								"config");
cmdline_parse_token_string_t cmd_config_max_pkt_len_all =
	TOKEN_STRING_INITIALIZER(struct cmd_config_max_pkt_len_result, all,
								"all");
cmdline_parse_token_string_t cmd_config_max_pkt_len_name =
	TOKEN_STRING_INITIALIZER(struct cmd_config_max_pkt_len_result, name,
								"max-pkt-len");
cmdline_parse_token_num_t cmd_config_max_pkt_len_value =
	TOKEN_NUM_INITIALIZER(struct cmd_config_max_pkt_len_result, value,
								UINT32);

cmdline_parse_inst_t cmd_config_max_pkt_len = {
	.f = cmd_config_max_pkt_len_parsed,
	.data = NULL,
	.help_str = "port config all max-pkt-len <value>",
	.tokens = {
		(void *)&cmd_config_max_pkt_len_port,
		(void *)&cmd_config_max_pkt_len_keyword,
		(void *)&cmd_config_max_pkt_len_all,
		(void *)&cmd_config_max_pkt_len_name,
		(void *)&cmd_config_max_pkt_len_value,
		NULL,
	},
};

/* *** configure port MTU *** */
struct cmd_config_mtu_result {
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t keyword;
	cmdline_fixed_string_t mtu;
	portid_t port_id;
	uint16_t value;
};

static void
cmd_config_mtu_parsed(void *parsed_result,
		      __attribute__((unused)) struct cmdline *cl,
		      __attribute__((unused)) void *data)
{
	struct cmd_config_mtu_result *res = parsed_result;

	if (res->value < ETHER_MIN_LEN) {
		printf("mtu cannot be less than %d\n", ETHER_MIN_LEN);
		return;
	}
	port_mtu_set(res->port_id, res->value);
}

cmdline_parse_token_string_t cmd_config_mtu_port =
	TOKEN_STRING_INITIALIZER(struct cmd_config_mtu_result, port,
				 "port");
cmdline_parse_token_string_t cmd_config_mtu_keyword =
	TOKEN_STRING_INITIALIZER(struct cmd_config_mtu_result, keyword,
				 "config");
cmdline_parse_token_string_t cmd_config_mtu_mtu =
	TOKEN_STRING_INITIALIZER(struct cmd_config_mtu_result, keyword,
				 "mtu");
cmdline_parse_token_num_t cmd_config_mtu_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_config_mtu_result, port_id, UINT16);
cmdline_parse_token_num_t cmd_config_mtu_value =
	TOKEN_NUM_INITIALIZER(struct cmd_config_mtu_result, value, UINT16);

cmdline_parse_inst_t cmd_config_mtu = {
	.f = cmd_config_mtu_parsed,
	.data = NULL,
	.help_str = "port config mtu <port_id> <value>",
	.tokens = {
		(void *)&cmd_config_mtu_port,
		(void *)&cmd_config_mtu_keyword,
		(void *)&cmd_config_mtu_mtu,
		(void *)&cmd_config_mtu_port_id,
		(void *)&cmd_config_mtu_value,
		NULL,
	},
};

/* *** configure rx mode *** */
struct cmd_config_rx_mode_flag {
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t keyword;
	cmdline_fixed_string_t all;
	cmdline_fixed_string_t name;
	cmdline_fixed_string_t value;
};

static void
cmd_config_rx_mode_flag_parsed(void *parsed_result,
				__attribute__((unused)) struct cmdline *cl,
				__attribute__((unused)) void *data)
{
	struct cmd_config_rx_mode_flag *res = parsed_result;
	portid_t pid;
	int k;

	if (!all_ports_stopped()) {
		printf("Please stop all ports first\n");
		return;
	}

	RTE_ETH_FOREACH_DEV(pid) {
		struct rte_port *port;
		uint64_t rx_offloads;

		port = &ports[pid];
		rx_offloads = port->dev_conf.rxmode.offloads;
		if (!strcmp(res->name, "crc-strip")) {
			if (!strcmp(res->value, "on")) {
				rx_offloads &= ~DEV_RX_OFFLOAD_KEEP_CRC;
			} else if (!strcmp(res->value, "off")) {
				rx_offloads |= DEV_RX_OFFLOAD_KEEP_CRC;
			} else {
				printf("Unknown parameter\n");
				return;
			}
		} else if (!strcmp(res->name, "scatter")) {
			if (!strcmp(res->value, "on")) {
				rx_offloads |= DEV_RX_OFFLOAD_SCATTER;
			} else if (!strcmp(res->value, "off")) {
				rx_offloads &= ~DEV_RX_OFFLOAD_SCATTER;
			} else {
				printf("Unknown parameter\n");
				return;
			}
		} else if (!strcmp(res->name, "rx-cksum")) {
			if (!strcmp(res->value, "on"))
				rx_offloads |= DEV_RX_OFFLOAD_CHECKSUM;
			else if (!strcmp(res->value, "off"))
				rx_offloads &= ~DEV_RX_OFFLOAD_CHECKSUM;
			else {
				printf("Unknown parameter\n");
				return;
			}
		} else if (!strcmp(res->name, "rx-timestamp")) {
			if (!strcmp(res->value, "on"))
				rx_offloads |= DEV_RX_OFFLOAD_TIMESTAMP;
			else if (!strcmp(res->value, "off"))
				rx_offloads &= ~DEV_RX_OFFLOAD_TIMESTAMP;
			else {
				printf("Unknown parameter\n");
				return;
			}
		} else if (!strcmp(res->name, "hw-vlan")) {
			if (!strcmp(res->value, "on")) {
				rx_offloads |= (DEV_RX_OFFLOAD_VLAN_FILTER |
						DEV_RX_OFFLOAD_VLAN_STRIP);
			} else if (!strcmp(res->value, "off")) {
				rx_offloads &= ~(DEV_RX_OFFLOAD_VLAN_FILTER |
						DEV_RX_OFFLOAD_VLAN_STRIP);
			} else {
				printf("Unknown parameter\n");
				return;
			}
		} else if (!strcmp(res->name, "hw-vlan-filter")) {
			if (!strcmp(res->value, "on"))
				rx_offloads |= DEV_RX_OFFLOAD_VLAN_FILTER;
			else if (!strcmp(res->value, "off"))
				rx_offloads &= ~DEV_RX_OFFLOAD_VLAN_FILTER;
			else {
				printf("Unknown parameter\n");
				return;
			}
		} else if (!strcmp(res->name, "hw-vlan-strip")) {
			if (!strcmp(res->value, "on"))
				rx_offloads |= DEV_RX_OFFLOAD_VLAN_STRIP;
			else if (!strcmp(res->value, "off"))
				rx_offloads &= ~DEV_RX_OFFLOAD_VLAN_STRIP;
			else {
				printf("Unknown parameter\n");
				return;
			}
		} else if (!strcmp(res->name, "hw-vlan-extend")) {
			if (!strcmp(res->value, "on"))
				rx_offloads |= DEV_RX_OFFLOAD_VLAN_EXTEND;
			else if (!strcmp(res->value, "off"))
				rx_offloads &= ~DEV_RX_OFFLOAD_VLAN_EXTEND;
			else {
				printf("Unknown parameter\n");
				return;
			}
		} else if (!strcmp(res->name, "drop-en")) {
			if (!strcmp(res->value, "on"))
				rx_drop_en = 1;
			else if (!strcmp(res->value, "off"))
				rx_drop_en = 0;
			else {
				printf("Unknown parameter\n");
				return;
			}
		} else {
			printf("Unknown parameter\n");
			return;
		}
		port->dev_conf.rxmode.offloads = rx_offloads;
		/* Apply Rx offloads configuration */
		for (k = 0; k < port->dev_info.max_rx_queues; k++)
			port->rx_conf[k].offloads =
				port->dev_conf.rxmode.offloads;
	}

	init_port_config();

	cmd_reconfig_device_queue(RTE_PORT_ALL, 1, 1);
}

cmdline_parse_token_string_t cmd_config_rx_mode_flag_port =
	TOKEN_STRING_INITIALIZER(struct cmd_config_rx_mode_flag, port, "port");
cmdline_parse_token_string_t cmd_config_rx_mode_flag_keyword =
	TOKEN_STRING_INITIALIZER(struct cmd_config_rx_mode_flag, keyword,
								"config");
cmdline_parse_token_string_t cmd_config_rx_mode_flag_all =
	TOKEN_STRING_INITIALIZER(struct cmd_config_rx_mode_flag, all, "all");
cmdline_parse_token_string_t cmd_config_rx_mode_flag_name =
	TOKEN_STRING_INITIALIZER(struct cmd_config_rx_mode_flag, name,
					"crc-strip#scatter#rx-cksum#rx-timestamp#hw-vlan#"
					"hw-vlan-filter#hw-vlan-strip#hw-vlan-extend");
cmdline_parse_token_string_t cmd_config_rx_mode_flag_value =
	TOKEN_STRING_INITIALIZER(struct cmd_config_rx_mode_flag, value,
							"on#off");

cmdline_parse_inst_t cmd_config_rx_mode_flag = {
	.f = cmd_config_rx_mode_flag_parsed,
	.data = NULL,
	.help_str = "port config all crc-strip|scatter|rx-cksum|rx-timestamp|hw-vlan|"
		"hw-vlan-filter|hw-vlan-strip|hw-vlan-extend on|off",
	.tokens = {
		(void *)&cmd_config_rx_mode_flag_port,
		(void *)&cmd_config_rx_mode_flag_keyword,
		(void *)&cmd_config_rx_mode_flag_all,
		(void *)&cmd_config_rx_mode_flag_name,
		(void *)&cmd_config_rx_mode_flag_value,
		NULL,
	},
};

/* *** configure rss *** */
struct cmd_config_rss {
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t keyword;
	cmdline_fixed_string_t all;
	cmdline_fixed_string_t name;
	cmdline_fixed_string_t value;
};

static void
cmd_config_rss_parsed(void *parsed_result,
			__attribute__((unused)) struct cmdline *cl,
			__attribute__((unused)) void *data)
{
	struct cmd_config_rss *res = parsed_result;
	struct rte_eth_rss_conf rss_conf = { .rss_key_len = 0, };
	struct rte_eth_dev_info dev_info = { .flow_type_rss_offloads = 0, };
	int use_default = 0;
	int all_updated = 1;
	int diag;
	uint16_t i;

	if (!strcmp(res->value, "all"))
		rss_conf.rss_hf = ETH_RSS_IP | ETH_RSS_TCP |
				ETH_RSS_UDP | ETH_RSS_SCTP |
					ETH_RSS_L2_PAYLOAD;
	else if (!strcmp(res->value, "ip"))
		rss_conf.rss_hf = ETH_RSS_IP;
	else if (!strcmp(res->value, "udp"))
		rss_conf.rss_hf = ETH_RSS_UDP;
	else if (!strcmp(res->value, "tcp"))
		rss_conf.rss_hf = ETH_RSS_TCP;
	else if (!strcmp(res->value, "sctp"))
		rss_conf.rss_hf = ETH_RSS_SCTP;
	else if (!strcmp(res->value, "ether"))
		rss_conf.rss_hf = ETH_RSS_L2_PAYLOAD;
	else if (!strcmp(res->value, "port"))
		rss_conf.rss_hf = ETH_RSS_PORT;
	else if (!strcmp(res->value, "vxlan"))
		rss_conf.rss_hf = ETH_RSS_VXLAN;
	else if (!strcmp(res->value, "geneve"))
		rss_conf.rss_hf = ETH_RSS_GENEVE;
	else if (!strcmp(res->value, "nvgre"))
		rss_conf.rss_hf = ETH_RSS_NVGRE;
	else if (!strcmp(res->value, "none"))
		rss_conf.rss_hf = 0;
	else if (!strcmp(res->value, "default"))
		use_default = 1;
	else if (isdigit(res->value[0]) && atoi(res->value) > 0 &&
						atoi(res->value) < 64)
		rss_conf.rss_hf = 1ULL << atoi(res->value);
	else {
		printf("Unknown parameter\n");
		return;
	}
	rss_conf.rss_key = NULL;
	/* Update global configuration for RSS types. */
	RTE_ETH_FOREACH_DEV(i) {
		struct rte_eth_rss_conf local_rss_conf;

		rte_eth_dev_info_get(i, &dev_info);
		if (use_default)
			rss_conf.rss_hf = dev_info.flow_type_rss_offloads;

		local_rss_conf = rss_conf;
		local_rss_conf.rss_hf = rss_conf.rss_hf &
			dev_info.flow_type_rss_offloads;
		if (local_rss_conf.rss_hf != rss_conf.rss_hf) {
			printf("Port %u modified RSS hash function based on hardware support,"
				"requested:%#"PRIx64" configured:%#"PRIx64"\n",
				i, rss_conf.rss_hf, local_rss_conf.rss_hf);
		}
		diag = rte_eth_dev_rss_hash_update(i, &local_rss_conf);
		if (diag < 0) {
			all_updated = 0;
			printf("Configuration of RSS hash at ethernet port %d "
				"failed with error (%d): %s.\n",
				i, -diag, strerror(-diag));
		}
	}
	if (all_updated && !use_default)
		rss_hf = rss_conf.rss_hf;
}

cmdline_parse_token_string_t cmd_config_rss_port =
	TOKEN_STRING_INITIALIZER(struct cmd_config_rss, port, "port");
cmdline_parse_token_string_t cmd_config_rss_keyword =
	TOKEN_STRING_INITIALIZER(struct cmd_config_rss, keyword, "config");
cmdline_parse_token_string_t cmd_config_rss_all =
	TOKEN_STRING_INITIALIZER(struct cmd_config_rss, all, "all");
cmdline_parse_token_string_t cmd_config_rss_name =
	TOKEN_STRING_INITIALIZER(struct cmd_config_rss, name, "rss");
cmdline_parse_token_string_t cmd_config_rss_value =
	TOKEN_STRING_INITIALIZER(struct cmd_config_rss, value, NULL);

cmdline_parse_inst_t cmd_config_rss = {
	.f = cmd_config_rss_parsed,
	.data = NULL,
	.help_str = "port config all rss "
		"all|default|ip|tcp|udp|sctp|ether|port|vxlan|geneve|nvgre|none|<flowtype_id>",
	.tokens = {
		(void *)&cmd_config_rss_port,
		(void *)&cmd_config_rss_keyword,
		(void *)&cmd_config_rss_all,
		(void *)&cmd_config_rss_name,
		(void *)&cmd_config_rss_value,
		NULL,
	},
};

/* *** configure rss hash key *** */
struct cmd_config_rss_hash_key {
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t config;
	portid_t port_id;
	cmdline_fixed_string_t rss_hash_key;
	cmdline_fixed_string_t rss_type;
	cmdline_fixed_string_t key;
};

static uint8_t
hexa_digit_to_value(char hexa_digit)
{
	if ((hexa_digit >= '0') && (hexa_digit <= '9'))
		return (uint8_t) (hexa_digit - '0');
	if ((hexa_digit >= 'a') && (hexa_digit <= 'f'))
		return (uint8_t) ((hexa_digit - 'a') + 10);
	if ((hexa_digit >= 'A') && (hexa_digit <= 'F'))
		return (uint8_t) ((hexa_digit - 'A') + 10);
	/* Invalid hexa digit */
	return 0xFF;
}

static uint8_t
parse_and_check_key_hexa_digit(char *key, int idx)
{
	uint8_t hexa_v;

	hexa_v = hexa_digit_to_value(key[idx]);
	if (hexa_v == 0xFF)
		printf("invalid key: character %c at position %d is not a "
		       "valid hexa digit\n", key[idx], idx);
	return hexa_v;
}

static void
cmd_config_rss_hash_key_parsed(void *parsed_result,
			       __attribute__((unused)) struct cmdline *cl,
			       __attribute__((unused)) void *data)
{
	struct cmd_config_rss_hash_key *res = parsed_result;
	uint8_t hash_key[RSS_HASH_KEY_LENGTH];
	uint8_t xdgt0;
	uint8_t xdgt1;
	int i;
	struct rte_eth_dev_info dev_info;
	uint8_t hash_key_size;
	uint32_t key_len;

	memset(&dev_info, 0, sizeof(dev_info));
	rte_eth_dev_info_get(res->port_id, &dev_info);
	if (dev_info.hash_key_size > 0 &&
			dev_info.hash_key_size <= sizeof(hash_key))
		hash_key_size = dev_info.hash_key_size;
	else {
		printf("dev_info did not provide a valid hash key size\n");
		return;
	}
	/* Check the length of the RSS hash key */
	key_len = strlen(res->key);
	if (key_len != (hash_key_size * 2)) {
		printf("key length: %d invalid - key must be a string of %d"
			   " hexa-decimal numbers\n",
			   (int) key_len, hash_key_size * 2);
		return;
	}
	/* Translate RSS hash key into binary representation */
	for (i = 0; i < hash_key_size; i++) {
		xdgt0 = parse_and_check_key_hexa_digit(res->key, (i * 2));
		if (xdgt0 == 0xFF)
			return;
		xdgt1 = parse_and_check_key_hexa_digit(res->key, (i * 2) + 1);
		if (xdgt1 == 0xFF)
			return;
		hash_key[i] = (uint8_t) ((xdgt0 * 16) + xdgt1);
	}
	port_rss_hash_key_update(res->port_id, res->rss_type, hash_key,
			hash_key_size);
}

cmdline_parse_token_string_t cmd_config_rss_hash_key_port =
	TOKEN_STRING_INITIALIZER(struct cmd_config_rss_hash_key, port, "port");
cmdline_parse_token_string_t cmd_config_rss_hash_key_config =
	TOKEN_STRING_INITIALIZER(struct cmd_config_rss_hash_key, config,
				 "config");
cmdline_parse_token_num_t cmd_config_rss_hash_key_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_config_rss_hash_key, port_id, UINT16);
cmdline_parse_token_string_t cmd_config_rss_hash_key_rss_hash_key =
	TOKEN_STRING_INITIALIZER(struct cmd_config_rss_hash_key,
				 rss_hash_key, "rss-hash-key");
cmdline_parse_token_string_t cmd_config_rss_hash_key_rss_type =
	TOKEN_STRING_INITIALIZER(struct cmd_config_rss_hash_key, rss_type,
				 "ipv4#ipv4-frag#ipv4-tcp#ipv4-udp#ipv4-sctp#"
				 "ipv4-other#ipv6#ipv6-frag#ipv6-tcp#ipv6-udp#"
				 "ipv6-sctp#ipv6-other#l2-payload#ipv6-ex#"
				 "ipv6-tcp-ex#ipv6-udp-ex");
cmdline_parse_token_string_t cmd_config_rss_hash_key_value =
	TOKEN_STRING_INITIALIZER(struct cmd_config_rss_hash_key, key, NULL);

cmdline_parse_inst_t cmd_config_rss_hash_key = {
	.f = cmd_config_rss_hash_key_parsed,
	.data = NULL,
	.help_str = "port config <port_id> rss-hash-key "
		"ipv4|ipv4-frag|ipv4-tcp|ipv4-udp|ipv4-sctp|ipv4-other|"
		"ipv6|ipv6-frag|ipv6-tcp|ipv6-udp|ipv6-sctp|ipv6-other|"
		"l2-payload|ipv6-ex|ipv6-tcp-ex|ipv6-udp-ex "
		"<string of hex digits (variable length, NIC dependent)>",
	.tokens = {
		(void *)&cmd_config_rss_hash_key_port,
		(void *)&cmd_config_rss_hash_key_config,
		(void *)&cmd_config_rss_hash_key_port_id,
		(void *)&cmd_config_rss_hash_key_rss_hash_key,
		(void *)&cmd_config_rss_hash_key_rss_type,
		(void *)&cmd_config_rss_hash_key_value,
		NULL,
	},
};

/* *** configure port rxq/txq ring size *** */
struct cmd_config_rxtx_ring_size {
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t config;
	portid_t portid;
	cmdline_fixed_string_t rxtxq;
	uint16_t qid;
	cmdline_fixed_string_t rsize;
	uint16_t size;
};

static void
cmd_config_rxtx_ring_size_parsed(void *parsed_result,
				 __attribute__((unused)) struct cmdline *cl,
				 __attribute__((unused)) void *data)
{
	struct cmd_config_rxtx_ring_size *res = parsed_result;
	struct rte_port *port;
	uint8_t isrx;

	if (port_id_is_invalid(res->portid, ENABLED_WARN))
		return;

	if (res->portid == (portid_t)RTE_PORT_ALL) {
		printf("Invalid port id\n");
		return;
	}

	port = &ports[res->portid];

	if (!strcmp(res->rxtxq, "rxq"))
		isrx = 1;
	else if (!strcmp(res->rxtxq, "txq"))
		isrx = 0;
	else {
		printf("Unknown parameter\n");
		return;
	}

	if (isrx && rx_queue_id_is_invalid(res->qid))
		return;
	else if (!isrx && tx_queue_id_is_invalid(res->qid))
		return;

	if (isrx && res->size != 0 && res->size <= rx_free_thresh) {
		printf("Invalid rx ring_size, must > rx_free_thresh: %d\n",
		       rx_free_thresh);
		return;
	}

	if (isrx)
		port->nb_rx_desc[res->qid] = res->size;
	else
		port->nb_tx_desc[res->qid] = res->size;

	cmd_reconfig_device_queue(res->portid, 0, 1);
}

cmdline_parse_token_string_t cmd_config_rxtx_ring_size_port =
	TOKEN_STRING_INITIALIZER(struct cmd_config_rxtx_ring_size,
				 port, "port");
cmdline_parse_token_string_t cmd_config_rxtx_ring_size_config =
	TOKEN_STRING_INITIALIZER(struct cmd_config_rxtx_ring_size,
				 config, "config");
cmdline_parse_token_num_t cmd_config_rxtx_ring_size_portid =
	TOKEN_NUM_INITIALIZER(struct cmd_config_rxtx_ring_size,
				 portid, UINT16);
cmdline_parse_token_string_t cmd_config_rxtx_ring_size_rxtxq =
	TOKEN_STRING_INITIALIZER(struct cmd_config_rxtx_ring_size,
				 rxtxq, "rxq#txq");
cmdline_parse_token_num_t cmd_config_rxtx_ring_size_qid =
	TOKEN_NUM_INITIALIZER(struct cmd_config_rxtx_ring_size,
			      qid, UINT16);
cmdline_parse_token_string_t cmd_config_rxtx_ring_size_rsize =
	TOKEN_STRING_INITIALIZER(struct cmd_config_rxtx_ring_size,
				 rsize, "ring_size");
cmdline_parse_token_num_t cmd_config_rxtx_ring_size_size =
	TOKEN_NUM_INITIALIZER(struct cmd_config_rxtx_ring_size,
			      size, UINT16);

cmdline_parse_inst_t cmd_config_rxtx_ring_size = {
	.f = cmd_config_rxtx_ring_size_parsed,
	.data = NULL,
	.help_str = "port config <port_id> rxq|txq <queue_id> ring_size <value>",
	.tokens = {
		(void *)&cmd_config_rxtx_ring_size_port,
		(void *)&cmd_config_rxtx_ring_size_config,
		(void *)&cmd_config_rxtx_ring_size_portid,
		(void *)&cmd_config_rxtx_ring_size_rxtxq,
		(void *)&cmd_config_rxtx_ring_size_qid,
		(void *)&cmd_config_rxtx_ring_size_rsize,
		(void *)&cmd_config_rxtx_ring_size_size,
		NULL,
	},
};

/* *** configure port rxq/txq start/stop *** */
struct cmd_config_rxtx_queue {
	cmdline_fixed_string_t port;
	portid_t portid;
	cmdline_fixed_string_t rxtxq;
	uint16_t qid;
	cmdline_fixed_string_t opname;
};

static void
cmd_config_rxtx_queue_parsed(void *parsed_result,
			__attribute__((unused)) struct cmdline *cl,
			__attribute__((unused)) void *data)
{
	struct cmd_config_rxtx_queue *res = parsed_result;
	uint8_t isrx;
	uint8_t isstart;
	int ret = 0;

	if (test_done == 0) {
		printf("Please stop forwarding first\n");
		return;
	}

	if (port_id_is_invalid(res->portid, ENABLED_WARN))
		return;

	if (port_is_started(res->portid) != 1) {
		printf("Please start port %u first\n", res->portid);
		return;
	}

	if (!strcmp(res->rxtxq, "rxq"))
		isrx = 1;
	else if (!strcmp(res->rxtxq, "txq"))
		isrx = 0;
	else {
		printf("Unknown parameter\n");
		return;
	}

	if (isrx && rx_queue_id_is_invalid(res->qid))
		return;
	else if (!isrx && tx_queue_id_is_invalid(res->qid))
		return;

	if (!strcmp(res->opname, "start"))
		isstart = 1;
	else if (!strcmp(res->opname, "stop"))
		isstart = 0;
	else {
		printf("Unknown parameter\n");
		return;
	}

	if (isstart && isrx)
		ret = rte_eth_dev_rx_queue_start(res->portid, res->qid);
	else if (!isstart && isrx)
		ret = rte_eth_dev_rx_queue_stop(res->portid, res->qid);
	else if (isstart && !isrx)
		ret = rte_eth_dev_tx_queue_start(res->portid, res->qid);
	else
		ret = rte_eth_dev_tx_queue_stop(res->portid, res->qid);

	if (ret == -ENOTSUP)
		printf("Function not supported in PMD driver\n");
}

cmdline_parse_token_string_t cmd_config_rxtx_queue_port =
	TOKEN_STRING_INITIALIZER(struct cmd_config_rxtx_queue, port, "port");
cmdline_parse_token_num_t cmd_config_rxtx_queue_portid =
	TOKEN_NUM_INITIALIZER(struct cmd_config_rxtx_queue, portid, UINT16);
cmdline_parse_token_string_t cmd_config_rxtx_queue_rxtxq =
	TOKEN_STRING_INITIALIZER(struct cmd_config_rxtx_queue, rxtxq, "rxq#txq");
cmdline_parse_token_num_t cmd_config_rxtx_queue_qid =
	TOKEN_NUM_INITIALIZER(struct cmd_config_rxtx_queue, qid, UINT16);
cmdline_parse_token_string_t cmd_config_rxtx_queue_opname =
	TOKEN_STRING_INITIALIZER(struct cmd_config_rxtx_queue, opname,
						"start#stop");

cmdline_parse_inst_t cmd_config_rxtx_queue = {
	.f = cmd_config_rxtx_queue_parsed,
	.data = NULL,
	.help_str = "port <port_id> rxq|txq <queue_id> start|stop",
	.tokens = {
		(void *)&cmd_config_rxtx_queue_port,
		(void *)&cmd_config_rxtx_queue_portid,
		(void *)&cmd_config_rxtx_queue_rxtxq,
		(void *)&cmd_config_rxtx_queue_qid,
		(void *)&cmd_config_rxtx_queue_opname,
		NULL,
	},
};

/* *** configure port rxq/txq deferred start on/off *** */
struct cmd_config_deferred_start_rxtx_queue {
	cmdline_fixed_string_t port;
	portid_t port_id;
	cmdline_fixed_string_t rxtxq;
	uint16_t qid;
	cmdline_fixed_string_t opname;
	cmdline_fixed_string_t state;
};

static void
cmd_config_deferred_start_rxtx_queue_parsed(void *parsed_result,
			__attribute__((unused)) struct cmdline *cl,
			__attribute__((unused)) void *data)
{
	struct cmd_config_deferred_start_rxtx_queue *res = parsed_result;
	struct rte_port *port;
	uint8_t isrx;
	uint8_t ison;
	uint8_t needreconfig = 0;

	if (port_id_is_invalid(res->port_id, ENABLED_WARN))
		return;

	if (port_is_started(res->port_id) != 0) {
		printf("Please stop port %u first\n", res->port_id);
		return;
	}

	port = &ports[res->port_id];

	isrx = !strcmp(res->rxtxq, "rxq");

	if (isrx && rx_queue_id_is_invalid(res->qid))
		return;
	else if (!isrx && tx_queue_id_is_invalid(res->qid))
		return;

	ison = !strcmp(res->state, "on");

	if (isrx && port->rx_conf[res->qid].rx_deferred_start != ison) {
		port->rx_conf[res->qid].rx_deferred_start = ison;
		needreconfig = 1;
	} else if (!isrx && port->tx_conf[res->qid].tx_deferred_start != ison) {
		port->tx_conf[res->qid].tx_deferred_start = ison;
		needreconfig = 1;
	}

	if (needreconfig)
		cmd_reconfig_device_queue(res->port_id, 0, 1);
}

cmdline_parse_token_string_t cmd_config_deferred_start_rxtx_queue_port =
	TOKEN_STRING_INITIALIZER(struct cmd_config_deferred_start_rxtx_queue,
						port, "port");
cmdline_parse_token_num_t cmd_config_deferred_start_rxtx_queue_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_config_deferred_start_rxtx_queue,
						port_id, UINT16);
cmdline_parse_token_string_t cmd_config_deferred_start_rxtx_queue_rxtxq =
	TOKEN_STRING_INITIALIZER(struct cmd_config_deferred_start_rxtx_queue,
						rxtxq, "rxq#txq");
cmdline_parse_token_num_t cmd_config_deferred_start_rxtx_queue_qid =
	TOKEN_NUM_INITIALIZER(struct cmd_config_deferred_start_rxtx_queue,
						qid, UINT16);
cmdline_parse_token_string_t cmd_config_deferred_start_rxtx_queue_opname =
	TOKEN_STRING_INITIALIZER(struct cmd_config_deferred_start_rxtx_queue,
						opname, "deferred_start");
cmdline_parse_token_string_t cmd_config_deferred_start_rxtx_queue_state =
	TOKEN_STRING_INITIALIZER(struct cmd_config_deferred_start_rxtx_queue,
						state, "on#off");

cmdline_parse_inst_t cmd_config_deferred_start_rxtx_queue = {
	.f = cmd_config_deferred_start_rxtx_queue_parsed,
	.data = NULL,
	.help_str = "port <port_id> rxq|txq <queue_id> deferred_start on|off",
	.tokens = {
		(void *)&cmd_config_deferred_start_rxtx_queue_port,
		(void *)&cmd_config_deferred_start_rxtx_queue_port_id,
		(void *)&cmd_config_deferred_start_rxtx_queue_rxtxq,
		(void *)&cmd_config_deferred_start_rxtx_queue_qid,
		(void *)&cmd_config_deferred_start_rxtx_queue_opname,
		(void *)&cmd_config_deferred_start_rxtx_queue_state,
		NULL,
	},
};

/* *** configure port rxq/txq setup *** */
struct cmd_setup_rxtx_queue {
	cmdline_fixed_string_t port;
	portid_t portid;
	cmdline_fixed_string_t rxtxq;
	uint16_t qid;
	cmdline_fixed_string_t setup;
};

/* Common CLI fields for queue setup */
cmdline_parse_token_string_t cmd_setup_rxtx_queue_port =
	TOKEN_STRING_INITIALIZER(struct cmd_setup_rxtx_queue, port, "port");
cmdline_parse_token_num_t cmd_setup_rxtx_queue_portid =
	TOKEN_NUM_INITIALIZER(struct cmd_setup_rxtx_queue, portid, UINT16);
cmdline_parse_token_string_t cmd_setup_rxtx_queue_rxtxq =
	TOKEN_STRING_INITIALIZER(struct cmd_setup_rxtx_queue, rxtxq, "rxq#txq");
cmdline_parse_token_num_t cmd_setup_rxtx_queue_qid =
	TOKEN_NUM_INITIALIZER(struct cmd_setup_rxtx_queue, qid, UINT16);
cmdline_parse_token_string_t cmd_setup_rxtx_queue_setup =
	TOKEN_STRING_INITIALIZER(struct cmd_setup_rxtx_queue, setup, "setup");

static void
cmd_setup_rxtx_queue_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_setup_rxtx_queue *res = parsed_result;
	struct rte_port *port;
	struct rte_mempool *mp;
	unsigned int socket_id;
	uint8_t isrx = 0;
	int ret;

	if (port_id_is_invalid(res->portid, ENABLED_WARN))
		return;

	if (res->portid == (portid_t)RTE_PORT_ALL) {
		printf("Invalid port id\n");
		return;
	}

	if (!strcmp(res->rxtxq, "rxq"))
		isrx = 1;
	else if (!strcmp(res->rxtxq, "txq"))
		isrx = 0;
	else {
		printf("Unknown parameter\n");
		return;
	}

	if (isrx && rx_queue_id_is_invalid(res->qid)) {
		printf("Invalid rx queue\n");
		return;
	} else if (!isrx && tx_queue_id_is_invalid(res->qid)) {
		printf("Invalid tx queue\n");
		return;
	}

	port = &ports[res->portid];
	if (isrx) {
		socket_id = rxring_numa[res->portid];
		if (!numa_support || socket_id == NUMA_NO_CONFIG)
			socket_id = port->socket_id;

		mp = mbuf_pool_find(socket_id);
		if (mp == NULL) {
			printf("Failed to setup RX queue: "
				"No mempool allocation"
				" on the socket %d\n",
				rxring_numa[res->portid]);
			return;
		}
		ret = rte_eth_rx_queue_setup(res->portid,
					     res->qid,
					     port->nb_rx_desc[res->qid],
					     socket_id,
					     &port->rx_conf[res->qid],
					     mp);
		if (ret)
			printf("Failed to setup RX queue\n");
	} else {
		socket_id = txring_numa[res->portid];
		if (!numa_support || socket_id == NUMA_NO_CONFIG)
			socket_id = port->socket_id;

		ret = rte_eth_tx_queue_setup(res->portid,
					     res->qid,
					     port->nb_tx_desc[res->qid],
					     socket_id,
					     &port->tx_conf[res->qid]);
		if (ret)
			printf("Failed to setup TX queue\n");
	}
}

cmdline_parse_inst_t cmd_setup_rxtx_queue = {
	.f = cmd_setup_rxtx_queue_parsed,
	.data = NULL,
	.help_str = "port <port_id> rxq|txq <queue_idx> setup",
	.tokens = {
		(void *)&cmd_setup_rxtx_queue_port,
		(void *)&cmd_setup_rxtx_queue_portid,
		(void *)&cmd_setup_rxtx_queue_rxtxq,
		(void *)&cmd_setup_rxtx_queue_qid,
		(void *)&cmd_setup_rxtx_queue_setup,
		NULL,
	},
};


/* *** Configure RSS RETA *** */
struct cmd_config_rss_reta {
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t keyword;
	portid_t port_id;
	cmdline_fixed_string_t name;
	cmdline_fixed_string_t list_name;
	cmdline_fixed_string_t list_of_items;
};

static int
parse_reta_config(const char *str,
		  struct rte_eth_rss_reta_entry64 *reta_conf,
		  uint16_t nb_entries)
{
	int i;
	unsigned size;
	uint16_t hash_index, idx, shift;
	uint16_t nb_queue;
	char s[256];
	const char *p, *p0 = str;
	char *end;
	enum fieldnames {
		FLD_HASH_INDEX = 0,
		FLD_QUEUE,
		_NUM_FLD
	};
	unsigned long int_fld[_NUM_FLD];
	char *str_fld[_NUM_FLD];

	while ((p = strchr(p0,'(')) != NULL) {
		++p;
		if((p0 = strchr(p,')')) == NULL)
			return -1;

		size = p0 - p;
		if(size >= sizeof(s))
			return -1;

		snprintf(s, sizeof(s), "%.*s", size, p);
		if (rte_strsplit(s, sizeof(s), str_fld, _NUM_FLD, ',') != _NUM_FLD)
			return -1;
		for (i = 0; i < _NUM_FLD; i++) {
			errno = 0;
			int_fld[i] = strtoul(str_fld[i], &end, 0);
			if (errno != 0 || end == str_fld[i] ||
					int_fld[i] > 65535)
				return -1;
		}

		hash_index = (uint16_t)int_fld[FLD_HASH_INDEX];
		nb_queue = (uint16_t)int_fld[FLD_QUEUE];

		if (hash_index >= nb_entries) {
			printf("Invalid RETA hash index=%d\n", hash_index);
			return -1;
		}

		idx = hash_index / RTE_RETA_GROUP_SIZE;
		shift = hash_index % RTE_RETA_GROUP_SIZE;
		reta_conf[idx].mask |= (1ULL << shift);
		reta_conf[idx].reta[shift] = nb_queue;
	}

	return 0;
}

static void
cmd_set_rss_reta_parsed(void *parsed_result,
			__attribute__((unused)) struct cmdline *cl,
			__attribute__((unused)) void *data)
{
	int ret;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_rss_reta_entry64 reta_conf[8];
	struct cmd_config_rss_reta *res = parsed_result;

	memset(&dev_info, 0, sizeof(dev_info));
	rte_eth_dev_info_get(res->port_id, &dev_info);
	if (dev_info.reta_size == 0) {
		printf("Redirection table size is 0 which is "
					"invalid for RSS\n");
		return;
	} else
		printf("The reta size of port %d is %u\n",
			res->port_id, dev_info.reta_size);
	if (dev_info.reta_size > ETH_RSS_RETA_SIZE_512) {
		printf("Currently do not support more than %u entries of "
			"redirection table\n", ETH_RSS_RETA_SIZE_512);
		return;
	}

	memset(reta_conf, 0, sizeof(reta_conf));
	if (!strcmp(res->list_name, "reta")) {
		if (parse_reta_config(res->list_of_items, reta_conf,
						dev_info.reta_size)) {
			printf("Invalid RSS Redirection Table "
					"config entered\n");
			return;
		}
		ret = rte_eth_dev_rss_reta_update(res->port_id,
				reta_conf, dev_info.reta_size);
		if (ret != 0)
			printf("Bad redirection table parameter, "
					"return code = %d \n", ret);
	}
}

cmdline_parse_token_string_t cmd_config_rss_reta_port =
	TOKEN_STRING_INITIALIZER(struct cmd_config_rss_reta, port, "port");
cmdline_parse_token_string_t cmd_config_rss_reta_keyword =
	TOKEN_STRING_INITIALIZER(struct cmd_config_rss_reta, keyword, "config");
cmdline_parse_token_num_t cmd_config_rss_reta_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_config_rss_reta, port_id, UINT16);
cmdline_parse_token_string_t cmd_config_rss_reta_name =
	TOKEN_STRING_INITIALIZER(struct cmd_config_rss_reta, name, "rss");
cmdline_parse_token_string_t cmd_config_rss_reta_list_name =
	TOKEN_STRING_INITIALIZER(struct cmd_config_rss_reta, list_name, "reta");
cmdline_parse_token_string_t cmd_config_rss_reta_list_of_items =
        TOKEN_STRING_INITIALIZER(struct cmd_config_rss_reta, list_of_items,
                                 NULL);
cmdline_parse_inst_t cmd_config_rss_reta = {
	.f = cmd_set_rss_reta_parsed,
	.data = NULL,
	.help_str = "port config <port_id> rss reta <hash,queue[,hash,queue]*>",
	.tokens = {
		(void *)&cmd_config_rss_reta_port,
		(void *)&cmd_config_rss_reta_keyword,
		(void *)&cmd_config_rss_reta_port_id,
		(void *)&cmd_config_rss_reta_name,
		(void *)&cmd_config_rss_reta_list_name,
		(void *)&cmd_config_rss_reta_list_of_items,
		NULL,
	},
};

/* *** SHOW PORT RETA INFO *** */
struct cmd_showport_reta {
	cmdline_fixed_string_t show;
	cmdline_fixed_string_t port;
	portid_t port_id;
	cmdline_fixed_string_t rss;
	cmdline_fixed_string_t reta;
	uint16_t size;
	cmdline_fixed_string_t list_of_items;
};

static int
showport_parse_reta_config(struct rte_eth_rss_reta_entry64 *conf,
			   uint16_t nb_entries,
			   char *str)
{
	uint32_t size;
	const char *p, *p0 = str;
	char s[256];
	char *end;
	char *str_fld[8];
	uint16_t i;
	uint16_t num = (nb_entries + RTE_RETA_GROUP_SIZE - 1) /
			RTE_RETA_GROUP_SIZE;
	int ret;

	p = strchr(p0, '(');
	if (p == NULL)
		return -1;
	p++;
	p0 = strchr(p, ')');
	if (p0 == NULL)
		return -1;
	size = p0 - p;
	if (size >= sizeof(s)) {
		printf("The string size exceeds the internal buffer size\n");
		return -1;
	}
	snprintf(s, sizeof(s), "%.*s", size, p);
	ret = rte_strsplit(s, sizeof(s), str_fld, num, ',');
	if (ret <= 0 || ret != num) {
		printf("The bits of masks do not match the number of "
					"reta entries: %u\n", num);
		return -1;
	}
	for (i = 0; i < ret; i++)
		conf[i].mask = (uint64_t)strtoul(str_fld[i], &end, 0);

	return 0;
}

static void
cmd_showport_reta_parsed(void *parsed_result,
			 __attribute__((unused)) struct cmdline *cl,
			 __attribute__((unused)) void *data)
{
	struct cmd_showport_reta *res = parsed_result;
	struct rte_eth_rss_reta_entry64 reta_conf[8];
	struct rte_eth_dev_info dev_info;
	uint16_t max_reta_size;

	memset(&dev_info, 0, sizeof(dev_info));
	rte_eth_dev_info_get(res->port_id, &dev_info);
	max_reta_size = RTE_MIN(dev_info.reta_size, ETH_RSS_RETA_SIZE_512);
	if (res->size == 0 || res->size > max_reta_size) {
		printf("Invalid redirection table size: %u (1-%u)\n",
			res->size, max_reta_size);
		return;
	}

	memset(reta_conf, 0, sizeof(reta_conf));
	if (showport_parse_reta_config(reta_conf, res->size,
				res->list_of_items) < 0) {
		printf("Invalid string: %s for reta masks\n",
					res->list_of_items);
		return;
	}
	port_rss_reta_info(res->port_id, reta_conf, res->size);
}

cmdline_parse_token_string_t cmd_showport_reta_show =
	TOKEN_STRING_INITIALIZER(struct  cmd_showport_reta, show, "show");
cmdline_parse_token_string_t cmd_showport_reta_port =
	TOKEN_STRING_INITIALIZER(struct  cmd_showport_reta, port, "port");
cmdline_parse_token_num_t cmd_showport_reta_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_showport_reta, port_id, UINT16);
cmdline_parse_token_string_t cmd_showport_reta_rss =
	TOKEN_STRING_INITIALIZER(struct cmd_showport_reta, rss, "rss");
cmdline_parse_token_string_t cmd_showport_reta_reta =
	TOKEN_STRING_INITIALIZER(struct cmd_showport_reta, reta, "reta");
cmdline_parse_token_num_t cmd_showport_reta_size =
	TOKEN_NUM_INITIALIZER(struct cmd_showport_reta, size, UINT16);
cmdline_parse_token_string_t cmd_showport_reta_list_of_items =
	TOKEN_STRING_INITIALIZER(struct cmd_showport_reta,
					list_of_items, NULL);

cmdline_parse_inst_t cmd_showport_reta = {
	.f = cmd_showport_reta_parsed,
	.data = NULL,
	.help_str = "show port <port_id> rss reta <size> <mask0[,mask1]*>",
	.tokens = {
		(void *)&cmd_showport_reta_show,
		(void *)&cmd_showport_reta_port,
		(void *)&cmd_showport_reta_port_id,
		(void *)&cmd_showport_reta_rss,
		(void *)&cmd_showport_reta_reta,
		(void *)&cmd_showport_reta_size,
		(void *)&cmd_showport_reta_list_of_items,
		NULL,
	},
};

/* *** Show RSS hash configuration *** */
struct cmd_showport_rss_hash {
	cmdline_fixed_string_t show;
	cmdline_fixed_string_t port;
	portid_t port_id;
	cmdline_fixed_string_t rss_hash;
	cmdline_fixed_string_t rss_type;
	cmdline_fixed_string_t key; /* optional argument */
};

static void cmd_showport_rss_hash_parsed(void *parsed_result,
				__attribute__((unused)) struct cmdline *cl,
				void *show_rss_key)
{
	struct cmd_showport_rss_hash *res = parsed_result;

	port_rss_hash_conf_show(res->port_id, show_rss_key != NULL);
}

cmdline_parse_token_string_t cmd_showport_rss_hash_show =
	TOKEN_STRING_INITIALIZER(struct cmd_showport_rss_hash, show, "show");
cmdline_parse_token_string_t cmd_showport_rss_hash_port =
	TOKEN_STRING_INITIALIZER(struct cmd_showport_rss_hash, port, "port");
cmdline_parse_token_num_t cmd_showport_rss_hash_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_showport_rss_hash, port_id, UINT16);
cmdline_parse_token_string_t cmd_showport_rss_hash_rss_hash =
	TOKEN_STRING_INITIALIZER(struct cmd_showport_rss_hash, rss_hash,
				 "rss-hash");
cmdline_parse_token_string_t cmd_showport_rss_hash_rss_key =
	TOKEN_STRING_INITIALIZER(struct cmd_showport_rss_hash, key, "key");

cmdline_parse_inst_t cmd_showport_rss_hash = {
	.f = cmd_showport_rss_hash_parsed,
	.data = NULL,
	.help_str = "show port <port_id> rss-hash",
	.tokens = {
		(void *)&cmd_showport_rss_hash_show,
		(void *)&cmd_showport_rss_hash_port,
		(void *)&cmd_showport_rss_hash_port_id,
		(void *)&cmd_showport_rss_hash_rss_hash,
		NULL,
	},
};

cmdline_parse_inst_t cmd_showport_rss_hash_key = {
	.f = cmd_showport_rss_hash_parsed,
	.data = (void *)1,
	.help_str = "show port <port_id> rss-hash key",
	.tokens = {
		(void *)&cmd_showport_rss_hash_show,
		(void *)&cmd_showport_rss_hash_port,
		(void *)&cmd_showport_rss_hash_port_id,
		(void *)&cmd_showport_rss_hash_rss_hash,
		(void *)&cmd_showport_rss_hash_rss_key,
		NULL,
	},
};

/* *** Configure DCB *** */
struct cmd_config_dcb {
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t config;
	portid_t port_id;
	cmdline_fixed_string_t dcb;
	cmdline_fixed_string_t vt;
	cmdline_fixed_string_t vt_en;
	uint8_t num_tcs;
	cmdline_fixed_string_t pfc;
	cmdline_fixed_string_t pfc_en;
};

static void
cmd_config_dcb_parsed(void *parsed_result,
                        __attribute__((unused)) struct cmdline *cl,
                        __attribute__((unused)) void *data)
{
	struct cmd_config_dcb *res = parsed_result;
	portid_t port_id = res->port_id;
	struct rte_port *port;
	uint8_t pfc_en;
	int ret;

	port = &ports[port_id];
	/** Check if the port is not started **/
	if (port->port_status != RTE_PORT_STOPPED) {
		printf("Please stop port %d first\n", port_id);
		return;
	}

	if ((res->num_tcs != ETH_4_TCS) && (res->num_tcs != ETH_8_TCS)) {
		printf("The invalid number of traffic class,"
			" only 4 or 8 allowed.\n");
		return;
	}

	if (nb_fwd_lcores < res->num_tcs) {
		printf("nb_cores shouldn't be less than number of TCs.\n");
		return;
	}
	if (!strncmp(res->pfc_en, "on", 2))
		pfc_en = 1;
	else
		pfc_en = 0;

	/* DCB in VT mode */
	if (!strncmp(res->vt_en, "on", 2))
		ret = init_port_dcb_config(port_id, DCB_VT_ENABLED,
				(enum rte_eth_nb_tcs)res->num_tcs,
				pfc_en);
	else
		ret = init_port_dcb_config(port_id, DCB_ENABLED,
				(enum rte_eth_nb_tcs)res->num_tcs,
				pfc_en);


	if (ret != 0) {
		printf("Cannot initialize network ports.\n");
		return;
	}

	cmd_reconfig_device_queue(port_id, 1, 1);
}

cmdline_parse_token_string_t cmd_config_dcb_port =
        TOKEN_STRING_INITIALIZER(struct cmd_config_dcb, port, "port");
cmdline_parse_token_string_t cmd_config_dcb_config =
        TOKEN_STRING_INITIALIZER(struct cmd_config_dcb, config, "config");
cmdline_parse_token_num_t cmd_config_dcb_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_config_dcb, port_id, UINT16);
cmdline_parse_token_string_t cmd_config_dcb_dcb =
        TOKEN_STRING_INITIALIZER(struct cmd_config_dcb, dcb, "dcb");
cmdline_parse_token_string_t cmd_config_dcb_vt =
        TOKEN_STRING_INITIALIZER(struct cmd_config_dcb, vt, "vt");
cmdline_parse_token_string_t cmd_config_dcb_vt_en =
        TOKEN_STRING_INITIALIZER(struct cmd_config_dcb, vt_en, "on#off");
cmdline_parse_token_num_t cmd_config_dcb_num_tcs =
        TOKEN_NUM_INITIALIZER(struct cmd_config_dcb, num_tcs, UINT8);
cmdline_parse_token_string_t cmd_config_dcb_pfc=
        TOKEN_STRING_INITIALIZER(struct cmd_config_dcb, pfc, "pfc");
cmdline_parse_token_string_t cmd_config_dcb_pfc_en =
        TOKEN_STRING_INITIALIZER(struct cmd_config_dcb, pfc_en, "on#off");

cmdline_parse_inst_t cmd_config_dcb = {
	.f = cmd_config_dcb_parsed,
	.data = NULL,
	.help_str = "port config <port-id> dcb vt on|off <num_tcs> pfc on|off",
	.tokens = {
		(void *)&cmd_config_dcb_port,
		(void *)&cmd_config_dcb_config,
		(void *)&cmd_config_dcb_port_id,
		(void *)&cmd_config_dcb_dcb,
		(void *)&cmd_config_dcb_vt,
		(void *)&cmd_config_dcb_vt_en,
		(void *)&cmd_config_dcb_num_tcs,
		(void *)&cmd_config_dcb_pfc,
		(void *)&cmd_config_dcb_pfc_en,
                NULL,
        },
};

/* *** configure number of packets per burst *** */
struct cmd_config_burst {
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t keyword;
	cmdline_fixed_string_t all;
	cmdline_fixed_string_t name;
	uint16_t value;
};

static void
cmd_config_burst_parsed(void *parsed_result,
			__attribute__((unused)) struct cmdline *cl,
			__attribute__((unused)) void *data)
{
	struct cmd_config_burst *res = parsed_result;
	struct rte_eth_dev_info dev_info;
	uint16_t rec_nb_pkts;

	if (!all_ports_stopped()) {
		printf("Please stop all ports first\n");
		return;
	}

	if (!strcmp(res->name, "burst")) {
		if (res->value == 0) {
			/* If user gives a value of zero, query the PMD for
			 * its recommended Rx burst size. Testpmd uses a single
			 * size for all ports, so assume all ports are the same
			 * NIC model and use the values from Port 0.
			 */
			rte_eth_dev_info_get(0, &dev_info);
			rec_nb_pkts = dev_info.default_rxportconf.burst_size;

			if (rec_nb_pkts == 0) {
				printf("PMD does not recommend a burst size.\n"
					"User provided value must be between"
					" 1 and %d\n", MAX_PKT_BURST);
				return;
			} else if (rec_nb_pkts > MAX_PKT_BURST) {
				printf("PMD recommended burst size of %d"
					" exceeds maximum value of %d\n",
					rec_nb_pkts, MAX_PKT_BURST);
				return;
			}
			printf("Using PMD-provided burst value of %d\n",
				rec_nb_pkts);
			nb_pkt_per_burst = rec_nb_pkts;
		} else if (res->value > MAX_PKT_BURST) {
			printf("burst must be >= 1 && <= %d\n", MAX_PKT_BURST);
			return;
		} else
			nb_pkt_per_burst = res->value;
	} else {
		printf("Unknown parameter\n");
		return;
	}

	init_port_config();

	cmd_reconfig_device_queue(RTE_PORT_ALL, 1, 1);
}

cmdline_parse_token_string_t cmd_config_burst_port =
	TOKEN_STRING_INITIALIZER(struct cmd_config_burst, port, "port");
cmdline_parse_token_string_t cmd_config_burst_keyword =
	TOKEN_STRING_INITIALIZER(struct cmd_config_burst, keyword, "config");
cmdline_parse_token_string_t cmd_config_burst_all =
	TOKEN_STRING_INITIALIZER(struct cmd_config_burst, all, "all");
cmdline_parse_token_string_t cmd_config_burst_name =
	TOKEN_STRING_INITIALIZER(struct cmd_config_burst, name, "burst");
cmdline_parse_token_num_t cmd_config_burst_value =
	TOKEN_NUM_INITIALIZER(struct cmd_config_burst, value, UINT16);

cmdline_parse_inst_t cmd_config_burst = {
	.f = cmd_config_burst_parsed,
	.data = NULL,
	.help_str = "port config all burst <value>",
	.tokens = {
		(void *)&cmd_config_burst_port,
		(void *)&cmd_config_burst_keyword,
		(void *)&cmd_config_burst_all,
		(void *)&cmd_config_burst_name,
		(void *)&cmd_config_burst_value,
		NULL,
	},
};

/* *** configure rx/tx queues *** */
struct cmd_config_thresh {
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t keyword;
	cmdline_fixed_string_t all;
	cmdline_fixed_string_t name;
	uint8_t value;
};

static void
cmd_config_thresh_parsed(void *parsed_result,
			__attribute__((unused)) struct cmdline *cl,
			__attribute__((unused)) void *data)
{
	struct cmd_config_thresh *res = parsed_result;

	if (!all_ports_stopped()) {
		printf("Please stop all ports first\n");
		return;
	}

	if (!strcmp(res->name, "txpt"))
		tx_pthresh = res->value;
	else if(!strcmp(res->name, "txht"))
		tx_hthresh = res->value;
	else if(!strcmp(res->name, "txwt"))
		tx_wthresh = res->value;
	else if(!strcmp(res->name, "rxpt"))
		rx_pthresh = res->value;
	else if(!strcmp(res->name, "rxht"))
		rx_hthresh = res->value;
	else if(!strcmp(res->name, "rxwt"))
		rx_wthresh = res->value;
	else {
		printf("Unknown parameter\n");
		return;
	}

	init_port_config();

	cmd_reconfig_device_queue(RTE_PORT_ALL, 1, 1);
}

cmdline_parse_token_string_t cmd_config_thresh_port =
	TOKEN_STRING_INITIALIZER(struct cmd_config_thresh, port, "port");
cmdline_parse_token_string_t cmd_config_thresh_keyword =
	TOKEN_STRING_INITIALIZER(struct cmd_config_thresh, keyword, "config");
cmdline_parse_token_string_t cmd_config_thresh_all =
	TOKEN_STRING_INITIALIZER(struct cmd_config_thresh, all, "all");
cmdline_parse_token_string_t cmd_config_thresh_name =
	TOKEN_STRING_INITIALIZER(struct cmd_config_thresh, name,
				"txpt#txht#txwt#rxpt#rxht#rxwt");
cmdline_parse_token_num_t cmd_config_thresh_value =
	TOKEN_NUM_INITIALIZER(struct cmd_config_thresh, value, UINT8);

cmdline_parse_inst_t cmd_config_thresh = {
	.f = cmd_config_thresh_parsed,
	.data = NULL,
	.help_str = "port config all txpt|txht|txwt|rxpt|rxht|rxwt <value>",
	.tokens = {
		(void *)&cmd_config_thresh_port,
		(void *)&cmd_config_thresh_keyword,
		(void *)&cmd_config_thresh_all,
		(void *)&cmd_config_thresh_name,
		(void *)&cmd_config_thresh_value,
		NULL,
	},
};

/* *** configure free/rs threshold *** */
struct cmd_config_threshold {
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t keyword;
	cmdline_fixed_string_t all;
	cmdline_fixed_string_t name;
	uint16_t value;
};

static void
cmd_config_threshold_parsed(void *parsed_result,
			__attribute__((unused)) struct cmdline *cl,
			__attribute__((unused)) void *data)
{
	struct cmd_config_threshold *res = parsed_result;

	if (!all_ports_stopped()) {
		printf("Please stop all ports first\n");
		return;
	}

	if (!strcmp(res->name, "txfreet"))
		tx_free_thresh = res->value;
	else if (!strcmp(res->name, "txrst"))
		tx_rs_thresh = res->value;
	else if (!strcmp(res->name, "rxfreet"))
		rx_free_thresh = res->value;
	else {
		printf("Unknown parameter\n");
		return;
	}

	init_port_config();

	cmd_reconfig_device_queue(RTE_PORT_ALL, 1, 1);
}

cmdline_parse_token_string_t cmd_config_threshold_port =
	TOKEN_STRING_INITIALIZER(struct cmd_config_threshold, port, "port");
cmdline_parse_token_string_t cmd_config_threshold_keyword =
	TOKEN_STRING_INITIALIZER(struct cmd_config_threshold, keyword,
								"config");
cmdline_parse_token_string_t cmd_config_threshold_all =
	TOKEN_STRING_INITIALIZER(struct cmd_config_threshold, all, "all");
cmdline_parse_token_string_t cmd_config_threshold_name =
	TOKEN_STRING_INITIALIZER(struct cmd_config_threshold, name,
						"txfreet#txrst#rxfreet");
cmdline_parse_token_num_t cmd_config_threshold_value =
	TOKEN_NUM_INITIALIZER(struct cmd_config_threshold, value, UINT16);

cmdline_parse_inst_t cmd_config_threshold = {
	.f = cmd_config_threshold_parsed,
	.data = NULL,
	.help_str = "port config all txfreet|txrst|rxfreet <value>",
	.tokens = {
		(void *)&cmd_config_threshold_port,
		(void *)&cmd_config_threshold_keyword,
		(void *)&cmd_config_threshold_all,
		(void *)&cmd_config_threshold_name,
		(void *)&cmd_config_threshold_value,
		NULL,
	},
};

/* *** stop *** */
struct cmd_stop_result {
	cmdline_fixed_string_t stop;
};

static void cmd_stop_parsed(__attribute__((unused)) void *parsed_result,
			    __attribute__((unused)) struct cmdline *cl,
			    __attribute__((unused)) void *data)
{
	stop_packet_forwarding();
}

cmdline_parse_token_string_t cmd_stop_stop =
	TOKEN_STRING_INITIALIZER(struct cmd_stop_result, stop, "stop");

cmdline_parse_inst_t cmd_stop = {
	.f = cmd_stop_parsed,
	.data = NULL,
	.help_str = "stop: Stop packet forwarding",
	.tokens = {
		(void *)&cmd_stop_stop,
		NULL,
	},
};

/* *** SET CORELIST and PORTLIST CONFIGURATION *** */

unsigned int
parse_item_list(char* str, const char* item_name, unsigned int max_items,
		unsigned int *parsed_items, int check_unique_values)
{
	unsigned int nb_item;
	unsigned int value;
	unsigned int i;
	unsigned int j;
	int value_ok;
	char c;

	/*
	 * First parse all items in the list and store their value.
	 */
	value = 0;
	nb_item = 0;
	value_ok = 0;
	for (i = 0; i < strnlen(str, STR_TOKEN_SIZE); i++) {
		c = str[i];
		if ((c >= '0') && (c <= '9')) {
			value = (unsigned int) (value * 10 + (c - '0'));
			value_ok = 1;
			continue;
		}
		if (c != ',') {
			printf("character %c is not a decimal digit\n", c);
			return 0;
		}
		if (! value_ok) {
			printf("No valid value before comma\n");
			return 0;
		}
		if (nb_item < max_items) {
			parsed_items[nb_item] = value;
			value_ok = 0;
			value = 0;
		}
		nb_item++;
	}
	if (nb_item >= max_items) {
		printf("Number of %s = %u > %u (maximum items)\n",
		       item_name, nb_item + 1, max_items);
		return 0;
	}
	parsed_items[nb_item++] = value;
	if (! check_unique_values)
		return nb_item;

	/*
	 * Then, check that all values in the list are differents.
	 * No optimization here...
	 */
	for (i = 0; i < nb_item; i++) {
		for (j = i + 1; j < nb_item; j++) {
			if (parsed_items[j] == parsed_items[i]) {
				printf("duplicated %s %u at index %u and %u\n",
				       item_name, parsed_items[i], i, j);
				return 0;
			}
		}
	}
	return nb_item;
}

struct cmd_set_list_result {
	cmdline_fixed_string_t cmd_keyword;
	cmdline_fixed_string_t list_name;
	cmdline_fixed_string_t list_of_items;
};

static void cmd_set_list_parsed(void *parsed_result,
				__attribute__((unused)) struct cmdline *cl,
				__attribute__((unused)) void *data)
{
	struct cmd_set_list_result *res;
	union {
		unsigned int lcorelist[RTE_MAX_LCORE];
		unsigned int portlist[RTE_MAX_ETHPORTS];
	} parsed_items;
	unsigned int nb_item;

	if (test_done == 0) {
		printf("Please stop forwarding first\n");
		return;
	}

	res = parsed_result;
	if (!strcmp(res->list_name, "corelist")) {
		nb_item = parse_item_list(res->list_of_items, "core",
					  RTE_MAX_LCORE,
					  parsed_items.lcorelist, 1);
		if (nb_item > 0) {
			set_fwd_lcores_list(parsed_items.lcorelist, nb_item);
			fwd_config_setup();
		}
		return;
	}
	if (!strcmp(res->list_name, "portlist")) {
		nb_item = parse_item_list(res->list_of_items, "port",
					  RTE_MAX_ETHPORTS,
					  parsed_items.portlist, 1);
		if (nb_item > 0) {
			set_fwd_ports_list(parsed_items.portlist, nb_item);
			fwd_config_setup();
		}
	}
}

cmdline_parse_token_string_t cmd_set_list_keyword =
	TOKEN_STRING_INITIALIZER(struct cmd_set_list_result, cmd_keyword,
				 "set");
cmdline_parse_token_string_t cmd_set_list_name =
	TOKEN_STRING_INITIALIZER(struct cmd_set_list_result, list_name,
				 "corelist#portlist");
cmdline_parse_token_string_t cmd_set_list_of_items =
	TOKEN_STRING_INITIALIZER(struct cmd_set_list_result, list_of_items,
				 NULL);

cmdline_parse_inst_t cmd_set_fwd_list = {
	.f = cmd_set_list_parsed,
	.data = NULL,
	.help_str = "set corelist|portlist <list0[,list1]*>",
	.tokens = {
		(void *)&cmd_set_list_keyword,
		(void *)&cmd_set_list_name,
		(void *)&cmd_set_list_of_items,
		NULL,
	},
};

/* *** SET COREMASK and PORTMASK CONFIGURATION *** */

struct cmd_setmask_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t mask;
	uint64_t hexavalue;
};

static void cmd_set_mask_parsed(void *parsed_result,
				__attribute__((unused)) struct cmdline *cl,
				__attribute__((unused)) void *data)
{
	struct cmd_setmask_result *res = parsed_result;

	if (test_done == 0) {
		printf("Please stop forwarding first\n");
		return;
	}
	if (!strcmp(res->mask, "coremask")) {
		set_fwd_lcores_mask(res->hexavalue);
		fwd_config_setup();
	} else if (!strcmp(res->mask, "portmask")) {
		set_fwd_ports_mask(res->hexavalue);
		fwd_config_setup();
	}
}

cmdline_parse_token_string_t cmd_setmask_set =
	TOKEN_STRING_INITIALIZER(struct cmd_setmask_result, set, "set");
cmdline_parse_token_string_t cmd_setmask_mask =
	TOKEN_STRING_INITIALIZER(struct cmd_setmask_result, mask,
				 "coremask#portmask");
cmdline_parse_token_num_t cmd_setmask_value =
	TOKEN_NUM_INITIALIZER(struct cmd_setmask_result, hexavalue, UINT64);

cmdline_parse_inst_t cmd_set_fwd_mask = {
	.f = cmd_set_mask_parsed,
	.data = NULL,
	.help_str = "set coremask|portmask <hexadecimal value>",
	.tokens = {
		(void *)&cmd_setmask_set,
		(void *)&cmd_setmask_mask,
		(void *)&cmd_setmask_value,
		NULL,
	},
};

/*
 * SET NBPORT, NBCORE, PACKET BURST, and VERBOSE LEVEL CONFIGURATION
 */
struct cmd_set_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t what;
	uint16_t value;
};

static void cmd_set_parsed(void *parsed_result,
			   __attribute__((unused)) struct cmdline *cl,
			   __attribute__((unused)) void *data)
{
	struct cmd_set_result *res = parsed_result;
	if (!strcmp(res->what, "nbport")) {
		set_fwd_ports_number(res->value);
		fwd_config_setup();
	} else if (!strcmp(res->what, "nbcore")) {
		set_fwd_lcores_number(res->value);
		fwd_config_setup();
	} else if (!strcmp(res->what, "burst"))
		set_nb_pkt_per_burst(res->value);
	else if (!strcmp(res->what, "verbose"))
		set_verbose_level(res->value);
}

cmdline_parse_token_string_t cmd_set_set =
	TOKEN_STRING_INITIALIZER(struct cmd_set_result, set, "set");
cmdline_parse_token_string_t cmd_set_what =
	TOKEN_STRING_INITIALIZER(struct cmd_set_result, what,
				 "nbport#nbcore#burst#verbose");
cmdline_parse_token_num_t cmd_set_value =
	TOKEN_NUM_INITIALIZER(struct cmd_set_result, value, UINT16);

cmdline_parse_inst_t cmd_set_numbers = {
	.f = cmd_set_parsed,
	.data = NULL,
	.help_str = "set nbport|nbcore|burst|verbose <value>",
	.tokens = {
		(void *)&cmd_set_set,
		(void *)&cmd_set_what,
		(void *)&cmd_set_value,
		NULL,
	},
};

/* *** SET LOG LEVEL CONFIGURATION *** */

struct cmd_set_log_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t log;
	cmdline_fixed_string_t type;
	uint32_t level;
};

static void
cmd_set_log_parsed(void *parsed_result,
		   __attribute__((unused)) struct cmdline *cl,
		   __attribute__((unused)) void *data)
{
	struct cmd_set_log_result *res;
	int ret;

	res = parsed_result;
	if (!strcmp(res->type, "global"))
		rte_log_set_global_level(res->level);
	else {
		ret = rte_log_set_level_regexp(res->type, res->level);
		if (ret < 0)
			printf("Unable to set log level\n");
	}
}

cmdline_parse_token_string_t cmd_set_log_set =
	TOKEN_STRING_INITIALIZER(struct cmd_set_log_result, set, "set");
cmdline_parse_token_string_t cmd_set_log_log =
	TOKEN_STRING_INITIALIZER(struct cmd_set_log_result, log, "log");
cmdline_parse_token_string_t cmd_set_log_type =
	TOKEN_STRING_INITIALIZER(struct cmd_set_log_result, type, NULL);
cmdline_parse_token_num_t cmd_set_log_level =
	TOKEN_NUM_INITIALIZER(struct cmd_set_log_result, level, UINT32);

cmdline_parse_inst_t cmd_set_log = {
	.f = cmd_set_log_parsed,
	.data = NULL,
	.help_str = "set log global|<type> <level>",
	.tokens = {
		(void *)&cmd_set_log_set,
		(void *)&cmd_set_log_log,
		(void *)&cmd_set_log_type,
		(void *)&cmd_set_log_level,
		NULL,
	},
};

/* *** SET SEGMENT LENGTHS OF TXONLY PACKETS *** */

struct cmd_set_txpkts_result {
	cmdline_fixed_string_t cmd_keyword;
	cmdline_fixed_string_t txpkts;
	cmdline_fixed_string_t seg_lengths;
};

static void
cmd_set_txpkts_parsed(void *parsed_result,
		      __attribute__((unused)) struct cmdline *cl,
		      __attribute__((unused)) void *data)
{
	struct cmd_set_txpkts_result *res;
	unsigned seg_lengths[RTE_MAX_SEGS_PER_PKT];
	unsigned int nb_segs;

	res = parsed_result;
	nb_segs = parse_item_list(res->seg_lengths, "segment lengths",
				  RTE_MAX_SEGS_PER_PKT, seg_lengths, 0);
	if (nb_segs > 0)
		set_tx_pkt_segments(seg_lengths, nb_segs);
}

cmdline_parse_token_string_t cmd_set_txpkts_keyword =
	TOKEN_STRING_INITIALIZER(struct cmd_set_txpkts_result,
				 cmd_keyword, "set");
cmdline_parse_token_string_t cmd_set_txpkts_name =
	TOKEN_STRING_INITIALIZER(struct cmd_set_txpkts_result,
				 txpkts, "txpkts");
cmdline_parse_token_string_t cmd_set_txpkts_lengths =
	TOKEN_STRING_INITIALIZER(struct cmd_set_txpkts_result,
				 seg_lengths, NULL);

cmdline_parse_inst_t cmd_set_txpkts = {
	.f = cmd_set_txpkts_parsed,
	.data = NULL,
	.help_str = "set txpkts <len0[,len1]*>",
	.tokens = {
		(void *)&cmd_set_txpkts_keyword,
		(void *)&cmd_set_txpkts_name,
		(void *)&cmd_set_txpkts_lengths,
		NULL,
	},
};

/* *** SET COPY AND SPLIT POLICY ON TX PACKETS *** */

struct cmd_set_txsplit_result {
	cmdline_fixed_string_t cmd_keyword;
	cmdline_fixed_string_t txsplit;
	cmdline_fixed_string_t mode;
};

static void
cmd_set_txsplit_parsed(void *parsed_result,
		      __attribute__((unused)) struct cmdline *cl,
		      __attribute__((unused)) void *data)
{
	struct cmd_set_txsplit_result *res;

	res = parsed_result;
	set_tx_pkt_split(res->mode);
}

cmdline_parse_token_string_t cmd_set_txsplit_keyword =
	TOKEN_STRING_INITIALIZER(struct cmd_set_txsplit_result,
				 cmd_keyword, "set");
cmdline_parse_token_string_t cmd_set_txsplit_name =
	TOKEN_STRING_INITIALIZER(struct cmd_set_txsplit_result,
				 txsplit, "txsplit");
cmdline_parse_token_string_t cmd_set_txsplit_mode =
	TOKEN_STRING_INITIALIZER(struct cmd_set_txsplit_result,
				 mode, NULL);

cmdline_parse_inst_t cmd_set_txsplit = {
	.f = cmd_set_txsplit_parsed,
	.data = NULL,
	.help_str = "set txsplit on|off|rand",
	.tokens = {
		(void *)&cmd_set_txsplit_keyword,
		(void *)&cmd_set_txsplit_name,
		(void *)&cmd_set_txsplit_mode,
		NULL,
	},
};

/* *** ADD/REMOVE ALL VLAN IDENTIFIERS TO/FROM A PORT VLAN RX FILTER *** */
struct cmd_rx_vlan_filter_all_result {
	cmdline_fixed_string_t rx_vlan;
	cmdline_fixed_string_t what;
	cmdline_fixed_string_t all;
	portid_t port_id;
};

static void
cmd_rx_vlan_filter_all_parsed(void *parsed_result,
			      __attribute__((unused)) struct cmdline *cl,
			      __attribute__((unused)) void *data)
{
	struct cmd_rx_vlan_filter_all_result *res = parsed_result;

	if (!strcmp(res->what, "add"))
		rx_vlan_all_filter_set(res->port_id, 1);
	else
		rx_vlan_all_filter_set(res->port_id, 0);
}

cmdline_parse_token_string_t cmd_rx_vlan_filter_all_rx_vlan =
	TOKEN_STRING_INITIALIZER(struct cmd_rx_vlan_filter_all_result,
				 rx_vlan, "rx_vlan");
cmdline_parse_token_string_t cmd_rx_vlan_filter_all_what =
	TOKEN_STRING_INITIALIZER(struct cmd_rx_vlan_filter_all_result,
				 what, "add#rm");
cmdline_parse_token_string_t cmd_rx_vlan_filter_all_all =
	TOKEN_STRING_INITIALIZER(struct cmd_rx_vlan_filter_all_result,
				 all, "all");
cmdline_parse_token_num_t cmd_rx_vlan_filter_all_portid =
	TOKEN_NUM_INITIALIZER(struct cmd_rx_vlan_filter_all_result,
			      port_id, UINT16);

cmdline_parse_inst_t cmd_rx_vlan_filter_all = {
	.f = cmd_rx_vlan_filter_all_parsed,
	.data = NULL,
	.help_str = "rx_vlan add|rm all <port_id>: "
		"Add/Remove all identifiers to/from the set of VLAN "
		"identifiers filtered by a port",
	.tokens = {
		(void *)&cmd_rx_vlan_filter_all_rx_vlan,
		(void *)&cmd_rx_vlan_filter_all_what,
		(void *)&cmd_rx_vlan_filter_all_all,
		(void *)&cmd_rx_vlan_filter_all_portid,
		NULL,
	},
};

/* *** VLAN OFFLOAD SET ON A PORT *** */
struct cmd_vlan_offload_result {
	cmdline_fixed_string_t vlan;
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t vlan_type;
	cmdline_fixed_string_t what;
	cmdline_fixed_string_t on;
	cmdline_fixed_string_t port_id;
};

static void
cmd_vlan_offload_parsed(void *parsed_result,
			  __attribute__((unused)) struct cmdline *cl,
			  __attribute__((unused)) void *data)
{
	int on;
	struct cmd_vlan_offload_result *res = parsed_result;
	char *str;
	int i, len = 0;
	portid_t port_id = 0;
	unsigned int tmp;

	str = res->port_id;
	len = strnlen(str, STR_TOKEN_SIZE);
	i = 0;
	/* Get port_id first */
	while(i < len){
		if(str[i] == ',')
			break;

		i++;
	}
	str[i]='\0';
	tmp = strtoul(str, NULL, 0);
	/* If port_id greater that what portid_t can represent, return */
	if(tmp >= RTE_MAX_ETHPORTS)
		return;
	port_id = (portid_t)tmp;

	if (!strcmp(res->on, "on"))
		on = 1;
	else
		on = 0;

	if (!strcmp(res->what, "strip"))
		rx_vlan_strip_set(port_id,  on);
	else if(!strcmp(res->what, "stripq")){
		uint16_t queue_id = 0;

		/* No queue_id, return */
		if(i + 1 >= len) {
			printf("must specify (port,queue_id)\n");
			return;
		}
		tmp = strtoul(str + i + 1, NULL, 0);
		/* If queue_id greater that what 16-bits can represent, return */
		if(tmp > 0xffff)
			return;

		queue_id = (uint16_t)tmp;
		rx_vlan_strip_set_on_queue(port_id, queue_id, on);
	}
	else if (!strcmp(res->what, "filter"))
		rx_vlan_filter_set(port_id, on);
	else
		vlan_extend_set(port_id, on);

	return;
}

cmdline_parse_token_string_t cmd_vlan_offload_vlan =
	TOKEN_STRING_INITIALIZER(struct cmd_vlan_offload_result,
				 vlan, "vlan");
cmdline_parse_token_string_t cmd_vlan_offload_set =
	TOKEN_STRING_INITIALIZER(struct cmd_vlan_offload_result,
				 set, "set");
cmdline_parse_token_string_t cmd_vlan_offload_what =
	TOKEN_STRING_INITIALIZER(struct cmd_vlan_offload_result,
				 what, "strip#filter#qinq#stripq");
cmdline_parse_token_string_t cmd_vlan_offload_on =
	TOKEN_STRING_INITIALIZER(struct cmd_vlan_offload_result,
			      on, "on#off");
cmdline_parse_token_string_t cmd_vlan_offload_portid =
	TOKEN_STRING_INITIALIZER(struct cmd_vlan_offload_result,
			      port_id, NULL);

cmdline_parse_inst_t cmd_vlan_offload = {
	.f = cmd_vlan_offload_parsed,
	.data = NULL,
	.help_str = "vlan set strip|filter|qinq|stripq on|off "
		"<port_id[,queue_id]>: "
		"Filter/Strip for rx side qinq(extended) for both rx/tx sides",
	.tokens = {
		(void *)&cmd_vlan_offload_vlan,
		(void *)&cmd_vlan_offload_set,
		(void *)&cmd_vlan_offload_what,
		(void *)&cmd_vlan_offload_on,
		(void *)&cmd_vlan_offload_portid,
		NULL,
	},
};

/* *** VLAN TPID SET ON A PORT *** */
struct cmd_vlan_tpid_result {
	cmdline_fixed_string_t vlan;
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t vlan_type;
	cmdline_fixed_string_t what;
	uint16_t tp_id;
	portid_t port_id;
};

static void
cmd_vlan_tpid_parsed(void *parsed_result,
			  __attribute__((unused)) struct cmdline *cl,
			  __attribute__((unused)) void *data)
{
	struct cmd_vlan_tpid_result *res = parsed_result;
	enum rte_vlan_type vlan_type;

	if (!strcmp(res->vlan_type, "inner"))
		vlan_type = ETH_VLAN_TYPE_INNER;
	else if (!strcmp(res->vlan_type, "outer"))
		vlan_type = ETH_VLAN_TYPE_OUTER;
	else {
		printf("Unknown vlan type\n");
		return;
	}
	vlan_tpid_set(res->port_id, vlan_type, res->tp_id);
}

cmdline_parse_token_string_t cmd_vlan_tpid_vlan =
	TOKEN_STRING_INITIALIZER(struct cmd_vlan_tpid_result,
				 vlan, "vlan");
cmdline_parse_token_string_t cmd_vlan_tpid_set =
	TOKEN_STRING_INITIALIZER(struct cmd_vlan_tpid_result,
				 set, "set");
cmdline_parse_token_string_t cmd_vlan_type =
	TOKEN_STRING_INITIALIZER(struct cmd_vlan_tpid_result,
				 vlan_type, "inner#outer");
cmdline_parse_token_string_t cmd_vlan_tpid_what =
	TOKEN_STRING_INITIALIZER(struct cmd_vlan_tpid_result,
				 what, "tpid");
cmdline_parse_token_num_t cmd_vlan_tpid_tpid =
	TOKEN_NUM_INITIALIZER(struct cmd_vlan_tpid_result,
			      tp_id, UINT16);
cmdline_parse_token_num_t cmd_vlan_tpid_portid =
	TOKEN_NUM_INITIALIZER(struct cmd_vlan_tpid_result,
			      port_id, UINT16);

cmdline_parse_inst_t cmd_vlan_tpid = {
	.f = cmd_vlan_tpid_parsed,
	.data = NULL,
	.help_str = "vlan set inner|outer tpid <tp_id> <port_id>: "
		"Set the VLAN Ether type",
	.tokens = {
		(void *)&cmd_vlan_tpid_vlan,
		(void *)&cmd_vlan_tpid_set,
		(void *)&cmd_vlan_type,
		(void *)&cmd_vlan_tpid_what,
		(void *)&cmd_vlan_tpid_tpid,
		(void *)&cmd_vlan_tpid_portid,
		NULL,
	},
};

/* *** ADD/REMOVE A VLAN IDENTIFIER TO/FROM A PORT VLAN RX FILTER *** */
struct cmd_rx_vlan_filter_result {
	cmdline_fixed_string_t rx_vlan;
	cmdline_fixed_string_t what;
	uint16_t vlan_id;
	portid_t port_id;
};

static void
cmd_rx_vlan_filter_parsed(void *parsed_result,
			  __attribute__((unused)) struct cmdline *cl,
			  __attribute__((unused)) void *data)
{
	struct cmd_rx_vlan_filter_result *res = parsed_result;

	if (!strcmp(res->what, "add"))
		rx_vft_set(res->port_id, res->vlan_id, 1);
	else
		rx_vft_set(res->port_id, res->vlan_id, 0);
}

cmdline_parse_token_string_t cmd_rx_vlan_filter_rx_vlan =
	TOKEN_STRING_INITIALIZER(struct cmd_rx_vlan_filter_result,
				 rx_vlan, "rx_vlan");
cmdline_parse_token_string_t cmd_rx_vlan_filter_what =
	TOKEN_STRING_INITIALIZER(struct cmd_rx_vlan_filter_result,
				 what, "add#rm");
cmdline_parse_token_num_t cmd_rx_vlan_filter_vlanid =
	TOKEN_NUM_INITIALIZER(struct cmd_rx_vlan_filter_result,
			      vlan_id, UINT16);
cmdline_parse_token_num_t cmd_rx_vlan_filter_portid =
	TOKEN_NUM_INITIALIZER(struct cmd_rx_vlan_filter_result,
			      port_id, UINT16);

cmdline_parse_inst_t cmd_rx_vlan_filter = {
	.f = cmd_rx_vlan_filter_parsed,
	.data = NULL,
	.help_str = "rx_vlan add|rm <vlan_id> <port_id>: "
		"Add/Remove a VLAN identifier to/from the set of VLAN "
		"identifiers filtered by a port",
	.tokens = {
		(void *)&cmd_rx_vlan_filter_rx_vlan,
		(void *)&cmd_rx_vlan_filter_what,
		(void *)&cmd_rx_vlan_filter_vlanid,
		(void *)&cmd_rx_vlan_filter_portid,
		NULL,
	},
};

/* *** ENABLE HARDWARE INSERTION OF VLAN HEADER IN TX PACKETS *** */
struct cmd_tx_vlan_set_result {
	cmdline_fixed_string_t tx_vlan;
	cmdline_fixed_string_t set;
	portid_t port_id;
	uint16_t vlan_id;
};

static void
cmd_tx_vlan_set_parsed(void *parsed_result,
		       __attribute__((unused)) struct cmdline *cl,
		       __attribute__((unused)) void *data)
{
	struct cmd_tx_vlan_set_result *res = parsed_result;

	if (!port_is_stopped(res->port_id)) {
		printf("Please stop port %d first\n", res->port_id);
		return;
	}

	tx_vlan_set(res->port_id, res->vlan_id);

	cmd_reconfig_device_queue(res->port_id, 1, 1);
}

cmdline_parse_token_string_t cmd_tx_vlan_set_tx_vlan =
	TOKEN_STRING_INITIALIZER(struct cmd_tx_vlan_set_result,
				 tx_vlan, "tx_vlan");
cmdline_parse_token_string_t cmd_tx_vlan_set_set =
	TOKEN_STRING_INITIALIZER(struct cmd_tx_vlan_set_result,
				 set, "set");
cmdline_parse_token_num_t cmd_tx_vlan_set_portid =
	TOKEN_NUM_INITIALIZER(struct cmd_tx_vlan_set_result,
			      port_id, UINT16);
cmdline_parse_token_num_t cmd_tx_vlan_set_vlanid =
	TOKEN_NUM_INITIALIZER(struct cmd_tx_vlan_set_result,
			      vlan_id, UINT16);

cmdline_parse_inst_t cmd_tx_vlan_set = {
	.f = cmd_tx_vlan_set_parsed,
	.data = NULL,
	.help_str = "tx_vlan set <port_id> <vlan_id>: "
		"Enable hardware insertion of a single VLAN header "
		"with a given TAG Identifier in packets sent on a port",
	.tokens = {
		(void *)&cmd_tx_vlan_set_tx_vlan,
		(void *)&cmd_tx_vlan_set_set,
		(void *)&cmd_tx_vlan_set_portid,
		(void *)&cmd_tx_vlan_set_vlanid,
		NULL,
	},
};

/* *** ENABLE HARDWARE INSERTION OF Double VLAN HEADER IN TX PACKETS *** */
struct cmd_tx_vlan_set_qinq_result {
	cmdline_fixed_string_t tx_vlan;
	cmdline_fixed_string_t set;
	portid_t port_id;
	uint16_t vlan_id;
	uint16_t vlan_id_outer;
};

static void
cmd_tx_vlan_set_qinq_parsed(void *parsed_result,
			    __attribute__((unused)) struct cmdline *cl,
			    __attribute__((unused)) void *data)
{
	struct cmd_tx_vlan_set_qinq_result *res = parsed_result;

	if (!port_is_stopped(res->port_id)) {
		printf("Please stop port %d first\n", res->port_id);
		return;
	}

	tx_qinq_set(res->port_id, res->vlan_id, res->vlan_id_outer);

	cmd_reconfig_device_queue(res->port_id, 1, 1);
}

cmdline_parse_token_string_t cmd_tx_vlan_set_qinq_tx_vlan =
	TOKEN_STRING_INITIALIZER(struct cmd_tx_vlan_set_qinq_result,
		tx_vlan, "tx_vlan");
cmdline_parse_token_string_t cmd_tx_vlan_set_qinq_set =
	TOKEN_STRING_INITIALIZER(struct cmd_tx_vlan_set_qinq_result,
		set, "set");
cmdline_parse_token_num_t cmd_tx_vlan_set_qinq_portid =
	TOKEN_NUM_INITIALIZER(struct cmd_tx_vlan_set_qinq_result,
		port_id, UINT16);
cmdline_parse_token_num_t cmd_tx_vlan_set_qinq_vlanid =
	TOKEN_NUM_INITIALIZER(struct cmd_tx_vlan_set_qinq_result,
		vlan_id, UINT16);
cmdline_parse_token_num_t cmd_tx_vlan_set_qinq_vlanid_outer =
	TOKEN_NUM_INITIALIZER(struct cmd_tx_vlan_set_qinq_result,
		vlan_id_outer, UINT16);

cmdline_parse_inst_t cmd_tx_vlan_set_qinq = {
	.f = cmd_tx_vlan_set_qinq_parsed,
	.data = NULL,
	.help_str = "tx_vlan set <port_id> <vlan_id> <outer_vlan_id>: "
		"Enable hardware insertion of double VLAN header "
		"with given TAG Identifiers in packets sent on a port",
	.tokens = {
		(void *)&cmd_tx_vlan_set_qinq_tx_vlan,
		(void *)&cmd_tx_vlan_set_qinq_set,
		(void *)&cmd_tx_vlan_set_qinq_portid,
		(void *)&cmd_tx_vlan_set_qinq_vlanid,
		(void *)&cmd_tx_vlan_set_qinq_vlanid_outer,
		NULL,
	},
};

/* *** ENABLE/DISABLE PORT BASED TX VLAN INSERTION *** */
struct cmd_tx_vlan_set_pvid_result {
	cmdline_fixed_string_t tx_vlan;
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t pvid;
	portid_t port_id;
	uint16_t vlan_id;
	cmdline_fixed_string_t mode;
};

static void
cmd_tx_vlan_set_pvid_parsed(void *parsed_result,
			    __attribute__((unused)) struct cmdline *cl,
			    __attribute__((unused)) void *data)
{
	struct cmd_tx_vlan_set_pvid_result *res = parsed_result;

	if (strcmp(res->mode, "on") == 0)
		tx_vlan_pvid_set(res->port_id, res->vlan_id, 1);
	else
		tx_vlan_pvid_set(res->port_id, res->vlan_id, 0);
}

cmdline_parse_token_string_t cmd_tx_vlan_set_pvid_tx_vlan =
	TOKEN_STRING_INITIALIZER(struct cmd_tx_vlan_set_pvid_result,
				 tx_vlan, "tx_vlan");
cmdline_parse_token_string_t cmd_tx_vlan_set_pvid_set =
	TOKEN_STRING_INITIALIZER(struct cmd_tx_vlan_set_pvid_result,
				 set, "set");
cmdline_parse_token_string_t cmd_tx_vlan_set_pvid_pvid =
	TOKEN_STRING_INITIALIZER(struct cmd_tx_vlan_set_pvid_result,
				 pvid, "pvid");
cmdline_parse_token_num_t cmd_tx_vlan_set_pvid_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_tx_vlan_set_pvid_result,
			     port_id, UINT16);
cmdline_parse_token_num_t cmd_tx_vlan_set_pvid_vlan_id =
	TOKEN_NUM_INITIALIZER(struct cmd_tx_vlan_set_pvid_result,
			      vlan_id, UINT16);
cmdline_parse_token_string_t cmd_tx_vlan_set_pvid_mode =
	TOKEN_STRING_INITIALIZER(struct cmd_tx_vlan_set_pvid_result,
				 mode, "on#off");

cmdline_parse_inst_t cmd_tx_vlan_set_pvid = {
	.f = cmd_tx_vlan_set_pvid_parsed,
	.data = NULL,
	.help_str = "tx_vlan set pvid <port_id> <vlan_id> on|off",
	.tokens = {
		(void *)&cmd_tx_vlan_set_pvid_tx_vlan,
		(void *)&cmd_tx_vlan_set_pvid_set,
		(void *)&cmd_tx_vlan_set_pvid_pvid,
		(void *)&cmd_tx_vlan_set_pvid_port_id,
		(void *)&cmd_tx_vlan_set_pvid_vlan_id,
		(void *)&cmd_tx_vlan_set_pvid_mode,
		NULL,
	},
};

/* *** DISABLE HARDWARE INSERTION OF VLAN HEADER IN TX PACKETS *** */
struct cmd_tx_vlan_reset_result {
	cmdline_fixed_string_t tx_vlan;
	cmdline_fixed_string_t reset;
	portid_t port_id;
};

static void
cmd_tx_vlan_reset_parsed(void *parsed_result,
			 __attribute__((unused)) struct cmdline *cl,
			 __attribute__((unused)) void *data)
{
	struct cmd_tx_vlan_reset_result *res = parsed_result;

	if (!port_is_stopped(res->port_id)) {
		printf("Please stop port %d first\n", res->port_id);
		return;
	}

	tx_vlan_reset(res->port_id);

	cmd_reconfig_device_queue(res->port_id, 1, 1);
}

cmdline_parse_token_string_t cmd_tx_vlan_reset_tx_vlan =
	TOKEN_STRING_INITIALIZER(struct cmd_tx_vlan_reset_result,
				 tx_vlan, "tx_vlan");
cmdline_parse_token_string_t cmd_tx_vlan_reset_reset =
	TOKEN_STRING_INITIALIZER(struct cmd_tx_vlan_reset_result,
				 reset, "reset");
cmdline_parse_token_num_t cmd_tx_vlan_reset_portid =
	TOKEN_NUM_INITIALIZER(struct cmd_tx_vlan_reset_result,
			      port_id, UINT16);

cmdline_parse_inst_t cmd_tx_vlan_reset = {
	.f = cmd_tx_vlan_reset_parsed,
	.data = NULL,
	.help_str = "tx_vlan reset <port_id>: Disable hardware insertion of a "
		"VLAN header in packets sent on a port",
	.tokens = {
		(void *)&cmd_tx_vlan_reset_tx_vlan,
		(void *)&cmd_tx_vlan_reset_reset,
		(void *)&cmd_tx_vlan_reset_portid,
		NULL,
	},
};


/* *** ENABLE HARDWARE INSERTION OF CHECKSUM IN TX PACKETS *** */
struct cmd_csum_result {
	cmdline_fixed_string_t csum;
	cmdline_fixed_string_t mode;
	cmdline_fixed_string_t proto;
	cmdline_fixed_string_t hwsw;
	portid_t port_id;
};

static void
csum_show(int port_id)
{
	struct rte_eth_dev_info dev_info;
	uint64_t tx_offloads;

	tx_offloads = ports[port_id].dev_conf.txmode.offloads;
	printf("Parse tunnel is %s\n",
		(ports[port_id].parse_tunnel) ? "on" : "off");
	printf("IP checksum offload is %s\n",
		(tx_offloads & DEV_TX_OFFLOAD_IPV4_CKSUM) ? "hw" : "sw");
	printf("UDP checksum offload is %s\n",
		(tx_offloads & DEV_TX_OFFLOAD_UDP_CKSUM) ? "hw" : "sw");
	printf("TCP checksum offload is %s\n",
		(tx_offloads & DEV_TX_OFFLOAD_TCP_CKSUM) ? "hw" : "sw");
	printf("SCTP checksum offload is %s\n",
		(tx_offloads & DEV_TX_OFFLOAD_SCTP_CKSUM) ? "hw" : "sw");
	printf("Outer-Ip checksum offload is %s\n",
		(tx_offloads & DEV_TX_OFFLOAD_OUTER_IPV4_CKSUM) ? "hw" : "sw");
	printf("Outer-Udp checksum offload is %s\n",
		(tx_offloads & DEV_TX_OFFLOAD_OUTER_UDP_CKSUM) ? "hw" : "sw");

	/* display warnings if configuration is not supported by the NIC */
	rte_eth_dev_info_get(port_id, &dev_info);
	if ((tx_offloads & DEV_TX_OFFLOAD_IPV4_CKSUM) &&
		(dev_info.tx_offload_capa & DEV_TX_OFFLOAD_IPV4_CKSUM) == 0) {
		printf("Warning: hardware IP checksum enabled but not "
			"supported by port %d\n", port_id);
	}
	if ((tx_offloads & DEV_TX_OFFLOAD_UDP_CKSUM) &&
		(dev_info.tx_offload_capa & DEV_TX_OFFLOAD_UDP_CKSUM) == 0) {
		printf("Warning: hardware UDP checksum enabled but not "
			"supported by port %d\n", port_id);
	}
	if ((tx_offloads & DEV_TX_OFFLOAD_TCP_CKSUM) &&
		(dev_info.tx_offload_capa & DEV_TX_OFFLOAD_TCP_CKSUM) == 0) {
		printf("Warning: hardware TCP checksum enabled but not "
			"supported by port %d\n", port_id);
	}
	if ((tx_offloads & DEV_TX_OFFLOAD_SCTP_CKSUM) &&
		(dev_info.tx_offload_capa & DEV_TX_OFFLOAD_SCTP_CKSUM) == 0) {
		printf("Warning: hardware SCTP checksum enabled but not "
			"supported by port %d\n", port_id);
	}
	if ((tx_offloads & DEV_TX_OFFLOAD_OUTER_IPV4_CKSUM) &&
		(dev_info.tx_offload_capa & DEV_TX_OFFLOAD_OUTER_IPV4_CKSUM) == 0) {
		printf("Warning: hardware outer IP checksum enabled but not "
			"supported by port %d\n", port_id);
	}
	if ((tx_offloads & DEV_TX_OFFLOAD_OUTER_UDP_CKSUM) &&
		(dev_info.tx_offload_capa & DEV_TX_OFFLOAD_OUTER_UDP_CKSUM)
			== 0) {
		printf("Warning: hardware outer UDP checksum enabled but not "
			"supported by port %d\n", port_id);
	}
}

static void
cmd_config_queue_tx_offloads(struct rte_port *port)
{
	int k;

	/* Apply queue tx offloads configuration */
	for (k = 0; k < port->dev_info.max_rx_queues; k++)
		port->tx_conf[k].offloads =
			port->dev_conf.txmode.offloads;
}

static void
cmd_csum_parsed(void *parsed_result,
		       __attribute__((unused)) struct cmdline *cl,
		       __attribute__((unused)) void *data)
{
	struct cmd_csum_result *res = parsed_result;
	int hw = 0;
	uint64_t csum_offloads = 0;
	struct rte_eth_dev_info dev_info;

	if (port_id_is_invalid(res->port_id, ENABLED_WARN)) {
		printf("invalid port %d\n", res->port_id);
		return;
	}
	if (!port_is_stopped(res->port_id)) {
		printf("Please stop port %d first\n", res->port_id);
		return;
	}

	rte_eth_dev_info_get(res->port_id, &dev_info);
	if (!strcmp(res->mode, "set")) {

		if (!strcmp(res->hwsw, "hw"))
			hw = 1;

		if (!strcmp(res->proto, "ip")) {
			if (hw == 0 || (dev_info.tx_offload_capa &
						DEV_TX_OFFLOAD_IPV4_CKSUM)) {
				csum_offloads |= DEV_TX_OFFLOAD_IPV4_CKSUM;
			} else {
				printf("IP checksum offload is not supported "
				       "by port %u\n", res->port_id);
			}
		} else if (!strcmp(res->proto, "udp")) {
			if (hw == 0 || (dev_info.tx_offload_capa &
						DEV_TX_OFFLOAD_UDP_CKSUM)) {
				csum_offloads |= DEV_TX_OFFLOAD_UDP_CKSUM;
			} else {
				printf("UDP checksum offload is not supported "
				       "by port %u\n", res->port_id);
			}
		} else if (!strcmp(res->proto, "tcp")) {
			if (hw == 0 || (dev_info.tx_offload_capa &
						DEV_TX_OFFLOAD_TCP_CKSUM)) {
				csum_offloads |= DEV_TX_OFFLOAD_TCP_CKSUM;
			} else {
				printf("TCP checksum offload is not supported "
				       "by port %u\n", res->port_id);
			}
		} else if (!strcmp(res->proto, "sctp")) {
			if (hw == 0 || (dev_info.tx_offload_capa &
						DEV_TX_OFFLOAD_SCTP_CKSUM)) {
				csum_offloads |= DEV_TX_OFFLOAD_SCTP_CKSUM;
			} else {
				printf("SCTP checksum offload is not supported "
				       "by port %u\n", res->port_id);
			}
		} else if (!strcmp(res->proto, "outer-ip")) {
			if (hw == 0 || (dev_info.tx_offload_capa &
					DEV_TX_OFFLOAD_OUTER_IPV4_CKSUM)) {
				csum_offloads |=
						DEV_TX_OFFLOAD_OUTER_IPV4_CKSUM;
			} else {
				printf("Outer IP checksum offload is not "
				       "supported by port %u\n", res->port_id);
			}
		} else if (!strcmp(res->proto, "outer-udp")) {
			if (hw == 0 || (dev_info.tx_offload_capa &
					DEV_TX_OFFLOAD_OUTER_UDP_CKSUM)) {
				csum_offloads |=
						DEV_TX_OFFLOAD_OUTER_UDP_CKSUM;
			} else {
				printf("Outer UDP checksum offload is not "
				       "supported by port %u\n", res->port_id);
			}
		}

		if (hw) {
			ports[res->port_id].dev_conf.txmode.offloads |=
							csum_offloads;
		} else {
			ports[res->port_id].dev_conf.txmode.offloads &=
							(~csum_offloads);
		}
		cmd_config_queue_tx_offloads(&ports[res->port_id]);
	}
	csum_show(res->port_id);

	cmd_reconfig_device_queue(res->port_id, 1, 1);
}

cmdline_parse_token_string_t cmd_csum_csum =
	TOKEN_STRING_INITIALIZER(struct cmd_csum_result,
				csum, "csum");
cmdline_parse_token_string_t cmd_csum_mode =
	TOKEN_STRING_INITIALIZER(struct cmd_csum_result,
				mode, "set");
cmdline_parse_token_string_t cmd_csum_proto =
	TOKEN_STRING_INITIALIZER(struct cmd_csum_result,
				proto, "ip#tcp#udp#sctp#outer-ip#outer-udp");
cmdline_parse_token_string_t cmd_csum_hwsw =
	TOKEN_STRING_INITIALIZER(struct cmd_csum_result,
				hwsw, "hw#sw");
cmdline_parse_token_num_t cmd_csum_portid =
	TOKEN_NUM_INITIALIZER(struct cmd_csum_result,
				port_id, UINT16);

cmdline_parse_inst_t cmd_csum_set = {
	.f = cmd_csum_parsed,
	.data = NULL,
	.help_str = "csum set ip|tcp|udp|sctp|outer-ip|outer-udp hw|sw <port_id>: "
		"Enable/Disable hardware calculation of L3/L4 checksum when "
		"using csum forward engine",
	.tokens = {
		(void *)&cmd_csum_csum,
		(void *)&cmd_csum_mode,
		(void *)&cmd_csum_proto,
		(void *)&cmd_csum_hwsw,
		(void *)&cmd_csum_portid,
		NULL,
	},
};

cmdline_parse_token_string_t cmd_csum_mode_show =
	TOKEN_STRING_INITIALIZER(struct cmd_csum_result,
				mode, "show");

cmdline_parse_inst_t cmd_csum_show = {
	.f = cmd_csum_parsed,
	.data = NULL,
	.help_str = "csum show <port_id>: Show checksum offload configuration",
	.tokens = {
		(void *)&cmd_csum_csum,
		(void *)&cmd_csum_mode_show,
		(void *)&cmd_csum_portid,
		NULL,
	},
};

/* Enable/disable tunnel parsing */
struct cmd_csum_tunnel_result {
	cmdline_fixed_string_t csum;
	cmdline_fixed_string_t parse;
	cmdline_fixed_string_t onoff;
	portid_t port_id;
};

static void
cmd_csum_tunnel_parsed(void *parsed_result,
		       __attribute__((unused)) struct cmdline *cl,
		       __attribute__((unused)) void *data)
{
	struct cmd_csum_tunnel_result *res = parsed_result;

	if (port_id_is_invalid(res->port_id, ENABLED_WARN))
		return;

	if (!strcmp(res->onoff, "on"))
		ports[res->port_id].parse_tunnel = 1;
	else
		ports[res->port_id].parse_tunnel = 0;

	csum_show(res->port_id);
}

cmdline_parse_token_string_t cmd_csum_tunnel_csum =
	TOKEN_STRING_INITIALIZER(struct cmd_csum_tunnel_result,
				csum, "csum");
cmdline_parse_token_string_t cmd_csum_tunnel_parse =
	TOKEN_STRING_INITIALIZER(struct cmd_csum_tunnel_result,
				parse, "parse-tunnel");
cmdline_parse_token_string_t cmd_csum_tunnel_onoff =
	TOKEN_STRING_INITIALIZER(struct cmd_csum_tunnel_result,
				onoff, "on#off");
cmdline_parse_token_num_t cmd_csum_tunnel_portid =
	TOKEN_NUM_INITIALIZER(struct cmd_csum_tunnel_result,
				port_id, UINT16);

cmdline_parse_inst_t cmd_csum_tunnel = {
	.f = cmd_csum_tunnel_parsed,
	.data = NULL,
	.help_str = "csum parse-tunnel on|off <port_id>: "
		"Enable/Disable parsing of tunnels for csum engine",
	.tokens = {
		(void *)&cmd_csum_tunnel_csum,
		(void *)&cmd_csum_tunnel_parse,
		(void *)&cmd_csum_tunnel_onoff,
		(void *)&cmd_csum_tunnel_portid,
		NULL,
	},
};

/* *** ENABLE HARDWARE SEGMENTATION IN TX NON-TUNNELED PACKETS *** */
struct cmd_tso_set_result {
	cmdline_fixed_string_t tso;
	cmdline_fixed_string_t mode;
	uint16_t tso_segsz;
	portid_t port_id;
};

static void
cmd_tso_set_parsed(void *parsed_result,
		       __attribute__((unused)) struct cmdline *cl,
		       __attribute__((unused)) void *data)
{
	struct cmd_tso_set_result *res = parsed_result;
	struct rte_eth_dev_info dev_info;

	if (port_id_is_invalid(res->port_id, ENABLED_WARN))
		return;
	if (!port_is_stopped(res->port_id)) {
		printf("Please stop port %d first\n", res->port_id);
		return;
	}

	if (!strcmp(res->mode, "set"))
		ports[res->port_id].tso_segsz = res->tso_segsz;

	rte_eth_dev_info_get(res->port_id, &dev_info);
	if ((ports[res->port_id].tso_segsz != 0) &&
		(dev_info.tx_offload_capa & DEV_TX_OFFLOAD_TCP_TSO) == 0) {
		printf("Error: TSO is not supported by port %d\n",
		       res->port_id);
		return;
	}

	if (ports[res->port_id].tso_segsz == 0) {
		ports[res->port_id].dev_conf.txmode.offloads &=
						~DEV_TX_OFFLOAD_TCP_TSO;
		printf("TSO for non-tunneled packets is disabled\n");
	} else {
		ports[res->port_id].dev_conf.txmode.offloads |=
						DEV_TX_OFFLOAD_TCP_TSO;
		printf("TSO segment size for non-tunneled packets is %d\n",
			ports[res->port_id].tso_segsz);
	}
	cmd_config_queue_tx_offloads(&ports[res->port_id]);

	/* display warnings if configuration is not supported by the NIC */
	rte_eth_dev_info_get(res->port_id, &dev_info);
	if ((ports[res->port_id].tso_segsz != 0) &&
		(dev_info.tx_offload_capa & DEV_TX_OFFLOAD_TCP_TSO) == 0) {
		printf("Warning: TSO enabled but not "
			"supported by port %d\n", res->port_id);
	}

	cmd_reconfig_device_queue(res->port_id, 1, 1);
}

cmdline_parse_token_string_t cmd_tso_set_tso =
	TOKEN_STRING_INITIALIZER(struct cmd_tso_set_result,
				tso, "tso");
cmdline_parse_token_string_t cmd_tso_set_mode =
	TOKEN_STRING_INITIALIZER(struct cmd_tso_set_result,
				mode, "set");
cmdline_parse_token_num_t cmd_tso_set_tso_segsz =
	TOKEN_NUM_INITIALIZER(struct cmd_tso_set_result,
				tso_segsz, UINT16);
cmdline_parse_token_num_t cmd_tso_set_portid =
	TOKEN_NUM_INITIALIZER(struct cmd_tso_set_result,
				port_id, UINT16);

cmdline_parse_inst_t cmd_tso_set = {
	.f = cmd_tso_set_parsed,
	.data = NULL,
	.help_str = "tso set <tso_segsz> <port_id>: "
		"Set TSO segment size of non-tunneled packets for csum engine "
		"(0 to disable)",
	.tokens = {
		(void *)&cmd_tso_set_tso,
		(void *)&cmd_tso_set_mode,
		(void *)&cmd_tso_set_tso_segsz,
		(void *)&cmd_tso_set_portid,
		NULL,
	},
};

cmdline_parse_token_string_t cmd_tso_show_mode =
	TOKEN_STRING_INITIALIZER(struct cmd_tso_set_result,
				mode, "show");


cmdline_parse_inst_t cmd_tso_show = {
	.f = cmd_tso_set_parsed,
	.data = NULL,
	.help_str = "tso show <port_id>: "
		"Show TSO segment size of non-tunneled packets for csum engine",
	.tokens = {
		(void *)&cmd_tso_set_tso,
		(void *)&cmd_tso_show_mode,
		(void *)&cmd_tso_set_portid,
		NULL,
	},
};

/* *** ENABLE HARDWARE SEGMENTATION IN TX TUNNELED PACKETS *** */
struct cmd_tunnel_tso_set_result {
	cmdline_fixed_string_t tso;
	cmdline_fixed_string_t mode;
	uint16_t tso_segsz;
	portid_t port_id;
};

static struct rte_eth_dev_info
check_tunnel_tso_nic_support(portid_t port_id)
{
	struct rte_eth_dev_info dev_info;

	rte_eth_dev_info_get(port_id, &dev_info);
	if (!(dev_info.tx_offload_capa & DEV_TX_OFFLOAD_VXLAN_TNL_TSO))
		printf("Warning: VXLAN TUNNEL TSO not supported therefore "
		       "not enabled for port %d\n", port_id);
	if (!(dev_info.tx_offload_capa & DEV_TX_OFFLOAD_GRE_TNL_TSO))
		printf("Warning: GRE TUNNEL TSO	not supported therefore "
		       "not enabled for port %d\n", port_id);
	if (!(dev_info.tx_offload_capa & DEV_TX_OFFLOAD_IPIP_TNL_TSO))
		printf("Warning: IPIP TUNNEL TSO not supported therefore "
		       "not enabled for port %d\n", port_id);
	if (!(dev_info.tx_offload_capa & DEV_TX_OFFLOAD_GENEVE_TNL_TSO))
		printf("Warning: GENEVE TUNNEL TSO not supported therefore "
		       "not enabled for port %d\n", port_id);
	if (!(dev_info.tx_offload_capa & DEV_TX_OFFLOAD_IP_TNL_TSO))
		printf("Warning: IP TUNNEL TSO not supported therefore "
		       "not enabled for port %d\n", port_id);
	if (!(dev_info.tx_offload_capa & DEV_TX_OFFLOAD_UDP_TNL_TSO))
		printf("Warning: UDP TUNNEL TSO not supported therefore "
		       "not enabled for port %d\n", port_id);
	return dev_info;
}

static void
cmd_tunnel_tso_set_parsed(void *parsed_result,
			  __attribute__((unused)) struct cmdline *cl,
			  __attribute__((unused)) void *data)
{
	struct cmd_tunnel_tso_set_result *res = parsed_result;
	struct rte_eth_dev_info dev_info;

	if (port_id_is_invalid(res->port_id, ENABLED_WARN))
		return;
	if (!port_is_stopped(res->port_id)) {
		printf("Please stop port %d first\n", res->port_id);
		return;
	}

	if (!strcmp(res->mode, "set"))
		ports[res->port_id].tunnel_tso_segsz = res->tso_segsz;

	dev_info = check_tunnel_tso_nic_support(res->port_id);
	if (ports[res->port_id].tunnel_tso_segsz == 0) {
		ports[res->port_id].dev_conf.txmode.offloads &=
			~(DEV_TX_OFFLOAD_VXLAN_TNL_TSO |
			  DEV_TX_OFFLOAD_GRE_TNL_TSO |
			  DEV_TX_OFFLOAD_IPIP_TNL_TSO |
			  DEV_TX_OFFLOAD_GENEVE_TNL_TSO |
			  DEV_TX_OFFLOAD_IP_TNL_TSO |
			  DEV_TX_OFFLOAD_UDP_TNL_TSO);
		printf("TSO for tunneled packets is disabled\n");
	} else {
		uint64_t tso_offloads = (DEV_TX_OFFLOAD_VXLAN_TNL_TSO |
					 DEV_TX_OFFLOAD_GRE_TNL_TSO |
					 DEV_TX_OFFLOAD_IPIP_TNL_TSO |
					 DEV_TX_OFFLOAD_GENEVE_TNL_TSO |
					 DEV_TX_OFFLOAD_IP_TNL_TSO |
					 DEV_TX_OFFLOAD_UDP_TNL_TSO);

		ports[res->port_id].dev_conf.txmode.offloads |=
			(tso_offloads & dev_info.tx_offload_capa);
		printf("TSO segment size for tunneled packets is %d\n",
			ports[res->port_id].tunnel_tso_segsz);

		/* Below conditions are needed to make it work:
		 * (1) tunnel TSO is supported by the NIC;
		 * (2) "csum parse_tunnel" must be set so that tunneled pkts
		 * are recognized;
		 * (3) for tunneled pkts with outer L3 of IPv4,
		 * "csum set outer-ip" must be set to hw, because after tso,
		 * total_len of outer IP header is changed, and the checksum
		 * of outer IP header calculated by sw should be wrong; that
		 * is not necessary for IPv6 tunneled pkts because there's no
		 * checksum in IP header anymore.
		 */

		if (!ports[res->port_id].parse_tunnel)
			printf("Warning: csum parse_tunnel must be set "
				"so that tunneled packets are recognized\n");
		if (!(ports[res->port_id].dev_conf.txmode.offloads &
		      DEV_TX_OFFLOAD_OUTER_IPV4_CKSUM))
			printf("Warning: csum set outer-ip must be set to hw "
				"if outer L3 is IPv4; not necessary for IPv6\n");
	}

	cmd_config_queue_tx_offloads(&ports[res->port_id]);
	cmd_reconfig_device_queue(res->port_id, 1, 1);
}

cmdline_parse_token_string_t cmd_tunnel_tso_set_tso =
	TOKEN_STRING_INITIALIZER(struct cmd_tunnel_tso_set_result,
				tso, "tunnel_tso");
cmdline_parse_token_string_t cmd_tunnel_tso_set_mode =
	TOKEN_STRING_INITIALIZER(struct cmd_tunnel_tso_set_result,
				mode, "set");
cmdline_parse_token_num_t cmd_tunnel_tso_set_tso_segsz =
	TOKEN_NUM_INITIALIZER(struct cmd_tunnel_tso_set_result,
				tso_segsz, UINT16);
cmdline_parse_token_num_t cmd_tunnel_tso_set_portid =
	TOKEN_NUM_INITIALIZER(struct cmd_tunnel_tso_set_result,
				port_id, UINT16);

cmdline_parse_inst_t cmd_tunnel_tso_set = {
	.f = cmd_tunnel_tso_set_parsed,
	.data = NULL,
	.help_str = "tunnel_tso set <tso_segsz> <port_id>: "
		"Set TSO segment size of tunneled packets for csum engine "
		"(0 to disable)",
	.tokens = {
		(void *)&cmd_tunnel_tso_set_tso,
		(void *)&cmd_tunnel_tso_set_mode,
		(void *)&cmd_tunnel_tso_set_tso_segsz,
		(void *)&cmd_tunnel_tso_set_portid,
		NULL,
	},
};

cmdline_parse_token_string_t cmd_tunnel_tso_show_mode =
	TOKEN_STRING_INITIALIZER(struct cmd_tunnel_tso_set_result,
				mode, "show");


cmdline_parse_inst_t cmd_tunnel_tso_show = {
	.f = cmd_tunnel_tso_set_parsed,
	.data = NULL,
	.help_str = "tunnel_tso show <port_id> "
		"Show TSO segment size of tunneled packets for csum engine",
	.tokens = {
		(void *)&cmd_tunnel_tso_set_tso,
		(void *)&cmd_tunnel_tso_show_mode,
		(void *)&cmd_tunnel_tso_set_portid,
		NULL,
	},
};

/* *** SET GRO FOR A PORT *** */
struct cmd_gro_enable_result {
	cmdline_fixed_string_t cmd_set;
	cmdline_fixed_string_t cmd_port;
	cmdline_fixed_string_t cmd_keyword;
	cmdline_fixed_string_t cmd_onoff;
	portid_t cmd_pid;
};

static void
cmd_gro_enable_parsed(void *parsed_result,
		__attribute__((unused)) struct cmdline *cl,
		__attribute__((unused)) void *data)
{
	struct cmd_gro_enable_result *res;

	res = parsed_result;
	if (!strcmp(res->cmd_keyword, "gro"))
		setup_gro(res->cmd_onoff, res->cmd_pid);
}

cmdline_parse_token_string_t cmd_gro_enable_set =
	TOKEN_STRING_INITIALIZER(struct cmd_gro_enable_result,
			cmd_set, "set");
cmdline_parse_token_string_t cmd_gro_enable_port =
	TOKEN_STRING_INITIALIZER(struct cmd_gro_enable_result,
			cmd_keyword, "port");
cmdline_parse_token_num_t cmd_gro_enable_pid =
	TOKEN_NUM_INITIALIZER(struct cmd_gro_enable_result,
			cmd_pid, UINT16);
cmdline_parse_token_string_t cmd_gro_enable_keyword =
	TOKEN_STRING_INITIALIZER(struct cmd_gro_enable_result,
			cmd_keyword, "gro");
cmdline_parse_token_string_t cmd_gro_enable_onoff =
	TOKEN_STRING_INITIALIZER(struct cmd_gro_enable_result,
			cmd_onoff, "on#off");

cmdline_parse_inst_t cmd_gro_enable = {
	.f = cmd_gro_enable_parsed,
	.data = NULL,
	.help_str = "set port <port_id> gro on|off",
	.tokens = {
		(void *)&cmd_gro_enable_set,
		(void *)&cmd_gro_enable_port,
		(void *)&cmd_gro_enable_pid,
		(void *)&cmd_gro_enable_keyword,
		(void *)&cmd_gro_enable_onoff,
		NULL,
	},
};

/* *** DISPLAY GRO CONFIGURATION *** */
struct cmd_gro_show_result {
	cmdline_fixed_string_t cmd_show;
	cmdline_fixed_string_t cmd_port;
	cmdline_fixed_string_t cmd_keyword;
	portid_t cmd_pid;
};

static void
cmd_gro_show_parsed(void *parsed_result,
		__attribute__((unused)) struct cmdline *cl,
		__attribute__((unused)) void *data)
{
	struct cmd_gro_show_result *res;

	res = parsed_result;
	if (!strcmp(res->cmd_keyword, "gro"))
		show_gro(res->cmd_pid);
}

cmdline_parse_token_string_t cmd_gro_show_show =
	TOKEN_STRING_INITIALIZER(struct cmd_gro_show_result,
			cmd_show, "show");
cmdline_parse_token_string_t cmd_gro_show_port =
	TOKEN_STRING_INITIALIZER(struct cmd_gro_show_result,
			cmd_port, "port");
cmdline_parse_token_num_t cmd_gro_show_pid =
	TOKEN_NUM_INITIALIZER(struct cmd_gro_show_result,
			cmd_pid, UINT16);
cmdline_parse_token_string_t cmd_gro_show_keyword =
	TOKEN_STRING_INITIALIZER(struct cmd_gro_show_result,
			cmd_keyword, "gro");

cmdline_parse_inst_t cmd_gro_show = {
	.f = cmd_gro_show_parsed,
	.data = NULL,
	.help_str = "show port <port_id> gro",
	.tokens = {
		(void *)&cmd_gro_show_show,
		(void *)&cmd_gro_show_port,
		(void *)&cmd_gro_show_pid,
		(void *)&cmd_gro_show_keyword,
		NULL,
	},
};

/* *** SET FLUSH CYCLES FOR GRO *** */
struct cmd_gro_flush_result {
	cmdline_fixed_string_t cmd_set;
	cmdline_fixed_string_t cmd_keyword;
	cmdline_fixed_string_t cmd_flush;
	uint8_t cmd_cycles;
};

static void
cmd_gro_flush_parsed(void *parsed_result,
		__attribute__((unused)) struct cmdline *cl,
		__attribute__((unused)) void *data)
{
	struct cmd_gro_flush_result *res;

	res = parsed_result;
	if ((!strcmp(res->cmd_keyword, "gro")) &&
			(!strcmp(res->cmd_flush, "flush")))
		setup_gro_flush_cycles(res->cmd_cycles);
}

cmdline_parse_token_string_t cmd_gro_flush_set =
	TOKEN_STRING_INITIALIZER(struct cmd_gro_flush_result,
			cmd_set, "set");
cmdline_parse_token_string_t cmd_gro_flush_keyword =
	TOKEN_STRING_INITIALIZER(struct cmd_gro_flush_result,
			cmd_keyword, "gro");
cmdline_parse_token_string_t cmd_gro_flush_flush =
	TOKEN_STRING_INITIALIZER(struct cmd_gro_flush_result,
			cmd_flush, "flush");
cmdline_parse_token_num_t cmd_gro_flush_cycles =
	TOKEN_NUM_INITIALIZER(struct cmd_gro_flush_result,
			cmd_cycles, UINT8);

cmdline_parse_inst_t cmd_gro_flush = {
	.f = cmd_gro_flush_parsed,
	.data = NULL,
	.help_str = "set gro flush <cycles>",
	.tokens = {
		(void *)&cmd_gro_flush_set,
		(void *)&cmd_gro_flush_keyword,
		(void *)&cmd_gro_flush_flush,
		(void *)&cmd_gro_flush_cycles,
		NULL,
	},
};

/* *** ENABLE/DISABLE GSO *** */
struct cmd_gso_enable_result {
	cmdline_fixed_string_t cmd_set;
	cmdline_fixed_string_t cmd_port;
	cmdline_fixed_string_t cmd_keyword;
	cmdline_fixed_string_t cmd_mode;
	portid_t cmd_pid;
};

static void
cmd_gso_enable_parsed(void *parsed_result,
		__attribute__((unused)) struct cmdline *cl,
		__attribute__((unused)) void *data)
{
	struct cmd_gso_enable_result *res;

	res = parsed_result;
	if (!strcmp(res->cmd_keyword, "gso"))
		setup_gso(res->cmd_mode, res->cmd_pid);
}

cmdline_parse_token_string_t cmd_gso_enable_set =
	TOKEN_STRING_INITIALIZER(struct cmd_gso_enable_result,
			cmd_set, "set");
cmdline_parse_token_string_t cmd_gso_enable_port =
	TOKEN_STRING_INITIALIZER(struct cmd_gso_enable_result,
			cmd_port, "port");
cmdline_parse_token_string_t cmd_gso_enable_keyword =
	TOKEN_STRING_INITIALIZER(struct cmd_gso_enable_result,
			cmd_keyword, "gso");
cmdline_parse_token_string_t cmd_gso_enable_mode =
	TOKEN_STRING_INITIALIZER(struct cmd_gso_enable_result,
			cmd_mode, "on#off");
cmdline_parse_token_num_t cmd_gso_enable_pid =
	TOKEN_NUM_INITIALIZER(struct cmd_gso_enable_result,
			cmd_pid, UINT16);

cmdline_parse_inst_t cmd_gso_enable = {
	.f = cmd_gso_enable_parsed,
	.data = NULL,
	.help_str = "set port <port_id> gso on|off",
	.tokens = {
		(void *)&cmd_gso_enable_set,
		(void *)&cmd_gso_enable_port,
		(void *)&cmd_gso_enable_pid,
		(void *)&cmd_gso_enable_keyword,
		(void *)&cmd_gso_enable_mode,
		NULL,
	},
};

/* *** SET MAX PACKET LENGTH FOR GSO SEGMENTS *** */
struct cmd_gso_size_result {
	cmdline_fixed_string_t cmd_set;
	cmdline_fixed_string_t cmd_keyword;
	cmdline_fixed_string_t cmd_segsz;
	uint16_t cmd_size;
};

static void
cmd_gso_size_parsed(void *parsed_result,
		       __attribute__((unused)) struct cmdline *cl,
		       __attribute__((unused)) void *data)
{
	struct cmd_gso_size_result *res = parsed_result;

	if (test_done == 0) {
		printf("Before setting GSO segsz, please first"
				" stop fowarding\n");
		return;
	}

	if (!strcmp(res->cmd_keyword, "gso") &&
			!strcmp(res->cmd_segsz, "segsz")) {
		if (res->cmd_size < RTE_GSO_SEG_SIZE_MIN)
			printf("gso_size should be larger than %zu."
					" Please input a legal value\n",
					RTE_GSO_SEG_SIZE_MIN);
		else
			gso_max_segment_size = res->cmd_size;
	}
}

cmdline_parse_token_string_t cmd_gso_size_set =
	TOKEN_STRING_INITIALIZER(struct cmd_gso_size_result,
				cmd_set, "set");
cmdline_parse_token_string_t cmd_gso_size_keyword =
	TOKEN_STRING_INITIALIZER(struct cmd_gso_size_result,
				cmd_keyword, "gso");
cmdline_parse_token_string_t cmd_gso_size_segsz =
	TOKEN_STRING_INITIALIZER(struct cmd_gso_size_result,
				cmd_segsz, "segsz");
cmdline_parse_token_num_t cmd_gso_size_size =
	TOKEN_NUM_INITIALIZER(struct cmd_gso_size_result,
				cmd_size, UINT16);

cmdline_parse_inst_t cmd_gso_size = {
	.f = cmd_gso_size_parsed,
	.data = NULL,
	.help_str = "set gso segsz <length>",
	.tokens = {
		(void *)&cmd_gso_size_set,
		(void *)&cmd_gso_size_keyword,
		(void *)&cmd_gso_size_segsz,
		(void *)&cmd_gso_size_size,
		NULL,
	},
};

/* *** SHOW GSO CONFIGURATION *** */
struct cmd_gso_show_result {
	cmdline_fixed_string_t cmd_show;
	cmdline_fixed_string_t cmd_port;
	cmdline_fixed_string_t cmd_keyword;
	portid_t cmd_pid;
};

static void
cmd_gso_show_parsed(void *parsed_result,
		       __attribute__((unused)) struct cmdline *cl,
		       __attribute__((unused)) void *data)
{
	struct cmd_gso_show_result *res = parsed_result;

	if (!rte_eth_dev_is_valid_port(res->cmd_pid)) {
		printf("invalid port id %u\n", res->cmd_pid);
		return;
	}
	if (!strcmp(res->cmd_keyword, "gso")) {
		if (gso_ports[res->cmd_pid].enable) {
			printf("Max GSO'd packet size: %uB\n"
					"Supported GSO types: TCP/IPv4, "
					"UDP/IPv4, VxLAN with inner "
					"TCP/IPv4 packet, GRE with inner "
					"TCP/IPv4 packet\n",
					gso_max_segment_size);
		} else
			printf("GSO is not enabled on Port %u\n", res->cmd_pid);
	}
}

cmdline_parse_token_string_t cmd_gso_show_show =
TOKEN_STRING_INITIALIZER(struct cmd_gso_show_result,
		cmd_show, "show");
cmdline_parse_token_string_t cmd_gso_show_port =
TOKEN_STRING_INITIALIZER(struct cmd_gso_show_result,
		cmd_port, "port");
cmdline_parse_token_string_t cmd_gso_show_keyword =
	TOKEN_STRING_INITIALIZER(struct cmd_gso_show_result,
				cmd_keyword, "gso");
cmdline_parse_token_num_t cmd_gso_show_pid =
	TOKEN_NUM_INITIALIZER(struct cmd_gso_show_result,
				cmd_pid, UINT16);

cmdline_parse_inst_t cmd_gso_show = {
	.f = cmd_gso_show_parsed,
	.data = NULL,
	.help_str = "show port <port_id> gso",
	.tokens = {
		(void *)&cmd_gso_show_show,
		(void *)&cmd_gso_show_port,
		(void *)&cmd_gso_show_pid,
		(void *)&cmd_gso_show_keyword,
		NULL,
	},
};

/* *** ENABLE/DISABLE FLUSH ON RX STREAMS *** */
struct cmd_set_flush_rx {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t flush_rx;
	cmdline_fixed_string_t mode;
};

static void
cmd_set_flush_rx_parsed(void *parsed_result,
		__attribute__((unused)) struct cmdline *cl,
		__attribute__((unused)) void *data)
{
	struct cmd_set_flush_rx *res = parsed_result;
	no_flush_rx = (uint8_t)((strcmp(res->mode, "on") == 0) ? 0 : 1);
}

cmdline_parse_token_string_t cmd_setflushrx_set =
	TOKEN_STRING_INITIALIZER(struct cmd_set_flush_rx,
			set, "set");
cmdline_parse_token_string_t cmd_setflushrx_flush_rx =
	TOKEN_STRING_INITIALIZER(struct cmd_set_flush_rx,
			flush_rx, "flush_rx");
cmdline_parse_token_string_t cmd_setflushrx_mode =
	TOKEN_STRING_INITIALIZER(struct cmd_set_flush_rx,
			mode, "on#off");


cmdline_parse_inst_t cmd_set_flush_rx = {
	.f = cmd_set_flush_rx_parsed,
	.help_str = "set flush_rx on|off: Enable/Disable flush on rx streams",
	.data = NULL,
	.tokens = {
		(void *)&cmd_setflushrx_set,
		(void *)&cmd_setflushrx_flush_rx,
		(void *)&cmd_setflushrx_mode,
		NULL,
	},
};

/* *** ENABLE/DISABLE LINK STATUS CHECK *** */
struct cmd_set_link_check {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t link_check;
	cmdline_fixed_string_t mode;
};

static void
cmd_set_link_check_parsed(void *parsed_result,
		__attribute__((unused)) struct cmdline *cl,
		__attribute__((unused)) void *data)
{
	struct cmd_set_link_check *res = parsed_result;
	no_link_check = (uint8_t)((strcmp(res->mode, "on") == 0) ? 0 : 1);
}

cmdline_parse_token_string_t cmd_setlinkcheck_set =
	TOKEN_STRING_INITIALIZER(struct cmd_set_link_check,
			set, "set");
cmdline_parse_token_string_t cmd_setlinkcheck_link_check =
	TOKEN_STRING_INITIALIZER(struct cmd_set_link_check,
			link_check, "link_check");
cmdline_parse_token_string_t cmd_setlinkcheck_mode =
	TOKEN_STRING_INITIALIZER(struct cmd_set_link_check,
			mode, "on#off");


cmdline_parse_inst_t cmd_set_link_check = {
	.f = cmd_set_link_check_parsed,
	.help_str = "set link_check on|off: Enable/Disable link status check "
	            "when starting/stopping a port",
	.data = NULL,
	.tokens = {
		(void *)&cmd_setlinkcheck_set,
		(void *)&cmd_setlinkcheck_link_check,
		(void *)&cmd_setlinkcheck_mode,
		NULL,
	},
};

/* *** SET NIC BYPASS MODE *** */
struct cmd_set_bypass_mode_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t bypass;
	cmdline_fixed_string_t mode;
	cmdline_fixed_string_t value;
	portid_t port_id;
};

static void
cmd_set_bypass_mode_parsed(void *parsed_result,
		__attribute__((unused)) struct cmdline *cl,
		__attribute__((unused)) void *data)
{
	struct cmd_set_bypass_mode_result *res = parsed_result;
	portid_t port_id = res->port_id;
	int32_t rc = -EINVAL;

#if defined RTE_LIBRTE_IXGBE_PMD && defined RTE_LIBRTE_IXGBE_BYPASS
	uint32_t bypass_mode = RTE_PMD_IXGBE_BYPASS_MODE_NORMAL;

	if (!strcmp(res->value, "bypass"))
		bypass_mode = RTE_PMD_IXGBE_BYPASS_MODE_BYPASS;
	else if (!strcmp(res->value, "isolate"))
		bypass_mode = RTE_PMD_IXGBE_BYPASS_MODE_ISOLATE;
	else
		bypass_mode = RTE_PMD_IXGBE_BYPASS_MODE_NORMAL;

	/* Set the bypass mode for the relevant port. */
	rc = rte_pmd_ixgbe_bypass_state_set(port_id, &bypass_mode);
#endif
	if (rc != 0)
		printf("\t Failed to set bypass mode for port = %d.\n", port_id);
}

cmdline_parse_token_string_t cmd_setbypass_mode_set =
	TOKEN_STRING_INITIALIZER(struct cmd_set_bypass_mode_result,
			set, "set");
cmdline_parse_token_string_t cmd_setbypass_mode_bypass =
	TOKEN_STRING_INITIALIZER(struct cmd_set_bypass_mode_result,
			bypass, "bypass");
cmdline_parse_token_string_t cmd_setbypass_mode_mode =
	TOKEN_STRING_INITIALIZER(struct cmd_set_bypass_mode_result,
			mode, "mode");
cmdline_parse_token_string_t cmd_setbypass_mode_value =
	TOKEN_STRING_INITIALIZER(struct cmd_set_bypass_mode_result,
			value, "normal#bypass#isolate");
cmdline_parse_token_num_t cmd_setbypass_mode_port =
	TOKEN_NUM_INITIALIZER(struct cmd_set_bypass_mode_result,
				port_id, UINT16);

cmdline_parse_inst_t cmd_set_bypass_mode = {
	.f = cmd_set_bypass_mode_parsed,
	.help_str = "set bypass mode normal|bypass|isolate <port_id>: "
	            "Set the NIC bypass mode for port_id",
	.data = NULL,
	.tokens = {
		(void *)&cmd_setbypass_mode_set,
		(void *)&cmd_setbypass_mode_bypass,
		(void *)&cmd_setbypass_mode_mode,
		(void *)&cmd_setbypass_mode_value,
		(void *)&cmd_setbypass_mode_port,
		NULL,
	},
};

/* *** SET NIC BYPASS EVENT *** */
struct cmd_set_bypass_event_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t bypass;
	cmdline_fixed_string_t event;
	cmdline_fixed_string_t event_value;
	cmdline_fixed_string_t mode;
	cmdline_fixed_string_t mode_value;
	portid_t port_id;
};

static void
cmd_set_bypass_event_parsed(void *parsed_result,
		__attribute__((unused)) struct cmdline *cl,
		__attribute__((unused)) void *data)
{
	int32_t rc = -EINVAL;
	struct cmd_set_bypass_event_result *res = parsed_result;
	portid_t port_id = res->port_id;

#if defined RTE_LIBRTE_IXGBE_PMD && defined RTE_LIBRTE_IXGBE_BYPASS
	uint32_t bypass_event = RTE_PMD_IXGBE_BYPASS_EVENT_NONE;
	uint32_t bypass_mode = RTE_PMD_IXGBE_BYPASS_MODE_NORMAL;

	if (!strcmp(res->event_value, "timeout"))
		bypass_event = RTE_PMD_IXGBE_BYPASS_EVENT_TIMEOUT;
	else if (!strcmp(res->event_value, "os_on"))
		bypass_event = RTE_PMD_IXGBE_BYPASS_EVENT_OS_ON;
	else if (!strcmp(res->event_value, "os_off"))
		bypass_event = RTE_PMD_IXGBE_BYPASS_EVENT_OS_OFF;
	else if (!strcmp(res->event_value, "power_on"))
		bypass_event = RTE_PMD_IXGBE_BYPASS_EVENT_POWER_ON;
	else if (!strcmp(res->event_value, "power_off"))
		bypass_event = RTE_PMD_IXGBE_BYPASS_EVENT_POWER_OFF;
	else
		bypass_event = RTE_PMD_IXGBE_BYPASS_EVENT_NONE;

	if (!strcmp(res->mode_value, "bypass"))
		bypass_mode = RTE_PMD_IXGBE_BYPASS_MODE_BYPASS;
	else if (!strcmp(res->mode_value, "isolate"))
		bypass_mode = RTE_PMD_IXGBE_BYPASS_MODE_ISOLATE;
	else
		bypass_mode = RTE_PMD_IXGBE_BYPASS_MODE_NORMAL;

	/* Set the watchdog timeout. */
	if (bypass_event == RTE_PMD_IXGBE_BYPASS_EVENT_TIMEOUT) {

		rc = -EINVAL;
		if (RTE_PMD_IXGBE_BYPASS_TMT_VALID(bypass_timeout)) {
			rc = rte_pmd_ixgbe_bypass_wd_timeout_store(port_id,
							   bypass_timeout);
		}
		if (rc != 0) {
			printf("Failed to set timeout value %u "
			"for port %d, errto code: %d.\n",
			bypass_timeout, port_id, rc);
		}
	}

	/* Set the bypass event to transition to bypass mode. */
	rc = rte_pmd_ixgbe_bypass_event_store(port_id, bypass_event,
					      bypass_mode);
#endif

	if (rc != 0)
		printf("\t Failed to set bypass event for port = %d.\n",
		       port_id);
}

cmdline_parse_token_string_t cmd_setbypass_event_set =
	TOKEN_STRING_INITIALIZER(struct cmd_set_bypass_event_result,
			set, "set");
cmdline_parse_token_string_t cmd_setbypass_event_bypass =
	TOKEN_STRING_INITIALIZER(struct cmd_set_bypass_event_result,
			bypass, "bypass");
cmdline_parse_token_string_t cmd_setbypass_event_event =
	TOKEN_STRING_INITIALIZER(struct cmd_set_bypass_event_result,
			event, "event");
cmdline_parse_token_string_t cmd_setbypass_event_event_value =
	TOKEN_STRING_INITIALIZER(struct cmd_set_bypass_event_result,
			event_value, "none#timeout#os_off#os_on#power_on#power_off");
cmdline_parse_token_string_t cmd_setbypass_event_mode =
	TOKEN_STRING_INITIALIZER(struct cmd_set_bypass_event_result,
			mode, "mode");
cmdline_parse_token_string_t cmd_setbypass_event_mode_value =
	TOKEN_STRING_INITIALIZER(struct cmd_set_bypass_event_result,
			mode_value, "normal#bypass#isolate");
cmdline_parse_token_num_t cmd_setbypass_event_port =
	TOKEN_NUM_INITIALIZER(struct cmd_set_bypass_event_result,
				port_id, UINT16);

cmdline_parse_inst_t cmd_set_bypass_event = {
	.f = cmd_set_bypass_event_parsed,
	.help_str = "set bypass event none|timeout|os_on|os_off|power_on|"
		"power_off mode normal|bypass|isolate <port_id>: "
		"Set the NIC bypass event mode for port_id",
	.data = NULL,
	.tokens = {
		(void *)&cmd_setbypass_event_set,
		(void *)&cmd_setbypass_event_bypass,
		(void *)&cmd_setbypass_event_event,
		(void *)&cmd_setbypass_event_event_value,
		(void *)&cmd_setbypass_event_mode,
		(void *)&cmd_setbypass_event_mode_value,
		(void *)&cmd_setbypass_event_port,
		NULL,
	},
};


/* *** SET NIC BYPASS TIMEOUT *** */
struct cmd_set_bypass_timeout_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t bypass;
	cmdline_fixed_string_t timeout;
	cmdline_fixed_string_t value;
};

static void
cmd_set_bypass_timeout_parsed(void *parsed_result,
		__attribute__((unused)) struct cmdline *cl,
		__attribute__((unused)) void *data)
{
	__rte_unused struct cmd_set_bypass_timeout_result *res = parsed_result;

#if defined RTE_LIBRTE_IXGBE_PMD && defined RTE_LIBRTE_IXGBE_BYPASS
	if (!strcmp(res->value, "1.5"))
		bypass_timeout = RTE_PMD_IXGBE_BYPASS_TMT_1_5_SEC;
	else if (!strcmp(res->value, "2"))
		bypass_timeout = RTE_PMD_IXGBE_BYPASS_TMT_2_SEC;
	else if (!strcmp(res->value, "3"))
		bypass_timeout = RTE_PMD_IXGBE_BYPASS_TMT_3_SEC;
	else if (!strcmp(res->value, "4"))
		bypass_timeout = RTE_PMD_IXGBE_BYPASS_TMT_4_SEC;
	else if (!strcmp(res->value, "8"))
		bypass_timeout = RTE_PMD_IXGBE_BYPASS_TMT_8_SEC;
	else if (!strcmp(res->value, "16"))
		bypass_timeout = RTE_PMD_IXGBE_BYPASS_TMT_16_SEC;
	else if (!strcmp(res->value, "32"))
		bypass_timeout = RTE_PMD_IXGBE_BYPASS_TMT_32_SEC;
	else
		bypass_timeout = RTE_PMD_IXGBE_BYPASS_TMT_OFF;
#endif
}

cmdline_parse_token_string_t cmd_setbypass_timeout_set =
	TOKEN_STRING_INITIALIZER(struct cmd_set_bypass_timeout_result,
			set, "set");
cmdline_parse_token_string_t cmd_setbypass_timeout_bypass =
	TOKEN_STRING_INITIALIZER(struct cmd_set_bypass_timeout_result,
			bypass, "bypass");
cmdline_parse_token_string_t cmd_setbypass_timeout_timeout =
	TOKEN_STRING_INITIALIZER(struct cmd_set_bypass_timeout_result,
			timeout, "timeout");
cmdline_parse_token_string_t cmd_setbypass_timeout_value =
	TOKEN_STRING_INITIALIZER(struct cmd_set_bypass_timeout_result,
			value, "0#1.5#2#3#4#8#16#32");

cmdline_parse_inst_t cmd_set_bypass_timeout = {
	.f = cmd_set_bypass_timeout_parsed,
	.help_str = "set bypass timeout 0|1.5|2|3|4|8|16|32: "
		"Set the NIC bypass watchdog timeout in seconds",
	.data = NULL,
	.tokens = {
		(void *)&cmd_setbypass_timeout_set,
		(void *)&cmd_setbypass_timeout_bypass,
		(void *)&cmd_setbypass_timeout_timeout,
		(void *)&cmd_setbypass_timeout_value,
		NULL,
	},
};

/* *** SHOW NIC BYPASS MODE *** */
struct cmd_show_bypass_config_result {
	cmdline_fixed_string_t show;
	cmdline_fixed_string_t bypass;
	cmdline_fixed_string_t config;
	portid_t port_id;
};

static void
cmd_show_bypass_config_parsed(void *parsed_result,
		__attribute__((unused)) struct cmdline *cl,
		__attribute__((unused)) void *data)
{
	struct cmd_show_bypass_config_result *res = parsed_result;
	portid_t port_id = res->port_id;
	int rc = -EINVAL;
#if defined RTE_LIBRTE_IXGBE_PMD && defined RTE_LIBRTE_IXGBE_BYPASS
	uint32_t event_mode;
	uint32_t bypass_mode;
	uint32_t timeout = bypass_timeout;
	int i;

	static const char * const timeouts[RTE_PMD_IXGBE_BYPASS_TMT_NUM] =
		{"off", "1.5", "2", "3", "4", "8", "16", "32"};
	static const char * const modes[RTE_PMD_IXGBE_BYPASS_MODE_NUM] =
		{"UNKNOWN", "normal", "bypass", "isolate"};
	static const char * const events[RTE_PMD_IXGBE_BYPASS_EVENT_NUM] = {
		"NONE",
		"OS/board on",
		"power supply on",
		"OS/board off",
		"power supply off",
		"timeout"};
	int num_events = (sizeof events) / (sizeof events[0]);

	/* Display the bypass mode.*/
	if (rte_pmd_ixgbe_bypass_state_show(port_id, &bypass_mode) != 0) {
		printf("\tFailed to get bypass mode for port = %d\n", port_id);
		return;
	}
	else {
		if (!RTE_PMD_IXGBE_BYPASS_MODE_VALID(bypass_mode))
			bypass_mode = RTE_PMD_IXGBE_BYPASS_MODE_NONE;

		printf("\tbypass mode    = %s\n",  modes[bypass_mode]);
	}

	/* Display the bypass timeout.*/
	if (!RTE_PMD_IXGBE_BYPASS_TMT_VALID(timeout))
		timeout = RTE_PMD_IXGBE_BYPASS_TMT_OFF;

	printf("\tbypass timeout = %s\n", timeouts[timeout]);

	/* Display the bypass events and associated modes. */
	for (i = RTE_PMD_IXGBE_BYPASS_EVENT_START; i < num_events; i++) {

		if (rte_pmd_ixgbe_bypass_event_show(port_id, i, &event_mode)) {
			printf("\tFailed to get bypass mode for event = %s\n",
				events[i]);
		} else {
			if (!RTE_PMD_IXGBE_BYPASS_MODE_VALID(event_mode))
				event_mode = RTE_PMD_IXGBE_BYPASS_MODE_NONE;

			printf("\tbypass event: %-16s = %s\n", events[i],
				modes[event_mode]);
		}
	}
#endif
	if (rc != 0)
		printf("\tFailed to get bypass configuration for port = %d\n",
		       port_id);
}

cmdline_parse_token_string_t cmd_showbypass_config_show =
	TOKEN_STRING_INITIALIZER(struct cmd_show_bypass_config_result,
			show, "show");
cmdline_parse_token_string_t cmd_showbypass_config_bypass =
	TOKEN_STRING_INITIALIZER(struct cmd_show_bypass_config_result,
			bypass, "bypass");
cmdline_parse_token_string_t cmd_showbypass_config_config =
	TOKEN_STRING_INITIALIZER(struct cmd_show_bypass_config_result,
			config, "config");
cmdline_parse_token_num_t cmd_showbypass_config_port =
	TOKEN_NUM_INITIALIZER(struct cmd_show_bypass_config_result,
				port_id, UINT16);

cmdline_parse_inst_t cmd_show_bypass_config = {
	.f = cmd_show_bypass_config_parsed,
	.help_str = "show bypass config <port_id>: "
	            "Show the NIC bypass config for port_id",
	.data = NULL,
	.tokens = {
		(void *)&cmd_showbypass_config_show,
		(void *)&cmd_showbypass_config_bypass,
		(void *)&cmd_showbypass_config_config,
		(void *)&cmd_showbypass_config_port,
		NULL,
	},
};

#ifdef RTE_LIBRTE_PMD_BOND
/* *** SET BONDING MODE *** */
struct cmd_set_bonding_mode_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t bonding;
	cmdline_fixed_string_t mode;
	uint8_t value;
	portid_t port_id;
};

static void cmd_set_bonding_mode_parsed(void *parsed_result,
		__attribute__((unused))  struct cmdline *cl,
		__attribute__((unused)) void *data)
{
	struct cmd_set_bonding_mode_result *res = parsed_result;
	portid_t port_id = res->port_id;

	/* Set the bonding mode for the relevant port. */
	if (0 != rte_eth_bond_mode_set(port_id, res->value))
		printf("\t Failed to set bonding mode for port = %d.\n", port_id);
}

cmdline_parse_token_string_t cmd_setbonding_mode_set =
TOKEN_STRING_INITIALIZER(struct cmd_set_bonding_mode_result,
		set, "set");
cmdline_parse_token_string_t cmd_setbonding_mode_bonding =
TOKEN_STRING_INITIALIZER(struct cmd_set_bonding_mode_result,
		bonding, "bonding");
cmdline_parse_token_string_t cmd_setbonding_mode_mode =
TOKEN_STRING_INITIALIZER(struct cmd_set_bonding_mode_result,
		mode, "mode");
cmdline_parse_token_num_t cmd_setbonding_mode_value =
TOKEN_NUM_INITIALIZER(struct cmd_set_bonding_mode_result,
		value, UINT8);
cmdline_parse_token_num_t cmd_setbonding_mode_port =
TOKEN_NUM_INITIALIZER(struct cmd_set_bonding_mode_result,
		port_id, UINT16);

cmdline_parse_inst_t cmd_set_bonding_mode = {
		.f = cmd_set_bonding_mode_parsed,
		.help_str = "set bonding mode <mode_value> <port_id>: "
			"Set the bonding mode for port_id",
		.data = NULL,
		.tokens = {
				(void *) &cmd_setbonding_mode_set,
				(void *) &cmd_setbonding_mode_bonding,
				(void *) &cmd_setbonding_mode_mode,
				(void *) &cmd_setbonding_mode_value,
				(void *) &cmd_setbonding_mode_port,
				NULL
		}
};

/* *** SET BONDING SLOW_QUEUE SW/HW *** */
struct cmd_set_bonding_lacp_dedicated_queues_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t bonding;
	cmdline_fixed_string_t lacp;
	cmdline_fixed_string_t dedicated_queues;
	portid_t port_id;
	cmdline_fixed_string_t mode;
};

static void cmd_set_bonding_lacp_dedicated_queues_parsed(void *parsed_result,
		__attribute__((unused))  struct cmdline *cl,
		__attribute__((unused)) void *data)
{
	struct cmd_set_bonding_lacp_dedicated_queues_result *res = parsed_result;
	portid_t port_id = res->port_id;
	struct rte_port *port;

	port = &ports[port_id];

	/** Check if the port is not started **/
	if (port->port_status != RTE_PORT_STOPPED) {
		printf("Please stop port %d first\n", port_id);
		return;
	}

	if (!strcmp(res->mode, "enable")) {
		if (rte_eth_bond_8023ad_dedicated_queues_enable(port_id) == 0)
			printf("Dedicate queues for LACP control packets"
					" enabled\n");
		else
			printf("Enabling dedicate queues for LACP control "
					"packets on port %d failed\n", port_id);
	} else if (!strcmp(res->mode, "disable")) {
		if (rte_eth_bond_8023ad_dedicated_queues_disable(port_id) == 0)
			printf("Dedicated queues for LACP control packets "
					"disabled\n");
		else
			printf("Disabling dedicated queues for LACP control "
					"traffic on port %d failed\n", port_id);
	}
}

cmdline_parse_token_string_t cmd_setbonding_lacp_dedicated_queues_set =
TOKEN_STRING_INITIALIZER(struct cmd_set_bonding_lacp_dedicated_queues_result,
		set, "set");
cmdline_parse_token_string_t cmd_setbonding_lacp_dedicated_queues_bonding =
TOKEN_STRING_INITIALIZER(struct cmd_set_bonding_lacp_dedicated_queues_result,
		bonding, "bonding");
cmdline_parse_token_string_t cmd_setbonding_lacp_dedicated_queues_lacp =
TOKEN_STRING_INITIALIZER(struct cmd_set_bonding_lacp_dedicated_queues_result,
		lacp, "lacp");
cmdline_parse_token_string_t cmd_setbonding_lacp_dedicated_queues_dedicated_queues =
TOKEN_STRING_INITIALIZER(struct cmd_set_bonding_lacp_dedicated_queues_result,
		dedicated_queues, "dedicated_queues");
cmdline_parse_token_num_t cmd_setbonding_lacp_dedicated_queues_port_id =
TOKEN_NUM_INITIALIZER(struct cmd_set_bonding_lacp_dedicated_queues_result,
		port_id, UINT16);
cmdline_parse_token_string_t cmd_setbonding_lacp_dedicated_queues_mode =
TOKEN_STRING_INITIALIZER(struct cmd_set_bonding_lacp_dedicated_queues_result,
		mode, "enable#disable");

cmdline_parse_inst_t cmd_set_lacp_dedicated_queues = {
		.f = cmd_set_bonding_lacp_dedicated_queues_parsed,
		.help_str = "set bonding lacp dedicated_queues <port_id> "
			"enable|disable: "
			"Enable/disable dedicated queues for LACP control traffic for port_id",
		.data = NULL,
		.tokens = {
			(void *)&cmd_setbonding_lacp_dedicated_queues_set,
			(void *)&cmd_setbonding_lacp_dedicated_queues_bonding,
			(void *)&cmd_setbonding_lacp_dedicated_queues_lacp,
			(void *)&cmd_setbonding_lacp_dedicated_queues_dedicated_queues,
			(void *)&cmd_setbonding_lacp_dedicated_queues_port_id,
			(void *)&cmd_setbonding_lacp_dedicated_queues_mode,
			NULL
		}
};

/* *** SET BALANCE XMIT POLICY *** */
struct cmd_set_bonding_balance_xmit_policy_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t bonding;
	cmdline_fixed_string_t balance_xmit_policy;
	portid_t port_id;
	cmdline_fixed_string_t policy;
};

static void cmd_set_bonding_balance_xmit_policy_parsed(void *parsed_result,
		__attribute__((unused))  struct cmdline *cl,
		__attribute__((unused)) void *data)
{
	struct cmd_set_bonding_balance_xmit_policy_result *res = parsed_result;
	portid_t port_id = res->port_id;
	uint8_t policy;

	if (!strcmp(res->policy, "l2")) {
		policy = BALANCE_XMIT_POLICY_LAYER2;
	} else if (!strcmp(res->policy, "l23")) {
		policy = BALANCE_XMIT_POLICY_LAYER23;
	} else if (!strcmp(res->policy, "l34")) {
		policy = BALANCE_XMIT_POLICY_LAYER34;
	} else {
		printf("\t Invalid xmit policy selection");
		return;
	}

	/* Set the bonding mode for the relevant port. */
	if (0 != rte_eth_bond_xmit_policy_set(port_id, policy)) {
		printf("\t Failed to set bonding balance xmit policy for port = %d.\n",
				port_id);
	}
}

cmdline_parse_token_string_t cmd_setbonding_balance_xmit_policy_set =
TOKEN_STRING_INITIALIZER(struct cmd_set_bonding_balance_xmit_policy_result,
		set, "set");
cmdline_parse_token_string_t cmd_setbonding_balance_xmit_policy_bonding =
TOKEN_STRING_INITIALIZER(struct cmd_set_bonding_balance_xmit_policy_result,
		bonding, "bonding");
cmdline_parse_token_string_t cmd_setbonding_balance_xmit_policy_balance_xmit_policy =
TOKEN_STRING_INITIALIZER(struct cmd_set_bonding_balance_xmit_policy_result,
		balance_xmit_policy, "balance_xmit_policy");
cmdline_parse_token_num_t cmd_setbonding_balance_xmit_policy_port =
TOKEN_NUM_INITIALIZER(struct cmd_set_bonding_balance_xmit_policy_result,
		port_id, UINT16);
cmdline_parse_token_string_t cmd_setbonding_balance_xmit_policy_policy =
TOKEN_STRING_INITIALIZER(struct cmd_set_bonding_balance_xmit_policy_result,
		policy, "l2#l23#l34");

cmdline_parse_inst_t cmd_set_balance_xmit_policy = {
		.f = cmd_set_bonding_balance_xmit_policy_parsed,
		.help_str = "set bonding balance_xmit_policy <port_id> "
			"l2|l23|l34: "
			"Set the bonding balance_xmit_policy for port_id",
		.data = NULL,
		.tokens = {
				(void *)&cmd_setbonding_balance_xmit_policy_set,
				(void *)&cmd_setbonding_balance_xmit_policy_bonding,
				(void *)&cmd_setbonding_balance_xmit_policy_balance_xmit_policy,
				(void *)&cmd_setbonding_balance_xmit_policy_port,
				(void *)&cmd_setbonding_balance_xmit_policy_policy,
				NULL
		}
};

/* *** SHOW NIC BONDING CONFIGURATION *** */
struct cmd_show_bonding_config_result {
	cmdline_fixed_string_t show;
	cmdline_fixed_string_t bonding;
	cmdline_fixed_string_t config;
	portid_t port_id;
};

static void cmd_show_bonding_config_parsed(void *parsed_result,
		__attribute__((unused))  struct cmdline *cl,
		__attribute__((unused)) void *data)
{
	struct cmd_show_bonding_config_result *res = parsed_result;
	int bonding_mode, agg_mode;
	portid_t slaves[RTE_MAX_ETHPORTS];
	int num_slaves, num_active_slaves;
	int primary_id;
	int i;
	portid_t port_id = res->port_id;

	/* Display the bonding mode.*/
	bonding_mode = rte_eth_bond_mode_get(port_id);
	if (bonding_mode < 0) {
		printf("\tFailed to get bonding mode for port = %d\n", port_id);
		return;
	} else
		printf("\tBonding mode: %d\n", bonding_mode);

	if (bonding_mode == BONDING_MODE_BALANCE) {
		int balance_xmit_policy;

		balance_xmit_policy = rte_eth_bond_xmit_policy_get(port_id);
		if (balance_xmit_policy < 0) {
			printf("\tFailed to get balance xmit policy for port = %d\n",
					port_id);
			return;
		} else {
			printf("\tBalance Xmit Policy: ");

			switch (balance_xmit_policy) {
			case BALANCE_XMIT_POLICY_LAYER2:
				printf("BALANCE_XMIT_POLICY_LAYER2");
				break;
			case BALANCE_XMIT_POLICY_LAYER23:
				printf("BALANCE_XMIT_POLICY_LAYER23");
				break;
			case BALANCE_XMIT_POLICY_LAYER34:
				printf("BALANCE_XMIT_POLICY_LAYER34");
				break;
			}
			printf("\n");
		}
	}

	if (bonding_mode == BONDING_MODE_8023AD) {
		agg_mode = rte_eth_bond_8023ad_agg_selection_get(port_id);
		printf("\tIEEE802.3AD Aggregator Mode: ");
		switch (agg_mode) {
		case AGG_BANDWIDTH:
			printf("bandwidth");
			break;
		case AGG_STABLE:
			printf("stable");
			break;
		case AGG_COUNT:
			printf("count");
			break;
		}
		printf("\n");
	}

	num_slaves = rte_eth_bond_slaves_get(port_id, slaves, RTE_MAX_ETHPORTS);

	if (num_slaves < 0) {
		printf("\tFailed to get slave list for port = %d\n", port_id);
		return;
	}
	if (num_slaves > 0) {
		printf("\tSlaves (%d): [", num_slaves);
		for (i = 0; i < num_slaves - 1; i++)
			printf("%d ", slaves[i]);

		printf("%d]\n", slaves[num_slaves - 1]);
	} else {
		printf("\tSlaves: []\n");

	}

	num_active_slaves = rte_eth_bond_active_slaves_get(port_id, slaves,
			RTE_MAX_ETHPORTS);

	if (num_active_slaves < 0) {
		printf("\tFailed to get active slave list for port = %d\n", port_id);
		return;
	}
	if (num_active_slaves > 0) {
		printf("\tActive Slaves (%d): [", num_active_slaves);
		for (i = 0; i < num_active_slaves - 1; i++)
			printf("%d ", slaves[i]);

		printf("%d]\n", slaves[num_active_slaves - 1]);

	} else {
		printf("\tActive Slaves: []\n");

	}

	primary_id = rte_eth_bond_primary_get(port_id);
	if (primary_id < 0) {
		printf("\tFailed to get primary slave for port = %d\n", port_id);
		return;
	} else
		printf("\tPrimary: [%d]\n", primary_id);

}

cmdline_parse_token_string_t cmd_showbonding_config_show =
TOKEN_STRING_INITIALIZER(struct cmd_show_bonding_config_result,
		show, "show");
cmdline_parse_token_string_t cmd_showbonding_config_bonding =
TOKEN_STRING_INITIALIZER(struct cmd_show_bonding_config_result,
		bonding, "bonding");
cmdline_parse_token_string_t cmd_showbonding_config_config =
TOKEN_STRING_INITIALIZER(struct cmd_show_bonding_config_result,
		config, "config");
cmdline_parse_token_num_t cmd_showbonding_config_port =
TOKEN_NUM_INITIALIZER(struct cmd_show_bonding_config_result,
		port_id, UINT16);

cmdline_parse_inst_t cmd_show_bonding_config = {
		.f = cmd_show_bonding_config_parsed,
		.help_str = "show bonding config <port_id>: "
			"Show the bonding config for port_id",
		.data = NULL,
		.tokens = {
				(void *)&cmd_showbonding_config_show,
				(void *)&cmd_showbonding_config_bonding,
				(void *)&cmd_showbonding_config_config,
				(void *)&cmd_showbonding_config_port,
				NULL
		}
};

/* *** SET BONDING PRIMARY *** */
struct cmd_set_bonding_primary_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t bonding;
	cmdline_fixed_string_t primary;
	portid_t slave_id;
	portid_t port_id;
};

static void cmd_set_bonding_primary_parsed(void *parsed_result,
		__attribute__((unused))  struct cmdline *cl,
		__attribute__((unused)) void *data)
{
	struct cmd_set_bonding_primary_result *res = parsed_result;
	portid_t master_port_id = res->port_id;
	portid_t slave_port_id = res->slave_id;

	/* Set the primary slave for a bonded device. */
	if (0 != rte_eth_bond_primary_set(master_port_id, slave_port_id)) {
		printf("\t Failed to set primary slave for port = %d.\n",
				master_port_id);
		return;
	}
	init_port_config();
}

cmdline_parse_token_string_t cmd_setbonding_primary_set =
TOKEN_STRING_INITIALIZER(struct cmd_set_bonding_primary_result,
		set, "set");
cmdline_parse_token_string_t cmd_setbonding_primary_bonding =
TOKEN_STRING_INITIALIZER(struct cmd_set_bonding_primary_result,
		bonding, "bonding");
cmdline_parse_token_string_t cmd_setbonding_primary_primary =
TOKEN_STRING_INITIALIZER(struct cmd_set_bonding_primary_result,
		primary, "primary");
cmdline_parse_token_num_t cmd_setbonding_primary_slave =
TOKEN_NUM_INITIALIZER(struct cmd_set_bonding_primary_result,
		slave_id, UINT16);
cmdline_parse_token_num_t cmd_setbonding_primary_port =
TOKEN_NUM_INITIALIZER(struct cmd_set_bonding_primary_result,
		port_id, UINT16);

cmdline_parse_inst_t cmd_set_bonding_primary = {
		.f = cmd_set_bonding_primary_parsed,
		.help_str = "set bonding primary <slave_id> <port_id>: "
			"Set the primary slave for port_id",
		.data = NULL,
		.tokens = {
				(void *)&cmd_setbonding_primary_set,
				(void *)&cmd_setbonding_primary_bonding,
				(void *)&cmd_setbonding_primary_primary,
				(void *)&cmd_setbonding_primary_slave,
				(void *)&cmd_setbonding_primary_port,
				NULL
		}
};

/* *** ADD SLAVE *** */
struct cmd_add_bonding_slave_result {
	cmdline_fixed_string_t add;
	cmdline_fixed_string_t bonding;
	cmdline_fixed_string_t slave;
	portid_t slave_id;
	portid_t port_id;
};

static void cmd_add_bonding_slave_parsed(void *parsed_result,
		__attribute__((unused))  struct cmdline *cl,
		__attribute__((unused)) void *data)
{
	struct cmd_add_bonding_slave_result *res = parsed_result;
	portid_t master_port_id = res->port_id;
	portid_t slave_port_id = res->slave_id;

	/* add the slave for a bonded device. */
	if (0 != rte_eth_bond_slave_add(master_port_id, slave_port_id)) {
		printf("\t Failed to add slave %d to master port = %d.\n",
				slave_port_id, master_port_id);
		return;
	}
	init_port_config();
	set_port_slave_flag(slave_port_id);
}

cmdline_parse_token_string_t cmd_addbonding_slave_add =
TOKEN_STRING_INITIALIZER(struct cmd_add_bonding_slave_result,
		add, "add");
cmdline_parse_token_string_t cmd_addbonding_slave_bonding =
TOKEN_STRING_INITIALIZER(struct cmd_add_bonding_slave_result,
		bonding, "bonding");
cmdline_parse_token_string_t cmd_addbonding_slave_slave =
TOKEN_STRING_INITIALIZER(struct cmd_add_bonding_slave_result,
		slave, "slave");
cmdline_parse_token_num_t cmd_addbonding_slave_slaveid =
TOKEN_NUM_INITIALIZER(struct cmd_add_bonding_slave_result,
		slave_id, UINT16);
cmdline_parse_token_num_t cmd_addbonding_slave_port =
TOKEN_NUM_INITIALIZER(struct cmd_add_bonding_slave_result,
		port_id, UINT16);

cmdline_parse_inst_t cmd_add_bonding_slave = {
		.f = cmd_add_bonding_slave_parsed,
		.help_str = "add bonding slave <slave_id> <port_id>: "
			"Add a slave device to a bonded device",
		.data = NULL,
		.tokens = {
				(void *)&cmd_addbonding_slave_add,
				(void *)&cmd_addbonding_slave_bonding,
				(void *)&cmd_addbonding_slave_slave,
				(void *)&cmd_addbonding_slave_slaveid,
				(void *)&cmd_addbonding_slave_port,
				NULL
		}
};

/* *** REMOVE SLAVE *** */
struct cmd_remove_bonding_slave_result {
	cmdline_fixed_string_t remove;
	cmdline_fixed_string_t bonding;
	cmdline_fixed_string_t slave;
	portid_t slave_id;
	portid_t port_id;
};

static void cmd_remove_bonding_slave_parsed(void *parsed_result,
		__attribute__((unused))  struct cmdline *cl,
		__attribute__((unused)) void *data)
{
	struct cmd_remove_bonding_slave_result *res = parsed_result;
	portid_t master_port_id = res->port_id;
	portid_t slave_port_id = res->slave_id;

	/* remove the slave from a bonded device. */
	if (0 != rte_eth_bond_slave_remove(master_port_id, slave_port_id)) {
		printf("\t Failed to remove slave %d from master port = %d.\n",
				slave_port_id, master_port_id);
		return;
	}
	init_port_config();
	clear_port_slave_flag(slave_port_id);
}

cmdline_parse_token_string_t cmd_removebonding_slave_remove =
		TOKEN_STRING_INITIALIZER(struct cmd_remove_bonding_slave_result,
				remove, "remove");
cmdline_parse_token_string_t cmd_removebonding_slave_bonding =
		TOKEN_STRING_INITIALIZER(struct cmd_remove_bonding_slave_result,
				bonding, "bonding");
cmdline_parse_token_string_t cmd_removebonding_slave_slave =
		TOKEN_STRING_INITIALIZER(struct cmd_remove_bonding_slave_result,
				slave, "slave");
cmdline_parse_token_num_t cmd_removebonding_slave_slaveid =
		TOKEN_NUM_INITIALIZER(struct cmd_remove_bonding_slave_result,
				slave_id, UINT16);
cmdline_parse_token_num_t cmd_removebonding_slave_port =
		TOKEN_NUM_INITIALIZER(struct cmd_remove_bonding_slave_result,
				port_id, UINT16);

cmdline_parse_inst_t cmd_remove_bonding_slave = {
		.f = cmd_remove_bonding_slave_parsed,
		.help_str = "remove bonding slave <slave_id> <port_id>: "
			"Remove a slave device from a bonded device",
		.data = NULL,
		.tokens = {
				(void *)&cmd_removebonding_slave_remove,
				(void *)&cmd_removebonding_slave_bonding,
				(void *)&cmd_removebonding_slave_slave,
				(void *)&cmd_removebonding_slave_slaveid,
				(void *)&cmd_removebonding_slave_port,
				NULL
		}
};

/* *** CREATE BONDED DEVICE *** */
struct cmd_create_bonded_device_result {
	cmdline_fixed_string_t create;
	cmdline_fixed_string_t bonded;
	cmdline_fixed_string_t device;
	uint8_t mode;
	uint8_t socket;
};

static int bond_dev_num = 0;

static void cmd_create_bonded_device_parsed(void *parsed_result,
		__attribute__((unused))  struct cmdline *cl,
		__attribute__((unused)) void *data)
{
	struct cmd_create_bonded_device_result *res = parsed_result;
	char ethdev_name[RTE_ETH_NAME_MAX_LEN];
	int port_id;

	if (test_done == 0) {
		printf("Please stop forwarding first\n");
		return;
	}

	snprintf(ethdev_name, RTE_ETH_NAME_MAX_LEN, "net_bonding_testpmd_%d",
			bond_dev_num++);

	/* Create a new bonded device. */
	port_id = rte_eth_bond_create(ethdev_name, res->mode, res->socket);
	if (port_id < 0) {
		printf("\t Failed to create bonded device.\n");
		return;
	} else {
		printf("Created new bonded device %s on (port %d).\n", ethdev_name,
				port_id);

		/* Update number of ports */
		nb_ports = rte_eth_dev_count_avail();
		reconfig(port_id, res->socket);
		rte_eth_promiscuous_enable(port_id);
		ports[port_id].need_setup = 0;
		ports[port_id].port_status = RTE_PORT_STOPPED;
	}

}

cmdline_parse_token_string_t cmd_createbonded_device_create =
		TOKEN_STRING_INITIALIZER(struct cmd_create_bonded_device_result,
				create, "create");
cmdline_parse_token_string_t cmd_createbonded_device_bonded =
		TOKEN_STRING_INITIALIZER(struct cmd_create_bonded_device_result,
				bonded, "bonded");
cmdline_parse_token_string_t cmd_createbonded_device_device =
		TOKEN_STRING_INITIALIZER(struct cmd_create_bonded_device_result,
				device, "device");
cmdline_parse_token_num_t cmd_createbonded_device_mode =
		TOKEN_NUM_INITIALIZER(struct cmd_create_bonded_device_result,
				mode, UINT8);
cmdline_parse_token_num_t cmd_createbonded_device_socket =
		TOKEN_NUM_INITIALIZER(struct cmd_create_bonded_device_result,
				socket, UINT8);

cmdline_parse_inst_t cmd_create_bonded_device = {
		.f = cmd_create_bonded_device_parsed,
		.help_str = "create bonded device <mode> <socket>: "
			"Create a new bonded device with specific bonding mode and socket",
		.data = NULL,
		.tokens = {
				(void *)&cmd_createbonded_device_create,
				(void *)&cmd_createbonded_device_bonded,
				(void *)&cmd_createbonded_device_device,
				(void *)&cmd_createbonded_device_mode,
				(void *)&cmd_createbonded_device_socket,
				NULL
		}
};

/* *** SET MAC ADDRESS IN BONDED DEVICE *** */
struct cmd_set_bond_mac_addr_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t bonding;
	cmdline_fixed_string_t mac_addr;
	uint16_t port_num;
	struct ether_addr address;
};

static void cmd_set_bond_mac_addr_parsed(void *parsed_result,
		__attribute__((unused))  struct cmdline *cl,
		__attribute__((unused)) void *data)
{
	struct cmd_set_bond_mac_addr_result *res = parsed_result;
	int ret;

	if (port_id_is_invalid(res->port_num, ENABLED_WARN))
		return;

	ret = rte_eth_bond_mac_address_set(res->port_num, &res->address);

	/* check the return value and print it if is < 0 */
	if (ret < 0)
		printf("set_bond_mac_addr error: (%s)\n", strerror(-ret));
}

cmdline_parse_token_string_t cmd_set_bond_mac_addr_set =
		TOKEN_STRING_INITIALIZER(struct cmd_set_bond_mac_addr_result, set, "set");
cmdline_parse_token_string_t cmd_set_bond_mac_addr_bonding =
		TOKEN_STRING_INITIALIZER(struct cmd_set_bond_mac_addr_result, bonding,
				"bonding");
cmdline_parse_token_string_t cmd_set_bond_mac_addr_mac =
		TOKEN_STRING_INITIALIZER(struct cmd_set_bond_mac_addr_result, mac_addr,
				"mac_addr");
cmdline_parse_token_num_t cmd_set_bond_mac_addr_portnum =
		TOKEN_NUM_INITIALIZER(struct cmd_set_bond_mac_addr_result,
				port_num, UINT16);
cmdline_parse_token_etheraddr_t cmd_set_bond_mac_addr_addr =
		TOKEN_ETHERADDR_INITIALIZER(struct cmd_set_bond_mac_addr_result, address);

cmdline_parse_inst_t cmd_set_bond_mac_addr = {
		.f = cmd_set_bond_mac_addr_parsed,
		.data = (void *) 0,
		.help_str = "set bonding mac_addr <port_id> <mac_addr>",
		.tokens = {
				(void *)&cmd_set_bond_mac_addr_set,
				(void *)&cmd_set_bond_mac_addr_bonding,
				(void *)&cmd_set_bond_mac_addr_mac,
				(void *)&cmd_set_bond_mac_addr_portnum,
				(void *)&cmd_set_bond_mac_addr_addr,
				NULL
		}
};


/* *** SET LINK STATUS MONITORING POLLING PERIOD ON BONDED DEVICE *** */
struct cmd_set_bond_mon_period_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t bonding;
	cmdline_fixed_string_t mon_period;
	uint16_t port_num;
	uint32_t period_ms;
};

static void cmd_set_bond_mon_period_parsed(void *parsed_result,
		__attribute__((unused))  struct cmdline *cl,
		__attribute__((unused)) void *data)
{
	struct cmd_set_bond_mon_period_result *res = parsed_result;
	int ret;

	ret = rte_eth_bond_link_monitoring_set(res->port_num, res->period_ms);

	/* check the return value and print it if is < 0 */
	if (ret < 0)
		printf("set_bond_mac_addr error: (%s)\n", strerror(-ret));
}

cmdline_parse_token_string_t cmd_set_bond_mon_period_set =
		TOKEN_STRING_INITIALIZER(struct cmd_set_bond_mon_period_result,
				set, "set");
cmdline_parse_token_string_t cmd_set_bond_mon_period_bonding =
		TOKEN_STRING_INITIALIZER(struct cmd_set_bond_mon_period_result,
				bonding, "bonding");
cmdline_parse_token_string_t cmd_set_bond_mon_period_mon_period =
		TOKEN_STRING_INITIALIZER(struct cmd_set_bond_mon_period_result,
				mon_period,	"mon_period");
cmdline_parse_token_num_t cmd_set_bond_mon_period_portnum =
		TOKEN_NUM_INITIALIZER(struct cmd_set_bond_mon_period_result,
				port_num, UINT16);
cmdline_parse_token_num_t cmd_set_bond_mon_period_period_ms =
		TOKEN_NUM_INITIALIZER(struct cmd_set_bond_mon_period_result,
				period_ms, UINT32);

cmdline_parse_inst_t cmd_set_bond_mon_period = {
		.f = cmd_set_bond_mon_period_parsed,
		.data = (void *) 0,
		.help_str = "set bonding mon_period <port_id> <period_ms>",
		.tokens = {
				(void *)&cmd_set_bond_mon_period_set,
				(void *)&cmd_set_bond_mon_period_bonding,
				(void *)&cmd_set_bond_mon_period_mon_period,
				(void *)&cmd_set_bond_mon_period_portnum,
				(void *)&cmd_set_bond_mon_period_period_ms,
				NULL
		}
};



struct cmd_set_bonding_agg_mode_policy_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t bonding;
	cmdline_fixed_string_t agg_mode;
	uint16_t port_num;
	cmdline_fixed_string_t policy;
};


static void
cmd_set_bonding_agg_mode(void *parsed_result,
		__attribute__((unused)) struct cmdline *cl,
		__attribute__((unused)) void *data)
{
	struct cmd_set_bonding_agg_mode_policy_result *res = parsed_result;
	uint8_t policy = AGG_BANDWIDTH;

	if (!strcmp(res->policy, "bandwidth"))
		policy = AGG_BANDWIDTH;
	else if (!strcmp(res->policy, "stable"))
		policy = AGG_STABLE;
	else if (!strcmp(res->policy, "count"))
		policy = AGG_COUNT;

	rte_eth_bond_8023ad_agg_selection_set(res->port_num, policy);
}


cmdline_parse_token_string_t cmd_set_bonding_agg_mode_set =
	TOKEN_STRING_INITIALIZER(struct cmd_set_bonding_agg_mode_policy_result,
				set, "set");
cmdline_parse_token_string_t cmd_set_bonding_agg_mode_bonding =
	TOKEN_STRING_INITIALIZER(struct cmd_set_bonding_agg_mode_policy_result,
				bonding, "bonding");

cmdline_parse_token_string_t cmd_set_bonding_agg_mode_agg_mode =
	TOKEN_STRING_INITIALIZER(struct cmd_set_bonding_agg_mode_policy_result,
				agg_mode, "agg_mode");

cmdline_parse_token_num_t cmd_set_bonding_agg_mode_portnum =
	TOKEN_NUM_INITIALIZER(struct cmd_set_bonding_agg_mode_policy_result,
				port_num, UINT16);

cmdline_parse_token_string_t cmd_set_bonding_agg_mode_policy_string =
	TOKEN_STRING_INITIALIZER(
			struct cmd_set_bonding_balance_xmit_policy_result,
		policy, "stable#bandwidth#count");

cmdline_parse_inst_t cmd_set_bonding_agg_mode_policy = {
	.f = cmd_set_bonding_agg_mode,
	.data = (void *) 0,
	.help_str = "set bonding mode IEEE802.3AD aggregator policy <port_id> <agg_name>",
	.tokens = {
			(void *)&cmd_set_bonding_agg_mode_set,
			(void *)&cmd_set_bonding_agg_mode_bonding,
			(void *)&cmd_set_bonding_agg_mode_agg_mode,
			(void *)&cmd_set_bonding_agg_mode_portnum,
			(void *)&cmd_set_bonding_agg_mode_policy_string,
			NULL
		}
};


#endif /* RTE_LIBRTE_PMD_BOND */

/* *** SET FORWARDING MODE *** */
struct cmd_set_fwd_mode_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t fwd;
	cmdline_fixed_string_t mode;
};

static void cmd_set_fwd_mode_parsed(void *parsed_result,
				    __attribute__((unused)) struct cmdline *cl,
				    __attribute__((unused)) void *data)
{
	struct cmd_set_fwd_mode_result *res = parsed_result;

	retry_enabled = 0;
	set_pkt_forwarding_mode(res->mode);
}

cmdline_parse_token_string_t cmd_setfwd_set =
	TOKEN_STRING_INITIALIZER(struct cmd_set_fwd_mode_result, set, "set");
cmdline_parse_token_string_t cmd_setfwd_fwd =
	TOKEN_STRING_INITIALIZER(struct cmd_set_fwd_mode_result, fwd, "fwd");
cmdline_parse_token_string_t cmd_setfwd_mode =
	TOKEN_STRING_INITIALIZER(struct cmd_set_fwd_mode_result, mode,
		"" /* defined at init */);

cmdline_parse_inst_t cmd_set_fwd_mode = {
	.f = cmd_set_fwd_mode_parsed,
	.data = NULL,
	.help_str = NULL, /* defined at init */
	.tokens = {
		(void *)&cmd_setfwd_set,
		(void *)&cmd_setfwd_fwd,
		(void *)&cmd_setfwd_mode,
		NULL,
	},
};

static void cmd_set_fwd_mode_init(void)
{
	char *modes, *c;
	static char token[128];
	static char help[256];
	cmdline_parse_token_string_t *token_struct;

	modes = list_pkt_forwarding_modes();
	snprintf(help, sizeof(help), "set fwd %s: "
		"Set packet forwarding mode", modes);
	cmd_set_fwd_mode.help_str = help;

	/* string token separator is # */
	for (c = token; *modes != '\0'; modes++)
		if (*modes == '|')
			*c++ = '#';
		else
			*c++ = *modes;
	token_struct = (cmdline_parse_token_string_t*)cmd_set_fwd_mode.tokens[2];
	token_struct->string_data.str = token;
}

/* *** SET RETRY FORWARDING MODE *** */
struct cmd_set_fwd_retry_mode_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t fwd;
	cmdline_fixed_string_t mode;
	cmdline_fixed_string_t retry;
};

static void cmd_set_fwd_retry_mode_parsed(void *parsed_result,
			    __attribute__((unused)) struct cmdline *cl,
			    __attribute__((unused)) void *data)
{
	struct cmd_set_fwd_retry_mode_result *res = parsed_result;

	retry_enabled = 1;
	set_pkt_forwarding_mode(res->mode);
}

cmdline_parse_token_string_t cmd_setfwd_retry_set =
	TOKEN_STRING_INITIALIZER(struct cmd_set_fwd_retry_mode_result,
			set, "set");
cmdline_parse_token_string_t cmd_setfwd_retry_fwd =
	TOKEN_STRING_INITIALIZER(struct cmd_set_fwd_retry_mode_result,
			fwd, "fwd");
cmdline_parse_token_string_t cmd_setfwd_retry_mode =
	TOKEN_STRING_INITIALIZER(struct cmd_set_fwd_retry_mode_result,
			mode,
		"" /* defined at init */);
cmdline_parse_token_string_t cmd_setfwd_retry_retry =
	TOKEN_STRING_INITIALIZER(struct cmd_set_fwd_retry_mode_result,
			retry, "retry");

cmdline_parse_inst_t cmd_set_fwd_retry_mode = {
	.f = cmd_set_fwd_retry_mode_parsed,
	.data = NULL,
	.help_str = NULL, /* defined at init */
	.tokens = {
		(void *)&cmd_setfwd_retry_set,
		(void *)&cmd_setfwd_retry_fwd,
		(void *)&cmd_setfwd_retry_mode,
		(void *)&cmd_setfwd_retry_retry,
		NULL,
	},
};

static void cmd_set_fwd_retry_mode_init(void)
{
	char *modes, *c;
	static char token[128];
	static char help[256];
	cmdline_parse_token_string_t *token_struct;

	modes = list_pkt_forwarding_retry_modes();
	snprintf(help, sizeof(help), "set fwd %s retry: "
		"Set packet forwarding mode with retry", modes);
	cmd_set_fwd_retry_mode.help_str = help;

	/* string token separator is # */
	for (c = token; *modes != '\0'; modes++)
		if (*modes == '|')
			*c++ = '#';
		else
			*c++ = *modes;
	token_struct = (cmdline_parse_token_string_t *)
		cmd_set_fwd_retry_mode.tokens[2];
	token_struct->string_data.str = token;
}

/* *** SET BURST TX DELAY TIME RETRY NUMBER *** */
struct cmd_set_burst_tx_retry_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t burst;
	cmdline_fixed_string_t tx;
	cmdline_fixed_string_t delay;
	uint32_t time;
	cmdline_fixed_string_t retry;
	uint32_t retry_num;
};

static void cmd_set_burst_tx_retry_parsed(void *parsed_result,
					__attribute__((unused)) struct cmdline *cl,
					__attribute__((unused)) void *data)
{
	struct cmd_set_burst_tx_retry_result *res = parsed_result;

	if (!strcmp(res->set, "set") && !strcmp(res->burst, "burst")
		&& !strcmp(res->tx, "tx")) {
		if (!strcmp(res->delay, "delay"))
			burst_tx_delay_time = res->time;
		if (!strcmp(res->retry, "retry"))
			burst_tx_retry_num = res->retry_num;
	}

}

cmdline_parse_token_string_t cmd_set_burst_tx_retry_set =
	TOKEN_STRING_INITIALIZER(struct cmd_set_burst_tx_retry_result, set, "set");
cmdline_parse_token_string_t cmd_set_burst_tx_retry_burst =
	TOKEN_STRING_INITIALIZER(struct cmd_set_burst_tx_retry_result, burst,
				 "burst");
cmdline_parse_token_string_t cmd_set_burst_tx_retry_tx =
	TOKEN_STRING_INITIALIZER(struct cmd_set_burst_tx_retry_result, tx, "tx");
cmdline_parse_token_string_t cmd_set_burst_tx_retry_delay =
	TOKEN_STRING_INITIALIZER(struct cmd_set_burst_tx_retry_result, delay, "delay");
cmdline_parse_token_num_t cmd_set_burst_tx_retry_time =
	TOKEN_NUM_INITIALIZER(struct cmd_set_burst_tx_retry_result, time, UINT32);
cmdline_parse_token_string_t cmd_set_burst_tx_retry_retry =
	TOKEN_STRING_INITIALIZER(struct cmd_set_burst_tx_retry_result, retry, "retry");
cmdline_parse_token_num_t cmd_set_burst_tx_retry_retry_num =
	TOKEN_NUM_INITIALIZER(struct cmd_set_burst_tx_retry_result, retry_num, UINT32);

cmdline_parse_inst_t cmd_set_burst_tx_retry = {
	.f = cmd_set_burst_tx_retry_parsed,
	.help_str = "set burst tx delay <delay_usec> retry <num_retry>",
	.tokens = {
		(void *)&cmd_set_burst_tx_retry_set,
		(void *)&cmd_set_burst_tx_retry_burst,
		(void *)&cmd_set_burst_tx_retry_tx,
		(void *)&cmd_set_burst_tx_retry_delay,
		(void *)&cmd_set_burst_tx_retry_time,
		(void *)&cmd_set_burst_tx_retry_retry,
		(void *)&cmd_set_burst_tx_retry_retry_num,
		NULL,
	},
};

/* *** SET PROMISC MODE *** */
struct cmd_set_promisc_mode_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t promisc;
	cmdline_fixed_string_t port_all; /* valid if "allports" argument == 1 */
	uint16_t port_num;               /* valid if "allports" argument == 0 */
	cmdline_fixed_string_t mode;
};

static void cmd_set_promisc_mode_parsed(void *parsed_result,
					__attribute__((unused)) struct cmdline *cl,
					void *allports)
{
	struct cmd_set_promisc_mode_result *res = parsed_result;
	int enable;
	portid_t i;

	if (!strcmp(res->mode, "on"))
		enable = 1;
	else
		enable = 0;

	/* all ports */
	if (allports) {
		RTE_ETH_FOREACH_DEV(i) {
			if (enable)
				rte_eth_promiscuous_enable(i);
			else
				rte_eth_promiscuous_disable(i);
		}
	}
	else {
		if (enable)
			rte_eth_promiscuous_enable(res->port_num);
		else
			rte_eth_promiscuous_disable(res->port_num);
	}
}

cmdline_parse_token_string_t cmd_setpromisc_set =
	TOKEN_STRING_INITIALIZER(struct cmd_set_promisc_mode_result, set, "set");
cmdline_parse_token_string_t cmd_setpromisc_promisc =
	TOKEN_STRING_INITIALIZER(struct cmd_set_promisc_mode_result, promisc,
				 "promisc");
cmdline_parse_token_string_t cmd_setpromisc_portall =
	TOKEN_STRING_INITIALIZER(struct cmd_set_promisc_mode_result, port_all,
				 "all");
cmdline_parse_token_num_t cmd_setpromisc_portnum =
	TOKEN_NUM_INITIALIZER(struct cmd_set_promisc_mode_result, port_num,
			      UINT16);
cmdline_parse_token_string_t cmd_setpromisc_mode =
	TOKEN_STRING_INITIALIZER(struct cmd_set_promisc_mode_result, mode,
				 "on#off");

cmdline_parse_inst_t cmd_set_promisc_mode_all = {
	.f = cmd_set_promisc_mode_parsed,
	.data = (void *)1,
	.help_str = "set promisc all on|off: Set promisc mode for all ports",
	.tokens = {
		(void *)&cmd_setpromisc_set,
		(void *)&cmd_setpromisc_promisc,
		(void *)&cmd_setpromisc_portall,
		(void *)&cmd_setpromisc_mode,
		NULL,
	},
};

cmdline_parse_inst_t cmd_set_promisc_mode_one = {
	.f = cmd_set_promisc_mode_parsed,
	.data = (void *)0,
	.help_str = "set promisc <port_id> on|off: Set promisc mode on port_id",
	.tokens = {
		(void *)&cmd_setpromisc_set,
		(void *)&cmd_setpromisc_promisc,
		(void *)&cmd_setpromisc_portnum,
		(void *)&cmd_setpromisc_mode,
		NULL,
	},
};

/* *** SET ALLMULTI MODE *** */
struct cmd_set_allmulti_mode_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t allmulti;
	cmdline_fixed_string_t port_all; /* valid if "allports" argument == 1 */
	uint16_t port_num;               /* valid if "allports" argument == 0 */
	cmdline_fixed_string_t mode;
};

static void cmd_set_allmulti_mode_parsed(void *parsed_result,
					__attribute__((unused)) struct cmdline *cl,
					void *allports)
{
	struct cmd_set_allmulti_mode_result *res = parsed_result;
	int enable;
	portid_t i;

	if (!strcmp(res->mode, "on"))
		enable = 1;
	else
		enable = 0;

	/* all ports */
	if (allports) {
		RTE_ETH_FOREACH_DEV(i) {
			if (enable)
				rte_eth_allmulticast_enable(i);
			else
				rte_eth_allmulticast_disable(i);
		}
	}
	else {
		if (enable)
			rte_eth_allmulticast_enable(res->port_num);
		else
			rte_eth_allmulticast_disable(res->port_num);
	}
}

cmdline_parse_token_string_t cmd_setallmulti_set =
	TOKEN_STRING_INITIALIZER(struct cmd_set_allmulti_mode_result, set, "set");
cmdline_parse_token_string_t cmd_setallmulti_allmulti =
	TOKEN_STRING_INITIALIZER(struct cmd_set_allmulti_mode_result, allmulti,
				 "allmulti");
cmdline_parse_token_string_t cmd_setallmulti_portall =
	TOKEN_STRING_INITIALIZER(struct cmd_set_allmulti_mode_result, port_all,
				 "all");
cmdline_parse_token_num_t cmd_setallmulti_portnum =
	TOKEN_NUM_INITIALIZER(struct cmd_set_allmulti_mode_result, port_num,
			      UINT16);
cmdline_parse_token_string_t cmd_setallmulti_mode =
	TOKEN_STRING_INITIALIZER(struct cmd_set_allmulti_mode_result, mode,
				 "on#off");

cmdline_parse_inst_t cmd_set_allmulti_mode_all = {
	.f = cmd_set_allmulti_mode_parsed,
	.data = (void *)1,
	.help_str = "set allmulti all on|off: Set allmulti mode for all ports",
	.tokens = {
		(void *)&cmd_setallmulti_set,
		(void *)&cmd_setallmulti_allmulti,
		(void *)&cmd_setallmulti_portall,
		(void *)&cmd_setallmulti_mode,
		NULL,
	},
};

cmdline_parse_inst_t cmd_set_allmulti_mode_one = {
	.f = cmd_set_allmulti_mode_parsed,
	.data = (void *)0,
	.help_str = "set allmulti <port_id> on|off: "
		"Set allmulti mode on port_id",
	.tokens = {
		(void *)&cmd_setallmulti_set,
		(void *)&cmd_setallmulti_allmulti,
		(void *)&cmd_setallmulti_portnum,
		(void *)&cmd_setallmulti_mode,
		NULL,
	},
};

/* *** SETUP ETHERNET LINK FLOW CONTROL *** */
struct cmd_link_flow_ctrl_set_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t flow_ctrl;
	cmdline_fixed_string_t rx;
	cmdline_fixed_string_t rx_lfc_mode;
	cmdline_fixed_string_t tx;
	cmdline_fixed_string_t tx_lfc_mode;
	cmdline_fixed_string_t mac_ctrl_frame_fwd;
	cmdline_fixed_string_t mac_ctrl_frame_fwd_mode;
	cmdline_fixed_string_t autoneg_str;
	cmdline_fixed_string_t autoneg;
	cmdline_fixed_string_t hw_str;
	uint32_t high_water;
	cmdline_fixed_string_t lw_str;
	uint32_t low_water;
	cmdline_fixed_string_t pt_str;
	uint16_t pause_time;
	cmdline_fixed_string_t xon_str;
	uint16_t send_xon;
	portid_t port_id;
};

cmdline_parse_token_string_t cmd_lfc_set_set =
	TOKEN_STRING_INITIALIZER(struct cmd_link_flow_ctrl_set_result,
				set, "set");
cmdline_parse_token_string_t cmd_lfc_set_flow_ctrl =
	TOKEN_STRING_INITIALIZER(struct cmd_link_flow_ctrl_set_result,
				flow_ctrl, "flow_ctrl");
cmdline_parse_token_string_t cmd_lfc_set_rx =
	TOKEN_STRING_INITIALIZER(struct cmd_link_flow_ctrl_set_result,
				rx, "rx");
cmdline_parse_token_string_t cmd_lfc_set_rx_mode =
	TOKEN_STRING_INITIALIZER(struct cmd_link_flow_ctrl_set_result,
				rx_lfc_mode, "on#off");
cmdline_parse_token_string_t cmd_lfc_set_tx =
	TOKEN_STRING_INITIALIZER(struct cmd_link_flow_ctrl_set_result,
				tx, "tx");
cmdline_parse_token_string_t cmd_lfc_set_tx_mode =
	TOKEN_STRING_INITIALIZER(struct cmd_link_flow_ctrl_set_result,
				tx_lfc_mode, "on#off");
cmdline_parse_token_string_t cmd_lfc_set_high_water_str =
	TOKEN_STRING_INITIALIZER(struct cmd_link_flow_ctrl_set_result,
				hw_str, "high_water");
cmdline_parse_token_num_t cmd_lfc_set_high_water =
	TOKEN_NUM_INITIALIZER(struct cmd_link_flow_ctrl_set_result,
				high_water, UINT32);
cmdline_parse_token_string_t cmd_lfc_set_low_water_str =
	TOKEN_STRING_INITIALIZER(struct cmd_link_flow_ctrl_set_result,
				lw_str, "low_water");
cmdline_parse_token_num_t cmd_lfc_set_low_water =
	TOKEN_NUM_INITIALIZER(struct cmd_link_flow_ctrl_set_result,
				low_water, UINT32);
cmdline_parse_token_string_t cmd_lfc_set_pause_time_str =
	TOKEN_STRING_INITIALIZER(struct cmd_link_flow_ctrl_set_result,
				pt_str, "pause_time");
cmdline_parse_token_num_t cmd_lfc_set_pause_time =
	TOKEN_NUM_INITIALIZER(struct cmd_link_flow_ctrl_set_result,
				pause_time, UINT16);
cmdline_parse_token_string_t cmd_lfc_set_send_xon_str =
	TOKEN_STRING_INITIALIZER(struct cmd_link_flow_ctrl_set_result,
				xon_str, "send_xon");
cmdline_parse_token_num_t cmd_lfc_set_send_xon =
	TOKEN_NUM_INITIALIZER(struct cmd_link_flow_ctrl_set_result,
				send_xon, UINT16);
cmdline_parse_token_string_t cmd_lfc_set_mac_ctrl_frame_fwd_mode =
	TOKEN_STRING_INITIALIZER(struct cmd_link_flow_ctrl_set_result,
				mac_ctrl_frame_fwd, "mac_ctrl_frame_fwd");
cmdline_parse_token_string_t cmd_lfc_set_mac_ctrl_frame_fwd =
	TOKEN_STRING_INITIALIZER(struct cmd_link_flow_ctrl_set_result,
				mac_ctrl_frame_fwd_mode, "on#off");
cmdline_parse_token_string_t cmd_lfc_set_autoneg_str =
	TOKEN_STRING_INITIALIZER(struct cmd_link_flow_ctrl_set_result,
				autoneg_str, "autoneg");
cmdline_parse_token_string_t cmd_lfc_set_autoneg =
	TOKEN_STRING_INITIALIZER(struct cmd_link_flow_ctrl_set_result,
				autoneg, "on#off");
cmdline_parse_token_num_t cmd_lfc_set_portid =
	TOKEN_NUM_INITIALIZER(struct cmd_link_flow_ctrl_set_result,
				port_id, UINT16);

/* forward declaration */
static void
cmd_link_flow_ctrl_set_parsed(void *parsed_result, struct cmdline *cl,
			      void *data);

cmdline_parse_inst_t cmd_link_flow_control_set = {
	.f = cmd_link_flow_ctrl_set_parsed,
	.data = NULL,
	.help_str = "set flow_ctrl rx on|off tx on|off <high_water> "
		"<low_water> <pause_time> <send_xon> mac_ctrl_frame_fwd on|off "
		"autoneg on|off <port_id>: Configure the Ethernet flow control",
	.tokens = {
		(void *)&cmd_lfc_set_set,
		(void *)&cmd_lfc_set_flow_ctrl,
		(void *)&cmd_lfc_set_rx,
		(void *)&cmd_lfc_set_rx_mode,
		(void *)&cmd_lfc_set_tx,
		(void *)&cmd_lfc_set_tx_mode,
		(void *)&cmd_lfc_set_high_water,
		(void *)&cmd_lfc_set_low_water,
		(void *)&cmd_lfc_set_pause_time,
		(void *)&cmd_lfc_set_send_xon,
		(void *)&cmd_lfc_set_mac_ctrl_frame_fwd_mode,
		(void *)&cmd_lfc_set_mac_ctrl_frame_fwd,
		(void *)&cmd_lfc_set_autoneg_str,
		(void *)&cmd_lfc_set_autoneg,
		(void *)&cmd_lfc_set_portid,
		NULL,
	},
};

cmdline_parse_inst_t cmd_link_flow_control_set_rx = {
	.f = cmd_link_flow_ctrl_set_parsed,
	.data = (void *)&cmd_link_flow_control_set_rx,
	.help_str = "set flow_ctrl rx on|off <port_id>: "
		"Change rx flow control parameter",
	.tokens = {
		(void *)&cmd_lfc_set_set,
		(void *)&cmd_lfc_set_flow_ctrl,
		(void *)&cmd_lfc_set_rx,
		(void *)&cmd_lfc_set_rx_mode,
		(void *)&cmd_lfc_set_portid,
		NULL,
	},
};

cmdline_parse_inst_t cmd_link_flow_control_set_tx = {
	.f = cmd_link_flow_ctrl_set_parsed,
	.data = (void *)&cmd_link_flow_control_set_tx,
	.help_str = "set flow_ctrl tx on|off <port_id>: "
		"Change tx flow control parameter",
	.tokens = {
		(void *)&cmd_lfc_set_set,
		(void *)&cmd_lfc_set_flow_ctrl,
		(void *)&cmd_lfc_set_tx,
		(void *)&cmd_lfc_set_tx_mode,
		(void *)&cmd_lfc_set_portid,
		NULL,
	},
};

cmdline_parse_inst_t cmd_link_flow_control_set_hw = {
	.f = cmd_link_flow_ctrl_set_parsed,
	.data = (void *)&cmd_link_flow_control_set_hw,
	.help_str = "set flow_ctrl high_water <value> <port_id>: "
		"Change high water flow control parameter",
	.tokens = {
		(void *)&cmd_lfc_set_set,
		(void *)&cmd_lfc_set_flow_ctrl,
		(void *)&cmd_lfc_set_high_water_str,
		(void *)&cmd_lfc_set_high_water,
		(void *)&cmd_lfc_set_portid,
		NULL,
	},
};

cmdline_parse_inst_t cmd_link_flow_control_set_lw = {
	.f = cmd_link_flow_ctrl_set_parsed,
	.data = (void *)&cmd_link_flow_control_set_lw,
	.help_str = "set flow_ctrl low_water <value> <port_id>: "
		"Change low water flow control parameter",
	.tokens = {
		(void *)&cmd_lfc_set_set,
		(void *)&cmd_lfc_set_flow_ctrl,
		(void *)&cmd_lfc_set_low_water_str,
		(void *)&cmd_lfc_set_low_water,
		(void *)&cmd_lfc_set_portid,
		NULL,
	},
};

cmdline_parse_inst_t cmd_link_flow_control_set_pt = {
	.f = cmd_link_flow_ctrl_set_parsed,
	.data = (void *)&cmd_link_flow_control_set_pt,
	.help_str = "set flow_ctrl pause_time <value> <port_id>: "
		"Change pause time flow control parameter",
	.tokens = {
		(void *)&cmd_lfc_set_set,
		(void *)&cmd_lfc_set_flow_ctrl,
		(void *)&cmd_lfc_set_pause_time_str,
		(void *)&cmd_lfc_set_pause_time,
		(void *)&cmd_lfc_set_portid,
		NULL,
	},
};

cmdline_parse_inst_t cmd_link_flow_control_set_xon = {
	.f = cmd_link_flow_ctrl_set_parsed,
	.data = (void *)&cmd_link_flow_control_set_xon,
	.help_str = "set flow_ctrl send_xon <value> <port_id>: "
		"Change send_xon flow control parameter",
	.tokens = {
		(void *)&cmd_lfc_set_set,
		(void *)&cmd_lfc_set_flow_ctrl,
		(void *)&cmd_lfc_set_send_xon_str,
		(void *)&cmd_lfc_set_send_xon,
		(void *)&cmd_lfc_set_portid,
		NULL,
	},
};

cmdline_parse_inst_t cmd_link_flow_control_set_macfwd = {
	.f = cmd_link_flow_ctrl_set_parsed,
	.data = (void *)&cmd_link_flow_control_set_macfwd,
	.help_str = "set flow_ctrl mac_ctrl_frame_fwd on|off <port_id>: "
		"Change mac ctrl fwd flow control parameter",
	.tokens = {
		(void *)&cmd_lfc_set_set,
		(void *)&cmd_lfc_set_flow_ctrl,
		(void *)&cmd_lfc_set_mac_ctrl_frame_fwd_mode,
		(void *)&cmd_lfc_set_mac_ctrl_frame_fwd,
		(void *)&cmd_lfc_set_portid,
		NULL,
	},
};

cmdline_parse_inst_t cmd_link_flow_control_set_autoneg = {
	.f = cmd_link_flow_ctrl_set_parsed,
	.data = (void *)&cmd_link_flow_control_set_autoneg,
	.help_str = "set flow_ctrl autoneg on|off <port_id>: "
		"Change autoneg flow control parameter",
	.tokens = {
		(void *)&cmd_lfc_set_set,
		(void *)&cmd_lfc_set_flow_ctrl,
		(void *)&cmd_lfc_set_autoneg_str,
		(void *)&cmd_lfc_set_autoneg,
		(void *)&cmd_lfc_set_portid,
		NULL,
	},
};

static void
cmd_link_flow_ctrl_set_parsed(void *parsed_result,
			      __attribute__((unused)) struct cmdline *cl,
			      void *data)
{
	struct cmd_link_flow_ctrl_set_result *res = parsed_result;
	cmdline_parse_inst_t *cmd = data;
	struct rte_eth_fc_conf fc_conf;
	int rx_fc_en = 0;
	int tx_fc_en = 0;
	int ret;

	/*
	 * Rx on/off, flow control is enabled/disabled on RX side. This can indicate
	 * the RTE_FC_TX_PAUSE, Transmit pause frame at the Rx side.
	 * Tx on/off, flow control is enabled/disabled on TX side. This can indicate
	 * the RTE_FC_RX_PAUSE, Respond to the pause frame at the Tx side.
	 */
	static enum rte_eth_fc_mode rx_tx_onoff_2_lfc_mode[2][2] = {
			{RTE_FC_NONE, RTE_FC_TX_PAUSE}, {RTE_FC_RX_PAUSE, RTE_FC_FULL}
	};

	/* Partial command line, retrieve current configuration */
	if (cmd) {
		ret = rte_eth_dev_flow_ctrl_get(res->port_id, &fc_conf);
		if (ret != 0) {
			printf("cannot get current flow ctrl parameters, return"
			       "code = %d\n", ret);
			return;
		}

		if ((fc_conf.mode == RTE_FC_RX_PAUSE) ||
		    (fc_conf.mode == RTE_FC_FULL))
			rx_fc_en = 1;
		if ((fc_conf.mode == RTE_FC_TX_PAUSE) ||
		    (fc_conf.mode == RTE_FC_FULL))
			tx_fc_en = 1;
	}

	if (!cmd || cmd == &cmd_link_flow_control_set_rx)
		rx_fc_en = (!strcmp(res->rx_lfc_mode, "on")) ? 1 : 0;

	if (!cmd || cmd == &cmd_link_flow_control_set_tx)
		tx_fc_en = (!strcmp(res->tx_lfc_mode, "on")) ? 1 : 0;

	fc_conf.mode = rx_tx_onoff_2_lfc_mode[rx_fc_en][tx_fc_en];

	if (!cmd || cmd == &cmd_link_flow_control_set_hw)
		fc_conf.high_water = res->high_water;

	if (!cmd || cmd == &cmd_link_flow_control_set_lw)
		fc_conf.low_water = res->low_water;

	if (!cmd || cmd == &cmd_link_flow_control_set_pt)
		fc_conf.pause_time = res->pause_time;

	if (!cmd || cmd == &cmd_link_flow_control_set_xon)
		fc_conf.send_xon = res->send_xon;

	if (!cmd || cmd == &cmd_link_flow_control_set_macfwd) {
		if (!strcmp(res->mac_ctrl_frame_fwd_mode, "on"))
			fc_conf.mac_ctrl_frame_fwd = 1;
		else
			fc_conf.mac_ctrl_frame_fwd = 0;
	}

	if (!cmd || cmd == &cmd_link_flow_control_set_autoneg)
		fc_conf.autoneg = (!strcmp(res->autoneg, "on")) ? 1 : 0;

	ret = rte_eth_dev_flow_ctrl_set(res->port_id, &fc_conf);
	if (ret != 0)
		printf("bad flow contrl parameter, return code = %d \n", ret);
}

/* *** SETUP ETHERNET PRIORITY FLOW CONTROL *** */
struct cmd_priority_flow_ctrl_set_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t pfc_ctrl;
	cmdline_fixed_string_t rx;
	cmdline_fixed_string_t rx_pfc_mode;
	cmdline_fixed_string_t tx;
	cmdline_fixed_string_t tx_pfc_mode;
	uint32_t high_water;
	uint32_t low_water;
	uint16_t pause_time;
	uint8_t  priority;
	portid_t port_id;
};

static void
cmd_priority_flow_ctrl_set_parsed(void *parsed_result,
		       __attribute__((unused)) struct cmdline *cl,
		       __attribute__((unused)) void *data)
{
	struct cmd_priority_flow_ctrl_set_result *res = parsed_result;
	struct rte_eth_pfc_conf pfc_conf;
	int rx_fc_enable, tx_fc_enable;
	int ret;

	/*
	 * Rx on/off, flow control is enabled/disabled on RX side. This can indicate
	 * the RTE_FC_TX_PAUSE, Transmit pause frame at the Rx side.
	 * Tx on/off, flow control is enabled/disabled on TX side. This can indicate
	 * the RTE_FC_RX_PAUSE, Respond to the pause frame at the Tx side.
	 */
	static enum rte_eth_fc_mode rx_tx_onoff_2_pfc_mode[2][2] = {
			{RTE_FC_NONE, RTE_FC_RX_PAUSE}, {RTE_FC_TX_PAUSE, RTE_FC_FULL}
	};

	rx_fc_enable = (!strncmp(res->rx_pfc_mode, "on",2)) ? 1 : 0;
	tx_fc_enable = (!strncmp(res->tx_pfc_mode, "on",2)) ? 1 : 0;
	pfc_conf.fc.mode       = rx_tx_onoff_2_pfc_mode[rx_fc_enable][tx_fc_enable];
	pfc_conf.fc.high_water = res->high_water;
	pfc_conf.fc.low_water  = res->low_water;
	pfc_conf.fc.pause_time = res->pause_time;
	pfc_conf.priority      = res->priority;

	ret = rte_eth_dev_priority_flow_ctrl_set(res->port_id, &pfc_conf);
	if (ret != 0)
		printf("bad priority flow contrl parameter, return code = %d \n", ret);
}

cmdline_parse_token_string_t cmd_pfc_set_set =
	TOKEN_STRING_INITIALIZER(struct cmd_priority_flow_ctrl_set_result,
				set, "set");
cmdline_parse_token_string_t cmd_pfc_set_flow_ctrl =
	TOKEN_STRING_INITIALIZER(struct cmd_priority_flow_ctrl_set_result,
				pfc_ctrl, "pfc_ctrl");
cmdline_parse_token_string_t cmd_pfc_set_rx =
	TOKEN_STRING_INITIALIZER(struct cmd_priority_flow_ctrl_set_result,
				rx, "rx");
cmdline_parse_token_string_t cmd_pfc_set_rx_mode =
	TOKEN_STRING_INITIALIZER(struct cmd_priority_flow_ctrl_set_result,
				rx_pfc_mode, "on#off");
cmdline_parse_token_string_t cmd_pfc_set_tx =
	TOKEN_STRING_INITIALIZER(struct cmd_priority_flow_ctrl_set_result,
				tx, "tx");
cmdline_parse_token_string_t cmd_pfc_set_tx_mode =
	TOKEN_STRING_INITIALIZER(struct cmd_priority_flow_ctrl_set_result,
				tx_pfc_mode, "on#off");
cmdline_parse_token_num_t cmd_pfc_set_high_water =
	TOKEN_NUM_INITIALIZER(struct cmd_priority_flow_ctrl_set_result,
				high_water, UINT32);
cmdline_parse_token_num_t cmd_pfc_set_low_water =
	TOKEN_NUM_INITIALIZER(struct cmd_priority_flow_ctrl_set_result,
				low_water, UINT32);
cmdline_parse_token_num_t cmd_pfc_set_pause_time =
	TOKEN_NUM_INITIALIZER(struct cmd_priority_flow_ctrl_set_result,
				pause_time, UINT16);
cmdline_parse_token_num_t cmd_pfc_set_priority =
	TOKEN_NUM_INITIALIZER(struct cmd_priority_flow_ctrl_set_result,
				priority, UINT8);
cmdline_parse_token_num_t cmd_pfc_set_portid =
	TOKEN_NUM_INITIALIZER(struct cmd_priority_flow_ctrl_set_result,
				port_id, UINT16);

cmdline_parse_inst_t cmd_priority_flow_control_set = {
	.f = cmd_priority_flow_ctrl_set_parsed,
	.data = NULL,
	.help_str = "set pfc_ctrl rx on|off tx on|off <high_water> <low_water> "
		"<pause_time> <priority> <port_id>: "
		"Configure the Ethernet priority flow control",
	.tokens = {
		(void *)&cmd_pfc_set_set,
		(void *)&cmd_pfc_set_flow_ctrl,
		(void *)&cmd_pfc_set_rx,
		(void *)&cmd_pfc_set_rx_mode,
		(void *)&cmd_pfc_set_tx,
		(void *)&cmd_pfc_set_tx_mode,
		(void *)&cmd_pfc_set_high_water,
		(void *)&cmd_pfc_set_low_water,
		(void *)&cmd_pfc_set_pause_time,
		(void *)&cmd_pfc_set_priority,
		(void *)&cmd_pfc_set_portid,
		NULL,
	},
};

/* *** RESET CONFIGURATION *** */
struct cmd_reset_result {
	cmdline_fixed_string_t reset;
	cmdline_fixed_string_t def;
};

static void cmd_reset_parsed(__attribute__((unused)) void *parsed_result,
			     struct cmdline *cl,
			     __attribute__((unused)) void *data)
{
	cmdline_printf(cl, "Reset to default forwarding configuration...\n");
	set_def_fwd_config();
}

cmdline_parse_token_string_t cmd_reset_set =
	TOKEN_STRING_INITIALIZER(struct cmd_reset_result, reset, "set");
cmdline_parse_token_string_t cmd_reset_def =
	TOKEN_STRING_INITIALIZER(struct cmd_reset_result, def,
				 "default");

cmdline_parse_inst_t cmd_reset = {
	.f = cmd_reset_parsed,
	.data = NULL,
	.help_str = "set default: Reset default forwarding configuration",
	.tokens = {
		(void *)&cmd_reset_set,
		(void *)&cmd_reset_def,
		NULL,
	},
};

/* *** START FORWARDING *** */
struct cmd_start_result {
	cmdline_fixed_string_t start;
};

cmdline_parse_token_string_t cmd_start_start =
	TOKEN_STRING_INITIALIZER(struct cmd_start_result, start, "start");

static void cmd_start_parsed(__attribute__((unused)) void *parsed_result,
			     __attribute__((unused)) struct cmdline *cl,
			     __attribute__((unused)) void *data)
{
	start_packet_forwarding(0);
}

cmdline_parse_inst_t cmd_start = {
	.f = cmd_start_parsed,
	.data = NULL,
	.help_str = "start: Start packet forwarding",
	.tokens = {
		(void *)&cmd_start_start,
		NULL,
	},
};

/* *** START FORWARDING WITH ONE TX BURST FIRST *** */
struct cmd_start_tx_first_result {
	cmdline_fixed_string_t start;
	cmdline_fixed_string_t tx_first;
};

static void
cmd_start_tx_first_parsed(__attribute__((unused)) void *parsed_result,
			  __attribute__((unused)) struct cmdline *cl,
			  __attribute__((unused)) void *data)
{
	start_packet_forwarding(1);
}

cmdline_parse_token_string_t cmd_start_tx_first_start =
	TOKEN_STRING_INITIALIZER(struct cmd_start_tx_first_result, start,
				 "start");
cmdline_parse_token_string_t cmd_start_tx_first_tx_first =
	TOKEN_STRING_INITIALIZER(struct cmd_start_tx_first_result,
				 tx_first, "tx_first");

cmdline_parse_inst_t cmd_start_tx_first = {
	.f = cmd_start_tx_first_parsed,
	.data = NULL,
	.help_str = "start tx_first: Start packet forwarding, "
		"after sending 1 burst of packets",
	.tokens = {
		(void *)&cmd_start_tx_first_start,
		(void *)&cmd_start_tx_first_tx_first,
		NULL,
	},
};

/* *** START FORWARDING WITH N TX BURST FIRST *** */
struct cmd_start_tx_first_n_result {
	cmdline_fixed_string_t start;
	cmdline_fixed_string_t tx_first;
	uint32_t tx_num;
};

static void
cmd_start_tx_first_n_parsed(void *parsed_result,
			  __attribute__((unused)) struct cmdline *cl,
			  __attribute__((unused)) void *data)
{
	struct cmd_start_tx_first_n_result *res = parsed_result;

	start_packet_forwarding(res->tx_num);
}

cmdline_parse_token_string_t cmd_start_tx_first_n_start =
	TOKEN_STRING_INITIALIZER(struct cmd_start_tx_first_n_result,
			start, "start");
cmdline_parse_token_string_t cmd_start_tx_first_n_tx_first =
	TOKEN_STRING_INITIALIZER(struct cmd_start_tx_first_n_result,
			tx_first, "tx_first");
cmdline_parse_token_num_t cmd_start_tx_first_n_tx_num =
	TOKEN_NUM_INITIALIZER(struct cmd_start_tx_first_n_result,
			tx_num, UINT32);

cmdline_parse_inst_t cmd_start_tx_first_n = {
	.f = cmd_start_tx_first_n_parsed,
	.data = NULL,
	.help_str = "start tx_first <num>: "
		"packet forwarding, after sending <num> bursts of packets",
	.tokens = {
		(void *)&cmd_start_tx_first_n_start,
		(void *)&cmd_start_tx_first_n_tx_first,
		(void *)&cmd_start_tx_first_n_tx_num,
		NULL,
	},
};

/* *** SET LINK UP *** */
struct cmd_set_link_up_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t link_up;
	cmdline_fixed_string_t port;
	portid_t port_id;
};

cmdline_parse_token_string_t cmd_set_link_up_set =
	TOKEN_STRING_INITIALIZER(struct cmd_set_link_up_result, set, "set");
cmdline_parse_token_string_t cmd_set_link_up_link_up =
	TOKEN_STRING_INITIALIZER(struct cmd_set_link_up_result, link_up,
				"link-up");
cmdline_parse_token_string_t cmd_set_link_up_port =
	TOKEN_STRING_INITIALIZER(struct cmd_set_link_up_result, port, "port");
cmdline_parse_token_num_t cmd_set_link_up_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_set_link_up_result, port_id, UINT16);

static void cmd_set_link_up_parsed(__attribute__((unused)) void *parsed_result,
			     __attribute__((unused)) struct cmdline *cl,
			     __attribute__((unused)) void *data)
{
	struct cmd_set_link_up_result *res = parsed_result;
	dev_set_link_up(res->port_id);
}

cmdline_parse_inst_t cmd_set_link_up = {
	.f = cmd_set_link_up_parsed,
	.data = NULL,
	.help_str = "set link-up port <port id>",
	.tokens = {
		(void *)&cmd_set_link_up_set,
		(void *)&cmd_set_link_up_link_up,
		(void *)&cmd_set_link_up_port,
		(void *)&cmd_set_link_up_port_id,
		NULL,
	},
};

/* *** SET LINK DOWN *** */
struct cmd_set_link_down_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t link_down;
	cmdline_fixed_string_t port;
	portid_t port_id;
};

cmdline_parse_token_string_t cmd_set_link_down_set =
	TOKEN_STRING_INITIALIZER(struct cmd_set_link_down_result, set, "set");
cmdline_parse_token_string_t cmd_set_link_down_link_down =
	TOKEN_STRING_INITIALIZER(struct cmd_set_link_down_result, link_down,
				"link-down");
cmdline_parse_token_string_t cmd_set_link_down_port =
	TOKEN_STRING_INITIALIZER(struct cmd_set_link_down_result, port, "port");
cmdline_parse_token_num_t cmd_set_link_down_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_set_link_down_result, port_id, UINT16);

static void cmd_set_link_down_parsed(
				__attribute__((unused)) void *parsed_result,
				__attribute__((unused)) struct cmdline *cl,
				__attribute__((unused)) void *data)
{
	struct cmd_set_link_down_result *res = parsed_result;
	dev_set_link_down(res->port_id);
}

cmdline_parse_inst_t cmd_set_link_down = {
	.f = cmd_set_link_down_parsed,
	.data = NULL,
	.help_str = "set link-down port <port id>",
	.tokens = {
		(void *)&cmd_set_link_down_set,
		(void *)&cmd_set_link_down_link_down,
		(void *)&cmd_set_link_down_port,
		(void *)&cmd_set_link_down_port_id,
		NULL,
	},
};

/* *** SHOW CFG *** */
struct cmd_showcfg_result {
	cmdline_fixed_string_t show;
	cmdline_fixed_string_t cfg;
	cmdline_fixed_string_t what;
};

static void cmd_showcfg_parsed(void *parsed_result,
			       __attribute__((unused)) struct cmdline *cl,
			       __attribute__((unused)) void *data)
{
	struct cmd_showcfg_result *res = parsed_result;
	if (!strcmp(res->what, "rxtx"))
		rxtx_config_display();
	else if (!strcmp(res->what, "cores"))
		fwd_lcores_config_display();
	else if (!strcmp(res->what, "fwd"))
		pkt_fwd_config_display(&cur_fwd_config);
	else if (!strcmp(res->what, "txpkts"))
		show_tx_pkt_segments();
}

cmdline_parse_token_string_t cmd_showcfg_show =
	TOKEN_STRING_INITIALIZER(struct cmd_showcfg_result, show, "show");
cmdline_parse_token_string_t cmd_showcfg_port =
	TOKEN_STRING_INITIALIZER(struct cmd_showcfg_result, cfg, "config");
cmdline_parse_token_string_t cmd_showcfg_what =
	TOKEN_STRING_INITIALIZER(struct cmd_showcfg_result, what,
				 "rxtx#cores#fwd#txpkts");

cmdline_parse_inst_t cmd_showcfg = {
	.f = cmd_showcfg_parsed,
	.data = NULL,
	.help_str = "show config rxtx|cores|fwd|txpkts",
	.tokens = {
		(void *)&cmd_showcfg_show,
		(void *)&cmd_showcfg_port,
		(void *)&cmd_showcfg_what,
		NULL,
	},
};

/* *** SHOW ALL PORT INFO *** */
struct cmd_showportall_result {
	cmdline_fixed_string_t show;
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t what;
	cmdline_fixed_string_t all;
};

static void cmd_showportall_parsed(void *parsed_result,
				__attribute__((unused)) struct cmdline *cl,
				__attribute__((unused)) void *data)
{
	portid_t i;

	struct cmd_showportall_result *res = parsed_result;
	if (!strcmp(res->show, "clear")) {
		if (!strcmp(res->what, "stats"))
			RTE_ETH_FOREACH_DEV(i)
				nic_stats_clear(i);
		else if (!strcmp(res->what, "xstats"))
			RTE_ETH_FOREACH_DEV(i)
				nic_xstats_clear(i);
	} else if (!strcmp(res->what, "info"))
		RTE_ETH_FOREACH_DEV(i)
			port_infos_display(i);
	else if (!strcmp(res->what, "summary")) {
		port_summary_header_display();
		RTE_ETH_FOREACH_DEV(i)
			port_summary_display(i);
	}
	else if (!strcmp(res->what, "stats"))
		RTE_ETH_FOREACH_DEV(i)
			nic_stats_display(i);
	else if (!strcmp(res->what, "xstats"))
		RTE_ETH_FOREACH_DEV(i)
			nic_xstats_display(i);
	else if (!strcmp(res->what, "fdir"))
		RTE_ETH_FOREACH_DEV(i)
			fdir_get_infos(i);
	else if (!strcmp(res->what, "stat_qmap"))
		RTE_ETH_FOREACH_DEV(i)
			nic_stats_mapping_display(i);
	else if (!strcmp(res->what, "dcb_tc"))
		RTE_ETH_FOREACH_DEV(i)
			port_dcb_info_display(i);
	else if (!strcmp(res->what, "cap"))
		RTE_ETH_FOREACH_DEV(i)
			port_offload_cap_display(i);
}

cmdline_parse_token_string_t cmd_showportall_show =
	TOKEN_STRING_INITIALIZER(struct cmd_showportall_result, show,
				 "show#clear");
cmdline_parse_token_string_t cmd_showportall_port =
	TOKEN_STRING_INITIALIZER(struct cmd_showportall_result, port, "port");
cmdline_parse_token_string_t cmd_showportall_what =
	TOKEN_STRING_INITIALIZER(struct cmd_showportall_result, what,
				 "info#summary#stats#xstats#fdir#stat_qmap#dcb_tc#cap");
cmdline_parse_token_string_t cmd_showportall_all =
	TOKEN_STRING_INITIALIZER(struct cmd_showportall_result, all, "all");
cmdline_parse_inst_t cmd_showportall = {
	.f = cmd_showportall_parsed,
	.data = NULL,
	.help_str = "show|clear port "
		"info|summary|stats|xstats|fdir|stat_qmap|dcb_tc|cap all",
	.tokens = {
		(void *)&cmd_showportall_show,
		(void *)&cmd_showportall_port,
		(void *)&cmd_showportall_what,
		(void *)&cmd_showportall_all,
		NULL,
	},
};

/* *** SHOW PORT INFO *** */
struct cmd_showport_result {
	cmdline_fixed_string_t show;
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t what;
	uint16_t portnum;
};

static void cmd_showport_parsed(void *parsed_result,
				__attribute__((unused)) struct cmdline *cl,
				__attribute__((unused)) void *data)
{
	struct cmd_showport_result *res = parsed_result;
	if (!strcmp(res->show, "clear")) {
		if (!strcmp(res->what, "stats"))
			nic_stats_clear(res->portnum);
		else if (!strcmp(res->what, "xstats"))
			nic_xstats_clear(res->portnum);
	} else if (!strcmp(res->what, "info"))
		port_infos_display(res->portnum);
	else if (!strcmp(res->what, "summary")) {
		port_summary_header_display();
		port_summary_display(res->portnum);
	}
	else if (!strcmp(res->what, "stats"))
		nic_stats_display(res->portnum);
	else if (!strcmp(res->what, "xstats"))
		nic_xstats_display(res->portnum);
	else if (!strcmp(res->what, "fdir"))
		 fdir_get_infos(res->portnum);
	else if (!strcmp(res->what, "stat_qmap"))
		nic_stats_mapping_display(res->portnum);
	else if (!strcmp(res->what, "dcb_tc"))
		port_dcb_info_display(res->portnum);
	else if (!strcmp(res->what, "cap"))
		port_offload_cap_display(res->portnum);
}

cmdline_parse_token_string_t cmd_showport_show =
	TOKEN_STRING_INITIALIZER(struct cmd_showport_result, show,
				 "show#clear");
cmdline_parse_token_string_t cmd_showport_port =
	TOKEN_STRING_INITIALIZER(struct cmd_showport_result, port, "port");
cmdline_parse_token_string_t cmd_showport_what =
	TOKEN_STRING_INITIALIZER(struct cmd_showport_result, what,
				 "info#summary#stats#xstats#fdir#stat_qmap#dcb_tc#cap");
cmdline_parse_token_num_t cmd_showport_portnum =
	TOKEN_NUM_INITIALIZER(struct cmd_showport_result, portnum, UINT16);

cmdline_parse_inst_t cmd_showport = {
	.f = cmd_showport_parsed,
	.data = NULL,
	.help_str = "show|clear port "
		"info|summary|stats|xstats|fdir|stat_qmap|dcb_tc|cap "
		"<port_id>",
	.tokens = {
		(void *)&cmd_showport_show,
		(void *)&cmd_showport_port,
		(void *)&cmd_showport_what,
		(void *)&cmd_showport_portnum,
		NULL,
	},
};

/* *** SHOW QUEUE INFO *** */
struct cmd_showqueue_result {
	cmdline_fixed_string_t show;
	cmdline_fixed_string_t type;
	cmdline_fixed_string_t what;
	uint16_t portnum;
	uint16_t queuenum;
};

static void
cmd_showqueue_parsed(void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_showqueue_result *res = parsed_result;

	if (!strcmp(res->type, "rxq"))
		rx_queue_infos_display(res->portnum, res->queuenum);
	else if (!strcmp(res->type, "txq"))
		tx_queue_infos_display(res->portnum, res->queuenum);
}

cmdline_parse_token_string_t cmd_showqueue_show =
	TOKEN_STRING_INITIALIZER(struct cmd_showqueue_result, show, "show");
cmdline_parse_token_string_t cmd_showqueue_type =
	TOKEN_STRING_INITIALIZER(struct cmd_showqueue_result, type, "rxq#txq");
cmdline_parse_token_string_t cmd_showqueue_what =
	TOKEN_STRING_INITIALIZER(struct cmd_showqueue_result, what, "info");
cmdline_parse_token_num_t cmd_showqueue_portnum =
	TOKEN_NUM_INITIALIZER(struct cmd_showqueue_result, portnum, UINT16);
cmdline_parse_token_num_t cmd_showqueue_queuenum =
	TOKEN_NUM_INITIALIZER(struct cmd_showqueue_result, queuenum, UINT16);

cmdline_parse_inst_t cmd_showqueue = {
	.f = cmd_showqueue_parsed,
	.data = NULL,
	.help_str = "show rxq|txq info <port_id> <queue_id>",
	.tokens = {
		(void *)&cmd_showqueue_show,
		(void *)&cmd_showqueue_type,
		(void *)&cmd_showqueue_what,
		(void *)&cmd_showqueue_portnum,
		(void *)&cmd_showqueue_queuenum,
		NULL,
	},
};

/* *** READ PORT REGISTER *** */
struct cmd_read_reg_result {
	cmdline_fixed_string_t read;
	cmdline_fixed_string_t reg;
	portid_t port_id;
	uint32_t reg_off;
};

static void
cmd_read_reg_parsed(void *parsed_result,
		    __attribute__((unused)) struct cmdline *cl,
		    __attribute__((unused)) void *data)
{
	struct cmd_read_reg_result *res = parsed_result;
	port_reg_display(res->port_id, res->reg_off);
}

cmdline_parse_token_string_t cmd_read_reg_read =
	TOKEN_STRING_INITIALIZER(struct cmd_read_reg_result, read, "read");
cmdline_parse_token_string_t cmd_read_reg_reg =
	TOKEN_STRING_INITIALIZER(struct cmd_read_reg_result, reg, "reg");
cmdline_parse_token_num_t cmd_read_reg_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_read_reg_result, port_id, UINT16);
cmdline_parse_token_num_t cmd_read_reg_reg_off =
	TOKEN_NUM_INITIALIZER(struct cmd_read_reg_result, reg_off, UINT32);

cmdline_parse_inst_t cmd_read_reg = {
	.f = cmd_read_reg_parsed,
	.data = NULL,
	.help_str = "read reg <port_id> <reg_off>",
	.tokens = {
		(void *)&cmd_read_reg_read,
		(void *)&cmd_read_reg_reg,
		(void *)&cmd_read_reg_port_id,
		(void *)&cmd_read_reg_reg_off,
		NULL,
	},
};

/* *** READ PORT REGISTER BIT FIELD *** */
struct cmd_read_reg_bit_field_result {
	cmdline_fixed_string_t read;
	cmdline_fixed_string_t regfield;
	portid_t port_id;
	uint32_t reg_off;
	uint8_t bit1_pos;
	uint8_t bit2_pos;
};

static void
cmd_read_reg_bit_field_parsed(void *parsed_result,
			      __attribute__((unused)) struct cmdline *cl,
			      __attribute__((unused)) void *data)
{
	struct cmd_read_reg_bit_field_result *res = parsed_result;
	port_reg_bit_field_display(res->port_id, res->reg_off,
				   res->bit1_pos, res->bit2_pos);
}

cmdline_parse_token_string_t cmd_read_reg_bit_field_read =
	TOKEN_STRING_INITIALIZER(struct cmd_read_reg_bit_field_result, read,
				 "read");
cmdline_parse_token_string_t cmd_read_reg_bit_field_regfield =
	TOKEN_STRING_INITIALIZER(struct cmd_read_reg_bit_field_result,
				 regfield, "regfield");
cmdline_parse_token_num_t cmd_read_reg_bit_field_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_read_reg_bit_field_result, port_id,
			      UINT16);
cmdline_parse_token_num_t cmd_read_reg_bit_field_reg_off =
	TOKEN_NUM_INITIALIZER(struct cmd_read_reg_bit_field_result, reg_off,
			      UINT32);
cmdline_parse_token_num_t cmd_read_reg_bit_field_bit1_pos =
	TOKEN_NUM_INITIALIZER(struct cmd_read_reg_bit_field_result, bit1_pos,
			      UINT8);
cmdline_parse_token_num_t cmd_read_reg_bit_field_bit2_pos =
	TOKEN_NUM_INITIALIZER(struct cmd_read_reg_bit_field_result, bit2_pos,
			      UINT8);

cmdline_parse_inst_t cmd_read_reg_bit_field = {
	.f = cmd_read_reg_bit_field_parsed,
	.data = NULL,
	.help_str = "read regfield <port_id> <reg_off> <bit_x> <bit_y>: "
	"Read register bit field between bit_x and bit_y included",
	.tokens = {
		(void *)&cmd_read_reg_bit_field_read,
		(void *)&cmd_read_reg_bit_field_regfield,
		(void *)&cmd_read_reg_bit_field_port_id,
		(void *)&cmd_read_reg_bit_field_reg_off,
		(void *)&cmd_read_reg_bit_field_bit1_pos,
		(void *)&cmd_read_reg_bit_field_bit2_pos,
		NULL,
	},
};

/* *** READ PORT REGISTER BIT *** */
struct cmd_read_reg_bit_result {
	cmdline_fixed_string_t read;
	cmdline_fixed_string_t regbit;
	portid_t port_id;
	uint32_t reg_off;
	uint8_t bit_pos;
};

static void
cmd_read_reg_bit_parsed(void *parsed_result,
			__attribute__((unused)) struct cmdline *cl,
			__attribute__((unused)) void *data)
{
	struct cmd_read_reg_bit_result *res = parsed_result;
	port_reg_bit_display(res->port_id, res->reg_off, res->bit_pos);
}

cmdline_parse_token_string_t cmd_read_reg_bit_read =
	TOKEN_STRING_INITIALIZER(struct cmd_read_reg_bit_result, read, "read");
cmdline_parse_token_string_t cmd_read_reg_bit_regbit =
	TOKEN_STRING_INITIALIZER(struct cmd_read_reg_bit_result,
				 regbit, "regbit");
cmdline_parse_token_num_t cmd_read_reg_bit_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_read_reg_bit_result, port_id, UINT16);
cmdline_parse_token_num_t cmd_read_reg_bit_reg_off =
	TOKEN_NUM_INITIALIZER(struct cmd_read_reg_bit_result, reg_off, UINT32);
cmdline_parse_token_num_t cmd_read_reg_bit_bit_pos =
	TOKEN_NUM_INITIALIZER(struct cmd_read_reg_bit_result, bit_pos, UINT8);

cmdline_parse_inst_t cmd_read_reg_bit = {
	.f = cmd_read_reg_bit_parsed,
	.data = NULL,
	.help_str = "read regbit <port_id> <reg_off> <bit_x>: 0 <= bit_x <= 31",
	.tokens = {
		(void *)&cmd_read_reg_bit_read,
		(void *)&cmd_read_reg_bit_regbit,
		(void *)&cmd_read_reg_bit_port_id,
		(void *)&cmd_read_reg_bit_reg_off,
		(void *)&cmd_read_reg_bit_bit_pos,
		NULL,
	},
};

/* *** WRITE PORT REGISTER *** */
struct cmd_write_reg_result {
	cmdline_fixed_string_t write;
	cmdline_fixed_string_t reg;
	portid_t port_id;
	uint32_t reg_off;
	uint32_t value;
};

static void
cmd_write_reg_parsed(void *parsed_result,
		     __attribute__((unused)) struct cmdline *cl,
		     __attribute__((unused)) void *data)
{
	struct cmd_write_reg_result *res = parsed_result;
	port_reg_set(res->port_id, res->reg_off, res->value);
}

cmdline_parse_token_string_t cmd_write_reg_write =
	TOKEN_STRING_INITIALIZER(struct cmd_write_reg_result, write, "write");
cmdline_parse_token_string_t cmd_write_reg_reg =
	TOKEN_STRING_INITIALIZER(struct cmd_write_reg_result, reg, "reg");
cmdline_parse_token_num_t cmd_write_reg_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_write_reg_result, port_id, UINT16);
cmdline_parse_token_num_t cmd_write_reg_reg_off =
	TOKEN_NUM_INITIALIZER(struct cmd_write_reg_result, reg_off, UINT32);
cmdline_parse_token_num_t cmd_write_reg_value =
	TOKEN_NUM_INITIALIZER(struct cmd_write_reg_result, value, UINT32);

cmdline_parse_inst_t cmd_write_reg = {
	.f = cmd_write_reg_parsed,
	.data = NULL,
	.help_str = "write reg <port_id> <reg_off> <reg_value>",
	.tokens = {
		(void *)&cmd_write_reg_write,
		(void *)&cmd_write_reg_reg,
		(void *)&cmd_write_reg_port_id,
		(void *)&cmd_write_reg_reg_off,
		(void *)&cmd_write_reg_value,
		NULL,
	},
};

/* *** WRITE PORT REGISTER BIT FIELD *** */
struct cmd_write_reg_bit_field_result {
	cmdline_fixed_string_t write;
	cmdline_fixed_string_t regfield;
	portid_t port_id;
	uint32_t reg_off;
	uint8_t bit1_pos;
	uint8_t bit2_pos;
	uint32_t value;
};

static void
cmd_write_reg_bit_field_parsed(void *parsed_result,
			       __attribute__((unused)) struct cmdline *cl,
			       __attribute__((unused)) void *data)
{
	struct cmd_write_reg_bit_field_result *res = parsed_result;
	port_reg_bit_field_set(res->port_id, res->reg_off,
			  res->bit1_pos, res->bit2_pos, res->value);
}

cmdline_parse_token_string_t cmd_write_reg_bit_field_write =
	TOKEN_STRING_INITIALIZER(struct cmd_write_reg_bit_field_result, write,
				 "write");
cmdline_parse_token_string_t cmd_write_reg_bit_field_regfield =
	TOKEN_STRING_INITIALIZER(struct cmd_write_reg_bit_field_result,
				 regfield, "regfield");
cmdline_parse_token_num_t cmd_write_reg_bit_field_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_write_reg_bit_field_result, port_id,
			      UINT16);
cmdline_parse_token_num_t cmd_write_reg_bit_field_reg_off =
	TOKEN_NUM_INITIALIZER(struct cmd_write_reg_bit_field_result, reg_off,
			      UINT32);
cmdline_parse_token_num_t cmd_write_reg_bit_field_bit1_pos =
	TOKEN_NUM_INITIALIZER(struct cmd_write_reg_bit_field_result, bit1_pos,
			      UINT8);
cmdline_parse_token_num_t cmd_write_reg_bit_field_bit2_pos =
	TOKEN_NUM_INITIALIZER(struct cmd_write_reg_bit_field_result, bit2_pos,
			      UINT8);
cmdline_parse_token_num_t cmd_write_reg_bit_field_value =
	TOKEN_NUM_INITIALIZER(struct cmd_write_reg_bit_field_result, value,
			      UINT32);

cmdline_parse_inst_t cmd_write_reg_bit_field = {
	.f = cmd_write_reg_bit_field_parsed,
	.data = NULL,
	.help_str = "write regfield <port_id> <reg_off> <bit_x> <bit_y> "
		"<reg_value>: "
		"Set register bit field between bit_x and bit_y included",
	.tokens = {
		(void *)&cmd_write_reg_bit_field_write,
		(void *)&cmd_write_reg_bit_field_regfield,
		(void *)&cmd_write_reg_bit_field_port_id,
		(void *)&cmd_write_reg_bit_field_reg_off,
		(void *)&cmd_write_reg_bit_field_bit1_pos,
		(void *)&cmd_write_reg_bit_field_bit2_pos,
		(void *)&cmd_write_reg_bit_field_value,
		NULL,
	},
};

/* *** WRITE PORT REGISTER BIT *** */
struct cmd_write_reg_bit_result {
	cmdline_fixed_string_t write;
	cmdline_fixed_string_t regbit;
	portid_t port_id;
	uint32_t reg_off;
	uint8_t bit_pos;
	uint8_t value;
};

static void
cmd_write_reg_bit_parsed(void *parsed_result,
			 __attribute__((unused)) struct cmdline *cl,
			 __attribute__((unused)) void *data)
{
	struct cmd_write_reg_bit_result *res = parsed_result;
	port_reg_bit_set(res->port_id, res->reg_off, res->bit_pos, res->value);
}

cmdline_parse_token_string_t cmd_write_reg_bit_write =
	TOKEN_STRING_INITIALIZER(struct cmd_write_reg_bit_result, write,
				 "write");
cmdline_parse_token_string_t cmd_write_reg_bit_regbit =
	TOKEN_STRING_INITIALIZER(struct cmd_write_reg_bit_result,
				 regbit, "regbit");
cmdline_parse_token_num_t cmd_write_reg_bit_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_write_reg_bit_result, port_id, UINT16);
cmdline_parse_token_num_t cmd_write_reg_bit_reg_off =
	TOKEN_NUM_INITIALIZER(struct cmd_write_reg_bit_result, reg_off, UINT32);
cmdline_parse_token_num_t cmd_write_reg_bit_bit_pos =
	TOKEN_NUM_INITIALIZER(struct cmd_write_reg_bit_result, bit_pos, UINT8);
cmdline_parse_token_num_t cmd_write_reg_bit_value =
	TOKEN_NUM_INITIALIZER(struct cmd_write_reg_bit_result, value, UINT8);

cmdline_parse_inst_t cmd_write_reg_bit = {
	.f = cmd_write_reg_bit_parsed,
	.data = NULL,
	.help_str = "write regbit <port_id> <reg_off> <bit_x> 0|1: "
		"0 <= bit_x <= 31",
	.tokens = {
		(void *)&cmd_write_reg_bit_write,
		(void *)&cmd_write_reg_bit_regbit,
		(void *)&cmd_write_reg_bit_port_id,
		(void *)&cmd_write_reg_bit_reg_off,
		(void *)&cmd_write_reg_bit_bit_pos,
		(void *)&cmd_write_reg_bit_value,
		NULL,
	},
};

/* *** READ A RING DESCRIPTOR OF A PORT RX/TX QUEUE *** */
struct cmd_read_rxd_txd_result {
	cmdline_fixed_string_t read;
	cmdline_fixed_string_t rxd_txd;
	portid_t port_id;
	uint16_t queue_id;
	uint16_t desc_id;
};

static void
cmd_read_rxd_txd_parsed(void *parsed_result,
			__attribute__((unused)) struct cmdline *cl,
			__attribute__((unused)) void *data)
{
	struct cmd_read_rxd_txd_result *res = parsed_result;

	if (!strcmp(res->rxd_txd, "rxd"))
		rx_ring_desc_display(res->port_id, res->queue_id, res->desc_id);
	else if (!strcmp(res->rxd_txd, "txd"))
		tx_ring_desc_display(res->port_id, res->queue_id, res->desc_id);
}

cmdline_parse_token_string_t cmd_read_rxd_txd_read =
	TOKEN_STRING_INITIALIZER(struct cmd_read_rxd_txd_result, read, "read");
cmdline_parse_token_string_t cmd_read_rxd_txd_rxd_txd =
	TOKEN_STRING_INITIALIZER(struct cmd_read_rxd_txd_result, rxd_txd,
				 "rxd#txd");
cmdline_parse_token_num_t cmd_read_rxd_txd_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_read_rxd_txd_result, port_id, UINT16);
cmdline_parse_token_num_t cmd_read_rxd_txd_queue_id =
	TOKEN_NUM_INITIALIZER(struct cmd_read_rxd_txd_result, queue_id, UINT16);
cmdline_parse_token_num_t cmd_read_rxd_txd_desc_id =
	TOKEN_NUM_INITIALIZER(struct cmd_read_rxd_txd_result, desc_id, UINT16);

cmdline_parse_inst_t cmd_read_rxd_txd = {
	.f = cmd_read_rxd_txd_parsed,
	.data = NULL,
	.help_str = "read rxd|txd <port_id> <queue_id> <desc_id>",
	.tokens = {
		(void *)&cmd_read_rxd_txd_read,
		(void *)&cmd_read_rxd_txd_rxd_txd,
		(void *)&cmd_read_rxd_txd_port_id,
		(void *)&cmd_read_rxd_txd_queue_id,
		(void *)&cmd_read_rxd_txd_desc_id,
		NULL,
	},
};

/* *** QUIT *** */
struct cmd_quit_result {
	cmdline_fixed_string_t quit;
};

static void cmd_quit_parsed(__attribute__((unused)) void *parsed_result,
			    struct cmdline *cl,
			    __attribute__((unused)) void *data)
{
	cmdline_quit(cl);
}

cmdline_parse_token_string_t cmd_quit_quit =
	TOKEN_STRING_INITIALIZER(struct cmd_quit_result, quit, "quit");

cmdline_parse_inst_t cmd_quit = {
	.f = cmd_quit_parsed,
	.data = NULL,
	.help_str = "quit: Exit application",
	.tokens = {
		(void *)&cmd_quit_quit,
		NULL,
	},
};

/* *** ADD/REMOVE MAC ADDRESS FROM A PORT *** */
struct cmd_mac_addr_result {
	cmdline_fixed_string_t mac_addr_cmd;
	cmdline_fixed_string_t what;
	uint16_t port_num;
	struct ether_addr address;
};

static void cmd_mac_addr_parsed(void *parsed_result,
		__attribute__((unused)) struct cmdline *cl,
		__attribute__((unused)) void *data)
{
	struct cmd_mac_addr_result *res = parsed_result;
	int ret;

	if (strcmp(res->what, "add") == 0)
		ret = rte_eth_dev_mac_addr_add(res->port_num, &res->address, 0);
	else if (strcmp(res->what, "set") == 0)
		ret = rte_eth_dev_default_mac_addr_set(res->port_num,
						       &res->address);
	else
		ret = rte_eth_dev_mac_addr_remove(res->port_num, &res->address);

	/* check the return value and print it if is < 0 */
	if(ret < 0)
		printf("mac_addr_cmd error: (%s)\n", strerror(-ret));

}

cmdline_parse_token_string_t cmd_mac_addr_cmd =
	TOKEN_STRING_INITIALIZER(struct cmd_mac_addr_result, mac_addr_cmd,
				"mac_addr");
cmdline_parse_token_string_t cmd_mac_addr_what =
	TOKEN_STRING_INITIALIZER(struct cmd_mac_addr_result, what,
				"add#remove#set");
cmdline_parse_token_num_t cmd_mac_addr_portnum =
		TOKEN_NUM_INITIALIZER(struct cmd_mac_addr_result, port_num,
					UINT16);
cmdline_parse_token_etheraddr_t cmd_mac_addr_addr =
		TOKEN_ETHERADDR_INITIALIZER(struct cmd_mac_addr_result, address);

cmdline_parse_inst_t cmd_mac_addr = {
	.f = cmd_mac_addr_parsed,
	.data = (void *)0,
	.help_str = "mac_addr add|remove|set <port_id> <mac_addr>: "
			"Add/Remove/Set MAC address on port_id",
	.tokens = {
		(void *)&cmd_mac_addr_cmd,
		(void *)&cmd_mac_addr_what,
		(void *)&cmd_mac_addr_portnum,
		(void *)&cmd_mac_addr_addr,
		NULL,
	},
};

/* *** SET THE PEER ADDRESS FOR CERTAIN PORT *** */
struct cmd_eth_peer_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t eth_peer;
	portid_t port_id;
	cmdline_fixed_string_t peer_addr;
};

static void cmd_set_eth_peer_parsed(void *parsed_result,
			__attribute__((unused)) struct cmdline *cl,
			__attribute__((unused)) void *data)
{
		struct cmd_eth_peer_result *res = parsed_result;

		if (test_done == 0) {
			printf("Please stop forwarding first\n");
			return;
		}
		if (!strcmp(res->eth_peer, "eth-peer")) {
			set_fwd_eth_peer(res->port_id, res->peer_addr);
			fwd_config_setup();
		}
}
cmdline_parse_token_string_t cmd_eth_peer_set =
	TOKEN_STRING_INITIALIZER(struct cmd_eth_peer_result, set, "set");
cmdline_parse_token_string_t cmd_eth_peer =
	TOKEN_STRING_INITIALIZER(struct cmd_eth_peer_result, eth_peer, "eth-peer");
cmdline_parse_token_num_t cmd_eth_peer_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_eth_peer_result, port_id, UINT16);
cmdline_parse_token_string_t cmd_eth_peer_addr =
	TOKEN_STRING_INITIALIZER(struct cmd_eth_peer_result, peer_addr, NULL);

cmdline_parse_inst_t cmd_set_fwd_eth_peer = {
	.f = cmd_set_eth_peer_parsed,
	.data = NULL,
	.help_str = "set eth-peer <port_id> <peer_mac>",
	.tokens = {
		(void *)&cmd_eth_peer_set,
		(void *)&cmd_eth_peer,
		(void *)&cmd_eth_peer_port_id,
		(void *)&cmd_eth_peer_addr,
		NULL,
	},
};

/* *** CONFIGURE QUEUE STATS COUNTER MAPPINGS *** */
struct cmd_set_qmap_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t qmap;
	cmdline_fixed_string_t what;
	portid_t port_id;
	uint16_t queue_id;
	uint8_t map_value;
};

static void
cmd_set_qmap_parsed(void *parsed_result,
		       __attribute__((unused)) struct cmdline *cl,
		       __attribute__((unused)) void *data)
{
	struct cmd_set_qmap_result *res = parsed_result;
	int is_rx = (strcmp(res->what, "tx") == 0) ? 0 : 1;

	set_qmap(res->port_id, (uint8_t)is_rx, res->queue_id, res->map_value);
}

cmdline_parse_token_string_t cmd_setqmap_set =
	TOKEN_STRING_INITIALIZER(struct cmd_set_qmap_result,
				 set, "set");
cmdline_parse_token_string_t cmd_setqmap_qmap =
	TOKEN_STRING_INITIALIZER(struct cmd_set_qmap_result,
				 qmap, "stat_qmap");
cmdline_parse_token_string_t cmd_setqmap_what =
	TOKEN_STRING_INITIALIZER(struct cmd_set_qmap_result,
				 what, "tx#rx");
cmdline_parse_token_num_t cmd_setqmap_portid =
	TOKEN_NUM_INITIALIZER(struct cmd_set_qmap_result,
			      port_id, UINT16);
cmdline_parse_token_num_t cmd_setqmap_queueid =
	TOKEN_NUM_INITIALIZER(struct cmd_set_qmap_result,
			      queue_id, UINT16);
cmdline_parse_token_num_t cmd_setqmap_mapvalue =
	TOKEN_NUM_INITIALIZER(struct cmd_set_qmap_result,
			      map_value, UINT8);

cmdline_parse_inst_t cmd_set_qmap = {
	.f = cmd_set_qmap_parsed,
	.data = NULL,
	.help_str = "set stat_qmap rx|tx <port_id> <queue_id> <map_value>: "
		"Set statistics mapping value on tx|rx queue_id of port_id",
	.tokens = {
		(void *)&cmd_setqmap_set,
		(void *)&cmd_setqmap_qmap,
		(void *)&cmd_setqmap_what,
		(void *)&cmd_setqmap_portid,
		(void *)&cmd_setqmap_queueid,
		(void *)&cmd_setqmap_mapvalue,
		NULL,
	},
};

/* *** SET OPTION TO HIDE ZERO VALUES FOR XSTATS  DISPLAY *** */
struct cmd_set_xstats_hide_zero_result {
	cmdline_fixed_string_t keyword;
	cmdline_fixed_string_t name;
	cmdline_fixed_string_t on_off;
};

static void
cmd_set_xstats_hide_zero_parsed(void *parsed_result,
			__attribute__((unused)) struct cmdline *cl,
			__attribute__((unused)) void *data)
{
	struct cmd_set_xstats_hide_zero_result *res;
	uint16_t on_off = 0;

	res = parsed_result;
	on_off = !strcmp(res->on_off, "on") ? 1 : 0;
	set_xstats_hide_zero(on_off);
}

cmdline_parse_token_string_t cmd_set_xstats_hide_zero_keyword =
	TOKEN_STRING_INITIALIZER(struct cmd_set_xstats_hide_zero_result,
				 keyword, "set");
cmdline_parse_token_string_t cmd_set_xstats_hide_zero_name =
	TOKEN_STRING_INITIALIZER(struct cmd_set_xstats_hide_zero_result,
				 name, "xstats-hide-zero");
cmdline_parse_token_string_t cmd_set_xstats_hide_zero_on_off =
	TOKEN_STRING_INITIALIZER(struct cmd_set_xstats_hide_zero_result,
				 on_off, "on#off");

cmdline_parse_inst_t cmd_set_xstats_hide_zero = {
	.f = cmd_set_xstats_hide_zero_parsed,
	.data = NULL,
	.help_str = "set xstats-hide-zero on|off",
	.tokens = {
		(void *)&cmd_set_xstats_hide_zero_keyword,
		(void *)&cmd_set_xstats_hide_zero_name,
		(void *)&cmd_set_xstats_hide_zero_on_off,
		NULL,
	},
};

/* *** CONFIGURE UNICAST HASH TABLE *** */
struct cmd_set_uc_hash_table {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t port;
	portid_t port_id;
	cmdline_fixed_string_t what;
	struct ether_addr address;
	cmdline_fixed_string_t mode;
};

static void
cmd_set_uc_hash_parsed(void *parsed_result,
		       __attribute__((unused)) struct cmdline *cl,
		       __attribute__((unused)) void *data)
{
	int ret=0;
	struct cmd_set_uc_hash_table *res = parsed_result;

	int is_on = (strcmp(res->mode, "on") == 0) ? 1 : 0;

	if (strcmp(res->what, "uta") == 0)
		ret = rte_eth_dev_uc_hash_table_set(res->port_id,
						&res->address,(uint8_t)is_on);
	if (ret < 0)
		printf("bad unicast hash table parameter, return code = %d \n", ret);

}

cmdline_parse_token_string_t cmd_set_uc_hash_set =
	TOKEN_STRING_INITIALIZER(struct cmd_set_uc_hash_table,
				 set, "set");
cmdline_parse_token_string_t cmd_set_uc_hash_port =
	TOKEN_STRING_INITIALIZER(struct cmd_set_uc_hash_table,
				 port, "port");
cmdline_parse_token_num_t cmd_set_uc_hash_portid =
	TOKEN_NUM_INITIALIZER(struct cmd_set_uc_hash_table,
			      port_id, UINT16);
cmdline_parse_token_string_t cmd_set_uc_hash_what =
	TOKEN_STRING_INITIALIZER(struct cmd_set_uc_hash_table,
				 what, "uta");
cmdline_parse_token_etheraddr_t cmd_set_uc_hash_mac =
	TOKEN_ETHERADDR_INITIALIZER(struct cmd_set_uc_hash_table,
				address);
cmdline_parse_token_string_t cmd_set_uc_hash_mode =
	TOKEN_STRING_INITIALIZER(struct cmd_set_uc_hash_table,
				 mode, "on#off");

cmdline_parse_inst_t cmd_set_uc_hash_filter = {
	.f = cmd_set_uc_hash_parsed,
	.data = NULL,
	.help_str = "set port <port_id> uta <mac_addr> on|off)",
	.tokens = {
		(void *)&cmd_set_uc_hash_set,
		(void *)&cmd_set_uc_hash_port,
		(void *)&cmd_set_uc_hash_portid,
		(void *)&cmd_set_uc_hash_what,
		(void *)&cmd_set_uc_hash_mac,
		(void *)&cmd_set_uc_hash_mode,
		NULL,
	},
};

struct cmd_set_uc_all_hash_table {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t port;
	portid_t port_id;
	cmdline_fixed_string_t what;
	cmdline_fixed_string_t value;
	cmdline_fixed_string_t mode;
};

static void
cmd_set_uc_all_hash_parsed(void *parsed_result,
		       __attribute__((unused)) struct cmdline *cl,
		       __attribute__((unused)) void *data)
{
	int ret=0;
	struct cmd_set_uc_all_hash_table *res = parsed_result;

	int is_on = (strcmp(res->mode, "on") == 0) ? 1 : 0;

	if ((strcmp(res->what, "uta") == 0) &&
		(strcmp(res->value, "all") == 0))
		ret = rte_eth_dev_uc_all_hash_table_set(res->port_id,(uint8_t) is_on);
	if (ret < 0)
		printf("bad unicast hash table parameter,"
			"return code = %d \n", ret);
}

cmdline_parse_token_string_t cmd_set_uc_all_hash_set =
	TOKEN_STRING_INITIALIZER(struct cmd_set_uc_all_hash_table,
				 set, "set");
cmdline_parse_token_string_t cmd_set_uc_all_hash_port =
	TOKEN_STRING_INITIALIZER(struct cmd_set_uc_all_hash_table,
				 port, "port");
cmdline_parse_token_num_t cmd_set_uc_all_hash_portid =
	TOKEN_NUM_INITIALIZER(struct cmd_set_uc_all_hash_table,
			      port_id, UINT16);
cmdline_parse_token_string_t cmd_set_uc_all_hash_what =
	TOKEN_STRING_INITIALIZER(struct cmd_set_uc_all_hash_table,
				 what, "uta");
cmdline_parse_token_string_t cmd_set_uc_all_hash_value =
	TOKEN_STRING_INITIALIZER(struct cmd_set_uc_all_hash_table,
				value,"all");
cmdline_parse_token_string_t cmd_set_uc_all_hash_mode =
	TOKEN_STRING_INITIALIZER(struct cmd_set_uc_all_hash_table,
				 mode, "on#off");

cmdline_parse_inst_t cmd_set_uc_all_hash_filter = {
	.f = cmd_set_uc_all_hash_parsed,
	.data = NULL,
	.help_str = "set port <port_id> uta all on|off",
	.tokens = {
		(void *)&cmd_set_uc_all_hash_set,
		(void *)&cmd_set_uc_all_hash_port,
		(void *)&cmd_set_uc_all_hash_portid,
		(void *)&cmd_set_uc_all_hash_what,
		(void *)&cmd_set_uc_all_hash_value,
		(void *)&cmd_set_uc_all_hash_mode,
		NULL,
	},
};

/* *** CONFIGURE MACVLAN FILTER FOR VF(s) *** */
struct cmd_set_vf_macvlan_filter {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t port;
	portid_t port_id;
	cmdline_fixed_string_t vf;
	uint8_t vf_id;
	struct ether_addr address;
	cmdline_fixed_string_t filter_type;
	cmdline_fixed_string_t mode;
};

static void
cmd_set_vf_macvlan_parsed(void *parsed_result,
		       __attribute__((unused)) struct cmdline *cl,
		       __attribute__((unused)) void *data)
{
	int is_on, ret = 0;
	struct cmd_set_vf_macvlan_filter *res = parsed_result;
	struct rte_eth_mac_filter filter;

	memset(&filter, 0, sizeof(struct rte_eth_mac_filter));

	rte_memcpy(&filter.mac_addr, &res->address, ETHER_ADDR_LEN);

	/* set VF MAC filter */
	filter.is_vf = 1;

	/* set VF ID */
	filter.dst_id = res->vf_id;

	if (!strcmp(res->filter_type, "exact-mac"))
		filter.filter_type = RTE_MAC_PERFECT_MATCH;
	else if (!strcmp(res->filter_type, "exact-mac-vlan"))
		filter.filter_type = RTE_MACVLAN_PERFECT_MATCH;
	else if (!strcmp(res->filter_type, "hashmac"))
		filter.filter_type = RTE_MAC_HASH_MATCH;
	else if (!strcmp(res->filter_type, "hashmac-vlan"))
		filter.filter_type = RTE_MACVLAN_HASH_MATCH;

	is_on = (strcmp(res->mode, "on") == 0) ? 1 : 0;

	if (is_on)
		ret = rte_eth_dev_filter_ctrl(res->port_id,
					RTE_ETH_FILTER_MACVLAN,
					RTE_ETH_FILTER_ADD,
					 &filter);
	else
		ret = rte_eth_dev_filter_ctrl(res->port_id,
					RTE_ETH_FILTER_MACVLAN,
					RTE_ETH_FILTER_DELETE,
					&filter);

	if (ret < 0)
		printf("bad set MAC hash parameter, return code = %d\n", ret);

}

cmdline_parse_token_string_t cmd_set_vf_macvlan_set =
	TOKEN_STRING_INITIALIZER(struct cmd_set_vf_macvlan_filter,
				 set, "set");
cmdline_parse_token_string_t cmd_set_vf_macvlan_port =
	TOKEN_STRING_INITIALIZER(struct cmd_set_vf_macvlan_filter,
				 port, "port");
cmdline_parse_token_num_t cmd_set_vf_macvlan_portid =
	TOKEN_NUM_INITIALIZER(struct cmd_set_vf_macvlan_filter,
			      port_id, UINT16);
cmdline_parse_token_string_t cmd_set_vf_macvlan_vf =
	TOKEN_STRING_INITIALIZER(struct cmd_set_vf_macvlan_filter,
				 vf, "vf");
cmdline_parse_token_num_t cmd_set_vf_macvlan_vf_id =
	TOKEN_NUM_INITIALIZER(struct cmd_set_vf_macvlan_filter,
				vf_id, UINT8);
cmdline_parse_token_etheraddr_t cmd_set_vf_macvlan_mac =
	TOKEN_ETHERADDR_INITIALIZER(struct cmd_set_vf_macvlan_filter,
				address);
cmdline_parse_token_string_t cmd_set_vf_macvlan_filter_type =
	TOKEN_STRING_INITIALIZER(struct cmd_set_vf_macvlan_filter,
				filter_type, "exact-mac#exact-mac-vlan"
				"#hashmac#hashmac-vlan");
cmdline_parse_token_string_t cmd_set_vf_macvlan_mode =
	TOKEN_STRING_INITIALIZER(struct cmd_set_vf_macvlan_filter,
				 mode, "on#off");

cmdline_parse_inst_t cmd_set_vf_macvlan_filter = {
	.f = cmd_set_vf_macvlan_parsed,
	.data = NULL,
	.help_str = "set port <port_id> vf <vf_id> <mac_addr> "
		"exact-mac|exact-mac-vlan|hashmac|hashmac-vlan on|off: "
		"Exact match rule: exact match of MAC or MAC and VLAN; "
		"hash match rule: hash match of MAC and exact match of VLAN",
	.tokens = {
		(void *)&cmd_set_vf_macvlan_set,
		(void *)&cmd_set_vf_macvlan_port,
		(void *)&cmd_set_vf_macvlan_portid,
		(void *)&cmd_set_vf_macvlan_vf,
		(void *)&cmd_set_vf_macvlan_vf_id,
		(void *)&cmd_set_vf_macvlan_mac,
		(void *)&cmd_set_vf_macvlan_filter_type,
		(void *)&cmd_set_vf_macvlan_mode,
		NULL,
	},
};

/* *** CONFIGURE VF TRAFFIC CONTROL *** */
struct cmd_set_vf_traffic {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t port;
	portid_t port_id;
	cmdline_fixed_string_t vf;
	uint8_t vf_id;
	cmdline_fixed_string_t what;
	cmdline_fixed_string_t mode;
};

static void
cmd_set_vf_traffic_parsed(void *parsed_result,
		       __attribute__((unused)) struct cmdline *cl,
		       __attribute__((unused)) void *data)
{
	struct cmd_set_vf_traffic *res = parsed_result;
	int is_rx = (strcmp(res->what, "rx") == 0) ? 1 : 0;
	int is_on = (strcmp(res->mode, "on") == 0) ? 1 : 0;

	set_vf_traffic(res->port_id, (uint8_t)is_rx, res->vf_id,(uint8_t) is_on);
}

cmdline_parse_token_string_t cmd_setvf_traffic_set =
	TOKEN_STRING_INITIALIZER(struct cmd_set_vf_traffic,
				 set, "set");
cmdline_parse_token_string_t cmd_setvf_traffic_port =
	TOKEN_STRING_INITIALIZER(struct cmd_set_vf_traffic,
				 port, "port");
cmdline_parse_token_num_t cmd_setvf_traffic_portid =
	TOKEN_NUM_INITIALIZER(struct cmd_set_vf_traffic,
			      port_id, UINT16);
cmdline_parse_token_string_t cmd_setvf_traffic_vf =
	TOKEN_STRING_INITIALIZER(struct cmd_set_vf_traffic,
				 vf, "vf");
cmdline_parse_token_num_t cmd_setvf_traffic_vfid =
	TOKEN_NUM_INITIALIZER(struct cmd_set_vf_traffic,
			      vf_id, UINT8);
cmdline_parse_token_string_t cmd_setvf_traffic_what =
	TOKEN_STRING_INITIALIZER(struct cmd_set_vf_traffic,
				 what, "tx#rx");
cmdline_parse_token_string_t cmd_setvf_traffic_mode =
	TOKEN_STRING_INITIALIZER(struct cmd_set_vf_traffic,
				 mode, "on#off");

cmdline_parse_inst_t cmd_set_vf_traffic = {
	.f = cmd_set_vf_traffic_parsed,
	.data = NULL,
	.help_str = "set port <port_id> vf <vf_id> rx|tx on|off",
	.tokens = {
		(void *)&cmd_setvf_traffic_set,
		(void *)&cmd_setvf_traffic_port,
		(void *)&cmd_setvf_traffic_portid,
		(void *)&cmd_setvf_traffic_vf,
		(void *)&cmd_setvf_traffic_vfid,
		(void *)&cmd_setvf_traffic_what,
		(void *)&cmd_setvf_traffic_mode,
		NULL,
	},
};

/* *** CONFIGURE VF RECEIVE MODE *** */
struct cmd_set_vf_rxmode {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t port;
	portid_t port_id;
	cmdline_fixed_string_t vf;
	uint8_t vf_id;
	cmdline_fixed_string_t what;
	cmdline_fixed_string_t mode;
	cmdline_fixed_string_t on;
};

static void
cmd_set_vf_rxmode_parsed(void *parsed_result,
		       __attribute__((unused)) struct cmdline *cl,
		       __attribute__((unused)) void *data)
{
	int ret = -ENOTSUP;
	uint16_t vf_rxmode = 0;
	struct cmd_set_vf_rxmode *res = parsed_result;

	int is_on = (strcmp(res->on, "on") == 0) ? 1 : 0;
	if (!strcmp(res->what,"rxmode")) {
		if (!strcmp(res->mode, "AUPE"))
			vf_rxmode |= ETH_VMDQ_ACCEPT_UNTAG;
		else if (!strcmp(res->mode, "ROPE"))
			vf_rxmode |= ETH_VMDQ_ACCEPT_HASH_UC;
		else if (!strcmp(res->mode, "BAM"))
			vf_rxmode |= ETH_VMDQ_ACCEPT_BROADCAST;
		else if (!strncmp(res->mode, "MPE",3))
			vf_rxmode |= ETH_VMDQ_ACCEPT_MULTICAST;
	}

	RTE_SET_USED(is_on);

#ifdef RTE_LIBRTE_IXGBE_PMD
	if (ret == -ENOTSUP)
		ret = rte_pmd_ixgbe_set_vf_rxmode(res->port_id, res->vf_id,
						  vf_rxmode, (uint8_t)is_on);
#endif
#ifdef RTE_LIBRTE_BNXT_PMD
	if (ret == -ENOTSUP)
		ret = rte_pmd_bnxt_set_vf_rxmode(res->port_id, res->vf_id,
						 vf_rxmode, (uint8_t)is_on);
#endif
	if (ret < 0)
		printf("bad VF receive mode parameter, return code = %d \n",
		ret);
}

cmdline_parse_token_string_t cmd_set_vf_rxmode_set =
	TOKEN_STRING_INITIALIZER(struct cmd_set_vf_rxmode,
				 set, "set");
cmdline_parse_token_string_t cmd_set_vf_rxmode_port =
	TOKEN_STRING_INITIALIZER(struct cmd_set_vf_rxmode,
				 port, "port");
cmdline_parse_token_num_t cmd_set_vf_rxmode_portid =
	TOKEN_NUM_INITIALIZER(struct cmd_set_vf_rxmode,
			      port_id, UINT16);
cmdline_parse_token_string_t cmd_set_vf_rxmode_vf =
	TOKEN_STRING_INITIALIZER(struct cmd_set_vf_rxmode,
				 vf, "vf");
cmdline_parse_token_num_t cmd_set_vf_rxmode_vfid =
	TOKEN_NUM_INITIALIZER(struct cmd_set_vf_rxmode,
			      vf_id, UINT8);
cmdline_parse_token_string_t cmd_set_vf_rxmode_what =
	TOKEN_STRING_INITIALIZER(struct cmd_set_vf_rxmode,
				 what, "rxmode");
cmdline_parse_token_string_t cmd_set_vf_rxmode_mode =
	TOKEN_STRING_INITIALIZER(struct cmd_set_vf_rxmode,
				 mode, "AUPE#ROPE#BAM#MPE");
cmdline_parse_token_string_t cmd_set_vf_rxmode_on =
	TOKEN_STRING_INITIALIZER(struct cmd_set_vf_rxmode,
				 on, "on#off");

cmdline_parse_inst_t cmd_set_vf_rxmode = {
	.f = cmd_set_vf_rxmode_parsed,
	.data = NULL,
	.help_str = "set port <port_id> vf <vf_id> rxmode "
		"AUPE|ROPE|BAM|MPE on|off",
	.tokens = {
		(void *)&cmd_set_vf_rxmode_set,
		(void *)&cmd_set_vf_rxmode_port,
		(void *)&cmd_set_vf_rxmode_portid,
		(void *)&cmd_set_vf_rxmode_vf,
		(void *)&cmd_set_vf_rxmode_vfid,
		(void *)&cmd_set_vf_rxmode_what,
		(void *)&cmd_set_vf_rxmode_mode,
		(void *)&cmd_set_vf_rxmode_on,
		NULL,
	},
};

/* *** ADD MAC ADDRESS FILTER FOR A VF OF A PORT *** */
struct cmd_vf_mac_addr_result {
	cmdline_fixed_string_t mac_addr_cmd;
	cmdline_fixed_string_t what;
	cmdline_fixed_string_t port;
	uint16_t port_num;
	cmdline_fixed_string_t vf;
	uint8_t vf_num;
	struct ether_addr address;
};

static void cmd_vf_mac_addr_parsed(void *parsed_result,
		__attribute__((unused)) struct cmdline *cl,
		__attribute__((unused)) void *data)
{
	struct cmd_vf_mac_addr_result *res = parsed_result;
	int ret = -ENOTSUP;

	if (strcmp(res->what, "add") != 0)
		return;

#ifdef RTE_LIBRTE_I40E_PMD
	if (ret == -ENOTSUP)
		ret = rte_pmd_i40e_add_vf_mac_addr(res->port_num, res->vf_num,
						   &res->address);
#endif
#ifdef RTE_LIBRTE_BNXT_PMD
	if (ret == -ENOTSUP)
		ret = rte_pmd_bnxt_mac_addr_add(res->port_num, &res->address,
						res->vf_num);
#endif

	if(ret < 0)
		printf("vf_mac_addr_cmd error: (%s)\n", strerror(-ret));

}

cmdline_parse_token_string_t cmd_vf_mac_addr_cmd =
	TOKEN_STRING_INITIALIZER(struct cmd_vf_mac_addr_result,
				mac_addr_cmd,"mac_addr");
cmdline_parse_token_string_t cmd_vf_mac_addr_what =
	TOKEN_STRING_INITIALIZER(struct cmd_vf_mac_addr_result,
				what,"add");
cmdline_parse_token_string_t cmd_vf_mac_addr_port =
	TOKEN_STRING_INITIALIZER(struct cmd_vf_mac_addr_result,
				port,"port");
cmdline_parse_token_num_t cmd_vf_mac_addr_portnum =
	TOKEN_NUM_INITIALIZER(struct cmd_vf_mac_addr_result,
				port_num, UINT16);
cmdline_parse_token_string_t cmd_vf_mac_addr_vf =
	TOKEN_STRING_INITIALIZER(struct cmd_vf_mac_addr_result,
				vf,"vf");
cmdline_parse_token_num_t cmd_vf_mac_addr_vfnum =
	TOKEN_NUM_INITIALIZER(struct cmd_vf_mac_addr_result,
				vf_num, UINT8);
cmdline_parse_token_etheraddr_t cmd_vf_mac_addr_addr =
	TOKEN_ETHERADDR_INITIALIZER(struct cmd_vf_mac_addr_result,
				address);

cmdline_parse_inst_t cmd_vf_mac_addr_filter = {
	.f = cmd_vf_mac_addr_parsed,
	.data = (void *)0,
	.help_str = "mac_addr add port <port_id> vf <vf_id> <mac_addr>: "
		"Add MAC address filtering for a VF on port_id",
	.tokens = {
		(void *)&cmd_vf_mac_addr_cmd,
		(void *)&cmd_vf_mac_addr_what,
		(void *)&cmd_vf_mac_addr_port,
		(void *)&cmd_vf_mac_addr_portnum,
		(void *)&cmd_vf_mac_addr_vf,
		(void *)&cmd_vf_mac_addr_vfnum,
		(void *)&cmd_vf_mac_addr_addr,
		NULL,
	},
};

/* *** ADD/REMOVE A VLAN IDENTIFIER TO/FROM A PORT VLAN RX FILTER *** */
struct cmd_vf_rx_vlan_filter {
	cmdline_fixed_string_t rx_vlan;
	cmdline_fixed_string_t what;
	uint16_t vlan_id;
	cmdline_fixed_string_t port;
	portid_t port_id;
	cmdline_fixed_string_t vf;
	uint64_t vf_mask;
};

static void
cmd_vf_rx_vlan_filter_parsed(void *parsed_result,
			  __attribute__((unused)) struct cmdline *cl,
			  __attribute__((unused)) void *data)
{
	struct cmd_vf_rx_vlan_filter *res = parsed_result;
	int ret = -ENOTSUP;

	__rte_unused int is_add = (strcmp(res->what, "add") == 0) ? 1 : 0;

#ifdef RTE_LIBRTE_IXGBE_PMD
	if (ret == -ENOTSUP)
		ret = rte_pmd_ixgbe_set_vf_vlan_filter(res->port_id,
				res->vlan_id, res->vf_mask, is_add);
#endif
#ifdef RTE_LIBRTE_I40E_PMD
	if (ret == -ENOTSUP)
		ret = rte_pmd_i40e_set_vf_vlan_filter(res->port_id,
				res->vlan_id, res->vf_mask, is_add);
#endif
#ifdef RTE_LIBRTE_BNXT_PMD
	if (ret == -ENOTSUP)
		ret = rte_pmd_bnxt_set_vf_vlan_filter(res->port_id,
				res->vlan_id, res->vf_mask, is_add);
#endif

	switch (ret) {
	case 0:
		break;
	case -EINVAL:
		printf("invalid vlan_id %d or vf_mask %"PRIu64"\n",
				res->vlan_id, res->vf_mask);
		break;
	case -ENODEV:
		printf("invalid port_id %d\n", res->port_id);
		break;
	case -ENOTSUP:
		printf("function not implemented or supported\n");
		break;
	default:
		printf("programming error: (%s)\n", strerror(-ret));
	}
}

cmdline_parse_token_string_t cmd_vf_rx_vlan_filter_rx_vlan =
	TOKEN_STRING_INITIALIZER(struct cmd_vf_rx_vlan_filter,
				 rx_vlan, "rx_vlan");
cmdline_parse_token_string_t cmd_vf_rx_vlan_filter_what =
	TOKEN_STRING_INITIALIZER(struct cmd_vf_rx_vlan_filter,
				 what, "add#rm");
cmdline_parse_token_num_t cmd_vf_rx_vlan_filter_vlanid =
	TOKEN_NUM_INITIALIZER(struct cmd_vf_rx_vlan_filter,
			      vlan_id, UINT16);
cmdline_parse_token_string_t cmd_vf_rx_vlan_filter_port =
	TOKEN_STRING_INITIALIZER(struct cmd_vf_rx_vlan_filter,
				 port, "port");
cmdline_parse_token_num_t cmd_vf_rx_vlan_filter_portid =
	TOKEN_NUM_INITIALIZER(struct cmd_vf_rx_vlan_filter,
			      port_id, UINT16);
cmdline_parse_token_string_t cmd_vf_rx_vlan_filter_vf =
	TOKEN_STRING_INITIALIZER(struct cmd_vf_rx_vlan_filter,
				 vf, "vf");
cmdline_parse_token_num_t cmd_vf_rx_vlan_filter_vf_mask =
	TOKEN_NUM_INITIALIZER(struct cmd_vf_rx_vlan_filter,
			      vf_mask, UINT64);

cmdline_parse_inst_t cmd_vf_rxvlan_filter = {
	.f = cmd_vf_rx_vlan_filter_parsed,
	.data = NULL,
	.help_str = "rx_vlan add|rm <vlan_id> port <port_id> vf <vf_mask>: "
		"(vf_mask = hexadecimal VF mask)",
	.tokens = {
		(void *)&cmd_vf_rx_vlan_filter_rx_vlan,
		(void *)&cmd_vf_rx_vlan_filter_what,
		(void *)&cmd_vf_rx_vlan_filter_vlanid,
		(void *)&cmd_vf_rx_vlan_filter_port,
		(void *)&cmd_vf_rx_vlan_filter_portid,
		(void *)&cmd_vf_rx_vlan_filter_vf,
		(void *)&cmd_vf_rx_vlan_filter_vf_mask,
		NULL,
	},
};

/* *** SET RATE LIMIT FOR A QUEUE OF A PORT *** */
struct cmd_queue_rate_limit_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t port;
	uint16_t port_num;
	cmdline_fixed_string_t queue;
	uint8_t queue_num;
	cmdline_fixed_string_t rate;
	uint16_t rate_num;
};

static void cmd_queue_rate_limit_parsed(void *parsed_result,
		__attribute__((unused)) struct cmdline *cl,
		__attribute__((unused)) void *data)
{
	struct cmd_queue_rate_limit_result *res = parsed_result;
	int ret = 0;

	if ((strcmp(res->set, "set") == 0) && (strcmp(res->port, "port") == 0)
		&& (strcmp(res->queue, "queue") == 0)
		&& (strcmp(res->rate, "rate") == 0))
		ret = set_queue_rate_limit(res->port_num, res->queue_num,
					res->rate_num);
	if (ret < 0)
		printf("queue_rate_limit_cmd error: (%s)\n", strerror(-ret));

}

cmdline_parse_token_string_t cmd_queue_rate_limit_set =
	TOKEN_STRING_INITIALIZER(struct cmd_queue_rate_limit_result,
				set, "set");
cmdline_parse_token_string_t cmd_queue_rate_limit_port =
	TOKEN_STRING_INITIALIZER(struct cmd_queue_rate_limit_result,
				port, "port");
cmdline_parse_token_num_t cmd_queue_rate_limit_portnum =
	TOKEN_NUM_INITIALIZER(struct cmd_queue_rate_limit_result,
				port_num, UINT16);
cmdline_parse_token_string_t cmd_queue_rate_limit_queue =
	TOKEN_STRING_INITIALIZER(struct cmd_queue_rate_limit_result,
				queue, "queue");
cmdline_parse_token_num_t cmd_queue_rate_limit_queuenum =
	TOKEN_NUM_INITIALIZER(struct cmd_queue_rate_limit_result,
				queue_num, UINT8);
cmdline_parse_token_string_t cmd_queue_rate_limit_rate =
	TOKEN_STRING_INITIALIZER(struct cmd_queue_rate_limit_result,
				rate, "rate");
cmdline_parse_token_num_t cmd_queue_rate_limit_ratenum =
	TOKEN_NUM_INITIALIZER(struct cmd_queue_rate_limit_result,
				rate_num, UINT16);

cmdline_parse_inst_t cmd_queue_rate_limit = {
	.f = cmd_queue_rate_limit_parsed,
	.data = (void *)0,
	.help_str = "set port <port_id> queue <queue_id> rate <rate_value>: "
		"Set rate limit for a queue on port_id",
	.tokens = {
		(void *)&cmd_queue_rate_limit_set,
		(void *)&cmd_queue_rate_limit_port,
		(void *)&cmd_queue_rate_limit_portnum,
		(void *)&cmd_queue_rate_limit_queue,
		(void *)&cmd_queue_rate_limit_queuenum,
		(void *)&cmd_queue_rate_limit_rate,
		(void *)&cmd_queue_rate_limit_ratenum,
		NULL,
	},
};

/* *** SET RATE LIMIT FOR A VF OF A PORT *** */
struct cmd_vf_rate_limit_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t port;
	uint16_t port_num;
	cmdline_fixed_string_t vf;
	uint8_t vf_num;
	cmdline_fixed_string_t rate;
	uint16_t rate_num;
	cmdline_fixed_string_t q_msk;
	uint64_t q_msk_val;
};

static void cmd_vf_rate_limit_parsed(void *parsed_result,
		__attribute__((unused)) struct cmdline *cl,
		__attribute__((unused)) void *data)
{
	struct cmd_vf_rate_limit_result *res = parsed_result;
	int ret = 0;

	if ((strcmp(res->set, "set") == 0) && (strcmp(res->port, "port") == 0)
		&& (strcmp(res->vf, "vf") == 0)
		&& (strcmp(res->rate, "rate") == 0)
		&& (strcmp(res->q_msk, "queue_mask") == 0))
		ret = set_vf_rate_limit(res->port_num, res->vf_num,
					res->rate_num, res->q_msk_val);
	if (ret < 0)
		printf("vf_rate_limit_cmd error: (%s)\n", strerror(-ret));

}

cmdline_parse_token_string_t cmd_vf_rate_limit_set =
	TOKEN_STRING_INITIALIZER(struct cmd_vf_rate_limit_result,
				set, "set");
cmdline_parse_token_string_t cmd_vf_rate_limit_port =
	TOKEN_STRING_INITIALIZER(struct cmd_vf_rate_limit_result,
				port, "port");
cmdline_parse_token_num_t cmd_vf_rate_limit_portnum =
	TOKEN_NUM_INITIALIZER(struct cmd_vf_rate_limit_result,
				port_num, UINT16);
cmdline_parse_token_string_t cmd_vf_rate_limit_vf =
	TOKEN_STRING_INITIALIZER(struct cmd_vf_rate_limit_result,
				vf, "vf");
cmdline_parse_token_num_t cmd_vf_rate_limit_vfnum =
	TOKEN_NUM_INITIALIZER(struct cmd_vf_rate_limit_result,
				vf_num, UINT8);
cmdline_parse_token_string_t cmd_vf_rate_limit_rate =
	TOKEN_STRING_INITIALIZER(struct cmd_vf_rate_limit_result,
				rate, "rate");
cmdline_parse_token_num_t cmd_vf_rate_limit_ratenum =
	TOKEN_NUM_INITIALIZER(struct cmd_vf_rate_limit_result,
				rate_num, UINT16);
cmdline_parse_token_string_t cmd_vf_rate_limit_q_msk =
	TOKEN_STRING_INITIALIZER(struct cmd_vf_rate_limit_result,
				q_msk, "queue_mask");
cmdline_parse_token_num_t cmd_vf_rate_limit_q_msk_val =
	TOKEN_NUM_INITIALIZER(struct cmd_vf_rate_limit_result,
				q_msk_val, UINT64);

cmdline_parse_inst_t cmd_vf_rate_limit = {
	.f = cmd_vf_rate_limit_parsed,
	.data = (void *)0,
	.help_str = "set port <port_id> vf <vf_id> rate <rate_value> "
		"queue_mask <queue_mask_value>: "
		"Set rate limit for queues of VF on port_id",
	.tokens = {
		(void *)&cmd_vf_rate_limit_set,
		(void *)&cmd_vf_rate_limit_port,
		(void *)&cmd_vf_rate_limit_portnum,
		(void *)&cmd_vf_rate_limit_vf,
		(void *)&cmd_vf_rate_limit_vfnum,
		(void *)&cmd_vf_rate_limit_rate,
		(void *)&cmd_vf_rate_limit_ratenum,
		(void *)&cmd_vf_rate_limit_q_msk,
		(void *)&cmd_vf_rate_limit_q_msk_val,
		NULL,
	},
};

/* *** ADD TUNNEL FILTER OF A PORT *** */
struct cmd_tunnel_filter_result {
	cmdline_fixed_string_t cmd;
	cmdline_fixed_string_t what;
	portid_t port_id;
	struct ether_addr outer_mac;
	struct ether_addr inner_mac;
	cmdline_ipaddr_t ip_value;
	uint16_t inner_vlan;
	cmdline_fixed_string_t tunnel_type;
	cmdline_fixed_string_t filter_type;
	uint32_t tenant_id;
	uint16_t queue_num;
};

static void
cmd_tunnel_filter_parsed(void *parsed_result,
			  __attribute__((unused)) struct cmdline *cl,
			  __attribute__((unused)) void *data)
{
	struct cmd_tunnel_filter_result *res = parsed_result;
	struct rte_eth_tunnel_filter_conf tunnel_filter_conf;
	int ret = 0;

	memset(&tunnel_filter_conf, 0, sizeof(tunnel_filter_conf));

	ether_addr_copy(&res->outer_mac, &tunnel_filter_conf.outer_mac);
	ether_addr_copy(&res->inner_mac, &tunnel_filter_conf.inner_mac);
	tunnel_filter_conf.inner_vlan = res->inner_vlan;

	if (res->ip_value.family == AF_INET) {
		tunnel_filter_conf.ip_addr.ipv4_addr =
			res->ip_value.addr.ipv4.s_addr;
		tunnel_filter_conf.ip_type = RTE_TUNNEL_IPTYPE_IPV4;
	} else {
		memcpy(&(tunnel_filter_conf.ip_addr.ipv6_addr),
			&(res->ip_value.addr.ipv6),
			sizeof(struct in6_addr));
		tunnel_filter_conf.ip_type = RTE_TUNNEL_IPTYPE_IPV6;
	}

	if (!strcmp(res->filter_type, "imac-ivlan"))
		tunnel_filter_conf.filter_type = RTE_TUNNEL_FILTER_IMAC_IVLAN;
	else if (!strcmp(res->filter_type, "imac-ivlan-tenid"))
		tunnel_filter_conf.filter_type =
			RTE_TUNNEL_FILTER_IMAC_IVLAN_TENID;
	else if (!strcmp(res->filter_type, "imac-tenid"))
		tunnel_filter_conf.filter_type = RTE_TUNNEL_FILTER_IMAC_TENID;
	else if (!strcmp(res->filter_type, "imac"))
		tunnel_filter_conf.filter_type = ETH_TUNNEL_FILTER_IMAC;
	else if (!strcmp(res->filter_type, "omac-imac-tenid"))
		tunnel_filter_conf.filter_type =
			RTE_TUNNEL_FILTER_OMAC_TENID_IMAC;
	else if (!strcmp(res->filter_type, "oip"))
		tunnel_filter_conf.filter_type = ETH_TUNNEL_FILTER_OIP;
	else if (!strcmp(res->filter_type, "iip"))
		tunnel_filter_conf.filter_type = ETH_TUNNEL_FILTER_IIP;
	else {
		printf("The filter type is not supported");
		return;
	}

	if (!strcmp(res->tunnel_type, "vxlan"))
		tunnel_filter_conf.tunnel_type = RTE_TUNNEL_TYPE_VXLAN;
	else if (!strcmp(res->tunnel_type, "nvgre"))
		tunnel_filter_conf.tunnel_type = RTE_TUNNEL_TYPE_NVGRE;
	else if (!strcmp(res->tunnel_type, "ipingre"))
		tunnel_filter_conf.tunnel_type = RTE_TUNNEL_TYPE_IP_IN_GRE;
	else {
		printf("The tunnel type %s not supported.\n", res->tunnel_type);
		return;
	}

	tunnel_filter_conf.tenant_id = res->tenant_id;
	tunnel_filter_conf.queue_id = res->queue_num;
	if (!strcmp(res->what, "add"))
		ret = rte_eth_dev_filter_ctrl(res->port_id,
					RTE_ETH_FILTER_TUNNEL,
					RTE_ETH_FILTER_ADD,
					&tunnel_filter_conf);
	else
		ret = rte_eth_dev_filter_ctrl(res->port_id,
					RTE_ETH_FILTER_TUNNEL,
					RTE_ETH_FILTER_DELETE,
					&tunnel_filter_conf);
	if (ret < 0)
		printf("cmd_tunnel_filter_parsed error: (%s)\n",
				strerror(-ret));

}
cmdline_parse_token_string_t cmd_tunnel_filter_cmd =
	TOKEN_STRING_INITIALIZER(struct cmd_tunnel_filter_result,
	cmd, "tunnel_filter");
cmdline_parse_token_string_t cmd_tunnel_filter_what =
	TOKEN_STRING_INITIALIZER(struct cmd_tunnel_filter_result,
	what, "add#rm");
cmdline_parse_token_num_t cmd_tunnel_filter_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_tunnel_filter_result,
	port_id, UINT16);
cmdline_parse_token_etheraddr_t cmd_tunnel_filter_outer_mac =
	TOKEN_ETHERADDR_INITIALIZER(struct cmd_tunnel_filter_result,
	outer_mac);
cmdline_parse_token_etheraddr_t cmd_tunnel_filter_inner_mac =
	TOKEN_ETHERADDR_INITIALIZER(struct cmd_tunnel_filter_result,
	inner_mac);
cmdline_parse_token_num_t cmd_tunnel_filter_innner_vlan =
	TOKEN_NUM_INITIALIZER(struct cmd_tunnel_filter_result,
	inner_vlan, UINT16);
cmdline_parse_token_ipaddr_t cmd_tunnel_filter_ip_value =
	TOKEN_IPADDR_INITIALIZER(struct cmd_tunnel_filter_result,
	ip_value);
cmdline_parse_token_string_t cmd_tunnel_filter_tunnel_type =
	TOKEN_STRING_INITIALIZER(struct cmd_tunnel_filter_result,
	tunnel_type, "vxlan#nvgre#ipingre");

cmdline_parse_token_string_t cmd_tunnel_filter_filter_type =
	TOKEN_STRING_INITIALIZER(struct cmd_tunnel_filter_result,
	filter_type, "oip#iip#imac-ivlan#imac-ivlan-tenid#imac-tenid#"
		"imac#omac-imac-tenid");
cmdline_parse_token_num_t cmd_tunnel_filter_tenant_id =
	TOKEN_NUM_INITIALIZER(struct cmd_tunnel_filter_result,
	tenant_id, UINT32);
cmdline_parse_token_num_t cmd_tunnel_filter_queue_num =
	TOKEN_NUM_INITIALIZER(struct cmd_tunnel_filter_result,
	queue_num, UINT16);

cmdline_parse_inst_t cmd_tunnel_filter = {
	.f = cmd_tunnel_filter_parsed,
	.data = (void *)0,
	.help_str = "tunnel_filter add|rm <port_id> <outer_mac> <inner_mac> "
		"<ip> <inner_vlan> vxlan|nvgre|ipingre oip|iip|imac-ivlan|"
		"imac-ivlan-tenid|imac-tenid|imac|omac-imac-tenid <tenant_id> "
		"<queue_id>: Add/Rm tunnel filter of a port",
	.tokens = {
		(void *)&cmd_tunnel_filter_cmd,
		(void *)&cmd_tunnel_filter_what,
		(void *)&cmd_tunnel_filter_port_id,
		(void *)&cmd_tunnel_filter_outer_mac,
		(void *)&cmd_tunnel_filter_inner_mac,
		(void *)&cmd_tunnel_filter_ip_value,
		(void *)&cmd_tunnel_filter_innner_vlan,
		(void *)&cmd_tunnel_filter_tunnel_type,
		(void *)&cmd_tunnel_filter_filter_type,
		(void *)&cmd_tunnel_filter_tenant_id,
		(void *)&cmd_tunnel_filter_queue_num,
		NULL,
	},
};

/* *** CONFIGURE TUNNEL UDP PORT *** */
struct cmd_tunnel_udp_config {
	cmdline_fixed_string_t cmd;
	cmdline_fixed_string_t what;
	uint16_t udp_port;
	portid_t port_id;
};

static void
cmd_tunnel_udp_config_parsed(void *parsed_result,
			  __attribute__((unused)) struct cmdline *cl,
			  __attribute__((unused)) void *data)
{
	struct cmd_tunnel_udp_config *res = parsed_result;
	struct rte_eth_udp_tunnel tunnel_udp;
	int ret;

	tunnel_udp.udp_port = res->udp_port;

	if (!strcmp(res->cmd, "rx_vxlan_port"))
		tunnel_udp.prot_type = RTE_TUNNEL_TYPE_VXLAN;

	if (!strcmp(res->what, "add"))
		ret = rte_eth_dev_udp_tunnel_port_add(res->port_id,
						      &tunnel_udp);
	else
		ret = rte_eth_dev_udp_tunnel_port_delete(res->port_id,
							 &tunnel_udp);

	if (ret < 0)
		printf("udp tunneling add error: (%s)\n", strerror(-ret));
}

cmdline_parse_token_string_t cmd_tunnel_udp_config_cmd =
	TOKEN_STRING_INITIALIZER(struct cmd_tunnel_udp_config,
				cmd, "rx_vxlan_port");
cmdline_parse_token_string_t cmd_tunnel_udp_config_what =
	TOKEN_STRING_INITIALIZER(struct cmd_tunnel_udp_config,
				what, "add#rm");
cmdline_parse_token_num_t cmd_tunnel_udp_config_udp_port =
	TOKEN_NUM_INITIALIZER(struct cmd_tunnel_udp_config,
				udp_port, UINT16);
cmdline_parse_token_num_t cmd_tunnel_udp_config_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_tunnel_udp_config,
				port_id, UINT16);

cmdline_parse_inst_t cmd_tunnel_udp_config = {
	.f = cmd_tunnel_udp_config_parsed,
	.data = (void *)0,
	.help_str = "rx_vxlan_port add|rm <udp_port> <port_id>: "
		"Add/Remove a tunneling UDP port filter",
	.tokens = {
		(void *)&cmd_tunnel_udp_config_cmd,
		(void *)&cmd_tunnel_udp_config_what,
		(void *)&cmd_tunnel_udp_config_udp_port,
		(void *)&cmd_tunnel_udp_config_port_id,
		NULL,
	},
};

struct cmd_config_tunnel_udp_port {
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t config;
	portid_t port_id;
	cmdline_fixed_string_t udp_tunnel_port;
	cmdline_fixed_string_t action;
	cmdline_fixed_string_t tunnel_type;
	uint16_t udp_port;
};

static void
cmd_cfg_tunnel_udp_port_parsed(void *parsed_result,
			       __attribute__((unused)) struct cmdline *cl,
			       __attribute__((unused)) void *data)
{
	struct cmd_config_tunnel_udp_port *res = parsed_result;
	struct rte_eth_udp_tunnel tunnel_udp;
	int ret = 0;

	if (port_id_is_invalid(res->port_id, ENABLED_WARN))
		return;

	tunnel_udp.udp_port = res->udp_port;

	if (!strcmp(res->tunnel_type, "vxlan")) {
		tunnel_udp.prot_type = RTE_TUNNEL_TYPE_VXLAN;
	} else if (!strcmp(res->tunnel_type, "geneve")) {
		tunnel_udp.prot_type = RTE_TUNNEL_TYPE_GENEVE;
	} else {
		printf("Invalid tunnel type\n");
		return;
	}

	if (!strcmp(res->action, "add"))
		ret = rte_eth_dev_udp_tunnel_port_add(res->port_id,
						      &tunnel_udp);
	else
		ret = rte_eth_dev_udp_tunnel_port_delete(res->port_id,
							 &tunnel_udp);

	if (ret < 0)
		printf("udp tunneling port add error: (%s)\n", strerror(-ret));
}

cmdline_parse_token_string_t cmd_config_tunnel_udp_port_port =
	TOKEN_STRING_INITIALIZER(struct cmd_config_tunnel_udp_port, port,
				 "port");
cmdline_parse_token_string_t cmd_config_tunnel_udp_port_config =
	TOKEN_STRING_INITIALIZER(struct cmd_config_tunnel_udp_port, config,
				 "config");
cmdline_parse_token_num_t cmd_config_tunnel_udp_port_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_config_tunnel_udp_port, port_id,
			      UINT16);
cmdline_parse_token_string_t cmd_config_tunnel_udp_port_tunnel_port =
	TOKEN_STRING_INITIALIZER(struct cmd_config_tunnel_udp_port,
				 udp_tunnel_port,
				 "udp_tunnel_port");
cmdline_parse_token_string_t cmd_config_tunnel_udp_port_action =
	TOKEN_STRING_INITIALIZER(struct cmd_config_tunnel_udp_port, action,
				 "add#rm");
cmdline_parse_token_string_t cmd_config_tunnel_udp_port_tunnel_type =
	TOKEN_STRING_INITIALIZER(struct cmd_config_tunnel_udp_port, tunnel_type,
				 "vxlan#geneve");
cmdline_parse_token_num_t cmd_config_tunnel_udp_port_value =
	TOKEN_NUM_INITIALIZER(struct cmd_config_tunnel_udp_port, udp_port,
			      UINT16);

cmdline_parse_inst_t cmd_cfg_tunnel_udp_port = {
	.f = cmd_cfg_tunnel_udp_port_parsed,
	.data = NULL,
	.help_str = "port config <port_id> udp_tunnel_port add|rm vxlan|geneve <udp_port>",
	.tokens = {
		(void *)&cmd_config_tunnel_udp_port_port,
		(void *)&cmd_config_tunnel_udp_port_config,
		(void *)&cmd_config_tunnel_udp_port_port_id,
		(void *)&cmd_config_tunnel_udp_port_tunnel_port,
		(void *)&cmd_config_tunnel_udp_port_action,
		(void *)&cmd_config_tunnel_udp_port_tunnel_type,
		(void *)&cmd_config_tunnel_udp_port_value,
		NULL,
	},
};

/* *** GLOBAL CONFIG *** */
struct cmd_global_config_result {
	cmdline_fixed_string_t cmd;
	portid_t port_id;
	cmdline_fixed_string_t cfg_type;
	uint8_t len;
};

static void
cmd_global_config_parsed(void *parsed_result,
			 __attribute__((unused)) struct cmdline *cl,
			 __attribute__((unused)) void *data)
{
	struct cmd_global_config_result *res = parsed_result;
	struct rte_eth_global_cfg conf;
	int ret;

	memset(&conf, 0, sizeof(conf));
	conf.cfg_type = RTE_ETH_GLOBAL_CFG_TYPE_GRE_KEY_LEN;
	conf.cfg.gre_key_len = res->len;
	ret = rte_eth_dev_filter_ctrl(res->port_id, RTE_ETH_FILTER_NONE,
				      RTE_ETH_FILTER_SET, &conf);
	if (ret != 0)
		printf("Global config error\n");
}

cmdline_parse_token_string_t cmd_global_config_cmd =
	TOKEN_STRING_INITIALIZER(struct cmd_global_config_result, cmd,
		"global_config");
cmdline_parse_token_num_t cmd_global_config_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_global_config_result, port_id,
			       UINT16);
cmdline_parse_token_string_t cmd_global_config_type =
	TOKEN_STRING_INITIALIZER(struct cmd_global_config_result,
		cfg_type, "gre-key-len");
cmdline_parse_token_num_t cmd_global_config_gre_key_len =
	TOKEN_NUM_INITIALIZER(struct cmd_global_config_result,
		len, UINT8);

cmdline_parse_inst_t cmd_global_config = {
	.f = cmd_global_config_parsed,
	.data = (void *)NULL,
	.help_str = "global_config <port_id> gre-key-len <key_len>",
	.tokens = {
		(void *)&cmd_global_config_cmd,
		(void *)&cmd_global_config_port_id,
		(void *)&cmd_global_config_type,
		(void *)&cmd_global_config_gre_key_len,
		NULL,
	},
};

/* *** CONFIGURE VM MIRROR VLAN/POOL RULE *** */
struct cmd_set_mirror_mask_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t port;
	portid_t port_id;
	cmdline_fixed_string_t mirror;
	uint8_t rule_id;
	cmdline_fixed_string_t what;
	cmdline_fixed_string_t value;
	cmdline_fixed_string_t dstpool;
	uint8_t dstpool_id;
	cmdline_fixed_string_t on;
};

cmdline_parse_token_string_t cmd_mirror_mask_set =
	TOKEN_STRING_INITIALIZER(struct cmd_set_mirror_mask_result,
				set, "set");
cmdline_parse_token_string_t cmd_mirror_mask_port =
	TOKEN_STRING_INITIALIZER(struct cmd_set_mirror_mask_result,
				port, "port");
cmdline_parse_token_num_t cmd_mirror_mask_portid =
	TOKEN_NUM_INITIALIZER(struct cmd_set_mirror_mask_result,
				port_id, UINT16);
cmdline_parse_token_string_t cmd_mirror_mask_mirror =
	TOKEN_STRING_INITIALIZER(struct cmd_set_mirror_mask_result,
				mirror, "mirror-rule");
cmdline_parse_token_num_t cmd_mirror_mask_ruleid =
	TOKEN_NUM_INITIALIZER(struct cmd_set_mirror_mask_result,
				rule_id, UINT8);
cmdline_parse_token_string_t cmd_mirror_mask_what =
	TOKEN_STRING_INITIALIZER(struct cmd_set_mirror_mask_result,
				what, "pool-mirror-up#pool-mirror-down"
				      "#vlan-mirror");
cmdline_parse_token_string_t cmd_mirror_mask_value =
	TOKEN_STRING_INITIALIZER(struct cmd_set_mirror_mask_result,
				value, NULL);
cmdline_parse_token_string_t cmd_mirror_mask_dstpool =
	TOKEN_STRING_INITIALIZER(struct cmd_set_mirror_mask_result,
				dstpool, "dst-pool");
cmdline_parse_token_num_t cmd_mirror_mask_poolid =
	TOKEN_NUM_INITIALIZER(struct cmd_set_mirror_mask_result,
				dstpool_id, UINT8);
cmdline_parse_token_string_t cmd_mirror_mask_on =
	TOKEN_STRING_INITIALIZER(struct cmd_set_mirror_mask_result,
				on, "on#off");

static void
cmd_set_mirror_mask_parsed(void *parsed_result,
		       __attribute__((unused)) struct cmdline *cl,
		       __attribute__((unused)) void *data)
{
	int ret,nb_item,i;
	struct cmd_set_mirror_mask_result *res = parsed_result;
	struct rte_eth_mirror_conf mr_conf;

	memset(&mr_conf, 0, sizeof(struct rte_eth_mirror_conf));

	unsigned int vlan_list[ETH_MIRROR_MAX_VLANS];

	mr_conf.dst_pool = res->dstpool_id;

	if (!strcmp(res->what, "pool-mirror-up")) {
		mr_conf.pool_mask = strtoull(res->value, NULL, 16);
		mr_conf.rule_type = ETH_MIRROR_VIRTUAL_POOL_UP;
	} else if (!strcmp(res->what, "pool-mirror-down")) {
		mr_conf.pool_mask = strtoull(res->value, NULL, 16);
		mr_conf.rule_type = ETH_MIRROR_VIRTUAL_POOL_DOWN;
	} else if (!strcmp(res->what, "vlan-mirror")) {
		mr_conf.rule_type = ETH_MIRROR_VLAN;
		nb_item = parse_item_list(res->value, "vlan",
				ETH_MIRROR_MAX_VLANS, vlan_list, 1);
		if (nb_item <= 0)
			return;

		for (i = 0; i < nb_item; i++) {
			if (vlan_list[i] > ETHER_MAX_VLAN_ID) {
				printf("Invalid vlan_id: must be < 4096\n");
				return;
			}

			mr_conf.vlan.vlan_id[i] = (uint16_t)vlan_list[i];
			mr_conf.vlan.vlan_mask |= 1ULL << i;
		}
	}

	if (!strcmp(res->on, "on"))
		ret = rte_eth_mirror_rule_set(res->port_id, &mr_conf,
						res->rule_id, 1);
	else
		ret = rte_eth_mirror_rule_set(res->port_id, &mr_conf,
						res->rule_id, 0);
	if (ret < 0)
		printf("mirror rule add error: (%s)\n", strerror(-ret));
}

cmdline_parse_inst_t cmd_set_mirror_mask = {
		.f = cmd_set_mirror_mask_parsed,
		.data = NULL,
		.help_str = "set port <port_id> mirror-rule <rule_id> "
			"pool-mirror-up|pool-mirror-down|vlan-mirror "
			"<pool_mask|vlan_id[,vlan_id]*> dst-pool <pool_id> on|off",
		.tokens = {
			(void *)&cmd_mirror_mask_set,
			(void *)&cmd_mirror_mask_port,
			(void *)&cmd_mirror_mask_portid,
			(void *)&cmd_mirror_mask_mirror,
			(void *)&cmd_mirror_mask_ruleid,
			(void *)&cmd_mirror_mask_what,
			(void *)&cmd_mirror_mask_value,
			(void *)&cmd_mirror_mask_dstpool,
			(void *)&cmd_mirror_mask_poolid,
			(void *)&cmd_mirror_mask_on,
			NULL,
		},
};

/* *** CONFIGURE VM MIRROR UPLINK/DOWNLINK RULE *** */
struct cmd_set_mirror_link_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t port;
	portid_t port_id;
	cmdline_fixed_string_t mirror;
	uint8_t rule_id;
	cmdline_fixed_string_t what;
	cmdline_fixed_string_t dstpool;
	uint8_t dstpool_id;
	cmdline_fixed_string_t on;
};

cmdline_parse_token_string_t cmd_mirror_link_set =
	TOKEN_STRING_INITIALIZER(struct cmd_set_mirror_link_result,
				 set, "set");
cmdline_parse_token_string_t cmd_mirror_link_port =
	TOKEN_STRING_INITIALIZER(struct cmd_set_mirror_link_result,
				port, "port");
cmdline_parse_token_num_t cmd_mirror_link_portid =
	TOKEN_NUM_INITIALIZER(struct cmd_set_mirror_link_result,
				port_id, UINT16);
cmdline_parse_token_string_t cmd_mirror_link_mirror =
	TOKEN_STRING_INITIALIZER(struct cmd_set_mirror_link_result,
				mirror, "mirror-rule");
cmdline_parse_token_num_t cmd_mirror_link_ruleid =
	TOKEN_NUM_INITIALIZER(struct cmd_set_mirror_link_result,
			    rule_id, UINT8);
cmdline_parse_token_string_t cmd_mirror_link_what =
	TOKEN_STRING_INITIALIZER(struct cmd_set_mirror_link_result,
				what, "uplink-mirror#downlink-mirror");
cmdline_parse_token_string_t cmd_mirror_link_dstpool =
	TOKEN_STRING_INITIALIZER(struct cmd_set_mirror_link_result,
				dstpool, "dst-pool");
cmdline_parse_token_num_t cmd_mirror_link_poolid =
	TOKEN_NUM_INITIALIZER(struct cmd_set_mirror_link_result,
				dstpool_id, UINT8);
cmdline_parse_token_string_t cmd_mirror_link_on =
	TOKEN_STRING_INITIALIZER(struct cmd_set_mirror_link_result,
				on, "on#off");

static void
cmd_set_mirror_link_parsed(void *parsed_result,
		       __attribute__((unused)) struct cmdline *cl,
		       __attribute__((unused)) void *data)
{
	int ret;
	struct cmd_set_mirror_link_result *res = parsed_result;
	struct rte_eth_mirror_conf mr_conf;

	memset(&mr_conf, 0, sizeof(struct rte_eth_mirror_conf));
	if (!strcmp(res->what, "uplink-mirror"))
		mr_conf.rule_type = ETH_MIRROR_UPLINK_PORT;
	else
		mr_conf.rule_type = ETH_MIRROR_DOWNLINK_PORT;

	mr_conf.dst_pool = res->dstpool_id;

	if (!strcmp(res->on, "on"))
		ret = rte_eth_mirror_rule_set(res->port_id, &mr_conf,
						res->rule_id, 1);
	else
		ret = rte_eth_mirror_rule_set(res->port_id, &mr_conf,
						res->rule_id, 0);

	/* check the return value and print it if is < 0 */
	if (ret < 0)
		printf("mirror rule add error: (%s)\n", strerror(-ret));

}

cmdline_parse_inst_t cmd_set_mirror_link = {
		.f = cmd_set_mirror_link_parsed,
		.data = NULL,
		.help_str = "set port <port_id> mirror-rule <rule_id> "
			"uplink-mirror|downlink-mirror dst-pool <pool_id> on|off",
		.tokens = {
			(void *)&cmd_mirror_link_set,
			(void *)&cmd_mirror_link_port,
			(void *)&cmd_mirror_link_portid,
			(void *)&cmd_mirror_link_mirror,
			(void *)&cmd_mirror_link_ruleid,
			(void *)&cmd_mirror_link_what,
			(void *)&cmd_mirror_link_dstpool,
			(void *)&cmd_mirror_link_poolid,
			(void *)&cmd_mirror_link_on,
			NULL,
		},
};

/* *** RESET VM MIRROR RULE *** */
struct cmd_rm_mirror_rule_result {
	cmdline_fixed_string_t reset;
	cmdline_fixed_string_t port;
	portid_t port_id;
	cmdline_fixed_string_t mirror;
	uint8_t rule_id;
};

cmdline_parse_token_string_t cmd_rm_mirror_rule_reset =
	TOKEN_STRING_INITIALIZER(struct cmd_rm_mirror_rule_result,
				 reset, "reset");
cmdline_parse_token_string_t cmd_rm_mirror_rule_port =
	TOKEN_STRING_INITIALIZER(struct cmd_rm_mirror_rule_result,
				port, "port");
cmdline_parse_token_num_t cmd_rm_mirror_rule_portid =
	TOKEN_NUM_INITIALIZER(struct cmd_rm_mirror_rule_result,
				port_id, UINT16);
cmdline_parse_token_string_t cmd_rm_mirror_rule_mirror =
	TOKEN_STRING_INITIALIZER(struct cmd_rm_mirror_rule_result,
				mirror, "mirror-rule");
cmdline_parse_token_num_t cmd_rm_mirror_rule_ruleid =
	TOKEN_NUM_INITIALIZER(struct cmd_rm_mirror_rule_result,
				rule_id, UINT8);

static void
cmd_reset_mirror_rule_parsed(void *parsed_result,
		       __attribute__((unused)) struct cmdline *cl,
		       __attribute__((unused)) void *data)
{
	int ret;
	struct cmd_set_mirror_link_result *res = parsed_result;
        /* check rule_id */
	ret = rte_eth_mirror_rule_reset(res->port_id,res->rule_id);
	if(ret < 0)
		printf("mirror rule remove error: (%s)\n", strerror(-ret));
}

cmdline_parse_inst_t cmd_reset_mirror_rule = {
		.f = cmd_reset_mirror_rule_parsed,
		.data = NULL,
		.help_str = "reset port <port_id> mirror-rule <rule_id>",
		.tokens = {
			(void *)&cmd_rm_mirror_rule_reset,
			(void *)&cmd_rm_mirror_rule_port,
			(void *)&cmd_rm_mirror_rule_portid,
			(void *)&cmd_rm_mirror_rule_mirror,
			(void *)&cmd_rm_mirror_rule_ruleid,
			NULL,
		},
};

/* ******************************************************************************** */

struct cmd_dump_result {
	cmdline_fixed_string_t dump;
};

static void
dump_struct_sizes(void)
{
#define DUMP_SIZE(t) printf("sizeof(" #t ") = %u\n", (unsigned)sizeof(t));
	DUMP_SIZE(struct rte_mbuf);
	DUMP_SIZE(struct rte_mempool);
	DUMP_SIZE(struct rte_ring);
#undef DUMP_SIZE
}

static void cmd_dump_parsed(void *parsed_result,
			    __attribute__((unused)) struct cmdline *cl,
			    __attribute__((unused)) void *data)
{
	struct cmd_dump_result *res = parsed_result;

	if (!strcmp(res->dump, "dump_physmem"))
		rte_dump_physmem_layout(stdout);
	else if (!strcmp(res->dump, "dump_memzone"))
		rte_memzone_dump(stdout);
	else if (!strcmp(res->dump, "dump_struct_sizes"))
		dump_struct_sizes();
	else if (!strcmp(res->dump, "dump_ring"))
		rte_ring_list_dump(stdout);
	else if (!strcmp(res->dump, "dump_mempool"))
		rte_mempool_list_dump(stdout);
	else if (!strcmp(res->dump, "dump_devargs"))
		rte_devargs_dump(stdout);
	else if (!strcmp(res->dump, "dump_log_types"))
		rte_log_dump(stdout);
}

cmdline_parse_token_string_t cmd_dump_dump =
	TOKEN_STRING_INITIALIZER(struct cmd_dump_result, dump,
		"dump_physmem#"
		"dump_memzone#"
		"dump_struct_sizes#"
		"dump_ring#"
		"dump_mempool#"
		"dump_devargs#"
		"dump_log_types");

cmdline_parse_inst_t cmd_dump = {
	.f = cmd_dump_parsed,  /* function to call */
	.data = NULL,      /* 2nd arg of func */
	.help_str = "Dump status",
	.tokens = {        /* token list, NULL terminated */
		(void *)&cmd_dump_dump,
		NULL,
	},
};

/* ******************************************************************************** */

struct cmd_dump_one_result {
	cmdline_fixed_string_t dump;
	cmdline_fixed_string_t name;
};

static void cmd_dump_one_parsed(void *parsed_result, struct cmdline *cl,
				__attribute__((unused)) void *data)
{
	struct cmd_dump_one_result *res = parsed_result;

	if (!strcmp(res->dump, "dump_ring")) {
		struct rte_ring *r;
		r = rte_ring_lookup(res->name);
		if (r == NULL) {
			cmdline_printf(cl, "Cannot find ring\n");
			return;
		}
		rte_ring_dump(stdout, r);
	} else if (!strcmp(res->dump, "dump_mempool")) {
		struct rte_mempool *mp;
		mp = rte_mempool_lookup(res->name);
		if (mp == NULL) {
			cmdline_printf(cl, "Cannot find mempool\n");
			return;
		}
		rte_mempool_dump(stdout, mp);
	}
}

cmdline_parse_token_string_t cmd_dump_one_dump =
	TOKEN_STRING_INITIALIZER(struct cmd_dump_one_result, dump,
				 "dump_ring#dump_mempool");

cmdline_parse_token_string_t cmd_dump_one_name =
	TOKEN_STRING_INITIALIZER(struct cmd_dump_one_result, name, NULL);

cmdline_parse_inst_t cmd_dump_one = {
	.f = cmd_dump_one_parsed,  /* function to call */
	.data = NULL,      /* 2nd arg of func */
	.help_str = "dump_ring|dump_mempool <name>: Dump one ring/mempool",
	.tokens = {        /* token list, NULL terminated */
		(void *)&cmd_dump_one_dump,
		(void *)&cmd_dump_one_name,
		NULL,
	},
};

/* *** Add/Del syn filter *** */
struct cmd_syn_filter_result {
	cmdline_fixed_string_t filter;
	portid_t port_id;
	cmdline_fixed_string_t ops;
	cmdline_fixed_string_t priority;
	cmdline_fixed_string_t high;
	cmdline_fixed_string_t queue;
	uint16_t queue_id;
};

static void
cmd_syn_filter_parsed(void *parsed_result,
			__attribute__((unused)) struct cmdline *cl,
			__attribute__((unused)) void *data)
{
	struct cmd_syn_filter_result *res = parsed_result;
	struct rte_eth_syn_filter syn_filter;
	int ret = 0;

	ret = rte_eth_dev_filter_supported(res->port_id,
					RTE_ETH_FILTER_SYN);
	if (ret < 0) {
		printf("syn filter is not supported on port %u.\n",
				res->port_id);
		return;
	}

	memset(&syn_filter, 0, sizeof(syn_filter));

	if (!strcmp(res->ops, "add")) {
		if (!strcmp(res->high, "high"))
			syn_filter.hig_pri = 1;
		else
			syn_filter.hig_pri = 0;

		syn_filter.queue = res->queue_id;
		ret = rte_eth_dev_filter_ctrl(res->port_id,
						RTE_ETH_FILTER_SYN,
						RTE_ETH_FILTER_ADD,
						&syn_filter);
	} else
		ret = rte_eth_dev_filter_ctrl(res->port_id,
						RTE_ETH_FILTER_SYN,
						RTE_ETH_FILTER_DELETE,
						&syn_filter);

	if (ret < 0)
		printf("syn filter programming error: (%s)\n",
				strerror(-ret));
}

cmdline_parse_token_string_t cmd_syn_filter_filter =
	TOKEN_STRING_INITIALIZER(struct cmd_syn_filter_result,
	filter, "syn_filter");
cmdline_parse_token_num_t cmd_syn_filter_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_syn_filter_result,
	port_id, UINT16);
cmdline_parse_token_string_t cmd_syn_filter_ops =
	TOKEN_STRING_INITIALIZER(struct cmd_syn_filter_result,
	ops, "add#del");
cmdline_parse_token_string_t cmd_syn_filter_priority =
	TOKEN_STRING_INITIALIZER(struct cmd_syn_filter_result,
				priority, "priority");
cmdline_parse_token_string_t cmd_syn_filter_high =
	TOKEN_STRING_INITIALIZER(struct cmd_syn_filter_result,
				high, "high#low");
cmdline_parse_token_string_t cmd_syn_filter_queue =
	TOKEN_STRING_INITIALIZER(struct cmd_syn_filter_result,
				queue, "queue");
cmdline_parse_token_num_t cmd_syn_filter_queue_id =
	TOKEN_NUM_INITIALIZER(struct cmd_syn_filter_result,
				queue_id, UINT16);

cmdline_parse_inst_t cmd_syn_filter = {
	.f = cmd_syn_filter_parsed,
	.data = NULL,
	.help_str = "syn_filter <port_id> add|del priority high|low queue "
		"<queue_id>: Add/Delete syn filter",
	.tokens = {
		(void *)&cmd_syn_filter_filter,
		(void *)&cmd_syn_filter_port_id,
		(void *)&cmd_syn_filter_ops,
		(void *)&cmd_syn_filter_priority,
		(void *)&cmd_syn_filter_high,
		(void *)&cmd_syn_filter_queue,
		(void *)&cmd_syn_filter_queue_id,
		NULL,
	},
};

/* *** queue region set *** */
struct cmd_queue_region_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t port;
	portid_t port_id;
	cmdline_fixed_string_t cmd;
	cmdline_fixed_string_t region;
	uint8_t  region_id;
	cmdline_fixed_string_t queue_start_index;
	uint8_t  queue_id;
	cmdline_fixed_string_t queue_num;
	uint8_t  queue_num_value;
};

static void
cmd_queue_region_parsed(void *parsed_result,
			__attribute__((unused)) struct cmdline *cl,
			__attribute__((unused)) void *data)
{
	struct cmd_queue_region_result *res = parsed_result;
	int ret = -ENOTSUP;
#ifdef RTE_LIBRTE_I40E_PMD
	struct rte_pmd_i40e_queue_region_conf region_conf;
	enum rte_pmd_i40e_queue_region_op op_type;
#endif

	if (port_id_is_invalid(res->port_id, ENABLED_WARN))
		return;

#ifdef RTE_LIBRTE_I40E_PMD
	memset(&region_conf, 0, sizeof(region_conf));
	op_type = RTE_PMD_I40E_RSS_QUEUE_REGION_SET;
	region_conf.region_id = res->region_id;
	region_conf.queue_num = res->queue_num_value;
	region_conf.queue_start_index = res->queue_id;

	ret = rte_pmd_i40e_rss_queue_region_conf(res->port_id,
				op_type, &region_conf);
#endif

	switch (ret) {
	case 0:
		break;
	case -ENOTSUP:
		printf("function not implemented or supported\n");
		break;
	default:
		printf("queue region config error: (%s)\n", strerror(-ret));
	}
}

cmdline_parse_token_string_t cmd_queue_region_set =
TOKEN_STRING_INITIALIZER(struct cmd_queue_region_result,
		set, "set");
cmdline_parse_token_string_t cmd_queue_region_port =
	TOKEN_STRING_INITIALIZER(struct cmd_queue_region_result, port, "port");
cmdline_parse_token_num_t cmd_queue_region_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_queue_region_result,
				port_id, UINT16);
cmdline_parse_token_string_t cmd_queue_region_cmd =
	TOKEN_STRING_INITIALIZER(struct cmd_queue_region_result,
				 cmd, "queue-region");
cmdline_parse_token_string_t cmd_queue_region_id =
	TOKEN_STRING_INITIALIZER(struct cmd_queue_region_result,
				region, "region_id");
cmdline_parse_token_num_t cmd_queue_region_index =
	TOKEN_NUM_INITIALIZER(struct cmd_queue_region_result,
				region_id, UINT8);
cmdline_parse_token_string_t cmd_queue_region_queue_start_index =
	TOKEN_STRING_INITIALIZER(struct cmd_queue_region_result,
				queue_start_index, "queue_start_index");
cmdline_parse_token_num_t cmd_queue_region_queue_id =
	TOKEN_NUM_INITIALIZER(struct cmd_queue_region_result,
				queue_id, UINT8);
cmdline_parse_token_string_t cmd_queue_region_queue_num =
	TOKEN_STRING_INITIALIZER(struct cmd_queue_region_result,
				queue_num, "queue_num");
cmdline_parse_token_num_t cmd_queue_region_queue_num_value =
	TOKEN_NUM_INITIALIZER(struct cmd_queue_region_result,
				queue_num_value, UINT8);

cmdline_parse_inst_t cmd_queue_region = {
	.f = cmd_queue_region_parsed,
	.data = NULL,
	.help_str = "set port <port_id> queue-region region_id <value> "
		"queue_start_index <value> queue_num <value>: Set a queue region",
	.tokens = {
		(void *)&cmd_queue_region_set,
		(void *)&cmd_queue_region_port,
		(void *)&cmd_queue_region_port_id,
		(void *)&cmd_queue_region_cmd,
		(void *)&cmd_queue_region_id,
		(void *)&cmd_queue_region_index,
		(void *)&cmd_queue_region_queue_start_index,
		(void *)&cmd_queue_region_queue_id,
		(void *)&cmd_queue_region_queue_num,
		(void *)&cmd_queue_region_queue_num_value,
		NULL,
	},
};

/* *** queue region and flowtype set *** */
struct cmd_region_flowtype_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t port;
	portid_t port_id;
	cmdline_fixed_string_t cmd;
	cmdline_fixed_string_t region;
	uint8_t  region_id;
	cmdline_fixed_string_t flowtype;
	uint8_t  flowtype_id;
};

static void
cmd_region_flowtype_parsed(void *parsed_result,
			__attribute__((unused)) struct cmdline *cl,
			__attribute__((unused)) void *data)
{
	struct cmd_region_flowtype_result *res = parsed_result;
	int ret = -ENOTSUP;
#ifdef RTE_LIBRTE_I40E_PMD
	struct rte_pmd_i40e_queue_region_conf region_conf;
	enum rte_pmd_i40e_queue_region_op op_type;
#endif

	if (port_id_is_invalid(res->port_id, ENABLED_WARN))
		return;

#ifdef RTE_LIBRTE_I40E_PMD
	memset(&region_conf, 0, sizeof(region_conf));

	op_type = RTE_PMD_I40E_RSS_QUEUE_REGION_FLOWTYPE_SET;
	region_conf.region_id = res->region_id;
	region_conf.hw_flowtype = res->flowtype_id;

	ret = rte_pmd_i40e_rss_queue_region_conf(res->port_id,
			op_type, &region_conf);
#endif

	switch (ret) {
	case 0:
		break;
	case -ENOTSUP:
		printf("function not implemented or supported\n");
		break;
	default:
		printf("region flowtype config error: (%s)\n", strerror(-ret));
	}
}

cmdline_parse_token_string_t cmd_region_flowtype_set =
TOKEN_STRING_INITIALIZER(struct cmd_region_flowtype_result,
				set, "set");
cmdline_parse_token_string_t cmd_region_flowtype_port =
	TOKEN_STRING_INITIALIZER(struct cmd_region_flowtype_result,
				port, "port");
cmdline_parse_token_num_t cmd_region_flowtype_port_index =
	TOKEN_NUM_INITIALIZER(struct cmd_region_flowtype_result,
				port_id, UINT16);
cmdline_parse_token_string_t cmd_region_flowtype_cmd =
	TOKEN_STRING_INITIALIZER(struct cmd_region_flowtype_result,
				cmd, "queue-region");
cmdline_parse_token_string_t cmd_region_flowtype_index =
	TOKEN_STRING_INITIALIZER(struct cmd_region_flowtype_result,
				region, "region_id");
cmdline_parse_token_num_t cmd_region_flowtype_id =
	TOKEN_NUM_INITIALIZER(struct cmd_region_flowtype_result,
				region_id, UINT8);
cmdline_parse_token_string_t cmd_region_flowtype_flow_index =
	TOKEN_STRING_INITIALIZER(struct cmd_region_flowtype_result,
				flowtype, "flowtype");
cmdline_parse_token_num_t cmd_region_flowtype_flow_id =
	TOKEN_NUM_INITIALIZER(struct cmd_region_flowtype_result,
				flowtype_id, UINT8);
cmdline_parse_inst_t cmd_region_flowtype = {
	.f = cmd_region_flowtype_parsed,
	.data = NULL,
	.help_str = "set port <port_id> queue-region region_id <value> "
		"flowtype <value>: Set a flowtype region index",
	.tokens = {
		(void *)&cmd_region_flowtype_set,
		(void *)&cmd_region_flowtype_port,
		(void *)&cmd_region_flowtype_port_index,
		(void *)&cmd_region_flowtype_cmd,
		(void *)&cmd_region_flowtype_index,
		(void *)&cmd_region_flowtype_id,
		(void *)&cmd_region_flowtype_flow_index,
		(void *)&cmd_region_flowtype_flow_id,
		NULL,
	},
};

/* *** User Priority (UP) to queue region (region_id) set *** */
struct cmd_user_priority_region_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t port;
	portid_t port_id;
	cmdline_fixed_string_t cmd;
	cmdline_fixed_string_t user_priority;
	uint8_t  user_priority_id;
	cmdline_fixed_string_t region;
	uint8_t  region_id;
};

static void
cmd_user_priority_region_parsed(void *parsed_result,
			__attribute__((unused)) struct cmdline *cl,
			__attribute__((unused)) void *data)
{
	struct cmd_user_priority_region_result *res = parsed_result;
	int ret = -ENOTSUP;
#ifdef RTE_LIBRTE_I40E_PMD
	struct rte_pmd_i40e_queue_region_conf region_conf;
	enum rte_pmd_i40e_queue_region_op op_type;
#endif

	if (port_id_is_invalid(res->port_id, ENABLED_WARN))
		return;

#ifdef RTE_LIBRTE_I40E_PMD
	memset(&region_conf, 0, sizeof(region_conf));
	op_type = RTE_PMD_I40E_RSS_QUEUE_REGION_USER_PRIORITY_SET;
	region_conf.user_priority = res->user_priority_id;
	region_conf.region_id = res->region_id;

	ret = rte_pmd_i40e_rss_queue_region_conf(res->port_id,
				op_type, &region_conf);
#endif

	switch (ret) {
	case 0:
		break;
	case -ENOTSUP:
		printf("function not implemented or supported\n");
		break;
	default:
		printf("user_priority region config error: (%s)\n",
				strerror(-ret));
	}
}

cmdline_parse_token_string_t cmd_user_priority_region_set =
	TOKEN_STRING_INITIALIZER(struct cmd_user_priority_region_result,
				set, "set");
cmdline_parse_token_string_t cmd_user_priority_region_port =
	TOKEN_STRING_INITIALIZER(struct cmd_user_priority_region_result,
				port, "port");
cmdline_parse_token_num_t cmd_user_priority_region_port_index =
	TOKEN_NUM_INITIALIZER(struct cmd_user_priority_region_result,
				port_id, UINT16);
cmdline_parse_token_string_t cmd_user_priority_region_cmd =
	TOKEN_STRING_INITIALIZER(struct cmd_user_priority_region_result,
				cmd, "queue-region");
cmdline_parse_token_string_t cmd_user_priority_region_UP =
	TOKEN_STRING_INITIALIZER(struct cmd_user_priority_region_result,
				user_priority, "UP");
cmdline_parse_token_num_t cmd_user_priority_region_UP_id =
	TOKEN_NUM_INITIALIZER(struct cmd_user_priority_region_result,
				user_priority_id, UINT8);
cmdline_parse_token_string_t cmd_user_priority_region_region =
	TOKEN_STRING_INITIALIZER(struct cmd_user_priority_region_result,
				region, "region_id");
cmdline_parse_token_num_t cmd_user_priority_region_region_id =
	TOKEN_NUM_INITIALIZER(struct cmd_user_priority_region_result,
				region_id, UINT8);

cmdline_parse_inst_t cmd_user_priority_region = {
	.f = cmd_user_priority_region_parsed,
	.data = NULL,
	.help_str = "set port <port_id> queue-region UP <value> "
		"region_id <value>: Set the mapping of User Priority (UP) "
		"to queue region (region_id) ",
	.tokens = {
		(void *)&cmd_user_priority_region_set,
		(void *)&cmd_user_priority_region_port,
		(void *)&cmd_user_priority_region_port_index,
		(void *)&cmd_user_priority_region_cmd,
		(void *)&cmd_user_priority_region_UP,
		(void *)&cmd_user_priority_region_UP_id,
		(void *)&cmd_user_priority_region_region,
		(void *)&cmd_user_priority_region_region_id,
		NULL,
	},
};

/* *** flush all queue region related configuration *** */
struct cmd_flush_queue_region_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t port;
	portid_t port_id;
	cmdline_fixed_string_t cmd;
	cmdline_fixed_string_t flush;
	cmdline_fixed_string_t what;
};

static void
cmd_flush_queue_region_parsed(void *parsed_result,
			__attribute__((unused)) struct cmdline *cl,
			__attribute__((unused)) void *data)
{
	struct cmd_flush_queue_region_result *res = parsed_result;
	int ret = -ENOTSUP;
#ifdef RTE_LIBRTE_I40E_PMD
	struct rte_pmd_i40e_queue_region_conf region_conf;
	enum rte_pmd_i40e_queue_region_op op_type;
#endif

	if (port_id_is_invalid(res->port_id, ENABLED_WARN))
		return;

#ifdef RTE_LIBRTE_I40E_PMD
	memset(&region_conf, 0, sizeof(region_conf));

	if (strcmp(res->what, "on") == 0)
		op_type = RTE_PMD_I40E_RSS_QUEUE_REGION_ALL_FLUSH_ON;
	else
		op_type = RTE_PMD_I40E_RSS_QUEUE_REGION_ALL_FLUSH_OFF;

	ret = rte_pmd_i40e_rss_queue_region_conf(res->port_id,
				op_type, &region_conf);
#endif

	switch (ret) {
	case 0:
		break;
	case -ENOTSUP:
		printf("function not implemented or supported\n");
		break;
	default:
		printf("queue region config flush error: (%s)\n",
				strerror(-ret));
	}
}

cmdline_parse_token_string_t cmd_flush_queue_region_set =
	TOKEN_STRING_INITIALIZER(struct cmd_flush_queue_region_result,
				set, "set");
cmdline_parse_token_string_t cmd_flush_queue_region_port =
	TOKEN_STRING_INITIALIZER(struct cmd_flush_queue_region_result,
				port, "port");
cmdline_parse_token_num_t cmd_flush_queue_region_port_index =
	TOKEN_NUM_INITIALIZER(struct cmd_flush_queue_region_result,
				port_id, UINT16);
cmdline_parse_token_string_t cmd_flush_queue_region_cmd =
	TOKEN_STRING_INITIALIZER(struct cmd_flush_queue_region_result,
				cmd, "queue-region");
cmdline_parse_token_string_t cmd_flush_queue_region_flush =
	TOKEN_STRING_INITIALIZER(struct cmd_flush_queue_region_result,
				flush, "flush");
cmdline_parse_token_string_t cmd_flush_queue_region_what =
	TOKEN_STRING_INITIALIZER(struct cmd_flush_queue_region_result,
				what, "on#off");

cmdline_parse_inst_t cmd_flush_queue_region = {
	.f = cmd_flush_queue_region_parsed,
	.data = NULL,
	.help_str = "set port <port_id> queue-region flush on|off"
		": flush all queue region related configuration",
	.tokens = {
		(void *)&cmd_flush_queue_region_set,
		(void *)&cmd_flush_queue_region_port,
		(void *)&cmd_flush_queue_region_port_index,
		(void *)&cmd_flush_queue_region_cmd,
		(void *)&cmd_flush_queue_region_flush,
		(void *)&cmd_flush_queue_region_what,
		NULL,
	},
};

/* *** get all queue region related configuration info *** */
struct cmd_show_queue_region_info {
	cmdline_fixed_string_t show;
	cmdline_fixed_string_t port;
	portid_t port_id;
	cmdline_fixed_string_t cmd;
};

static void
cmd_show_queue_region_info_parsed(void *parsed_result,
			__attribute__((unused)) struct cmdline *cl,
			__attribute__((unused)) void *data)
{
	struct cmd_show_queue_region_info *res = parsed_result;
	int ret = -ENOTSUP;
#ifdef RTE_LIBRTE_I40E_PMD
	struct rte_pmd_i40e_queue_regions rte_pmd_regions;
	enum rte_pmd_i40e_queue_region_op op_type;
#endif

	if (port_id_is_invalid(res->port_id, ENABLED_WARN))
		return;

#ifdef RTE_LIBRTE_I40E_PMD
	memset(&rte_pmd_regions, 0, sizeof(rte_pmd_regions));

	op_type = RTE_PMD_I40E_RSS_QUEUE_REGION_INFO_GET;

	ret = rte_pmd_i40e_rss_queue_region_conf(res->port_id,
					op_type, &rte_pmd_regions);

	port_queue_region_info_display(res->port_id, &rte_pmd_regions);
#endif

	switch (ret) {
	case 0:
		break;
	case -ENOTSUP:
		printf("function not implemented or supported\n");
		break;
	default:
		printf("queue region config info show error: (%s)\n",
				strerror(-ret));
	}
}

cmdline_parse_token_string_t cmd_show_queue_region_info_get =
TOKEN_STRING_INITIALIZER(struct cmd_show_queue_region_info,
				show, "show");
cmdline_parse_token_string_t cmd_show_queue_region_info_port =
	TOKEN_STRING_INITIALIZER(struct cmd_show_queue_region_info,
				port, "port");
cmdline_parse_token_num_t cmd_show_queue_region_info_port_index =
	TOKEN_NUM_INITIALIZER(struct cmd_show_queue_region_info,
				port_id, UINT16);
cmdline_parse_token_string_t cmd_show_queue_region_info_cmd =
	TOKEN_STRING_INITIALIZER(struct cmd_show_queue_region_info,
				cmd, "queue-region");

cmdline_parse_inst_t cmd_show_queue_region_info_all = {
	.f = cmd_show_queue_region_info_parsed,
	.data = NULL,
	.help_str = "show port <port_id> queue-region"
		": show all queue region related configuration info",
	.tokens = {
		(void *)&cmd_show_queue_region_info_get,
		(void *)&cmd_show_queue_region_info_port,
		(void *)&cmd_show_queue_region_info_port_index,
		(void *)&cmd_show_queue_region_info_cmd,
		NULL,
	},
};

/* *** ADD/REMOVE A 2tuple FILTER *** */
struct cmd_2tuple_filter_result {
	cmdline_fixed_string_t filter;
	portid_t port_id;
	cmdline_fixed_string_t ops;
	cmdline_fixed_string_t dst_port;
	uint16_t dst_port_value;
	cmdline_fixed_string_t protocol;
	uint8_t protocol_value;
	cmdline_fixed_string_t mask;
	uint8_t  mask_value;
	cmdline_fixed_string_t tcp_flags;
	uint8_t tcp_flags_value;
	cmdline_fixed_string_t priority;
	uint8_t  priority_value;
	cmdline_fixed_string_t queue;
	uint16_t  queue_id;
};

static void
cmd_2tuple_filter_parsed(void *parsed_result,
			__attribute__((unused)) struct cmdline *cl,
			__attribute__((unused)) void *data)
{
	struct rte_eth_ntuple_filter filter;
	struct cmd_2tuple_filter_result *res = parsed_result;
	int ret = 0;

	ret = rte_eth_dev_filter_supported(res->port_id, RTE_ETH_FILTER_NTUPLE);
	if (ret < 0) {
		printf("ntuple filter is not supported on port %u.\n",
			res->port_id);
		return;
	}

	memset(&filter, 0, sizeof(struct rte_eth_ntuple_filter));

	filter.flags = RTE_2TUPLE_FLAGS;
	filter.dst_port_mask = (res->mask_value & 0x02) ? UINT16_MAX : 0;
	filter.proto_mask = (res->mask_value & 0x01) ? UINT8_MAX : 0;
	filter.proto = res->protocol_value;
	filter.priority = res->priority_value;
	if (res->tcp_flags_value != 0 && filter.proto != IPPROTO_TCP) {
		printf("nonzero tcp_flags is only meaningful"
			" when protocol is TCP.\n");
		return;
	}
	if (res->tcp_flags_value > TCP_FLAG_ALL) {
		printf("invalid TCP flags.\n");
		return;
	}

	if (res->tcp_flags_value != 0) {
		filter.flags |= RTE_NTUPLE_FLAGS_TCP_FLAG;
		filter.tcp_flags = res->tcp_flags_value;
	}

	/* need convert to big endian. */
	filter.dst_port = rte_cpu_to_be_16(res->dst_port_value);
	filter.queue = res->queue_id;

	if (!strcmp(res->ops, "add"))
		ret = rte_eth_dev_filter_ctrl(res->port_id,
				RTE_ETH_FILTER_NTUPLE,
				RTE_ETH_FILTER_ADD,
				&filter);
	else
		ret = rte_eth_dev_filter_ctrl(res->port_id,
				RTE_ETH_FILTER_NTUPLE,
				RTE_ETH_FILTER_DELETE,
				&filter);
	if (ret < 0)
		printf("2tuple filter programming error: (%s)\n",
			strerror(-ret));

}

cmdline_parse_token_string_t cmd_2tuple_filter_filter =
	TOKEN_STRING_INITIALIZER(struct cmd_2tuple_filter_result,
				 filter, "2tuple_filter");
cmdline_parse_token_num_t cmd_2tuple_filter_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_2tuple_filter_result,
				port_id, UINT16);
cmdline_parse_token_string_t cmd_2tuple_filter_ops =
	TOKEN_STRING_INITIALIZER(struct cmd_2tuple_filter_result,
				 ops, "add#del");
cmdline_parse_token_string_t cmd_2tuple_filter_dst_port =
	TOKEN_STRING_INITIALIZER(struct cmd_2tuple_filter_result,
				dst_port, "dst_port");
cmdline_parse_token_num_t cmd_2tuple_filter_dst_port_value =
	TOKEN_NUM_INITIALIZER(struct cmd_2tuple_filter_result,
				dst_port_value, UINT16);
cmdline_parse_token_string_t cmd_2tuple_filter_protocol =
	TOKEN_STRING_INITIALIZER(struct cmd_2tuple_filter_result,
				protocol, "protocol");
cmdline_parse_token_num_t cmd_2tuple_filter_protocol_value =
	TOKEN_NUM_INITIALIZER(struct cmd_2tuple_filter_result,
				protocol_value, UINT8);
cmdline_parse_token_string_t cmd_2tuple_filter_mask =
	TOKEN_STRING_INITIALIZER(struct cmd_2tuple_filter_result,
				mask, "mask");
cmdline_parse_token_num_t cmd_2tuple_filter_mask_value =
	TOKEN_NUM_INITIALIZER(struct cmd_2tuple_filter_result,
				mask_value, INT8);
cmdline_parse_token_string_t cmd_2tuple_filter_tcp_flags =
	TOKEN_STRING_INITIALIZER(struct cmd_2tuple_filter_result,
				tcp_flags, "tcp_flags");
cmdline_parse_token_num_t cmd_2tuple_filter_tcp_flags_value =
	TOKEN_NUM_INITIALIZER(struct cmd_2tuple_filter_result,
				tcp_flags_value, UINT8);
cmdline_parse_token_string_t cmd_2tuple_filter_priority =
	TOKEN_STRING_INITIALIZER(struct cmd_2tuple_filter_result,
				priority, "priority");
cmdline_parse_token_num_t cmd_2tuple_filter_priority_value =
	TOKEN_NUM_INITIALIZER(struct cmd_2tuple_filter_result,
				priority_value, UINT8);
cmdline_parse_token_string_t cmd_2tuple_filter_queue =
	TOKEN_STRING_INITIALIZER(struct cmd_2tuple_filter_result,
				queue, "queue");
cmdline_parse_token_num_t cmd_2tuple_filter_queue_id =
	TOKEN_NUM_INITIALIZER(struct cmd_2tuple_filter_result,
				queue_id, UINT16);

cmdline_parse_inst_t cmd_2tuple_filter = {
	.f = cmd_2tuple_filter_parsed,
	.data = NULL,
	.help_str = "2tuple_filter <port_id> add|del dst_port <value> protocol "
		"<value> mask <value> tcp_flags <value> priority <value> queue "
		"<queue_id>: Add a 2tuple filter",
	.tokens = {
		(void *)&cmd_2tuple_filter_filter,
		(void *)&cmd_2tuple_filter_port_id,
		(void *)&cmd_2tuple_filter_ops,
		(void *)&cmd_2tuple_filter_dst_port,
		(void *)&cmd_2tuple_filter_dst_port_value,
		(void *)&cmd_2tuple_filter_protocol,
		(void *)&cmd_2tuple_filter_protocol_value,
		(void *)&cmd_2tuple_filter_mask,
		(void *)&cmd_2tuple_filter_mask_value,
		(void *)&cmd_2tuple_filter_tcp_flags,
		(void *)&cmd_2tuple_filter_tcp_flags_value,
		(void *)&cmd_2tuple_filter_priority,
		(void *)&cmd_2tuple_filter_priority_value,
		(void *)&cmd_2tuple_filter_queue,
		(void *)&cmd_2tuple_filter_queue_id,
		NULL,
	},
};

/* *** ADD/REMOVE A 5tuple FILTER *** */
struct cmd_5tuple_filter_result {
	cmdline_fixed_string_t filter;
	portid_t port_id;
	cmdline_fixed_string_t ops;
	cmdline_fixed_string_t dst_ip;
	cmdline_ipaddr_t dst_ip_value;
	cmdline_fixed_string_t src_ip;
	cmdline_ipaddr_t src_ip_value;
	cmdline_fixed_string_t dst_port;
	uint16_t dst_port_value;
	cmdline_fixed_string_t src_port;
	uint16_t src_port_value;
	cmdline_fixed_string_t protocol;
	uint8_t protocol_value;
	cmdline_fixed_string_t mask;
	uint8_t  mask_value;
	cmdline_fixed_string_t tcp_flags;
	uint8_t tcp_flags_value;
	cmdline_fixed_string_t priority;
	uint8_t  priority_value;
	cmdline_fixed_string_t queue;
	uint16_t  queue_id;
};

static void
cmd_5tuple_filter_parsed(void *parsed_result,
			__attribute__((unused)) struct cmdline *cl,
			__attribute__((unused)) void *data)
{
	struct rte_eth_ntuple_filter filter;
	struct cmd_5tuple_filter_result *res = parsed_result;
	int ret = 0;

	ret = rte_eth_dev_filter_supported(res->port_id, RTE_ETH_FILTER_NTUPLE);
	if (ret < 0) {
		printf("ntuple filter is not supported on port %u.\n",
			res->port_id);
		return;
	}

	memset(&filter, 0, sizeof(struct rte_eth_ntuple_filter));

	filter.flags = RTE_5TUPLE_FLAGS;
	filter.dst_ip_mask = (res->mask_value & 0x10) ? UINT32_MAX : 0;
	filter.src_ip_mask = (res->mask_value & 0x08) ? UINT32_MAX : 0;
	filter.dst_port_mask = (res->mask_value & 0x04) ? UINT16_MAX : 0;
	filter.src_port_mask = (res->mask_value & 0x02) ? UINT16_MAX : 0;
	filter.proto_mask = (res->mask_value & 0x01) ? UINT8_MAX : 0;
	filter.proto = res->protocol_value;
	filter.priority = res->priority_value;
	if (res->tcp_flags_value != 0 && filter.proto != IPPROTO_TCP) {
		printf("nonzero tcp_flags is only meaningful"
			" when protocol is TCP.\n");
		return;
	}
	if (res->tcp_flags_value > TCP_FLAG_ALL) {
		printf("invalid TCP flags.\n");
		return;
	}

	if (res->tcp_flags_value != 0) {
		filter.flags |= RTE_NTUPLE_FLAGS_TCP_FLAG;
		filter.tcp_flags = res->tcp_flags_value;
	}

	if (res->dst_ip_value.family == AF_INET)
		/* no need to convert, already big endian. */
		filter.dst_ip = res->dst_ip_value.addr.ipv4.s_addr;
	else {
		if (filter.dst_ip_mask == 0) {
			printf("can not support ipv6 involved compare.\n");
			return;
		}
		filter.dst_ip = 0;
	}

	if (res->src_ip_value.family == AF_INET)
		/* no need to convert, already big endian. */
		filter.src_ip = res->src_ip_value.addr.ipv4.s_addr;
	else {
		if (filter.src_ip_mask == 0) {
			printf("can not support ipv6 involved compare.\n");
			return;
		}
		filter.src_ip = 0;
	}
	/* need convert to big endian. */
	filter.dst_port = rte_cpu_to_be_16(res->dst_port_value);
	filter.src_port = rte_cpu_to_be_16(res->src_port_value);
	filter.queue = res->queue_id;

	if (!strcmp(res->ops, "add"))
		ret = rte_eth_dev_filter_ctrl(res->port_id,
				RTE_ETH_FILTER_NTUPLE,
				RTE_ETH_FILTER_ADD,
				&filter);
	else
		ret = rte_eth_dev_filter_ctrl(res->port_id,
				RTE_ETH_FILTER_NTUPLE,
				RTE_ETH_FILTER_DELETE,
				&filter);
	if (ret < 0)
		printf("5tuple filter programming error: (%s)\n",
			strerror(-ret));
}

cmdline_parse_token_string_t cmd_5tuple_filter_filter =
	TOKEN_STRING_INITIALIZER(struct cmd_5tuple_filter_result,
				 filter, "5tuple_filter");
cmdline_parse_token_num_t cmd_5tuple_filter_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_5tuple_filter_result,
				port_id, UINT16);
cmdline_parse_token_string_t cmd_5tuple_filter_ops =
	TOKEN_STRING_INITIALIZER(struct cmd_5tuple_filter_result,
				 ops, "add#del");
cmdline_parse_token_string_t cmd_5tuple_filter_dst_ip =
	TOKEN_STRING_INITIALIZER(struct cmd_5tuple_filter_result,
				dst_ip, "dst_ip");
cmdline_parse_token_ipaddr_t cmd_5tuple_filter_dst_ip_value =
	TOKEN_IPADDR_INITIALIZER(struct cmd_5tuple_filter_result,
				dst_ip_value);
cmdline_parse_token_string_t cmd_5tuple_filter_src_ip =
	TOKEN_STRING_INITIALIZER(struct cmd_5tuple_filter_result,
				src_ip, "src_ip");
cmdline_parse_token_ipaddr_t cmd_5tuple_filter_src_ip_value =
	TOKEN_IPADDR_INITIALIZER(struct cmd_5tuple_filter_result,
				src_ip_value);
cmdline_parse_token_string_t cmd_5tuple_filter_dst_port =
	TOKEN_STRING_INITIALIZER(struct cmd_5tuple_filter_result,
				dst_port, "dst_port");
cmdline_parse_token_num_t cmd_5tuple_filter_dst_port_value =
	TOKEN_NUM_INITIALIZER(struct cmd_5tuple_filter_result,
				dst_port_value, UINT16);
cmdline_parse_token_string_t cmd_5tuple_filter_src_port =
	TOKEN_STRING_INITIALIZER(struct cmd_5tuple_filter_result,
				src_port, "src_port");
cmdline_parse_token_num_t cmd_5tuple_filter_src_port_value =
	TOKEN_NUM_INITIALIZER(struct cmd_5tuple_filter_result,
				src_port_value, UINT16);
cmdline_parse_token_string_t cmd_5tuple_filter_protocol =
	TOKEN_STRING_INITIALIZER(struct cmd_5tuple_filter_result,
				protocol, "protocol");
cmdline_parse_token_num_t cmd_5tuple_filter_protocol_value =
	TOKEN_NUM_INITIALIZER(struct cmd_5tuple_filter_result,
				protocol_value, UINT8);
cmdline_parse_token_string_t cmd_5tuple_filter_mask =
	TOKEN_STRING_INITIALIZER(struct cmd_5tuple_filter_result,
				mask, "mask");
cmdline_parse_token_num_t cmd_5tuple_filter_mask_value =
	TOKEN_NUM_INITIALIZER(struct cmd_5tuple_filter_result,
				mask_value, INT8);
cmdline_parse_token_string_t cmd_5tuple_filter_tcp_flags =
	TOKEN_STRING_INITIALIZER(struct cmd_5tuple_filter_result,
				tcp_flags, "tcp_flags");
cmdline_parse_token_num_t cmd_5tuple_filter_tcp_flags_value =
	TOKEN_NUM_INITIALIZER(struct cmd_5tuple_filter_result,
				tcp_flags_value, UINT8);
cmdline_parse_token_string_t cmd_5tuple_filter_priority =
	TOKEN_STRING_INITIALIZER(struct cmd_5tuple_filter_result,
				priority, "priority");
cmdline_parse_token_num_t cmd_5tuple_filter_priority_value =
	TOKEN_NUM_INITIALIZER(struct cmd_5tuple_filter_result,
				priority_value, UINT8);
cmdline_parse_token_string_t cmd_5tuple_filter_queue =
	TOKEN_STRING_INITIALIZER(struct cmd_5tuple_filter_result,
				queue, "queue");
cmdline_parse_token_num_t cmd_5tuple_filter_queue_id =
	TOKEN_NUM_INITIALIZER(struct cmd_5tuple_filter_result,
				queue_id, UINT16);

cmdline_parse_inst_t cmd_5tuple_filter = {
	.f = cmd_5tuple_filter_parsed,
	.data = NULL,
	.help_str = "5tuple_filter <port_id> add|del dst_ip <value> "
		"src_ip <value> dst_port <value> src_port <value> "
		"protocol <value>  mask <value> tcp_flags <value> "
		"priority <value> queue <queue_id>: Add/Del a 5tuple filter",
	.tokens = {
		(void *)&cmd_5tuple_filter_filter,
		(void *)&cmd_5tuple_filter_port_id,
		(void *)&cmd_5tuple_filter_ops,
		(void *)&cmd_5tuple_filter_dst_ip,
		(void *)&cmd_5tuple_filter_dst_ip_value,
		(void *)&cmd_5tuple_filter_src_ip,
		(void *)&cmd_5tuple_filter_src_ip_value,
		(void *)&cmd_5tuple_filter_dst_port,
		(void *)&cmd_5tuple_filter_dst_port_value,
		(void *)&cmd_5tuple_filter_src_port,
		(void *)&cmd_5tuple_filter_src_port_value,
		(void *)&cmd_5tuple_filter_protocol,
		(void *)&cmd_5tuple_filter_protocol_value,
		(void *)&cmd_5tuple_filter_mask,
		(void *)&cmd_5tuple_filter_mask_value,
		(void *)&cmd_5tuple_filter_tcp_flags,
		(void *)&cmd_5tuple_filter_tcp_flags_value,
		(void *)&cmd_5tuple_filter_priority,
		(void *)&cmd_5tuple_filter_priority_value,
		(void *)&cmd_5tuple_filter_queue,
		(void *)&cmd_5tuple_filter_queue_id,
		NULL,
	},
};

/* *** ADD/REMOVE A flex FILTER *** */
struct cmd_flex_filter_result {
	cmdline_fixed_string_t filter;
	cmdline_fixed_string_t ops;
	portid_t port_id;
	cmdline_fixed_string_t len;
	uint8_t len_value;
	cmdline_fixed_string_t bytes;
	cmdline_fixed_string_t bytes_value;
	cmdline_fixed_string_t mask;
	cmdline_fixed_string_t mask_value;
	cmdline_fixed_string_t priority;
	uint8_t priority_value;
	cmdline_fixed_string_t queue;
	uint16_t queue_id;
};

static int xdigit2val(unsigned char c)
{
	int val;
	if (isdigit(c))
		val = c - '0';
	else if (isupper(c))
		val = c - 'A' + 10;
	else
		val = c - 'a' + 10;
	return val;
}

static void
cmd_flex_filter_parsed(void *parsed_result,
			  __attribute__((unused)) struct cmdline *cl,
			  __attribute__((unused)) void *data)
{
	int ret = 0;
	struct rte_eth_flex_filter filter;
	struct cmd_flex_filter_result *res = parsed_result;
	char *bytes_ptr, *mask_ptr;
	uint16_t len, i, j = 0;
	char c;
	int val;
	uint8_t byte = 0;

	if (res->len_value > RTE_FLEX_FILTER_MAXLEN) {
		printf("the len exceed the max length 128\n");
		return;
	}
	memset(&filter, 0, sizeof(struct rte_eth_flex_filter));
	filter.len = res->len_value;
	filter.priority = res->priority_value;
	filter.queue = res->queue_id;
	bytes_ptr = res->bytes_value;
	mask_ptr = res->mask_value;

	 /* translate bytes string to array. */
	if (bytes_ptr[0] == '0' && ((bytes_ptr[1] == 'x') ||
		(bytes_ptr[1] == 'X')))
		bytes_ptr += 2;
	len = strnlen(bytes_ptr, res->len_value * 2);
	if (len == 0 || (len % 8 != 0)) {
		printf("please check len and bytes input\n");
		return;
	}
	for (i = 0; i < len; i++) {
		c = bytes_ptr[i];
		if (isxdigit(c) == 0) {
			/* invalid characters. */
			printf("invalid input\n");
			return;
		}
		val = xdigit2val(c);
		if (i % 2) {
			byte |= val;
			filter.bytes[j] = byte;
			printf("bytes[%d]:%02x ", j, filter.bytes[j]);
			j++;
			byte = 0;
		} else
			byte |= val << 4;
	}
	printf("\n");
	 /* translate mask string to uint8_t array. */
	if (mask_ptr[0] == '0' && ((mask_ptr[1] == 'x') ||
		(mask_ptr[1] == 'X')))
		mask_ptr += 2;
	len = strnlen(mask_ptr, (res->len_value + 3) / 4);
	if (len == 0) {
		printf("invalid input\n");
		return;
	}
	j = 0;
	byte = 0;
	for (i = 0; i < len; i++) {
		c = mask_ptr[i];
		if (isxdigit(c) == 0) {
			/* invalid characters. */
			printf("invalid input\n");
			return;
		}
		val = xdigit2val(c);
		if (i % 2) {
			byte |= val;
			filter.mask[j] = byte;
			printf("mask[%d]:%02x ", j, filter.mask[j]);
			j++;
			byte = 0;
		} else
			byte |= val << 4;
	}
	printf("\n");

	if (!strcmp(res->ops, "add"))
		ret = rte_eth_dev_filter_ctrl(res->port_id,
				RTE_ETH_FILTER_FLEXIBLE,
				RTE_ETH_FILTER_ADD,
				&filter);
	else
		ret = rte_eth_dev_filter_ctrl(res->port_id,
				RTE_ETH_FILTER_FLEXIBLE,
				RTE_ETH_FILTER_DELETE,
				&filter);

	if (ret < 0)
		printf("flex filter setting error: (%s)\n", strerror(-ret));
}

cmdline_parse_token_string_t cmd_flex_filter_filter =
	TOKEN_STRING_INITIALIZER(struct cmd_flex_filter_result,
				filter, "flex_filter");
cmdline_parse_token_num_t cmd_flex_filter_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_flex_filter_result,
				port_id, UINT16);
cmdline_parse_token_string_t cmd_flex_filter_ops =
	TOKEN_STRING_INITIALIZER(struct cmd_flex_filter_result,
				ops, "add#del");
cmdline_parse_token_string_t cmd_flex_filter_len =
	TOKEN_STRING_INITIALIZER(struct cmd_flex_filter_result,
				len, "len");
cmdline_parse_token_num_t cmd_flex_filter_len_value =
	TOKEN_NUM_INITIALIZER(struct cmd_flex_filter_result,
				len_value, UINT8);
cmdline_parse_token_string_t cmd_flex_filter_bytes =
	TOKEN_STRING_INITIALIZER(struct cmd_flex_filter_result,
				bytes, "bytes");
cmdline_parse_token_string_t cmd_flex_filter_bytes_value =
	TOKEN_STRING_INITIALIZER(struct cmd_flex_filter_result,
				bytes_value, NULL);
cmdline_parse_token_string_t cmd_flex_filter_mask =
	TOKEN_STRING_INITIALIZER(struct cmd_flex_filter_result,
				mask, "mask");
cmdline_parse_token_string_t cmd_flex_filter_mask_value =
	TOKEN_STRING_INITIALIZER(struct cmd_flex_filter_result,
				mask_value, NULL);
cmdline_parse_token_string_t cmd_flex_filter_priority =
	TOKEN_STRING_INITIALIZER(struct cmd_flex_filter_result,
				priority, "priority");
cmdline_parse_token_num_t cmd_flex_filter_priority_value =
	TOKEN_NUM_INITIALIZER(struct cmd_flex_filter_result,
				priority_value, UINT8);
cmdline_parse_token_string_t cmd_flex_filter_queue =
	TOKEN_STRING_INITIALIZER(struct cmd_flex_filter_result,
				queue, "queue");
cmdline_parse_token_num_t cmd_flex_filter_queue_id =
	TOKEN_NUM_INITIALIZER(struct cmd_flex_filter_result,
				queue_id, UINT16);
cmdline_parse_inst_t cmd_flex_filter = {
	.f = cmd_flex_filter_parsed,
	.data = NULL,
	.help_str = "flex_filter <port_id> add|del len <value> bytes "
		"<value> mask <value> priority <value> queue <queue_id>: "
		"Add/Del a flex filter",
	.tokens = {
		(void *)&cmd_flex_filter_filter,
		(void *)&cmd_flex_filter_port_id,
		(void *)&cmd_flex_filter_ops,
		(void *)&cmd_flex_filter_len,
		(void *)&cmd_flex_filter_len_value,
		(void *)&cmd_flex_filter_bytes,
		(void *)&cmd_flex_filter_bytes_value,
		(void *)&cmd_flex_filter_mask,
		(void *)&cmd_flex_filter_mask_value,
		(void *)&cmd_flex_filter_priority,
		(void *)&cmd_flex_filter_priority_value,
		(void *)&cmd_flex_filter_queue,
		(void *)&cmd_flex_filter_queue_id,
		NULL,
	},
};

/* *** Filters Control *** */

/* *** deal with ethertype filter *** */
struct cmd_ethertype_filter_result {
	cmdline_fixed_string_t filter;
	portid_t port_id;
	cmdline_fixed_string_t ops;
	cmdline_fixed_string_t mac;
	struct ether_addr mac_addr;
	cmdline_fixed_string_t ethertype;
	uint16_t ethertype_value;
	cmdline_fixed_string_t drop;
	cmdline_fixed_string_t queue;
	uint16_t  queue_id;
};

cmdline_parse_token_string_t cmd_ethertype_filter_filter =
	TOKEN_STRING_INITIALIZER(struct cmd_ethertype_filter_result,
				 filter, "ethertype_filter");
cmdline_parse_token_num_t cmd_ethertype_filter_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_ethertype_filter_result,
			      port_id, UINT16);
cmdline_parse_token_string_t cmd_ethertype_filter_ops =
	TOKEN_STRING_INITIALIZER(struct cmd_ethertype_filter_result,
				 ops, "add#del");
cmdline_parse_token_string_t cmd_ethertype_filter_mac =
	TOKEN_STRING_INITIALIZER(struct cmd_ethertype_filter_result,
				 mac, "mac_addr#mac_ignr");
cmdline_parse_token_etheraddr_t cmd_ethertype_filter_mac_addr =
	TOKEN_ETHERADDR_INITIALIZER(struct cmd_ethertype_filter_result,
				     mac_addr);
cmdline_parse_token_string_t cmd_ethertype_filter_ethertype =
	TOKEN_STRING_INITIALIZER(struct cmd_ethertype_filter_result,
				 ethertype, "ethertype");
cmdline_parse_token_num_t cmd_ethertype_filter_ethertype_value =
	TOKEN_NUM_INITIALIZER(struct cmd_ethertype_filter_result,
			      ethertype_value, UINT16);
cmdline_parse_token_string_t cmd_ethertype_filter_drop =
	TOKEN_STRING_INITIALIZER(struct cmd_ethertype_filter_result,
				 drop, "drop#fwd");
cmdline_parse_token_string_t cmd_ethertype_filter_queue =
	TOKEN_STRING_INITIALIZER(struct cmd_ethertype_filter_result,
				 queue, "queue");
cmdline_parse_token_num_t cmd_ethertype_filter_queue_id =
	TOKEN_NUM_INITIALIZER(struct cmd_ethertype_filter_result,
			      queue_id, UINT16);

static void
cmd_ethertype_filter_parsed(void *parsed_result,
			  __attribute__((unused)) struct cmdline *cl,
			  __attribute__((unused)) void *data)
{
	struct cmd_ethertype_filter_result *res = parsed_result;
	struct rte_eth_ethertype_filter filter;
	int ret = 0;

	ret = rte_eth_dev_filter_supported(res->port_id,
			RTE_ETH_FILTER_ETHERTYPE);
	if (ret < 0) {
		printf("ethertype filter is not supported on port %u.\n",
			res->port_id);
		return;
	}

	memset(&filter, 0, sizeof(filter));
	if (!strcmp(res->mac, "mac_addr")) {
		filter.flags |= RTE_ETHTYPE_FLAGS_MAC;
		rte_memcpy(&filter.mac_addr, &res->mac_addr,
			sizeof(struct ether_addr));
	}
	if (!strcmp(res->drop, "drop"))
		filter.flags |= RTE_ETHTYPE_FLAGS_DROP;
	filter.ether_type = res->ethertype_value;
	filter.queue = res->queue_id;

	if (!strcmp(res->ops, "add"))
		ret = rte_eth_dev_filter_ctrl(res->port_id,
				RTE_ETH_FILTER_ETHERTYPE,
				RTE_ETH_FILTER_ADD,
				&filter);
	else
		ret = rte_eth_dev_filter_ctrl(res->port_id,
				RTE_ETH_FILTER_ETHERTYPE,
				RTE_ETH_FILTER_DELETE,
				&filter);
	if (ret < 0)
		printf("ethertype filter programming error: (%s)\n",
			strerror(-ret));
}

cmdline_parse_inst_t cmd_ethertype_filter = {
	.f = cmd_ethertype_filter_parsed,
	.data = NULL,
	.help_str = "ethertype_filter <port_id> add|del mac_addr|mac_ignr "
		"<mac_addr> ethertype <value> drop|fw queue <queue_id>: "
		"Add or delete an ethertype filter entry",
	.tokens = {
		(void *)&cmd_ethertype_filter_filter,
		(void *)&cmd_ethertype_filter_port_id,
		(void *)&cmd_ethertype_filter_ops,
		(void *)&cmd_ethertype_filter_mac,
		(void *)&cmd_ethertype_filter_mac_addr,
		(void *)&cmd_ethertype_filter_ethertype,
		(void *)&cmd_ethertype_filter_ethertype_value,
		(void *)&cmd_ethertype_filter_drop,
		(void *)&cmd_ethertype_filter_queue,
		(void *)&cmd_ethertype_filter_queue_id,
		NULL,
	},
};

/* *** deal with flow director filter *** */
struct cmd_flow_director_result {
	cmdline_fixed_string_t flow_director_filter;
	portid_t port_id;
	cmdline_fixed_string_t mode;
	cmdline_fixed_string_t mode_value;
	cmdline_fixed_string_t ops;
	cmdline_fixed_string_t flow;
	cmdline_fixed_string_t flow_type;
	cmdline_fixed_string_t ether;
	uint16_t ether_type;
	cmdline_fixed_string_t src;
	cmdline_ipaddr_t ip_src;
	uint16_t port_src;
	cmdline_fixed_string_t dst;
	cmdline_ipaddr_t ip_dst;
	uint16_t port_dst;
	cmdline_fixed_string_t verify_tag;
	uint32_t verify_tag_value;
	cmdline_fixed_string_t tos;
	uint8_t tos_value;
	cmdline_fixed_string_t proto;
	uint8_t proto_value;
	cmdline_fixed_string_t ttl;
	uint8_t ttl_value;
	cmdline_fixed_string_t vlan;
	uint16_t vlan_value;
	cmdline_fixed_string_t flexbytes;
	cmdline_fixed_string_t flexbytes_value;
	cmdline_fixed_string_t pf_vf;
	cmdline_fixed_string_t drop;
	cmdline_fixed_string_t queue;
	uint16_t  queue_id;
	cmdline_fixed_string_t fd_id;
	uint32_t  fd_id_value;
	cmdline_fixed_string_t mac;
	struct ether_addr mac_addr;
	cmdline_fixed_string_t tunnel;
	cmdline_fixed_string_t tunnel_type;
	cmdline_fixed_string_t tunnel_id;
	uint32_t tunnel_id_value;
	cmdline_fixed_string_t packet;
	char filepath[];
};

static inline int
parse_flexbytes(const char *q_arg, uint8_t *flexbytes, uint16_t max_num)
{
	char s[256];
	const char *p, *p0 = q_arg;
	char *end;
	unsigned long int_fld;
	char *str_fld[max_num];
	int i;
	unsigned size;
	int ret = -1;

	p = strchr(p0, '(');
	if (p == NULL)
		return -1;
	++p;
	p0 = strchr(p, ')');
	if (p0 == NULL)
		return -1;

	size = p0 - p;
	if (size >= sizeof(s))
		return -1;

	snprintf(s, sizeof(s), "%.*s", size, p);
	ret = rte_strsplit(s, sizeof(s), str_fld, max_num, ',');
	if (ret < 0 || ret > max_num)
		return -1;
	for (i = 0; i < ret; i++) {
		errno = 0;
		int_fld = strtoul(str_fld[i], &end, 0);
		if (errno != 0 || *end != '\0' || int_fld > UINT8_MAX)
			return -1;
		flexbytes[i] = (uint8_t)int_fld;
	}
	return ret;
}

static uint16_t
str2flowtype(char *string)
{
	uint8_t i = 0;
	static const struct {
		char str[32];
		uint16_t type;
	} flowtype_str[] = {
		{"raw", RTE_ETH_FLOW_RAW},
		{"ipv4", RTE_ETH_FLOW_IPV4},
		{"ipv4-frag", RTE_ETH_FLOW_FRAG_IPV4},
		{"ipv4-tcp", RTE_ETH_FLOW_NONFRAG_IPV4_TCP},
		{"ipv4-udp", RTE_ETH_FLOW_NONFRAG_IPV4_UDP},
		{"ipv4-sctp", RTE_ETH_FLOW_NONFRAG_IPV4_SCTP},
		{"ipv4-other", RTE_ETH_FLOW_NONFRAG_IPV4_OTHER},
		{"ipv6", RTE_ETH_FLOW_IPV6},
		{"ipv6-frag", RTE_ETH_FLOW_FRAG_IPV6},
		{"ipv6-tcp", RTE_ETH_FLOW_NONFRAG_IPV6_TCP},
		{"ipv6-udp", RTE_ETH_FLOW_NONFRAG_IPV6_UDP},
		{"ipv6-sctp", RTE_ETH_FLOW_NONFRAG_IPV6_SCTP},
		{"ipv6-other", RTE_ETH_FLOW_NONFRAG_IPV6_OTHER},
		{"l2_payload", RTE_ETH_FLOW_L2_PAYLOAD},
	};

	for (i = 0; i < RTE_DIM(flowtype_str); i++) {
		if (!strcmp(flowtype_str[i].str, string))
			return flowtype_str[i].type;
	}

	if (isdigit(string[0]) && atoi(string) > 0 && atoi(string) < 64)
		return (uint16_t)atoi(string);

	return RTE_ETH_FLOW_UNKNOWN;
}

static enum rte_eth_fdir_tunnel_type
str2fdir_tunneltype(char *string)
{
	uint8_t i = 0;

	static const struct {
		char str[32];
		enum rte_eth_fdir_tunnel_type type;
	} tunneltype_str[] = {
		{"NVGRE", RTE_FDIR_TUNNEL_TYPE_NVGRE},
		{"VxLAN", RTE_FDIR_TUNNEL_TYPE_VXLAN},
	};

	for (i = 0; i < RTE_DIM(tunneltype_str); i++) {
		if (!strcmp(tunneltype_str[i].str, string))
			return tunneltype_str[i].type;
	}
	return RTE_FDIR_TUNNEL_TYPE_UNKNOWN;
}

#define IPV4_ADDR_TO_UINT(ip_addr, ip) \
do { \
	if ((ip_addr).family == AF_INET) \
		(ip) = (ip_addr).addr.ipv4.s_addr; \
	else { \
		printf("invalid parameter.\n"); \
		return; \
	} \
} while (0)

#define IPV6_ADDR_TO_ARRAY(ip_addr, ip) \
do { \
	if ((ip_addr).family == AF_INET6) \
		rte_memcpy(&(ip), \
				 &((ip_addr).addr.ipv6), \
				 sizeof(struct in6_addr)); \
	else { \
		printf("invalid parameter.\n"); \
		return; \
	} \
} while (0)

static void
cmd_flow_director_filter_parsed(void *parsed_result,
			  __attribute__((unused)) struct cmdline *cl,
			  __attribute__((unused)) void *data)
{
	struct cmd_flow_director_result *res = parsed_result;
	struct rte_eth_fdir_filter entry;
	uint8_t flexbytes[RTE_ETH_FDIR_MAX_FLEXLEN];
	char *end;
	unsigned long vf_id;
	int ret = 0;

	ret = rte_eth_dev_filter_supported(res->port_id, RTE_ETH_FILTER_FDIR);
	if (ret < 0) {
		printf("flow director is not supported on port %u.\n",
			res->port_id);
		return;
	}
	memset(flexbytes, 0, sizeof(flexbytes));
	memset(&entry, 0, sizeof(struct rte_eth_fdir_filter));

	if (fdir_conf.mode ==  RTE_FDIR_MODE_PERFECT_MAC_VLAN) {
		if (strcmp(res->mode_value, "MAC-VLAN")) {
			printf("Please set mode to MAC-VLAN.\n");
			return;
		}
	} else if (fdir_conf.mode ==  RTE_FDIR_MODE_PERFECT_TUNNEL) {
		if (strcmp(res->mode_value, "Tunnel")) {
			printf("Please set mode to Tunnel.\n");
			return;
		}
	} else {
		if (!strcmp(res->mode_value, "raw")) {
#ifdef RTE_LIBRTE_I40E_PMD
			struct rte_pmd_i40e_flow_type_mapping
					mapping[RTE_PMD_I40E_FLOW_TYPE_MAX];
			struct rte_pmd_i40e_pkt_template_conf conf;
			uint16_t flow_type = str2flowtype(res->flow_type);
			uint16_t i, port = res->port_id;
			uint8_t add;

			memset(&conf, 0, sizeof(conf));

			if (flow_type == RTE_ETH_FLOW_UNKNOWN) {
				printf("Invalid flow type specified.\n");
				return;
			}
			ret = rte_pmd_i40e_flow_type_mapping_get(res->port_id,
								 mapping);
			if (ret)
				return;
			if (mapping[flow_type].pctype == 0ULL) {
				printf("Invalid flow type specified.\n");
				return;
			}
			for (i = 0; i < RTE_PMD_I40E_PCTYPE_MAX; i++) {
				if (mapping[flow_type].pctype & (1ULL << i)) {
					conf.input.pctype = i;
					break;
				}
			}

			conf.input.packet = open_file(res->filepath,
						&conf.input.length);
			if (!conf.input.packet)
				return;
			if (!strcmp(res->drop, "drop"))
				conf.action.behavior =
					RTE_PMD_I40E_PKT_TEMPLATE_REJECT;
			else
				conf.action.behavior =
					RTE_PMD_I40E_PKT_TEMPLATE_ACCEPT;
			conf.action.report_status =
					RTE_PMD_I40E_PKT_TEMPLATE_REPORT_ID;
			conf.action.rx_queue = res->queue_id;
			conf.soft_id = res->fd_id_value;
			add  = strcmp(res->ops, "del") ? 1 : 0;
			ret = rte_pmd_i40e_flow_add_del_packet_template(port,
									&conf,
									add);
			if (ret < 0)
				printf("flow director config error: (%s)\n",
				       strerror(-ret));
			close_file(conf.input.packet);
#endif
			return;
		} else if (strcmp(res->mode_value, "IP")) {
			printf("Please set mode to IP or raw.\n");
			return;
		}
		entry.input.flow_type = str2flowtype(res->flow_type);
	}

	ret = parse_flexbytes(res->flexbytes_value,
					flexbytes,
					RTE_ETH_FDIR_MAX_FLEXLEN);
	if (ret < 0) {
		printf("error: Cannot parse flexbytes input.\n");
		return;
	}

	switch (entry.input.flow_type) {
	case RTE_ETH_FLOW_FRAG_IPV4:
	case RTE_ETH_FLOW_NONFRAG_IPV4_OTHER:
		entry.input.flow.ip4_flow.proto = res->proto_value;
		/* fall-through */
	case RTE_ETH_FLOW_NONFRAG_IPV4_UDP:
	case RTE_ETH_FLOW_NONFRAG_IPV4_TCP:
		IPV4_ADDR_TO_UINT(res->ip_dst,
			entry.input.flow.ip4_flow.dst_ip);
		IPV4_ADDR_TO_UINT(res->ip_src,
			entry.input.flow.ip4_flow.src_ip);
		entry.input.flow.ip4_flow.tos = res->tos_value;
		entry.input.flow.ip4_flow.ttl = res->ttl_value;
		/* need convert to big endian. */
		entry.input.flow.udp4_flow.dst_port =
				rte_cpu_to_be_16(res->port_dst);
		entry.input.flow.udp4_flow.src_port =
				rte_cpu_to_be_16(res->port_src);
		break;
	case RTE_ETH_FLOW_NONFRAG_IPV4_SCTP:
		IPV4_ADDR_TO_UINT(res->ip_dst,
			entry.input.flow.sctp4_flow.ip.dst_ip);
		IPV4_ADDR_TO_UINT(res->ip_src,
			entry.input.flow.sctp4_flow.ip.src_ip);
		entry.input.flow.ip4_flow.tos = res->tos_value;
		entry.input.flow.ip4_flow.ttl = res->ttl_value;
		/* need convert to big endian. */
		entry.input.flow.sctp4_flow.dst_port =
				rte_cpu_to_be_16(res->port_dst);
		entry.input.flow.sctp4_flow.src_port =
				rte_cpu_to_be_16(res->port_src);
		entry.input.flow.sctp4_flow.verify_tag =
				rte_cpu_to_be_32(res->verify_tag_value);
		break;
	case RTE_ETH_FLOW_FRAG_IPV6:
	case RTE_ETH_FLOW_NONFRAG_IPV6_OTHER:
		entry.input.flow.ipv6_flow.proto = res->proto_value;
		/* fall-through */
	case RTE_ETH_FLOW_NONFRAG_IPV6_UDP:
	case RTE_ETH_FLOW_NONFRAG_IPV6_TCP:
		IPV6_ADDR_TO_ARRAY(res->ip_dst,
			entry.input.flow.ipv6_flow.dst_ip);
		IPV6_ADDR_TO_ARRAY(res->ip_src,
			entry.input.flow.ipv6_flow.src_ip);
		entry.input.flow.ipv6_flow.tc = res->tos_value;
		entry.input.flow.ipv6_flow.hop_limits = res->ttl_value;
		/* need convert to big endian. */
		entry.input.flow.udp6_flow.dst_port =
				rte_cpu_to_be_16(res->port_dst);
		entry.input.flow.udp6_flow.src_port =
				rte_cpu_to_be_16(res->port_src);
		break;
	case RTE_ETH_FLOW_NONFRAG_IPV6_SCTP:
		IPV6_ADDR_TO_ARRAY(res->ip_dst,
			entry.input.flow.sctp6_flow.ip.dst_ip);
		IPV6_ADDR_TO_ARRAY(res->ip_src,
			entry.input.flow.sctp6_flow.ip.src_ip);
		entry.input.flow.ipv6_flow.tc = res->tos_value;
		entry.input.flow.ipv6_flow.hop_limits = res->ttl_value;
		/* need convert to big endian. */
		entry.input.flow.sctp6_flow.dst_port =
				rte_cpu_to_be_16(res->port_dst);
		entry.input.flow.sctp6_flow.src_port =
				rte_cpu_to_be_16(res->port_src);
		entry.input.flow.sctp6_flow.verify_tag =
				rte_cpu_to_be_32(res->verify_tag_value);
		break;
	case RTE_ETH_FLOW_L2_PAYLOAD:
		entry.input.flow.l2_flow.ether_type =
			rte_cpu_to_be_16(res->ether_type);
		break;
	default:
		break;
	}

	if (fdir_conf.mode ==  RTE_FDIR_MODE_PERFECT_MAC_VLAN)
		rte_memcpy(&entry.input.flow.mac_vlan_flow.mac_addr,
				 &res->mac_addr,
				 sizeof(struct ether_addr));

	if (fdir_conf.mode ==  RTE_FDIR_MODE_PERFECT_TUNNEL) {
		rte_memcpy(&entry.input.flow.tunnel_flow.mac_addr,
				 &res->mac_addr,
				 sizeof(struct ether_addr));
		entry.input.flow.tunnel_flow.tunnel_type =
			str2fdir_tunneltype(res->tunnel_type);
		entry.input.flow.tunnel_flow.tunnel_id =
			rte_cpu_to_be_32(res->tunnel_id_value);
	}

	rte_memcpy(entry.input.flow_ext.flexbytes,
		   flexbytes,
		   RTE_ETH_FDIR_MAX_FLEXLEN);

	entry.input.flow_ext.vlan_tci = rte_cpu_to_be_16(res->vlan_value);

	entry.action.flex_off = 0;  /*use 0 by default */
	if (!strcmp(res->drop, "drop"))
		entry.action.behavior = RTE_ETH_FDIR_REJECT;
	else
		entry.action.behavior = RTE_ETH_FDIR_ACCEPT;

	if (fdir_conf.mode !=  RTE_FDIR_MODE_PERFECT_MAC_VLAN &&
	    fdir_conf.mode !=  RTE_FDIR_MODE_PERFECT_TUNNEL) {
		if (!strcmp(res->pf_vf, "pf"))
			entry.input.flow_ext.is_vf = 0;
		else if (!strncmp(res->pf_vf, "vf", 2)) {
			struct rte_eth_dev_info dev_info;

			memset(&dev_info, 0, sizeof(dev_info));
			rte_eth_dev_info_get(res->port_id, &dev_info);
			errno = 0;
			vf_id = strtoul(res->pf_vf + 2, &end, 10);
			if (errno != 0 || *end != '\0' ||
			    vf_id >= dev_info.max_vfs) {
				printf("invalid parameter %s.\n", res->pf_vf);
				return;
			}
			entry.input.flow_ext.is_vf = 1;
			entry.input.flow_ext.dst_id = (uint16_t)vf_id;
		} else {
			printf("invalid parameter %s.\n", res->pf_vf);
			return;
		}
	}

	/* set to report FD ID by default */
	entry.action.report_status = RTE_ETH_FDIR_REPORT_ID;
	entry.action.rx_queue = res->queue_id;
	entry.soft_id = res->fd_id_value;
	if (!strcmp(res->ops, "add"))
		ret = rte_eth_dev_filter_ctrl(res->port_id, RTE_ETH_FILTER_FDIR,
					     RTE_ETH_FILTER_ADD, &entry);
	else if (!strcmp(res->ops, "del"))
		ret = rte_eth_dev_filter_ctrl(res->port_id, RTE_ETH_FILTER_FDIR,
					     RTE_ETH_FILTER_DELETE, &entry);
	else
		ret = rte_eth_dev_filter_ctrl(res->port_id, RTE_ETH_FILTER_FDIR,
					     RTE_ETH_FILTER_UPDATE, &entry);
	if (ret < 0)
		printf("flow director programming error: (%s)\n",
			strerror(-ret));
}

cmdline_parse_token_string_t cmd_flow_director_filter =
	TOKEN_STRING_INITIALIZER(struct cmd_flow_director_result,
				 flow_director_filter, "flow_director_filter");
cmdline_parse_token_num_t cmd_flow_director_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_flow_director_result,
			      port_id, UINT16);
cmdline_parse_token_string_t cmd_flow_director_ops =
	TOKEN_STRING_INITIALIZER(struct cmd_flow_director_result,
				 ops, "add#del#update");
cmdline_parse_token_string_t cmd_flow_director_flow =
	TOKEN_STRING_INITIALIZER(struct cmd_flow_director_result,
				 flow, "flow");
cmdline_parse_token_string_t cmd_flow_director_flow_type =
	TOKEN_STRING_INITIALIZER(struct cmd_flow_director_result,
		flow_type, NULL);
cmdline_parse_token_string_t cmd_flow_director_ether =
	TOKEN_STRING_INITIALIZER(struct cmd_flow_director_result,
				 ether, "ether");
cmdline_parse_token_num_t cmd_flow_director_ether_type =
	TOKEN_NUM_INITIALIZER(struct cmd_flow_director_result,
			      ether_type, UINT16);
cmdline_parse_token_string_t cmd_flow_director_src =
	TOKEN_STRING_INITIALIZER(struct cmd_flow_director_result,
				 src, "src");
cmdline_parse_token_ipaddr_t cmd_flow_director_ip_src =
	TOKEN_IPADDR_INITIALIZER(struct cmd_flow_director_result,
				 ip_src);
cmdline_parse_token_num_t cmd_flow_director_port_src =
	TOKEN_NUM_INITIALIZER(struct cmd_flow_director_result,
			      port_src, UINT16);
cmdline_parse_token_string_t cmd_flow_director_dst =
	TOKEN_STRING_INITIALIZER(struct cmd_flow_director_result,
				 dst, "dst");
cmdline_parse_token_ipaddr_t cmd_flow_director_ip_dst =
	TOKEN_IPADDR_INITIALIZER(struct cmd_flow_director_result,
				 ip_dst);
cmdline_parse_token_num_t cmd_flow_director_port_dst =
	TOKEN_NUM_INITIALIZER(struct cmd_flow_director_result,
			      port_dst, UINT16);
cmdline_parse_token_string_t cmd_flow_director_verify_tag =
	TOKEN_STRING_INITIALIZER(struct cmd_flow_director_result,
				  verify_tag, "verify_tag");
cmdline_parse_token_num_t cmd_flow_director_verify_tag_value =
	TOKEN_NUM_INITIALIZER(struct cmd_flow_director_result,
			      verify_tag_value, UINT32);
cmdline_parse_token_string_t cmd_flow_director_tos =
	TOKEN_STRING_INITIALIZER(struct cmd_flow_director_result,
				 tos, "tos");
cmdline_parse_token_num_t cmd_flow_director_tos_value =
	TOKEN_NUM_INITIALIZER(struct cmd_flow_director_result,
			      tos_value, UINT8);
cmdline_parse_token_string_t cmd_flow_director_proto =
	TOKEN_STRING_INITIALIZER(struct cmd_flow_director_result,
				 proto, "proto");
cmdline_parse_token_num_t cmd_flow_director_proto_value =
	TOKEN_NUM_INITIALIZER(struct cmd_flow_director_result,
			      proto_value, UINT8);
cmdline_parse_token_string_t cmd_flow_director_ttl =
	TOKEN_STRING_INITIALIZER(struct cmd_flow_director_result,
				 ttl, "ttl");
cmdline_parse_token_num_t cmd_flow_director_ttl_value =
	TOKEN_NUM_INITIALIZER(struct cmd_flow_director_result,
			      ttl_value, UINT8);
cmdline_parse_token_string_t cmd_flow_director_vlan =
	TOKEN_STRING_INITIALIZER(struct cmd_flow_director_result,
				 vlan, "vlan");
cmdline_parse_token_num_t cmd_flow_director_vlan_value =
	TOKEN_NUM_INITIALIZER(struct cmd_flow_director_result,
			      vlan_value, UINT16);
cmdline_parse_token_string_t cmd_flow_director_flexbytes =
	TOKEN_STRING_INITIALIZER(struct cmd_flow_director_result,
				 flexbytes, "flexbytes");
cmdline_parse_token_string_t cmd_flow_director_flexbytes_value =
	TOKEN_STRING_INITIALIZER(struct cmd_flow_director_result,
			      flexbytes_value, NULL);
cmdline_parse_token_string_t cmd_flow_director_drop =
	TOKEN_STRING_INITIALIZER(struct cmd_flow_director_result,
				 drop, "drop#fwd");
cmdline_parse_token_string_t cmd_flow_director_pf_vf =
	TOKEN_STRING_INITIALIZER(struct cmd_flow_director_result,
			      pf_vf, NULL);
cmdline_parse_token_string_t cmd_flow_director_queue =
	TOKEN_STRING_INITIALIZER(struct cmd_flow_director_result,
				 queue, "queue");
cmdline_parse_token_num_t cmd_flow_director_queue_id =
	TOKEN_NUM_INITIALIZER(struct cmd_flow_director_result,
			      queue_id, UINT16);
cmdline_parse_token_string_t cmd_flow_director_fd_id =
	TOKEN_STRING_INITIALIZER(struct cmd_flow_director_result,
				 fd_id, "fd_id");
cmdline_parse_token_num_t cmd_flow_director_fd_id_value =
	TOKEN_NUM_INITIALIZER(struct cmd_flow_director_result,
			      fd_id_value, UINT32);

cmdline_parse_token_string_t cmd_flow_director_mode =
	TOKEN_STRING_INITIALIZER(struct cmd_flow_director_result,
				 mode, "mode");
cmdline_parse_token_string_t cmd_flow_director_mode_ip =
	TOKEN_STRING_INITIALIZER(struct cmd_flow_director_result,
				 mode_value, "IP");
cmdline_parse_token_string_t cmd_flow_director_mode_mac_vlan =
	TOKEN_STRING_INITIALIZER(struct cmd_flow_director_result,
				 mode_value, "MAC-VLAN");
cmdline_parse_token_string_t cmd_flow_director_mode_tunnel =
	TOKEN_STRING_INITIALIZER(struct cmd_flow_director_result,
				 mode_value, "Tunnel");
cmdline_parse_token_string_t cmd_flow_director_mode_raw =
	TOKEN_STRING_INITIALIZER(struct cmd_flow_director_result,
				 mode_value, "raw");
cmdline_parse_token_string_t cmd_flow_director_mac =
	TOKEN_STRING_INITIALIZER(struct cmd_flow_director_result,
				 mac, "mac");
cmdline_parse_token_etheraddr_t cmd_flow_director_mac_addr =
	TOKEN_ETHERADDR_INITIALIZER(struct cmd_flow_director_result,
				    mac_addr);
cmdline_parse_token_string_t cmd_flow_director_tunnel =
	TOKEN_STRING_INITIALIZER(struct cmd_flow_director_result,
				 tunnel, "tunnel");
cmdline_parse_token_string_t cmd_flow_director_tunnel_type =
	TOKEN_STRING_INITIALIZER(struct cmd_flow_director_result,
				 tunnel_type, "NVGRE#VxLAN");
cmdline_parse_token_string_t cmd_flow_director_tunnel_id =
	TOKEN_STRING_INITIALIZER(struct cmd_flow_director_result,
				 tunnel_id, "tunnel-id");
cmdline_parse_token_num_t cmd_flow_director_tunnel_id_value =
	TOKEN_NUM_INITIALIZER(struct cmd_flow_director_result,
			      tunnel_id_value, UINT32);
cmdline_parse_token_string_t cmd_flow_director_packet =
	TOKEN_STRING_INITIALIZER(struct cmd_flow_director_result,
				 packet, "packet");
cmdline_parse_token_string_t cmd_flow_director_filepath =
	TOKEN_STRING_INITIALIZER(struct cmd_flow_director_result,
				 filepath, NULL);

cmdline_parse_inst_t cmd_add_del_ip_flow_director = {
	.f = cmd_flow_director_filter_parsed,
	.data = NULL,
	.help_str = "flow_director_filter <port_id> mode IP add|del|update flow"
		" ipv4-other|ipv4-frag|ipv4-tcp|ipv4-udp|ipv4-sctp|"
		"ipv6-other|ipv6-frag|ipv6-tcp|ipv6-udp|ipv6-sctp|"
		"l2_payload src <src_ip> dst <dst_ip> tos <tos_value> "
		"proto <proto_value> ttl <ttl_value> vlan <vlan_value> "
		"flexbytes <flexbyte_values> drop|fw <pf_vf> queue <queue_id> "
		"fd_id <fd_id_value>: "
		"Add or delete an ip flow director entry on NIC",
	.tokens = {
		(void *)&cmd_flow_director_filter,
		(void *)&cmd_flow_director_port_id,
		(void *)&cmd_flow_director_mode,
		(void *)&cmd_flow_director_mode_ip,
		(void *)&cmd_flow_director_ops,
		(void *)&cmd_flow_director_flow,
		(void *)&cmd_flow_director_flow_type,
		(void *)&cmd_flow_director_src,
		(void *)&cmd_flow_director_ip_src,
		(void *)&cmd_flow_director_dst,
		(void *)&cmd_flow_director_ip_dst,
		(void *)&cmd_flow_director_tos,
		(void *)&cmd_flow_director_tos_value,
		(void *)&cmd_flow_director_proto,
		(void *)&cmd_flow_director_proto_value,
		(void *)&cmd_flow_director_ttl,
		(void *)&cmd_flow_director_ttl_value,
		(void *)&cmd_flow_director_vlan,
		(void *)&cmd_flow_director_vlan_value,
		(void *)&cmd_flow_director_flexbytes,
		(void *)&cmd_flow_director_flexbytes_value,
		(void *)&cmd_flow_director_drop,
		(void *)&cmd_flow_director_pf_vf,
		(void *)&cmd_flow_director_queue,
		(void *)&cmd_flow_director_queue_id,
		(void *)&cmd_flow_director_fd_id,
		(void *)&cmd_flow_director_fd_id_value,
		NULL,
	},
};

cmdline_parse_inst_t cmd_add_del_udp_flow_director = {
	.f = cmd_flow_director_filter_parsed,
	.data = NULL,
	.help_str = "flow_director_filter ... : Add or delete an udp/tcp flow "
		"director entry on NIC",
	.tokens = {
		(void *)&cmd_flow_director_filter,
		(void *)&cmd_flow_director_port_id,
		(void *)&cmd_flow_director_mode,
		(void *)&cmd_flow_director_mode_ip,
		(void *)&cmd_flow_director_ops,
		(void *)&cmd_flow_director_flow,
		(void *)&cmd_flow_director_flow_type,
		(void *)&cmd_flow_director_src,
		(void *)&cmd_flow_director_ip_src,
		(void *)&cmd_flow_director_port_src,
		(void *)&cmd_flow_director_dst,
		(void *)&cmd_flow_director_ip_dst,
		(void *)&cmd_flow_director_port_dst,
		(void *)&cmd_flow_director_tos,
		(void *)&cmd_flow_director_tos_value,
		(void *)&cmd_flow_director_ttl,
		(void *)&cmd_flow_director_ttl_value,
		(void *)&cmd_flow_director_vlan,
		(void *)&cmd_flow_director_vlan_value,
		(void *)&cmd_flow_director_flexbytes,
		(void *)&cmd_flow_director_flexbytes_value,
		(void *)&cmd_flow_director_drop,
		(void *)&cmd_flow_director_pf_vf,
		(void *)&cmd_flow_director_queue,
		(void *)&cmd_flow_director_queue_id,
		(void *)&cmd_flow_director_fd_id,
		(void *)&cmd_flow_director_fd_id_value,
		NULL,
	},
};

cmdline_parse_inst_t cmd_add_del_sctp_flow_director = {
	.f = cmd_flow_director_filter_parsed,
	.data = NULL,
	.help_str = "flow_director_filter ... : Add or delete a sctp flow "
		"director entry on NIC",
	.tokens = {
		(void *)&cmd_flow_director_filter,
		(void *)&cmd_flow_director_port_id,
		(void *)&cmd_flow_director_mode,
		(void *)&cmd_flow_director_mode_ip,
		(void *)&cmd_flow_director_ops,
		(void *)&cmd_flow_director_flow,
		(void *)&cmd_flow_director_flow_type,
		(void *)&cmd_flow_director_src,
		(void *)&cmd_flow_director_ip_src,
		(void *)&cmd_flow_director_port_src,
		(void *)&cmd_flow_director_dst,
		(void *)&cmd_flow_director_ip_dst,
		(void *)&cmd_flow_director_port_dst,
		(void *)&cmd_flow_director_verify_tag,
		(void *)&cmd_flow_director_verify_tag_value,
		(void *)&cmd_flow_director_tos,
		(void *)&cmd_flow_director_tos_value,
		(void *)&cmd_flow_director_ttl,
		(void *)&cmd_flow_director_ttl_value,
		(void *)&cmd_flow_director_vlan,
		(void *)&cmd_flow_director_vlan_value,
		(void *)&cmd_flow_director_flexbytes,
		(void *)&cmd_flow_director_flexbytes_value,
		(void *)&cmd_flow_director_drop,
		(void *)&cmd_flow_director_pf_vf,
		(void *)&cmd_flow_director_queue,
		(void *)&cmd_flow_director_queue_id,
		(void *)&cmd_flow_director_fd_id,
		(void *)&cmd_flow_director_fd_id_value,
		NULL,
	},
};

cmdline_parse_inst_t cmd_add_del_l2_flow_director = {
	.f = cmd_flow_director_filter_parsed,
	.data = NULL,
	.help_str = "flow_director_filter ... : Add or delete a L2 flow "
		"director entry on NIC",
	.tokens = {
		(void *)&cmd_flow_director_filter,
		(void *)&cmd_flow_director_port_id,
		(void *)&cmd_flow_director_mode,
		(void *)&cmd_flow_director_mode_ip,
		(void *)&cmd_flow_director_ops,
		(void *)&cmd_flow_director_flow,
		(void *)&cmd_flow_director_flow_type,
		(void *)&cmd_flow_director_ether,
		(void *)&cmd_flow_director_ether_type,
		(void *)&cmd_flow_director_flexbytes,
		(void *)&cmd_flow_director_flexbytes_value,
		(void *)&cmd_flow_director_drop,
		(void *)&cmd_flow_director_pf_vf,
		(void *)&cmd_flow_director_queue,
		(void *)&cmd_flow_director_queue_id,
		(void *)&cmd_flow_director_fd_id,
		(void *)&cmd_flow_director_fd_id_value,
		NULL,
	},
};

cmdline_parse_inst_t cmd_add_del_mac_vlan_flow_director = {
	.f = cmd_flow_director_filter_parsed,
	.data = NULL,
	.help_str = "flow_director_filter ... : Add or delete a MAC VLAN flow "
		"director entry on NIC",
	.tokens = {
		(void *)&cmd_flow_director_filter,
		(void *)&cmd_flow_director_port_id,
		(void *)&cmd_flow_director_mode,
		(void *)&cmd_flow_director_mode_mac_vlan,
		(void *)&cmd_flow_director_ops,
		(void *)&cmd_flow_director_mac,
		(void *)&cmd_flow_director_mac_addr,
		(void *)&cmd_flow_director_vlan,
		(void *)&cmd_flow_director_vlan_value,
		(void *)&cmd_flow_director_flexbytes,
		(void *)&cmd_flow_director_flexbytes_value,
		(void *)&cmd_flow_director_drop,
		(void *)&cmd_flow_director_queue,
		(void *)&cmd_flow_director_queue_id,
		(void *)&cmd_flow_director_fd_id,
		(void *)&cmd_flow_director_fd_id_value,
		NULL,
	},
};

cmdline_parse_inst_t cmd_add_del_tunnel_flow_director = {
	.f = cmd_flow_director_filter_parsed,
	.data = NULL,
	.help_str = "flow_director_filter ... : Add or delete a tunnel flow "
		"director entry on NIC",
	.tokens = {
		(void *)&cmd_flow_director_filter,
		(void *)&cmd_flow_director_port_id,
		(void *)&cmd_flow_director_mode,
		(void *)&cmd_flow_director_mode_tunnel,
		(void *)&cmd_flow_director_ops,
		(void *)&cmd_flow_director_mac,
		(void *)&cmd_flow_director_mac_addr,
		(void *)&cmd_flow_director_vlan,
		(void *)&cmd_flow_director_vlan_value,
		(void *)&cmd_flow_director_tunnel,
		(void *)&cmd_flow_director_tunnel_type,
		(void *)&cmd_flow_director_tunnel_id,
		(void *)&cmd_flow_director_tunnel_id_value,
		(void *)&cmd_flow_director_flexbytes,
		(void *)&cmd_flow_director_flexbytes_value,
		(void *)&cmd_flow_director_drop,
		(void *)&cmd_flow_director_queue,
		(void *)&cmd_flow_director_queue_id,
		(void *)&cmd_flow_director_fd_id,
		(void *)&cmd_flow_director_fd_id_value,
		NULL,
	},
};

cmdline_parse_inst_t cmd_add_del_raw_flow_director = {
	.f = cmd_flow_director_filter_parsed,
	.data = NULL,
	.help_str = "flow_director_filter ... : Add or delete a raw flow "
		"director entry on NIC",
	.tokens = {
		(void *)&cmd_flow_director_filter,
		(void *)&cmd_flow_director_port_id,
		(void *)&cmd_flow_director_mode,
		(void *)&cmd_flow_director_mode_raw,
		(void *)&cmd_flow_director_ops,
		(void *)&cmd_flow_director_flow,
		(void *)&cmd_flow_director_flow_type,
		(void *)&cmd_flow_director_drop,
		(void *)&cmd_flow_director_queue,
		(void *)&cmd_flow_director_queue_id,
		(void *)&cmd_flow_director_fd_id,
		(void *)&cmd_flow_director_fd_id_value,
		(void *)&cmd_flow_director_packet,
		(void *)&cmd_flow_director_filepath,
		NULL,
	},
};

struct cmd_flush_flow_director_result {
	cmdline_fixed_string_t flush_flow_director;
	portid_t port_id;
};

cmdline_parse_token_string_t cmd_flush_flow_director_flush =
	TOKEN_STRING_INITIALIZER(struct cmd_flush_flow_director_result,
				 flush_flow_director, "flush_flow_director");
cmdline_parse_token_num_t cmd_flush_flow_director_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_flush_flow_director_result,
			      port_id, UINT16);

static void
cmd_flush_flow_director_parsed(void *parsed_result,
			  __attribute__((unused)) struct cmdline *cl,
			  __attribute__((unused)) void *data)
{
	struct cmd_flow_director_result *res = parsed_result;
	int ret = 0;

	ret = rte_eth_dev_filter_supported(res->port_id, RTE_ETH_FILTER_FDIR);
	if (ret < 0) {
		printf("flow director is not supported on port %u.\n",
			res->port_id);
		return;
	}

	ret = rte_eth_dev_filter_ctrl(res->port_id, RTE_ETH_FILTER_FDIR,
			RTE_ETH_FILTER_FLUSH, NULL);
	if (ret < 0)
		printf("flow director table flushing error: (%s)\n",
			strerror(-ret));
}

cmdline_parse_inst_t cmd_flush_flow_director = {
	.f = cmd_flush_flow_director_parsed,
	.data = NULL,
	.help_str = "flush_flow_director <port_id>: "
		"Flush all flow director entries of a device on NIC",
	.tokens = {
		(void *)&cmd_flush_flow_director_flush,
		(void *)&cmd_flush_flow_director_port_id,
		NULL,
	},
};

/* *** deal with flow director mask *** */
struct cmd_flow_director_mask_result {
	cmdline_fixed_string_t flow_director_mask;
	portid_t port_id;
	cmdline_fixed_string_t mode;
	cmdline_fixed_string_t mode_value;
	cmdline_fixed_string_t vlan;
	uint16_t vlan_mask;
	cmdline_fixed_string_t src_mask;
	cmdline_ipaddr_t ipv4_src;
	cmdline_ipaddr_t ipv6_src;
	uint16_t port_src;
	cmdline_fixed_string_t dst_mask;
	cmdline_ipaddr_t ipv4_dst;
	cmdline_ipaddr_t ipv6_dst;
	uint16_t port_dst;
	cmdline_fixed_string_t mac;
	uint8_t mac_addr_byte_mask;
	cmdline_fixed_string_t tunnel_id;
	uint32_t tunnel_id_mask;
	cmdline_fixed_string_t tunnel_type;
	uint8_t tunnel_type_mask;
};

static void
cmd_flow_director_mask_parsed(void *parsed_result,
			  __attribute__((unused)) struct cmdline *cl,
			  __attribute__((unused)) void *data)
{
	struct cmd_flow_director_mask_result *res = parsed_result;
	struct rte_eth_fdir_masks *mask;
	struct rte_port *port;

	port = &ports[res->port_id];
	/** Check if the port is not started **/
	if (port->port_status != RTE_PORT_STOPPED) {
		printf("Please stop port %d first\n", res->port_id);
		return;
	}

	mask = &port->dev_conf.fdir_conf.mask;

	if (fdir_conf.mode ==  RTE_FDIR_MODE_PERFECT_MAC_VLAN) {
		if (strcmp(res->mode_value, "MAC-VLAN")) {
			printf("Please set mode to MAC-VLAN.\n");
			return;
		}

		mask->vlan_tci_mask = rte_cpu_to_be_16(res->vlan_mask);
	} else if (fdir_conf.mode ==  RTE_FDIR_MODE_PERFECT_TUNNEL) {
		if (strcmp(res->mode_value, "Tunnel")) {
			printf("Please set mode to Tunnel.\n");
			return;
		}

		mask->vlan_tci_mask = rte_cpu_to_be_16(res->vlan_mask);
		mask->mac_addr_byte_mask = res->mac_addr_byte_mask;
		mask->tunnel_id_mask = rte_cpu_to_be_32(res->tunnel_id_mask);
		mask->tunnel_type_mask = res->tunnel_type_mask;
	} else {
		if (strcmp(res->mode_value, "IP")) {
			printf("Please set mode to IP.\n");
			return;
		}

		mask->vlan_tci_mask = rte_cpu_to_be_16(res->vlan_mask);
		IPV4_ADDR_TO_UINT(res->ipv4_src, mask->ipv4_mask.src_ip);
		IPV4_ADDR_TO_UINT(res->ipv4_dst, mask->ipv4_mask.dst_ip);
		IPV6_ADDR_TO_ARRAY(res->ipv6_src, mask->ipv6_mask.src_ip);
		IPV6_ADDR_TO_ARRAY(res->ipv6_dst, mask->ipv6_mask.dst_ip);
		mask->src_port_mask = rte_cpu_to_be_16(res->port_src);
		mask->dst_port_mask = rte_cpu_to_be_16(res->port_dst);
	}

	cmd_reconfig_device_queue(res->port_id, 1, 1);
}

cmdline_parse_token_string_t cmd_flow_director_mask =
	TOKEN_STRING_INITIALIZER(struct cmd_flow_director_mask_result,
				 flow_director_mask, "flow_director_mask");
cmdline_parse_token_num_t cmd_flow_director_mask_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_flow_director_mask_result,
			      port_id, UINT16);
cmdline_parse_token_string_t cmd_flow_director_mask_vlan =
	TOKEN_STRING_INITIALIZER(struct cmd_flow_director_mask_result,
				 vlan, "vlan");
cmdline_parse_token_num_t cmd_flow_director_mask_vlan_value =
	TOKEN_NUM_INITIALIZER(struct cmd_flow_director_mask_result,
			      vlan_mask, UINT16);
cmdline_parse_token_string_t cmd_flow_director_mask_src =
	TOKEN_STRING_INITIALIZER(struct cmd_flow_director_mask_result,
				 src_mask, "src_mask");
cmdline_parse_token_ipaddr_t cmd_flow_director_mask_ipv4_src =
	TOKEN_IPADDR_INITIALIZER(struct cmd_flow_director_mask_result,
				 ipv4_src);
cmdline_parse_token_ipaddr_t cmd_flow_director_mask_ipv6_src =
	TOKEN_IPADDR_INITIALIZER(struct cmd_flow_director_mask_result,
				 ipv6_src);
cmdline_parse_token_num_t cmd_flow_director_mask_port_src =
	TOKEN_NUM_INITIALIZER(struct cmd_flow_director_mask_result,
			      port_src, UINT16);
cmdline_parse_token_string_t cmd_flow_director_mask_dst =
	TOKEN_STRING_INITIALIZER(struct cmd_flow_director_mask_result,
				 dst_mask, "dst_mask");
cmdline_parse_token_ipaddr_t cmd_flow_director_mask_ipv4_dst =
	TOKEN_IPADDR_INITIALIZER(struct cmd_flow_director_mask_result,
				 ipv4_dst);
cmdline_parse_token_ipaddr_t cmd_flow_director_mask_ipv6_dst =
	TOKEN_IPADDR_INITIALIZER(struct cmd_flow_director_mask_result,
				 ipv6_dst);
cmdline_parse_token_num_t cmd_flow_director_mask_port_dst =
	TOKEN_NUM_INITIALIZER(struct cmd_flow_director_mask_result,
			      port_dst, UINT16);

cmdline_parse_token_string_t cmd_flow_director_mask_mode =
	TOKEN_STRING_INITIALIZER(struct cmd_flow_director_mask_result,
				 mode, "mode");
cmdline_parse_token_string_t cmd_flow_director_mask_mode_ip =
	TOKEN_STRING_INITIALIZER(struct cmd_flow_director_mask_result,
				 mode_value, "IP");
cmdline_parse_token_string_t cmd_flow_director_mask_mode_mac_vlan =
	TOKEN_STRING_INITIALIZER(struct cmd_flow_director_mask_result,
				 mode_value, "MAC-VLAN");
cmdline_parse_token_string_t cmd_flow_director_mask_mode_tunnel =
	TOKEN_STRING_INITIALIZER(struct cmd_flow_director_mask_result,
				 mode_value, "Tunnel");
cmdline_parse_token_string_t cmd_flow_director_mask_mac =
	TOKEN_STRING_INITIALIZER(struct cmd_flow_director_mask_result,
				 mac, "mac");
cmdline_parse_token_num_t cmd_flow_director_mask_mac_value =
	TOKEN_NUM_INITIALIZER(struct cmd_flow_director_mask_result,
			      mac_addr_byte_mask, UINT8);
cmdline_parse_token_string_t cmd_flow_director_mask_tunnel_type =
	TOKEN_STRING_INITIALIZER(struct cmd_flow_director_mask_result,
				 tunnel_type, "tunnel-type");
cmdline_parse_token_num_t cmd_flow_director_mask_tunnel_type_value =
	TOKEN_NUM_INITIALIZER(struct cmd_flow_director_mask_result,
			      tunnel_type_mask, UINT8);
cmdline_parse_token_string_t cmd_flow_director_mask_tunnel_id =
	TOKEN_STRING_INITIALIZER(struct cmd_flow_director_mask_result,
				 tunnel_id, "tunnel-id");
cmdline_parse_token_num_t cmd_flow_director_mask_tunnel_id_value =
	TOKEN_NUM_INITIALIZER(struct cmd_flow_director_mask_result,
			      tunnel_id_mask, UINT32);

cmdline_parse_inst_t cmd_set_flow_director_ip_mask = {
	.f = cmd_flow_director_mask_parsed,
	.data = NULL,
	.help_str = "flow_director_mask ... : "
		"Set IP mode flow director's mask on NIC",
	.tokens = {
		(void *)&cmd_flow_director_mask,
		(void *)&cmd_flow_director_mask_port_id,
		(void *)&cmd_flow_director_mask_mode,
		(void *)&cmd_flow_director_mask_mode_ip,
		(void *)&cmd_flow_director_mask_vlan,
		(void *)&cmd_flow_director_mask_vlan_value,
		(void *)&cmd_flow_director_mask_src,
		(void *)&cmd_flow_director_mask_ipv4_src,
		(void *)&cmd_flow_director_mask_ipv6_src,
		(void *)&cmd_flow_director_mask_port_src,
		(void *)&cmd_flow_director_mask_dst,
		(void *)&cmd_flow_director_mask_ipv4_dst,
		(void *)&cmd_flow_director_mask_ipv6_dst,
		(void *)&cmd_flow_director_mask_port_dst,
		NULL,
	},
};

cmdline_parse_inst_t cmd_set_flow_director_mac_vlan_mask = {
	.f = cmd_flow_director_mask_parsed,
	.data = NULL,
	.help_str = "flow_director_mask ... : Set MAC VLAN mode "
		"flow director's mask on NIC",
	.tokens = {
		(void *)&cmd_flow_director_mask,
		(void *)&cmd_flow_director_mask_port_id,
		(void *)&cmd_flow_director_mask_mode,
		(void *)&cmd_flow_director_mask_mode_mac_vlan,
		(void *)&cmd_flow_director_mask_vlan,
		(void *)&cmd_flow_director_mask_vlan_value,
		NULL,
	},
};

cmdline_parse_inst_t cmd_set_flow_director_tunnel_mask = {
	.f = cmd_flow_director_mask_parsed,
	.data = NULL,
	.help_str = "flow_director_mask ... : Set tunnel mode "
		"flow director's mask on NIC",
	.tokens = {
		(void *)&cmd_flow_director_mask,
		(void *)&cmd_flow_director_mask_port_id,
		(void *)&cmd_flow_director_mask_mode,
		(void *)&cmd_flow_director_mask_mode_tunnel,
		(void *)&cmd_flow_director_mask_vlan,
		(void *)&cmd_flow_director_mask_vlan_value,
		(void *)&cmd_flow_director_mask_mac,
		(void *)&cmd_flow_director_mask_mac_value,
		(void *)&cmd_flow_director_mask_tunnel_type,
		(void *)&cmd_flow_director_mask_tunnel_type_value,
		(void *)&cmd_flow_director_mask_tunnel_id,
		(void *)&cmd_flow_director_mask_tunnel_id_value,
		NULL,
	},
};

/* *** deal with flow director mask on flexible payload *** */
struct cmd_flow_director_flex_mask_result {
	cmdline_fixed_string_t flow_director_flexmask;
	portid_t port_id;
	cmdline_fixed_string_t flow;
	cmdline_fixed_string_t flow_type;
	cmdline_fixed_string_t mask;
};

static void
cmd_flow_director_flex_mask_parsed(void *parsed_result,
			  __attribute__((unused)) struct cmdline *cl,
			  __attribute__((unused)) void *data)
{
	struct cmd_flow_director_flex_mask_result *res = parsed_result;
	struct rte_eth_fdir_info fdir_info;
	struct rte_eth_fdir_flex_mask flex_mask;
	struct rte_port *port;
	uint64_t flow_type_mask;
	uint16_t i;
	int ret;

	port = &ports[res->port_id];
	/** Check if the port is not started **/
	if (port->port_status != RTE_PORT_STOPPED) {
		printf("Please stop port %d first\n", res->port_id);
		return;
	}

	memset(&flex_mask, 0, sizeof(struct rte_eth_fdir_flex_mask));
	ret = parse_flexbytes(res->mask,
			flex_mask.mask,
			RTE_ETH_FDIR_MAX_FLEXLEN);
	if (ret < 0) {
		printf("error: Cannot parse mask input.\n");
		return;
	}

	memset(&fdir_info, 0, sizeof(fdir_info));
	ret = rte_eth_dev_filter_ctrl(res->port_id, RTE_ETH_FILTER_FDIR,
				RTE_ETH_FILTER_INFO, &fdir_info);
	if (ret < 0) {
		printf("Cannot get FDir filter info\n");
		return;
	}

	if (!strcmp(res->flow_type, "none")) {
		/* means don't specify the flow type */
		flex_mask.flow_type = RTE_ETH_FLOW_UNKNOWN;
		for (i = 0; i < RTE_ETH_FLOW_MAX; i++)
			memset(&port->dev_conf.fdir_conf.flex_conf.flex_mask[i],
			       0, sizeof(struct rte_eth_fdir_flex_mask));
		port->dev_conf.fdir_conf.flex_conf.nb_flexmasks = 1;
		rte_memcpy(&port->dev_conf.fdir_conf.flex_conf.flex_mask[0],
				 &flex_mask,
				 sizeof(struct rte_eth_fdir_flex_mask));
		cmd_reconfig_device_queue(res->port_id, 1, 1);
		return;
	}
	flow_type_mask = fdir_info.flow_types_mask[0];
	if (!strcmp(res->flow_type, "all")) {
		if (!flow_type_mask) {
			printf("No flow type supported\n");
			return;
		}
		for (i = RTE_ETH_FLOW_UNKNOWN; i < RTE_ETH_FLOW_MAX; i++) {
			if (flow_type_mask & (1ULL << i)) {
				flex_mask.flow_type = i;
				fdir_set_flex_mask(res->port_id, &flex_mask);
			}
		}
		cmd_reconfig_device_queue(res->port_id, 1, 1);
		return;
	}
	flex_mask.flow_type = str2flowtype(res->flow_type);
	if (!(flow_type_mask & (1ULL << flex_mask.flow_type))) {
		printf("Flow type %s not supported on port %d\n",
				res->flow_type, res->port_id);
		return;
	}
	fdir_set_flex_mask(res->port_id, &flex_mask);
	cmd_reconfig_device_queue(res->port_id, 1, 1);
}

cmdline_parse_token_string_t cmd_flow_director_flexmask =
	TOKEN_STRING_INITIALIZER(struct cmd_flow_director_flex_mask_result,
				 flow_director_flexmask,
				 "flow_director_flex_mask");
cmdline_parse_token_num_t cmd_flow_director_flexmask_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_flow_director_flex_mask_result,
			      port_id, UINT16);
cmdline_parse_token_string_t cmd_flow_director_flexmask_flow =
	TOKEN_STRING_INITIALIZER(struct cmd_flow_director_flex_mask_result,
				 flow, "flow");
cmdline_parse_token_string_t cmd_flow_director_flexmask_flow_type =
	TOKEN_STRING_INITIALIZER(struct cmd_flow_director_flex_mask_result,
		flow_type, "none#ipv4-other#ipv4-frag#ipv4-tcp#ipv4-udp#ipv4-sctp#"
		"ipv6-other#ipv6-frag#ipv6-tcp#ipv6-udp#ipv6-sctp#l2_payload#all");
cmdline_parse_token_string_t cmd_flow_director_flexmask_mask =
	TOKEN_STRING_INITIALIZER(struct cmd_flow_director_flex_mask_result,
				 mask, NULL);

cmdline_parse_inst_t cmd_set_flow_director_flex_mask = {
	.f = cmd_flow_director_flex_mask_parsed,
	.data = NULL,
	.help_str = "flow_director_flex_mask ... : "
		"Set flow director's flex mask on NIC",
	.tokens = {
		(void *)&cmd_flow_director_flexmask,
		(void *)&cmd_flow_director_flexmask_port_id,
		(void *)&cmd_flow_director_flexmask_flow,
		(void *)&cmd_flow_director_flexmask_flow_type,
		(void *)&cmd_flow_director_flexmask_mask,
		NULL,
	},
};

/* *** deal with flow director flexible payload configuration *** */
struct cmd_flow_director_flexpayload_result {
	cmdline_fixed_string_t flow_director_flexpayload;
	portid_t port_id;
	cmdline_fixed_string_t payload_layer;
	cmdline_fixed_string_t payload_cfg;
};

static inline int
parse_offsets(const char *q_arg, uint16_t *offsets, uint16_t max_num)
{
	char s[256];
	const char *p, *p0 = q_arg;
	char *end;
	unsigned long int_fld;
	char *str_fld[max_num];
	int i;
	unsigned size;
	int ret = -1;

	p = strchr(p0, '(');
	if (p == NULL)
		return -1;
	++p;
	p0 = strchr(p, ')');
	if (p0 == NULL)
		return -1;

	size = p0 - p;
	if (size >= sizeof(s))
		return -1;

	snprintf(s, sizeof(s), "%.*s", size, p);
	ret = rte_strsplit(s, sizeof(s), str_fld, max_num, ',');
	if (ret < 0 || ret > max_num)
		return -1;
	for (i = 0; i < ret; i++) {
		errno = 0;
		int_fld = strtoul(str_fld[i], &end, 0);
		if (errno != 0 || *end != '\0' || int_fld > UINT16_MAX)
			return -1;
		offsets[i] = (uint16_t)int_fld;
	}
	return ret;
}

static void
cmd_flow_director_flxpld_parsed(void *parsed_result,
			  __attribute__((unused)) struct cmdline *cl,
			  __attribute__((unused)) void *data)
{
	struct cmd_flow_director_flexpayload_result *res = parsed_result;
	struct rte_eth_flex_payload_cfg flex_cfg;
	struct rte_port *port;
	int ret = 0;

	port = &ports[res->port_id];
	/** Check if the port is not started **/
	if (port->port_status != RTE_PORT_STOPPED) {
		printf("Please stop port %d first\n", res->port_id);
		return;
	}

	memset(&flex_cfg, 0, sizeof(struct rte_eth_flex_payload_cfg));

	if (!strcmp(res->payload_layer, "raw"))
		flex_cfg.type = RTE_ETH_RAW_PAYLOAD;
	else if (!strcmp(res->payload_layer, "l2"))
		flex_cfg.type = RTE_ETH_L2_PAYLOAD;
	else if (!strcmp(res->payload_layer, "l3"))
		flex_cfg.type = RTE_ETH_L3_PAYLOAD;
	else if (!strcmp(res->payload_layer, "l4"))
		flex_cfg.type = RTE_ETH_L4_PAYLOAD;

	ret = parse_offsets(res->payload_cfg, flex_cfg.src_offset,
			    RTE_ETH_FDIR_MAX_FLEXLEN);
	if (ret < 0) {
		printf("error: Cannot parse flex payload input.\n");
		return;
	}

	fdir_set_flex_payload(res->port_id, &flex_cfg);
	cmd_reconfig_device_queue(res->port_id, 1, 1);
}

cmdline_parse_token_string_t cmd_flow_director_flexpayload =
	TOKEN_STRING_INITIALIZER(struct cmd_flow_director_flexpayload_result,
				 flow_director_flexpayload,
				 "flow_director_flex_payload");
cmdline_parse_token_num_t cmd_flow_director_flexpayload_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_flow_director_flexpayload_result,
			      port_id, UINT16);
cmdline_parse_token_string_t cmd_flow_director_flexpayload_payload_layer =
	TOKEN_STRING_INITIALIZER(struct cmd_flow_director_flexpayload_result,
				 payload_layer, "raw#l2#l3#l4");
cmdline_parse_token_string_t cmd_flow_director_flexpayload_payload_cfg =
	TOKEN_STRING_INITIALIZER(struct cmd_flow_director_flexpayload_result,
				 payload_cfg, NULL);

cmdline_parse_inst_t cmd_set_flow_director_flex_payload = {
	.f = cmd_flow_director_flxpld_parsed,
	.data = NULL,
	.help_str = "flow_director_flexpayload ... : "
		"Set flow director's flex payload on NIC",
	.tokens = {
		(void *)&cmd_flow_director_flexpayload,
		(void *)&cmd_flow_director_flexpayload_port_id,
		(void *)&cmd_flow_director_flexpayload_payload_layer,
		(void *)&cmd_flow_director_flexpayload_payload_cfg,
		NULL,
	},
};

/* Generic flow interface command. */
extern cmdline_parse_inst_t cmd_flow;

/* *** Classification Filters Control *** */
/* *** Get symmetric hash enable per port *** */
struct cmd_get_sym_hash_ena_per_port_result {
	cmdline_fixed_string_t get_sym_hash_ena_per_port;
	portid_t port_id;
};

static void
cmd_get_sym_hash_per_port_parsed(void *parsed_result,
				 __rte_unused struct cmdline *cl,
				 __rte_unused void *data)
{
	struct cmd_get_sym_hash_ena_per_port_result *res = parsed_result;
	struct rte_eth_hash_filter_info info;
	int ret;

	if (rte_eth_dev_filter_supported(res->port_id,
				RTE_ETH_FILTER_HASH) < 0) {
		printf("RTE_ETH_FILTER_HASH not supported on port: %d\n",
							res->port_id);
		return;
	}

	memset(&info, 0, sizeof(info));
	info.info_type = RTE_ETH_HASH_FILTER_SYM_HASH_ENA_PER_PORT;
	ret = rte_eth_dev_filter_ctrl(res->port_id, RTE_ETH_FILTER_HASH,
						RTE_ETH_FILTER_GET, &info);

	if (ret < 0) {
		printf("Cannot get symmetric hash enable per port "
					"on port %u\n", res->port_id);
		return;
	}

	printf("Symmetric hash is %s on port %u\n", info.info.enable ?
				"enabled" : "disabled", res->port_id);
}

cmdline_parse_token_string_t cmd_get_sym_hash_ena_per_port_all =
	TOKEN_STRING_INITIALIZER(struct cmd_get_sym_hash_ena_per_port_result,
		get_sym_hash_ena_per_port, "get_sym_hash_ena_per_port");
cmdline_parse_token_num_t cmd_get_sym_hash_ena_per_port_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_get_sym_hash_ena_per_port_result,
		port_id, UINT16);

cmdline_parse_inst_t cmd_get_sym_hash_ena_per_port = {
	.f = cmd_get_sym_hash_per_port_parsed,
	.data = NULL,
	.help_str = "get_sym_hash_ena_per_port <port_id>",
	.tokens = {
		(void *)&cmd_get_sym_hash_ena_per_port_all,
		(void *)&cmd_get_sym_hash_ena_per_port_port_id,
		NULL,
	},
};

/* *** Set symmetric hash enable per port *** */
struct cmd_set_sym_hash_ena_per_port_result {
	cmdline_fixed_string_t set_sym_hash_ena_per_port;
	cmdline_fixed_string_t enable;
	portid_t port_id;
};

static void
cmd_set_sym_hash_per_port_parsed(void *parsed_result,
				 __rte_unused struct cmdline *cl,
				 __rte_unused void *data)
{
	struct cmd_set_sym_hash_ena_per_port_result *res = parsed_result;
	struct rte_eth_hash_filter_info info;
	int ret;

	if (rte_eth_dev_filter_supported(res->port_id,
				RTE_ETH_FILTER_HASH) < 0) {
		printf("RTE_ETH_FILTER_HASH not supported on port: %d\n",
							res->port_id);
		return;
	}

	memset(&info, 0, sizeof(info));
	info.info_type = RTE_ETH_HASH_FILTER_SYM_HASH_ENA_PER_PORT;
	if (!strcmp(res->enable, "enable"))
		info.info.enable = 1;
	ret = rte_eth_dev_filter_ctrl(res->port_id, RTE_ETH_FILTER_HASH,
					RTE_ETH_FILTER_SET, &info);
	if (ret < 0) {
		printf("Cannot set symmetric hash enable per port on "
					"port %u\n", res->port_id);
		return;
	}
	printf("Symmetric hash has been set to %s on port %u\n",
					res->enable, res->port_id);
}

cmdline_parse_token_string_t cmd_set_sym_hash_ena_per_port_all =
	TOKEN_STRING_INITIALIZER(struct cmd_set_sym_hash_ena_per_port_result,
		set_sym_hash_ena_per_port, "set_sym_hash_ena_per_port");
cmdline_parse_token_num_t cmd_set_sym_hash_ena_per_port_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_set_sym_hash_ena_per_port_result,
		port_id, UINT16);
cmdline_parse_token_string_t cmd_set_sym_hash_ena_per_port_enable =
	TOKEN_STRING_INITIALIZER(struct cmd_set_sym_hash_ena_per_port_result,
		enable, "enable#disable");

cmdline_parse_inst_t cmd_set_sym_hash_ena_per_port = {
	.f = cmd_set_sym_hash_per_port_parsed,
	.data = NULL,
	.help_str = "set_sym_hash_ena_per_port <port_id> enable|disable",
	.tokens = {
		(void *)&cmd_set_sym_hash_ena_per_port_all,
		(void *)&cmd_set_sym_hash_ena_per_port_port_id,
		(void *)&cmd_set_sym_hash_ena_per_port_enable,
		NULL,
	},
};

/* Get global config of hash function */
struct cmd_get_hash_global_config_result {
	cmdline_fixed_string_t get_hash_global_config;
	portid_t port_id;
};

static char *
flowtype_to_str(uint16_t ftype)
{
	uint16_t i;
	static struct {
		char str[16];
		uint16_t ftype;
	} ftype_table[] = {
		{"ipv4", RTE_ETH_FLOW_IPV4},
		{"ipv4-frag", RTE_ETH_FLOW_FRAG_IPV4},
		{"ipv4-tcp", RTE_ETH_FLOW_NONFRAG_IPV4_TCP},
		{"ipv4-udp", RTE_ETH_FLOW_NONFRAG_IPV4_UDP},
		{"ipv4-sctp", RTE_ETH_FLOW_NONFRAG_IPV4_SCTP},
		{"ipv4-other", RTE_ETH_FLOW_NONFRAG_IPV4_OTHER},
		{"ipv6", RTE_ETH_FLOW_IPV6},
		{"ipv6-frag", RTE_ETH_FLOW_FRAG_IPV6},
		{"ipv6-tcp", RTE_ETH_FLOW_NONFRAG_IPV6_TCP},
		{"ipv6-udp", RTE_ETH_FLOW_NONFRAG_IPV6_UDP},
		{"ipv6-sctp", RTE_ETH_FLOW_NONFRAG_IPV6_SCTP},
		{"ipv6-other", RTE_ETH_FLOW_NONFRAG_IPV6_OTHER},
		{"l2_payload", RTE_ETH_FLOW_L2_PAYLOAD},
		{"port", RTE_ETH_FLOW_PORT},
		{"vxlan", RTE_ETH_FLOW_VXLAN},
		{"geneve", RTE_ETH_FLOW_GENEVE},
		{"nvgre", RTE_ETH_FLOW_NVGRE},
	};

	for (i = 0; i < RTE_DIM(ftype_table); i++) {
		if (ftype_table[i].ftype == ftype)
			return ftype_table[i].str;
	}

	return NULL;
}

static void
cmd_get_hash_global_config_parsed(void *parsed_result,
				  __rte_unused struct cmdline *cl,
				  __rte_unused void *data)
{
	struct cmd_get_hash_global_config_result *res = parsed_result;
	struct rte_eth_hash_filter_info info;
	uint32_t idx, offset;
	uint16_t i;
	char *str;
	int ret;

	if (rte_eth_dev_filter_supported(res->port_id,
			RTE_ETH_FILTER_HASH) < 0) {
		printf("RTE_ETH_FILTER_HASH not supported on port %d\n",
							res->port_id);
		return;
	}

	memset(&info, 0, sizeof(info));
	info.info_type = RTE_ETH_HASH_FILTER_GLOBAL_CONFIG;
	ret = rte_eth_dev_filter_ctrl(res->port_id, RTE_ETH_FILTER_HASH,
					RTE_ETH_FILTER_GET, &info);
	if (ret < 0) {
		printf("Cannot get hash global configurations by port %d\n",
							res->port_id);
		return;
	}

	switch (info.info.global_conf.hash_func) {
	case RTE_ETH_HASH_FUNCTION_TOEPLITZ:
		printf("Hash function is Toeplitz\n");
		break;
	case RTE_ETH_HASH_FUNCTION_SIMPLE_XOR:
		printf("Hash function is Simple XOR\n");
		break;
	default:
		printf("Unknown hash function\n");
		break;
	}

	for (i = 0; i < RTE_ETH_FLOW_MAX; i++) {
		idx = i / UINT64_BIT;
		offset = i % UINT64_BIT;
		if (!(info.info.global_conf.valid_bit_mask[idx] &
						(1ULL << offset)))
			continue;
		str = flowtype_to_str(i);
		if (!str)
			continue;
		printf("Symmetric hash is %s globally for flow type %s "
							"by port %d\n",
			((info.info.global_conf.sym_hash_enable_mask[idx] &
			(1ULL << offset)) ? "enabled" : "disabled"), str,
							res->port_id);
	}
}

cmdline_parse_token_string_t cmd_get_hash_global_config_all =
	TOKEN_STRING_INITIALIZER(struct cmd_get_hash_global_config_result,
		get_hash_global_config, "get_hash_global_config");
cmdline_parse_token_num_t cmd_get_hash_global_config_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_get_hash_global_config_result,
		port_id, UINT16);

cmdline_parse_inst_t cmd_get_hash_global_config = {
	.f = cmd_get_hash_global_config_parsed,
	.data = NULL,
	.help_str = "get_hash_global_config <port_id>",
	.tokens = {
		(void *)&cmd_get_hash_global_config_all,
		(void *)&cmd_get_hash_global_config_port_id,
		NULL,
	},
};

/* Set global config of hash function */
struct cmd_set_hash_global_config_result {
	cmdline_fixed_string_t set_hash_global_config;
	portid_t port_id;
	cmdline_fixed_string_t hash_func;
	cmdline_fixed_string_t flow_type;
	cmdline_fixed_string_t enable;
};

static void
cmd_set_hash_global_config_parsed(void *parsed_result,
				  __rte_unused struct cmdline *cl,
				  __rte_unused void *data)
{
	struct cmd_set_hash_global_config_result *res = parsed_result;
	struct rte_eth_hash_filter_info info;
	uint32_t ftype, idx, offset;
	int ret;

	if (rte_eth_dev_filter_supported(res->port_id,
				RTE_ETH_FILTER_HASH) < 0) {
		printf("RTE_ETH_FILTER_HASH not supported on port %d\n",
							res->port_id);
		return;
	}
	memset(&info, 0, sizeof(info));
	info.info_type = RTE_ETH_HASH_FILTER_GLOBAL_CONFIG;
	if (!strcmp(res->hash_func, "toeplitz"))
		info.info.global_conf.hash_func =
			RTE_ETH_HASH_FUNCTION_TOEPLITZ;
	else if (!strcmp(res->hash_func, "simple_xor"))
		info.info.global_conf.hash_func =
			RTE_ETH_HASH_FUNCTION_SIMPLE_XOR;
	else if (!strcmp(res->hash_func, "default"))
		info.info.global_conf.hash_func =
			RTE_ETH_HASH_FUNCTION_DEFAULT;

	ftype = str2flowtype(res->flow_type);
	idx = ftype / UINT64_BIT;
	offset = ftype % UINT64_BIT;
	info.info.global_conf.valid_bit_mask[idx] |= (1ULL << offset);
	if (!strcmp(res->enable, "enable"))
		info.info.global_conf.sym_hash_enable_mask[idx] |=
						(1ULL << offset);
	ret = rte_eth_dev_filter_ctrl(res->port_id, RTE_ETH_FILTER_HASH,
					RTE_ETH_FILTER_SET, &info);
	if (ret < 0)
		printf("Cannot set global hash configurations by port %d\n",
							res->port_id);
	else
		printf("Global hash configurations have been set "
			"successfully by port %d\n", res->port_id);
}

cmdline_parse_token_string_t cmd_set_hash_global_config_all =
	TOKEN_STRING_INITIALIZER(struct cmd_set_hash_global_config_result,
		set_hash_global_config, "set_hash_global_config");
cmdline_parse_token_num_t cmd_set_hash_global_config_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_set_hash_global_config_result,
		port_id, UINT16);
cmdline_parse_token_string_t cmd_set_hash_global_config_hash_func =
	TOKEN_STRING_INITIALIZER(struct cmd_set_hash_global_config_result,
		hash_func, "toeplitz#simple_xor#default");
cmdline_parse_token_string_t cmd_set_hash_global_config_flow_type =
	TOKEN_STRING_INITIALIZER(struct cmd_set_hash_global_config_result,
		flow_type,
		"ipv4#ipv4-frag#ipv4-tcp#ipv4-udp#ipv4-sctp#ipv4-other#ipv6#"
		"ipv6-frag#ipv6-tcp#ipv6-udp#ipv6-sctp#ipv6-other#l2_payload");
cmdline_parse_token_string_t cmd_set_hash_global_config_enable =
	TOKEN_STRING_INITIALIZER(struct cmd_set_hash_global_config_result,
		enable, "enable#disable");

cmdline_parse_inst_t cmd_set_hash_global_config = {
	.f = cmd_set_hash_global_config_parsed,
	.data = NULL,
	.help_str = "set_hash_global_config <port_id> "
		"toeplitz|simple_xor|default "
		"ipv4|ipv4-frag|ipv4-tcp|ipv4-udp|ipv4-sctp|ipv4-other|"
		"ipv6|ipv6-frag|ipv6-tcp|ipv6-udp|ipv6-sctp|ipv6-other|"
		"l2_payload enable|disable",
	.tokens = {
		(void *)&cmd_set_hash_global_config_all,
		(void *)&cmd_set_hash_global_config_port_id,
		(void *)&cmd_set_hash_global_config_hash_func,
		(void *)&cmd_set_hash_global_config_flow_type,
		(void *)&cmd_set_hash_global_config_enable,
		NULL,
	},
};

/* Set hash input set */
struct cmd_set_hash_input_set_result {
	cmdline_fixed_string_t set_hash_input_set;
	portid_t port_id;
	cmdline_fixed_string_t flow_type;
	cmdline_fixed_string_t inset_field;
	cmdline_fixed_string_t select;
};

static enum rte_eth_input_set_field
str2inset(char *string)
{
	uint16_t i;

	static const struct {
		char str[32];
		enum rte_eth_input_set_field inset;
	} inset_table[] = {
		{"ethertype", RTE_ETH_INPUT_SET_L2_ETHERTYPE},
		{"ovlan", RTE_ETH_INPUT_SET_L2_OUTER_VLAN},
		{"ivlan", RTE_ETH_INPUT_SET_L2_INNER_VLAN},
		{"src-ipv4", RTE_ETH_INPUT_SET_L3_SRC_IP4},
		{"dst-ipv4", RTE_ETH_INPUT_SET_L3_DST_IP4},
		{"ipv4-tos", RTE_ETH_INPUT_SET_L3_IP4_TOS},
		{"ipv4-proto", RTE_ETH_INPUT_SET_L3_IP4_PROTO},
		{"ipv4-ttl", RTE_ETH_INPUT_SET_L3_IP4_TTL},
		{"src-ipv6", RTE_ETH_INPUT_SET_L3_SRC_IP6},
		{"dst-ipv6", RTE_ETH_INPUT_SET_L3_DST_IP6},
		{"ipv6-tc", RTE_ETH_INPUT_SET_L3_IP6_TC},
		{"ipv6-next-header", RTE_ETH_INPUT_SET_L3_IP6_NEXT_HEADER},
		{"ipv6-hop-limits", RTE_ETH_INPUT_SET_L3_IP6_HOP_LIMITS},
		{"udp-src-port", RTE_ETH_INPUT_SET_L4_UDP_SRC_PORT},
		{"udp-dst-port", RTE_ETH_INPUT_SET_L4_UDP_DST_PORT},
		{"tcp-src-port", RTE_ETH_INPUT_SET_L4_TCP_SRC_PORT},
		{"tcp-dst-port", RTE_ETH_INPUT_SET_L4_TCP_DST_PORT},
		{"sctp-src-port", RTE_ETH_INPUT_SET_L4_SCTP_SRC_PORT},
		{"sctp-dst-port", RTE_ETH_INPUT_SET_L4_SCTP_DST_PORT},
		{"sctp-veri-tag", RTE_ETH_INPUT_SET_L4_SCTP_VERIFICATION_TAG},
		{"udp-key", RTE_ETH_INPUT_SET_TUNNEL_L4_UDP_KEY},
		{"gre-key", RTE_ETH_INPUT_SET_TUNNEL_GRE_KEY},
		{"fld-1st", RTE_ETH_INPUT_SET_FLEX_PAYLOAD_1ST_WORD},
		{"fld-2nd", RTE_ETH_INPUT_SET_FLEX_PAYLOAD_2ND_WORD},
		{"fld-3rd", RTE_ETH_INPUT_SET_FLEX_PAYLOAD_3RD_WORD},
		{"fld-4th", RTE_ETH_INPUT_SET_FLEX_PAYLOAD_4TH_WORD},
		{"fld-5th", RTE_ETH_INPUT_SET_FLEX_PAYLOAD_5TH_WORD},
		{"fld-6th", RTE_ETH_INPUT_SET_FLEX_PAYLOAD_6TH_WORD},
		{"fld-7th", RTE_ETH_INPUT_SET_FLEX_PAYLOAD_7TH_WORD},
		{"fld-8th", RTE_ETH_INPUT_SET_FLEX_PAYLOAD_8TH_WORD},
		{"none", RTE_ETH_INPUT_SET_NONE},
	};

	for (i = 0; i < RTE_DIM(inset_table); i++) {
		if (!strcmp(string, inset_table[i].str))
			return inset_table[i].inset;
	}

	return RTE_ETH_INPUT_SET_UNKNOWN;
}

static void
cmd_set_hash_input_set_parsed(void *parsed_result,
			      __rte_unused struct cmdline *cl,
			      __rte_unused void *data)
{
	struct cmd_set_hash_input_set_result *res = parsed_result;
	struct rte_eth_hash_filter_info info;

	memset(&info, 0, sizeof(info));
	info.info_type = RTE_ETH_HASH_FILTER_INPUT_SET_SELECT;
	info.info.input_set_conf.flow_type = str2flowtype(res->flow_type);
	info.info.input_set_conf.field[0] = str2inset(res->inset_field);
	info.info.input_set_conf.inset_size = 1;
	if (!strcmp(res->select, "select"))
		info.info.input_set_conf.op = RTE_ETH_INPUT_SET_SELECT;
	else if (!strcmp(res->select, "add"))
		info.info.input_set_conf.op = RTE_ETH_INPUT_SET_ADD;
	rte_eth_dev_filter_ctrl(res->port_id, RTE_ETH_FILTER_HASH,
				RTE_ETH_FILTER_SET, &info);
}

cmdline_parse_token_string_t cmd_set_hash_input_set_cmd =
	TOKEN_STRING_INITIALIZER(struct cmd_set_hash_input_set_result,
		set_hash_input_set, "set_hash_input_set");
cmdline_parse_token_num_t cmd_set_hash_input_set_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_set_hash_input_set_result,
		port_id, UINT16);
cmdline_parse_token_string_t cmd_set_hash_input_set_flow_type =
	TOKEN_STRING_INITIALIZER(struct cmd_set_hash_input_set_result,
		flow_type, NULL);
cmdline_parse_token_string_t cmd_set_hash_input_set_field =
	TOKEN_STRING_INITIALIZER(struct cmd_set_hash_input_set_result,
		inset_field,
		"ovlan#ivlan#src-ipv4#dst-ipv4#src-ipv6#dst-ipv6#"
		"ipv4-tos#ipv4-proto#ipv6-tc#ipv6-next-header#udp-src-port#"
		"udp-dst-port#tcp-src-port#tcp-dst-port#sctp-src-port#"
		"sctp-dst-port#sctp-veri-tag#udp-key#gre-key#fld-1st#"
		"fld-2nd#fld-3rd#fld-4th#fld-5th#fld-6th#fld-7th#"
		"fld-8th#none");
cmdline_parse_token_string_t cmd_set_hash_input_set_select =
	TOKEN_STRING_INITIALIZER(struct cmd_set_hash_input_set_result,
		select, "select#add");

cmdline_parse_inst_t cmd_set_hash_input_set = {
	.f = cmd_set_hash_input_set_parsed,
	.data = NULL,
	.help_str = "set_hash_input_set <port_id> "
	"ipv4-frag|ipv4-tcp|ipv4-udp|ipv4-sctp|ipv4-other|"
	"ipv6-frag|ipv6-tcp|ipv6-udp|ipv6-sctp|ipv6-other|l2_payload|<flowtype_id> "
	"ovlan|ivlan|src-ipv4|dst-ipv4|src-ipv6|dst-ipv6|ipv4-tos|ipv4-proto|"
	"ipv6-tc|ipv6-next-header|udp-src-port|udp-dst-port|tcp-src-port|"
	"tcp-dst-port|sctp-src-port|sctp-dst-port|sctp-veri-tag|udp-key|"
	"gre-key|fld-1st|fld-2nd|fld-3rd|fld-4th|fld-5th|fld-6th|"
	"fld-7th|fld-8th|none select|add",
	.tokens = {
		(void *)&cmd_set_hash_input_set_cmd,
		(void *)&cmd_set_hash_input_set_port_id,
		(void *)&cmd_set_hash_input_set_flow_type,
		(void *)&cmd_set_hash_input_set_field,
		(void *)&cmd_set_hash_input_set_select,
		NULL,
	},
};

/* Set flow director input set */
struct cmd_set_fdir_input_set_result {
	cmdline_fixed_string_t set_fdir_input_set;
	portid_t port_id;
	cmdline_fixed_string_t flow_type;
	cmdline_fixed_string_t inset_field;
	cmdline_fixed_string_t select;
};

static void
cmd_set_fdir_input_set_parsed(void *parsed_result,
	__rte_unused struct cmdline *cl,
	__rte_unused void *data)
{
	struct cmd_set_fdir_input_set_result *res = parsed_result;
	struct rte_eth_fdir_filter_info info;

	memset(&info, 0, sizeof(info));
	info.info_type = RTE_ETH_FDIR_FILTER_INPUT_SET_SELECT;
	info.info.input_set_conf.flow_type = str2flowtype(res->flow_type);
	info.info.input_set_conf.field[0] = str2inset(res->inset_field);
	info.info.input_set_conf.inset_size = 1;
	if (!strcmp(res->select, "select"))
		info.info.input_set_conf.op = RTE_ETH_INPUT_SET_SELECT;
	else if (!strcmp(res->select, "add"))
		info.info.input_set_conf.op = RTE_ETH_INPUT_SET_ADD;
	rte_eth_dev_filter_ctrl(res->port_id, RTE_ETH_FILTER_FDIR,
		RTE_ETH_FILTER_SET, &info);
}

cmdline_parse_token_string_t cmd_set_fdir_input_set_cmd =
	TOKEN_STRING_INITIALIZER(struct cmd_set_fdir_input_set_result,
	set_fdir_input_set, "set_fdir_input_set");
cmdline_parse_token_num_t cmd_set_fdir_input_set_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_set_fdir_input_set_result,
	port_id, UINT16);
cmdline_parse_token_string_t cmd_set_fdir_input_set_flow_type =
	TOKEN_STRING_INITIALIZER(struct cmd_set_fdir_input_set_result,
	flow_type,
	"ipv4-frag#ipv4-tcp#ipv4-udp#ipv4-sctp#ipv4-other#"
	"ipv6-frag#ipv6-tcp#ipv6-udp#ipv6-sctp#ipv6-other#l2_payload");
cmdline_parse_token_string_t cmd_set_fdir_input_set_field =
	TOKEN_STRING_INITIALIZER(struct cmd_set_fdir_input_set_result,
	inset_field,
	"ivlan#ethertype#src-ipv4#dst-ipv4#src-ipv6#dst-ipv6#"
	"ipv4-tos#ipv4-proto#ipv4-ttl#ipv6-tc#ipv6-next-header#"
	"ipv6-hop-limits#udp-src-port#udp-dst-port#"
	"tcp-src-port#tcp-dst-port#sctp-src-port#sctp-dst-port#"
	"sctp-veri-tag#none");
cmdline_parse_token_string_t cmd_set_fdir_input_set_select =
	TOKEN_STRING_INITIALIZER(struct cmd_set_fdir_input_set_result,
	select, "select#add");

cmdline_parse_inst_t cmd_set_fdir_input_set = {
	.f = cmd_set_fdir_input_set_parsed,
	.data = NULL,
	.help_str = "set_fdir_input_set <port_id> "
	"ipv4-frag|ipv4-tcp|ipv4-udp|ipv4-sctp|ipv4-other|"
	"ipv6-frag|ipv6-tcp|ipv6-udp|ipv6-sctp|ipv6-other|l2_payload "
	"ivlan|ethertype|src-ipv4|dst-ipv4|src-ipv6|dst-ipv6|"
	"ipv4-tos|ipv4-proto|ipv4-ttl|ipv6-tc|ipv6-next-header|"
	"ipv6-hop-limits|udp-src-port|udp-dst-port|"
	"tcp-src-port|tcp-dst-port|sctp-src-port|sctp-dst-port|"
	"sctp-veri-tag|none select|add",
	.tokens = {
		(void *)&cmd_set_fdir_input_set_cmd,
		(void *)&cmd_set_fdir_input_set_port_id,
		(void *)&cmd_set_fdir_input_set_flow_type,
		(void *)&cmd_set_fdir_input_set_field,
		(void *)&cmd_set_fdir_input_set_select,
		NULL,
	},
};

/* *** ADD/REMOVE A MULTICAST MAC ADDRESS TO/FROM A PORT *** */
struct cmd_mcast_addr_result {
	cmdline_fixed_string_t mcast_addr_cmd;
	cmdline_fixed_string_t what;
	uint16_t port_num;
	struct ether_addr mc_addr;
};

static void cmd_mcast_addr_parsed(void *parsed_result,
		__attribute__((unused)) struct cmdline *cl,
		__attribute__((unused)) void *data)
{
	struct cmd_mcast_addr_result *res = parsed_result;

	if (!is_multicast_ether_addr(&res->mc_addr)) {
		printf("Invalid multicast addr %02X:%02X:%02X:%02X:%02X:%02X\n",
		       res->mc_addr.addr_bytes[0], res->mc_addr.addr_bytes[1],
		       res->mc_addr.addr_bytes[2], res->mc_addr.addr_bytes[3],
		       res->mc_addr.addr_bytes[4], res->mc_addr.addr_bytes[5]);
		return;
	}
	if (strcmp(res->what, "add") == 0)
		mcast_addr_add(res->port_num, &res->mc_addr);
	else
		mcast_addr_remove(res->port_num, &res->mc_addr);
}

cmdline_parse_token_string_t cmd_mcast_addr_cmd =
	TOKEN_STRING_INITIALIZER(struct cmd_mcast_addr_result,
				 mcast_addr_cmd, "mcast_addr");
cmdline_parse_token_string_t cmd_mcast_addr_what =
	TOKEN_STRING_INITIALIZER(struct cmd_mcast_addr_result, what,
				 "add#remove");
cmdline_parse_token_num_t cmd_mcast_addr_portnum =
	TOKEN_NUM_INITIALIZER(struct cmd_mcast_addr_result, port_num, UINT16);
cmdline_parse_token_etheraddr_t cmd_mcast_addr_addr =
	TOKEN_ETHERADDR_INITIALIZER(struct cmd_mac_addr_result, address);

cmdline_parse_inst_t cmd_mcast_addr = {
	.f = cmd_mcast_addr_parsed,
	.data = (void *)0,
	.help_str = "mcast_addr add|remove <port_id> <mcast_addr>: "
		"Add/Remove multicast MAC address on port_id",
	.tokens = {
		(void *)&cmd_mcast_addr_cmd,
		(void *)&cmd_mcast_addr_what,
		(void *)&cmd_mcast_addr_portnum,
		(void *)&cmd_mcast_addr_addr,
		NULL,
	},
};

/* l2 tunnel config
 * only support E-tag now.
 */

/* Ether type config */
struct cmd_config_l2_tunnel_eth_type_result {
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t config;
	cmdline_fixed_string_t all;
	portid_t id;
	cmdline_fixed_string_t l2_tunnel;
	cmdline_fixed_string_t l2_tunnel_type;
	cmdline_fixed_string_t eth_type;
	uint16_t eth_type_val;
};

cmdline_parse_token_string_t cmd_config_l2_tunnel_eth_type_port =
	TOKEN_STRING_INITIALIZER
		(struct cmd_config_l2_tunnel_eth_type_result,
		 port, "port");
cmdline_parse_token_string_t cmd_config_l2_tunnel_eth_type_config =
	TOKEN_STRING_INITIALIZER
		(struct cmd_config_l2_tunnel_eth_type_result,
		 config, "config");
cmdline_parse_token_string_t cmd_config_l2_tunnel_eth_type_all_str =
	TOKEN_STRING_INITIALIZER
		(struct cmd_config_l2_tunnel_eth_type_result,
		 all, "all");
cmdline_parse_token_num_t cmd_config_l2_tunnel_eth_type_id =
	TOKEN_NUM_INITIALIZER
		(struct cmd_config_l2_tunnel_eth_type_result,
		 id, UINT16);
cmdline_parse_token_string_t cmd_config_l2_tunnel_eth_type_l2_tunnel =
	TOKEN_STRING_INITIALIZER
		(struct cmd_config_l2_tunnel_eth_type_result,
		 l2_tunnel, "l2-tunnel");
cmdline_parse_token_string_t cmd_config_l2_tunnel_eth_type_l2_tunnel_type =
	TOKEN_STRING_INITIALIZER
		(struct cmd_config_l2_tunnel_eth_type_result,
		 l2_tunnel_type, "E-tag");
cmdline_parse_token_string_t cmd_config_l2_tunnel_eth_type_eth_type =
	TOKEN_STRING_INITIALIZER
		(struct cmd_config_l2_tunnel_eth_type_result,
		 eth_type, "ether-type");
cmdline_parse_token_num_t cmd_config_l2_tunnel_eth_type_eth_type_val =
	TOKEN_NUM_INITIALIZER
		(struct cmd_config_l2_tunnel_eth_type_result,
		 eth_type_val, UINT16);

static enum rte_eth_tunnel_type
str2fdir_l2_tunnel_type(char *string)
{
	uint32_t i = 0;

	static const struct {
		char str[32];
		enum rte_eth_tunnel_type type;
	} l2_tunnel_type_str[] = {
		{"E-tag", RTE_L2_TUNNEL_TYPE_E_TAG},
	};

	for (i = 0; i < RTE_DIM(l2_tunnel_type_str); i++) {
		if (!strcmp(l2_tunnel_type_str[i].str, string))
			return l2_tunnel_type_str[i].type;
	}
	return RTE_TUNNEL_TYPE_NONE;
}

/* ether type config for all ports */
static void
cmd_config_l2_tunnel_eth_type_all_parsed
	(void *parsed_result,
	 __attribute__((unused)) struct cmdline *cl,
	 __attribute__((unused)) void *data)
{
	struct cmd_config_l2_tunnel_eth_type_result *res = parsed_result;
	struct rte_eth_l2_tunnel_conf entry;
	portid_t pid;

	entry.l2_tunnel_type = str2fdir_l2_tunnel_type(res->l2_tunnel_type);
	entry.ether_type = res->eth_type_val;

	RTE_ETH_FOREACH_DEV(pid) {
		rte_eth_dev_l2_tunnel_eth_type_conf(pid, &entry);
	}
}

cmdline_parse_inst_t cmd_config_l2_tunnel_eth_type_all = {
	.f = cmd_config_l2_tunnel_eth_type_all_parsed,
	.data = NULL,
	.help_str = "port config all l2-tunnel E-tag ether-type <value>",
	.tokens = {
		(void *)&cmd_config_l2_tunnel_eth_type_port,
		(void *)&cmd_config_l2_tunnel_eth_type_config,
		(void *)&cmd_config_l2_tunnel_eth_type_all_str,
		(void *)&cmd_config_l2_tunnel_eth_type_l2_tunnel,
		(void *)&cmd_config_l2_tunnel_eth_type_l2_tunnel_type,
		(void *)&cmd_config_l2_tunnel_eth_type_eth_type,
		(void *)&cmd_config_l2_tunnel_eth_type_eth_type_val,
		NULL,
	},
};

/* ether type config for a specific port */
static void
cmd_config_l2_tunnel_eth_type_specific_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_config_l2_tunnel_eth_type_result *res =
		 parsed_result;
	struct rte_eth_l2_tunnel_conf entry;

	if (port_id_is_invalid(res->id, ENABLED_WARN))
		return;

	entry.l2_tunnel_type = str2fdir_l2_tunnel_type(res->l2_tunnel_type);
	entry.ether_type = res->eth_type_val;

	rte_eth_dev_l2_tunnel_eth_type_conf(res->id, &entry);
}

cmdline_parse_inst_t cmd_config_l2_tunnel_eth_type_specific = {
	.f = cmd_config_l2_tunnel_eth_type_specific_parsed,
	.data = NULL,
	.help_str = "port config <port_id> l2-tunnel E-tag ether-type <value>",
	.tokens = {
		(void *)&cmd_config_l2_tunnel_eth_type_port,
		(void *)&cmd_config_l2_tunnel_eth_type_config,
		(void *)&cmd_config_l2_tunnel_eth_type_id,
		(void *)&cmd_config_l2_tunnel_eth_type_l2_tunnel,
		(void *)&cmd_config_l2_tunnel_eth_type_l2_tunnel_type,
		(void *)&cmd_config_l2_tunnel_eth_type_eth_type,
		(void *)&cmd_config_l2_tunnel_eth_type_eth_type_val,
		NULL,
	},
};

/* Enable/disable l2 tunnel */
struct cmd_config_l2_tunnel_en_dis_result {
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t config;
	cmdline_fixed_string_t all;
	portid_t id;
	cmdline_fixed_string_t l2_tunnel;
	cmdline_fixed_string_t l2_tunnel_type;
	cmdline_fixed_string_t en_dis;
};

cmdline_parse_token_string_t cmd_config_l2_tunnel_en_dis_port =
	TOKEN_STRING_INITIALIZER
		(struct cmd_config_l2_tunnel_en_dis_result,
		 port, "port");
cmdline_parse_token_string_t cmd_config_l2_tunnel_en_dis_config =
	TOKEN_STRING_INITIALIZER
		(struct cmd_config_l2_tunnel_en_dis_result,
		 config, "config");
cmdline_parse_token_string_t cmd_config_l2_tunnel_en_dis_all_str =
	TOKEN_STRING_INITIALIZER
		(struct cmd_config_l2_tunnel_en_dis_result,
		 all, "all");
cmdline_parse_token_num_t cmd_config_l2_tunnel_en_dis_id =
	TOKEN_NUM_INITIALIZER
		(struct cmd_config_l2_tunnel_en_dis_result,
		 id, UINT16);
cmdline_parse_token_string_t cmd_config_l2_tunnel_en_dis_l2_tunnel =
	TOKEN_STRING_INITIALIZER
		(struct cmd_config_l2_tunnel_en_dis_result,
		 l2_tunnel, "l2-tunnel");
cmdline_parse_token_string_t cmd_config_l2_tunnel_en_dis_l2_tunnel_type =
	TOKEN_STRING_INITIALIZER
		(struct cmd_config_l2_tunnel_en_dis_result,
		 l2_tunnel_type, "E-tag");
cmdline_parse_token_string_t cmd_config_l2_tunnel_en_dis_en_dis =
	TOKEN_STRING_INITIALIZER
		(struct cmd_config_l2_tunnel_en_dis_result,
		 en_dis, "enable#disable");

/* enable/disable l2 tunnel for all ports */
static void
cmd_config_l2_tunnel_en_dis_all_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_config_l2_tunnel_en_dis_result *res = parsed_result;
	struct rte_eth_l2_tunnel_conf entry;
	portid_t pid;
	uint8_t en;

	entry.l2_tunnel_type = str2fdir_l2_tunnel_type(res->l2_tunnel_type);

	if (!strcmp("enable", res->en_dis))
		en = 1;
	else
		en = 0;

	RTE_ETH_FOREACH_DEV(pid) {
		rte_eth_dev_l2_tunnel_offload_set(pid,
						  &entry,
						  ETH_L2_TUNNEL_ENABLE_MASK,
						  en);
	}
}

cmdline_parse_inst_t cmd_config_l2_tunnel_en_dis_all = {
	.f = cmd_config_l2_tunnel_en_dis_all_parsed,
	.data = NULL,
	.help_str = "port config all l2-tunnel E-tag enable|disable",
	.tokens = {
		(void *)&cmd_config_l2_tunnel_en_dis_port,
		(void *)&cmd_config_l2_tunnel_en_dis_config,
		(void *)&cmd_config_l2_tunnel_en_dis_all_str,
		(void *)&cmd_config_l2_tunnel_en_dis_l2_tunnel,
		(void *)&cmd_config_l2_tunnel_en_dis_l2_tunnel_type,
		(void *)&cmd_config_l2_tunnel_en_dis_en_dis,
		NULL,
	},
};

/* enable/disable l2 tunnel for a port */
static void
cmd_config_l2_tunnel_en_dis_specific_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_config_l2_tunnel_en_dis_result *res =
		parsed_result;
	struct rte_eth_l2_tunnel_conf entry;

	if (port_id_is_invalid(res->id, ENABLED_WARN))
		return;

	entry.l2_tunnel_type = str2fdir_l2_tunnel_type(res->l2_tunnel_type);

	if (!strcmp("enable", res->en_dis))
		rte_eth_dev_l2_tunnel_offload_set(res->id,
						  &entry,
						  ETH_L2_TUNNEL_ENABLE_MASK,
						  1);
	else
		rte_eth_dev_l2_tunnel_offload_set(res->id,
						  &entry,
						  ETH_L2_TUNNEL_ENABLE_MASK,
						  0);
}

cmdline_parse_inst_t cmd_config_l2_tunnel_en_dis_specific = {
	.f = cmd_config_l2_tunnel_en_dis_specific_parsed,
	.data = NULL,
	.help_str = "port config <port_id> l2-tunnel E-tag enable|disable",
	.tokens = {
		(void *)&cmd_config_l2_tunnel_en_dis_port,
		(void *)&cmd_config_l2_tunnel_en_dis_config,
		(void *)&cmd_config_l2_tunnel_en_dis_id,
		(void *)&cmd_config_l2_tunnel_en_dis_l2_tunnel,
		(void *)&cmd_config_l2_tunnel_en_dis_l2_tunnel_type,
		(void *)&cmd_config_l2_tunnel_en_dis_en_dis,
		NULL,
	},
};

/* E-tag configuration */

/* Common result structure for all E-tag configuration */
struct cmd_config_e_tag_result {
	cmdline_fixed_string_t e_tag;
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t insertion;
	cmdline_fixed_string_t stripping;
	cmdline_fixed_string_t forwarding;
	cmdline_fixed_string_t filter;
	cmdline_fixed_string_t add;
	cmdline_fixed_string_t del;
	cmdline_fixed_string_t on;
	cmdline_fixed_string_t off;
	cmdline_fixed_string_t on_off;
	cmdline_fixed_string_t port_tag_id;
	uint32_t port_tag_id_val;
	cmdline_fixed_string_t e_tag_id;
	uint16_t e_tag_id_val;
	cmdline_fixed_string_t dst_pool;
	uint8_t dst_pool_val;
	cmdline_fixed_string_t port;
	portid_t port_id;
	cmdline_fixed_string_t vf;
	uint8_t vf_id;
};

/* Common CLI fields for all E-tag configuration */
cmdline_parse_token_string_t cmd_config_e_tag_e_tag =
	TOKEN_STRING_INITIALIZER
		(struct cmd_config_e_tag_result,
		 e_tag, "E-tag");
cmdline_parse_token_string_t cmd_config_e_tag_set =
	TOKEN_STRING_INITIALIZER
		(struct cmd_config_e_tag_result,
		 set, "set");
cmdline_parse_token_string_t cmd_config_e_tag_insertion =
	TOKEN_STRING_INITIALIZER
		(struct cmd_config_e_tag_result,
		 insertion, "insertion");
cmdline_parse_token_string_t cmd_config_e_tag_stripping =
	TOKEN_STRING_INITIALIZER
		(struct cmd_config_e_tag_result,
		 stripping, "stripping");
cmdline_parse_token_string_t cmd_config_e_tag_forwarding =
	TOKEN_STRING_INITIALIZER
		(struct cmd_config_e_tag_result,
		 forwarding, "forwarding");
cmdline_parse_token_string_t cmd_config_e_tag_filter =
	TOKEN_STRING_INITIALIZER
		(struct cmd_config_e_tag_result,
		 filter, "filter");
cmdline_parse_token_string_t cmd_config_e_tag_add =
	TOKEN_STRING_INITIALIZER
		(struct cmd_config_e_tag_result,
		 add, "add");
cmdline_parse_token_string_t cmd_config_e_tag_del =
	TOKEN_STRING_INITIALIZER
		(struct cmd_config_e_tag_result,
		 del, "del");
cmdline_parse_token_string_t cmd_config_e_tag_on =
	TOKEN_STRING_INITIALIZER
		(struct cmd_config_e_tag_result,
		 on, "on");
cmdline_parse_token_string_t cmd_config_e_tag_off =
	TOKEN_STRING_INITIALIZER
		(struct cmd_config_e_tag_result,
		 off, "off");
cmdline_parse_token_string_t cmd_config_e_tag_on_off =
	TOKEN_STRING_INITIALIZER
		(struct cmd_config_e_tag_result,
		 on_off, "on#off");
cmdline_parse_token_string_t cmd_config_e_tag_port_tag_id =
	TOKEN_STRING_INITIALIZER
		(struct cmd_config_e_tag_result,
		 port_tag_id, "port-tag-id");
cmdline_parse_token_num_t cmd_config_e_tag_port_tag_id_val =
	TOKEN_NUM_INITIALIZER
		(struct cmd_config_e_tag_result,
		 port_tag_id_val, UINT32);
cmdline_parse_token_string_t cmd_config_e_tag_e_tag_id =
	TOKEN_STRING_INITIALIZER
		(struct cmd_config_e_tag_result,
		 e_tag_id, "e-tag-id");
cmdline_parse_token_num_t cmd_config_e_tag_e_tag_id_val =
	TOKEN_NUM_INITIALIZER
		(struct cmd_config_e_tag_result,
		 e_tag_id_val, UINT16);
cmdline_parse_token_string_t cmd_config_e_tag_dst_pool =
	TOKEN_STRING_INITIALIZER
		(struct cmd_config_e_tag_result,
		 dst_pool, "dst-pool");
cmdline_parse_token_num_t cmd_config_e_tag_dst_pool_val =
	TOKEN_NUM_INITIALIZER
		(struct cmd_config_e_tag_result,
		 dst_pool_val, UINT8);
cmdline_parse_token_string_t cmd_config_e_tag_port =
	TOKEN_STRING_INITIALIZER
		(struct cmd_config_e_tag_result,
		 port, "port");
cmdline_parse_token_num_t cmd_config_e_tag_port_id =
	TOKEN_NUM_INITIALIZER
		(struct cmd_config_e_tag_result,
		 port_id, UINT16);
cmdline_parse_token_string_t cmd_config_e_tag_vf =
	TOKEN_STRING_INITIALIZER
		(struct cmd_config_e_tag_result,
		 vf, "vf");
cmdline_parse_token_num_t cmd_config_e_tag_vf_id =
	TOKEN_NUM_INITIALIZER
		(struct cmd_config_e_tag_result,
		 vf_id, UINT8);

/* E-tag insertion configuration */
static void
cmd_config_e_tag_insertion_en_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_config_e_tag_result *res =
		parsed_result;
	struct rte_eth_l2_tunnel_conf entry;

	if (port_id_is_invalid(res->port_id, ENABLED_WARN))
		return;

	entry.l2_tunnel_type = RTE_L2_TUNNEL_TYPE_E_TAG;
	entry.tunnel_id = res->port_tag_id_val;
	entry.vf_id = res->vf_id;
	rte_eth_dev_l2_tunnel_offload_set(res->port_id,
					  &entry,
					  ETH_L2_TUNNEL_INSERTION_MASK,
					  1);
}

static void
cmd_config_e_tag_insertion_dis_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_config_e_tag_result *res =
		parsed_result;
	struct rte_eth_l2_tunnel_conf entry;

	if (port_id_is_invalid(res->port_id, ENABLED_WARN))
		return;

	entry.l2_tunnel_type = RTE_L2_TUNNEL_TYPE_E_TAG;
	entry.vf_id = res->vf_id;

	rte_eth_dev_l2_tunnel_offload_set(res->port_id,
					  &entry,
					  ETH_L2_TUNNEL_INSERTION_MASK,
					  0);
}

cmdline_parse_inst_t cmd_config_e_tag_insertion_en = {
	.f = cmd_config_e_tag_insertion_en_parsed,
	.data = NULL,
	.help_str = "E-tag ... : E-tag insertion enable",
	.tokens = {
		(void *)&cmd_config_e_tag_e_tag,
		(void *)&cmd_config_e_tag_set,
		(void *)&cmd_config_e_tag_insertion,
		(void *)&cmd_config_e_tag_on,
		(void *)&cmd_config_e_tag_port_tag_id,
		(void *)&cmd_config_e_tag_port_tag_id_val,
		(void *)&cmd_config_e_tag_port,
		(void *)&cmd_config_e_tag_port_id,
		(void *)&cmd_config_e_tag_vf,
		(void *)&cmd_config_e_tag_vf_id,
		NULL,
	},
};

cmdline_parse_inst_t cmd_config_e_tag_insertion_dis = {
	.f = cmd_config_e_tag_insertion_dis_parsed,
	.data = NULL,
	.help_str = "E-tag ... : E-tag insertion disable",
	.tokens = {
		(void *)&cmd_config_e_tag_e_tag,
		(void *)&cmd_config_e_tag_set,
		(void *)&cmd_config_e_tag_insertion,
		(void *)&cmd_config_e_tag_off,
		(void *)&cmd_config_e_tag_port,
		(void *)&cmd_config_e_tag_port_id,
		(void *)&cmd_config_e_tag_vf,
		(void *)&cmd_config_e_tag_vf_id,
		NULL,
	},
};

/* E-tag stripping configuration */
static void
cmd_config_e_tag_stripping_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_config_e_tag_result *res =
		parsed_result;
	struct rte_eth_l2_tunnel_conf entry;

	if (port_id_is_invalid(res->port_id, ENABLED_WARN))
		return;

	entry.l2_tunnel_type = RTE_L2_TUNNEL_TYPE_E_TAG;

	if (!strcmp(res->on_off, "on"))
		rte_eth_dev_l2_tunnel_offload_set
			(res->port_id,
			 &entry,
			 ETH_L2_TUNNEL_STRIPPING_MASK,
			 1);
	else
		rte_eth_dev_l2_tunnel_offload_set
			(res->port_id,
			 &entry,
			 ETH_L2_TUNNEL_STRIPPING_MASK,
			 0);
}

cmdline_parse_inst_t cmd_config_e_tag_stripping_en_dis = {
	.f = cmd_config_e_tag_stripping_parsed,
	.data = NULL,
	.help_str = "E-tag ... : E-tag stripping enable/disable",
	.tokens = {
		(void *)&cmd_config_e_tag_e_tag,
		(void *)&cmd_config_e_tag_set,
		(void *)&cmd_config_e_tag_stripping,
		(void *)&cmd_config_e_tag_on_off,
		(void *)&cmd_config_e_tag_port,
		(void *)&cmd_config_e_tag_port_id,
		NULL,
	},
};

/* E-tag forwarding configuration */
static void
cmd_config_e_tag_forwarding_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_config_e_tag_result *res = parsed_result;
	struct rte_eth_l2_tunnel_conf entry;

	if (port_id_is_invalid(res->port_id, ENABLED_WARN))
		return;

	entry.l2_tunnel_type = RTE_L2_TUNNEL_TYPE_E_TAG;

	if (!strcmp(res->on_off, "on"))
		rte_eth_dev_l2_tunnel_offload_set
			(res->port_id,
			 &entry,
			 ETH_L2_TUNNEL_FORWARDING_MASK,
			 1);
	else
		rte_eth_dev_l2_tunnel_offload_set
			(res->port_id,
			 &entry,
			 ETH_L2_TUNNEL_FORWARDING_MASK,
			 0);
}

cmdline_parse_inst_t cmd_config_e_tag_forwarding_en_dis = {
	.f = cmd_config_e_tag_forwarding_parsed,
	.data = NULL,
	.help_str = "E-tag ... : E-tag forwarding enable/disable",
	.tokens = {
		(void *)&cmd_config_e_tag_e_tag,
		(void *)&cmd_config_e_tag_set,
		(void *)&cmd_config_e_tag_forwarding,
		(void *)&cmd_config_e_tag_on_off,
		(void *)&cmd_config_e_tag_port,
		(void *)&cmd_config_e_tag_port_id,
		NULL,
	},
};

/* E-tag filter configuration */
static void
cmd_config_e_tag_filter_add_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_config_e_tag_result *res = parsed_result;
	struct rte_eth_l2_tunnel_conf entry;
	int ret = 0;

	if (port_id_is_invalid(res->port_id, ENABLED_WARN))
		return;

	if (res->e_tag_id_val > 0x3fff) {
		printf("e-tag-id must be equal or less than 0x3fff.\n");
		return;
	}

	ret = rte_eth_dev_filter_supported(res->port_id,
					   RTE_ETH_FILTER_L2_TUNNEL);
	if (ret < 0) {
		printf("E-tag filter is not supported on port %u.\n",
		       res->port_id);
		return;
	}

	entry.l2_tunnel_type = RTE_L2_TUNNEL_TYPE_E_TAG;
	entry.tunnel_id = res->e_tag_id_val;
	entry.pool = res->dst_pool_val;

	ret = rte_eth_dev_filter_ctrl(res->port_id,
				      RTE_ETH_FILTER_L2_TUNNEL,
				      RTE_ETH_FILTER_ADD,
				      &entry);
	if (ret < 0)
		printf("E-tag filter programming error: (%s)\n",
		       strerror(-ret));
}

cmdline_parse_inst_t cmd_config_e_tag_filter_add = {
	.f = cmd_config_e_tag_filter_add_parsed,
	.data = NULL,
	.help_str = "E-tag ... : E-tag filter add",
	.tokens = {
		(void *)&cmd_config_e_tag_e_tag,
		(void *)&cmd_config_e_tag_set,
		(void *)&cmd_config_e_tag_filter,
		(void *)&cmd_config_e_tag_add,
		(void *)&cmd_config_e_tag_e_tag_id,
		(void *)&cmd_config_e_tag_e_tag_id_val,
		(void *)&cmd_config_e_tag_dst_pool,
		(void *)&cmd_config_e_tag_dst_pool_val,
		(void *)&cmd_config_e_tag_port,
		(void *)&cmd_config_e_tag_port_id,
		NULL,
	},
};

static void
cmd_config_e_tag_filter_del_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_config_e_tag_result *res = parsed_result;
	struct rte_eth_l2_tunnel_conf entry;
	int ret = 0;

	if (port_id_is_invalid(res->port_id, ENABLED_WARN))
		return;

	if (res->e_tag_id_val > 0x3fff) {
		printf("e-tag-id must be less than 0x3fff.\n");
		return;
	}

	ret = rte_eth_dev_filter_supported(res->port_id,
					   RTE_ETH_FILTER_L2_TUNNEL);
	if (ret < 0) {
		printf("E-tag filter is not supported on port %u.\n",
		       res->port_id);
		return;
	}

	entry.l2_tunnel_type = RTE_L2_TUNNEL_TYPE_E_TAG;
	entry.tunnel_id = res->e_tag_id_val;

	ret = rte_eth_dev_filter_ctrl(res->port_id,
				      RTE_ETH_FILTER_L2_TUNNEL,
				      RTE_ETH_FILTER_DELETE,
				      &entry);
	if (ret < 0)
		printf("E-tag filter programming error: (%s)\n",
		       strerror(-ret));
}

cmdline_parse_inst_t cmd_config_e_tag_filter_del = {
	.f = cmd_config_e_tag_filter_del_parsed,
	.data = NULL,
	.help_str = "E-tag ... : E-tag filter delete",
	.tokens = {
		(void *)&cmd_config_e_tag_e_tag,
		(void *)&cmd_config_e_tag_set,
		(void *)&cmd_config_e_tag_filter,
		(void *)&cmd_config_e_tag_del,
		(void *)&cmd_config_e_tag_e_tag_id,
		(void *)&cmd_config_e_tag_e_tag_id_val,
		(void *)&cmd_config_e_tag_port,
		(void *)&cmd_config_e_tag_port_id,
		NULL,
	},
};

/* vf vlan anti spoof configuration */

/* Common result structure for vf vlan anti spoof */
struct cmd_vf_vlan_anti_spoof_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t vf;
	cmdline_fixed_string_t vlan;
	cmdline_fixed_string_t antispoof;
	portid_t port_id;
	uint32_t vf_id;
	cmdline_fixed_string_t on_off;
};

/* Common CLI fields for vf vlan anti spoof enable disable */
cmdline_parse_token_string_t cmd_vf_vlan_anti_spoof_set =
	TOKEN_STRING_INITIALIZER
		(struct cmd_vf_vlan_anti_spoof_result,
		 set, "set");
cmdline_parse_token_string_t cmd_vf_vlan_anti_spoof_vf =
	TOKEN_STRING_INITIALIZER
		(struct cmd_vf_vlan_anti_spoof_result,
		 vf, "vf");
cmdline_parse_token_string_t cmd_vf_vlan_anti_spoof_vlan =
	TOKEN_STRING_INITIALIZER
		(struct cmd_vf_vlan_anti_spoof_result,
		 vlan, "vlan");
cmdline_parse_token_string_t cmd_vf_vlan_anti_spoof_antispoof =
	TOKEN_STRING_INITIALIZER
		(struct cmd_vf_vlan_anti_spoof_result,
		 antispoof, "antispoof");
cmdline_parse_token_num_t cmd_vf_vlan_anti_spoof_port_id =
	TOKEN_NUM_INITIALIZER
		(struct cmd_vf_vlan_anti_spoof_result,
		 port_id, UINT16);
cmdline_parse_token_num_t cmd_vf_vlan_anti_spoof_vf_id =
	TOKEN_NUM_INITIALIZER
		(struct cmd_vf_vlan_anti_spoof_result,
		 vf_id, UINT32);
cmdline_parse_token_string_t cmd_vf_vlan_anti_spoof_on_off =
	TOKEN_STRING_INITIALIZER
		(struct cmd_vf_vlan_anti_spoof_result,
		 on_off, "on#off");

static void
cmd_set_vf_vlan_anti_spoof_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_vf_vlan_anti_spoof_result *res = parsed_result;
	int ret = -ENOTSUP;

	__rte_unused int is_on = (strcmp(res->on_off, "on") == 0) ? 1 : 0;

	if (port_id_is_invalid(res->port_id, ENABLED_WARN))
		return;

#ifdef RTE_LIBRTE_IXGBE_PMD
	if (ret == -ENOTSUP)
		ret = rte_pmd_ixgbe_set_vf_vlan_anti_spoof(res->port_id,
				res->vf_id, is_on);
#endif
#ifdef RTE_LIBRTE_I40E_PMD
	if (ret == -ENOTSUP)
		ret = rte_pmd_i40e_set_vf_vlan_anti_spoof(res->port_id,
				res->vf_id, is_on);
#endif
#ifdef RTE_LIBRTE_BNXT_PMD
	if (ret == -ENOTSUP)
		ret = rte_pmd_bnxt_set_vf_vlan_anti_spoof(res->port_id,
				res->vf_id, is_on);
#endif

	switch (ret) {
	case 0:
		break;
	case -EINVAL:
		printf("invalid vf_id %d\n", res->vf_id);
		break;
	case -ENODEV:
		printf("invalid port_id %d\n", res->port_id);
		break;
	case -ENOTSUP:
		printf("function not implemented\n");
		break;
	default:
		printf("programming error: (%s)\n", strerror(-ret));
	}
}

cmdline_parse_inst_t cmd_set_vf_vlan_anti_spoof = {
	.f = cmd_set_vf_vlan_anti_spoof_parsed,
	.data = NULL,
	.help_str = "set vf vlan antispoof <port_id> <vf_id> on|off",
	.tokens = {
		(void *)&cmd_vf_vlan_anti_spoof_set,
		(void *)&cmd_vf_vlan_anti_spoof_vf,
		(void *)&cmd_vf_vlan_anti_spoof_vlan,
		(void *)&cmd_vf_vlan_anti_spoof_antispoof,
		(void *)&cmd_vf_vlan_anti_spoof_port_id,
		(void *)&cmd_vf_vlan_anti_spoof_vf_id,
		(void *)&cmd_vf_vlan_anti_spoof_on_off,
		NULL,
	},
};

/* vf mac anti spoof configuration */

/* Common result structure for vf mac anti spoof */
struct cmd_vf_mac_anti_spoof_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t vf;
	cmdline_fixed_string_t mac;
	cmdline_fixed_string_t antispoof;
	portid_t port_id;
	uint32_t vf_id;
	cmdline_fixed_string_t on_off;
};

/* Common CLI fields for vf mac anti spoof enable disable */
cmdline_parse_token_string_t cmd_vf_mac_anti_spoof_set =
	TOKEN_STRING_INITIALIZER
		(struct cmd_vf_mac_anti_spoof_result,
		 set, "set");
cmdline_parse_token_string_t cmd_vf_mac_anti_spoof_vf =
	TOKEN_STRING_INITIALIZER
		(struct cmd_vf_mac_anti_spoof_result,
		 vf, "vf");
cmdline_parse_token_string_t cmd_vf_mac_anti_spoof_mac =
	TOKEN_STRING_INITIALIZER
		(struct cmd_vf_mac_anti_spoof_result,
		 mac, "mac");
cmdline_parse_token_string_t cmd_vf_mac_anti_spoof_antispoof =
	TOKEN_STRING_INITIALIZER
		(struct cmd_vf_mac_anti_spoof_result,
		 antispoof, "antispoof");
cmdline_parse_token_num_t cmd_vf_mac_anti_spoof_port_id =
	TOKEN_NUM_INITIALIZER
		(struct cmd_vf_mac_anti_spoof_result,
		 port_id, UINT16);
cmdline_parse_token_num_t cmd_vf_mac_anti_spoof_vf_id =
	TOKEN_NUM_INITIALIZER
		(struct cmd_vf_mac_anti_spoof_result,
		 vf_id, UINT32);
cmdline_parse_token_string_t cmd_vf_mac_anti_spoof_on_off =
	TOKEN_STRING_INITIALIZER
		(struct cmd_vf_mac_anti_spoof_result,
		 on_off, "on#off");

static void
cmd_set_vf_mac_anti_spoof_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_vf_mac_anti_spoof_result *res = parsed_result;
	int ret = -ENOTSUP;

	__rte_unused int is_on = (strcmp(res->on_off, "on") == 0) ? 1 : 0;

	if (port_id_is_invalid(res->port_id, ENABLED_WARN))
		return;

#ifdef RTE_LIBRTE_IXGBE_PMD
	if (ret == -ENOTSUP)
		ret = rte_pmd_ixgbe_set_vf_mac_anti_spoof(res->port_id,
			res->vf_id, is_on);
#endif
#ifdef RTE_LIBRTE_I40E_PMD
	if (ret == -ENOTSUP)
		ret = rte_pmd_i40e_set_vf_mac_anti_spoof(res->port_id,
			res->vf_id, is_on);
#endif
#ifdef RTE_LIBRTE_BNXT_PMD
	if (ret == -ENOTSUP)
		ret = rte_pmd_bnxt_set_vf_mac_anti_spoof(res->port_id,
			res->vf_id, is_on);
#endif

	switch (ret) {
	case 0:
		break;
	case -EINVAL:
		printf("invalid vf_id %d or is_on %d\n", res->vf_id, is_on);
		break;
	case -ENODEV:
		printf("invalid port_id %d\n", res->port_id);
		break;
	case -ENOTSUP:
		printf("function not implemented\n");
		break;
	default:
		printf("programming error: (%s)\n", strerror(-ret));
	}
}

cmdline_parse_inst_t cmd_set_vf_mac_anti_spoof = {
	.f = cmd_set_vf_mac_anti_spoof_parsed,
	.data = NULL,
	.help_str = "set vf mac antispoof <port_id> <vf_id> on|off",
	.tokens = {
		(void *)&cmd_vf_mac_anti_spoof_set,
		(void *)&cmd_vf_mac_anti_spoof_vf,
		(void *)&cmd_vf_mac_anti_spoof_mac,
		(void *)&cmd_vf_mac_anti_spoof_antispoof,
		(void *)&cmd_vf_mac_anti_spoof_port_id,
		(void *)&cmd_vf_mac_anti_spoof_vf_id,
		(void *)&cmd_vf_mac_anti_spoof_on_off,
		NULL,
	},
};

/* vf vlan strip queue configuration */

/* Common result structure for vf mac anti spoof */
struct cmd_vf_vlan_stripq_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t vf;
	cmdline_fixed_string_t vlan;
	cmdline_fixed_string_t stripq;
	portid_t port_id;
	uint16_t vf_id;
	cmdline_fixed_string_t on_off;
};

/* Common CLI fields for vf vlan strip enable disable */
cmdline_parse_token_string_t cmd_vf_vlan_stripq_set =
	TOKEN_STRING_INITIALIZER
		(struct cmd_vf_vlan_stripq_result,
		 set, "set");
cmdline_parse_token_string_t cmd_vf_vlan_stripq_vf =
	TOKEN_STRING_INITIALIZER
		(struct cmd_vf_vlan_stripq_result,
		 vf, "vf");
cmdline_parse_token_string_t cmd_vf_vlan_stripq_vlan =
	TOKEN_STRING_INITIALIZER
		(struct cmd_vf_vlan_stripq_result,
		 vlan, "vlan");
cmdline_parse_token_string_t cmd_vf_vlan_stripq_stripq =
	TOKEN_STRING_INITIALIZER
		(struct cmd_vf_vlan_stripq_result,
		 stripq, "stripq");
cmdline_parse_token_num_t cmd_vf_vlan_stripq_port_id =
	TOKEN_NUM_INITIALIZER
		(struct cmd_vf_vlan_stripq_result,
		 port_id, UINT16);
cmdline_parse_token_num_t cmd_vf_vlan_stripq_vf_id =
	TOKEN_NUM_INITIALIZER
		(struct cmd_vf_vlan_stripq_result,
		 vf_id, UINT16);
cmdline_parse_token_string_t cmd_vf_vlan_stripq_on_off =
	TOKEN_STRING_INITIALIZER
		(struct cmd_vf_vlan_stripq_result,
		 on_off, "on#off");

static void
cmd_set_vf_vlan_stripq_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_vf_vlan_stripq_result *res = parsed_result;
	int ret = -ENOTSUP;

	__rte_unused int is_on = (strcmp(res->on_off, "on") == 0) ? 1 : 0;

	if (port_id_is_invalid(res->port_id, ENABLED_WARN))
		return;

#ifdef RTE_LIBRTE_IXGBE_PMD
	if (ret == -ENOTSUP)
		ret = rte_pmd_ixgbe_set_vf_vlan_stripq(res->port_id,
			res->vf_id, is_on);
#endif
#ifdef RTE_LIBRTE_I40E_PMD
	if (ret == -ENOTSUP)
		ret = rte_pmd_i40e_set_vf_vlan_stripq(res->port_id,
			res->vf_id, is_on);
#endif
#ifdef RTE_LIBRTE_BNXT_PMD
	if (ret == -ENOTSUP)
		ret = rte_pmd_bnxt_set_vf_vlan_stripq(res->port_id,
			res->vf_id, is_on);
#endif

	switch (ret) {
	case 0:
		break;
	case -EINVAL:
		printf("invalid vf_id %d or is_on %d\n", res->vf_id, is_on);
		break;
	case -ENODEV:
		printf("invalid port_id %d\n", res->port_id);
		break;
	case -ENOTSUP:
		printf("function not implemented\n");
		break;
	default:
		printf("programming error: (%s)\n", strerror(-ret));
	}
}

cmdline_parse_inst_t cmd_set_vf_vlan_stripq = {
	.f = cmd_set_vf_vlan_stripq_parsed,
	.data = NULL,
	.help_str = "set vf vlan stripq <port_id> <vf_id> on|off",
	.tokens = {
		(void *)&cmd_vf_vlan_stripq_set,
		(void *)&cmd_vf_vlan_stripq_vf,
		(void *)&cmd_vf_vlan_stripq_vlan,
		(void *)&cmd_vf_vlan_stripq_stripq,
		(void *)&cmd_vf_vlan_stripq_port_id,
		(void *)&cmd_vf_vlan_stripq_vf_id,
		(void *)&cmd_vf_vlan_stripq_on_off,
		NULL,
	},
};

/* vf vlan insert configuration */

/* Common result structure for vf vlan insert */
struct cmd_vf_vlan_insert_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t vf;
	cmdline_fixed_string_t vlan;
	cmdline_fixed_string_t insert;
	portid_t port_id;
	uint16_t vf_id;
	uint16_t vlan_id;
};

/* Common CLI fields for vf vlan insert enable disable */
cmdline_parse_token_string_t cmd_vf_vlan_insert_set =
	TOKEN_STRING_INITIALIZER
		(struct cmd_vf_vlan_insert_result,
		 set, "set");
cmdline_parse_token_string_t cmd_vf_vlan_insert_vf =
	TOKEN_STRING_INITIALIZER
		(struct cmd_vf_vlan_insert_result,
		 vf, "vf");
cmdline_parse_token_string_t cmd_vf_vlan_insert_vlan =
	TOKEN_STRING_INITIALIZER
		(struct cmd_vf_vlan_insert_result,
		 vlan, "vlan");
cmdline_parse_token_string_t cmd_vf_vlan_insert_insert =
	TOKEN_STRING_INITIALIZER
		(struct cmd_vf_vlan_insert_result,
		 insert, "insert");
cmdline_parse_token_num_t cmd_vf_vlan_insert_port_id =
	TOKEN_NUM_INITIALIZER
		(struct cmd_vf_vlan_insert_result,
		 port_id, UINT16);
cmdline_parse_token_num_t cmd_vf_vlan_insert_vf_id =
	TOKEN_NUM_INITIALIZER
		(struct cmd_vf_vlan_insert_result,
		 vf_id, UINT16);
cmdline_parse_token_num_t cmd_vf_vlan_insert_vlan_id =
	TOKEN_NUM_INITIALIZER
		(struct cmd_vf_vlan_insert_result,
		 vlan_id, UINT16);

static void
cmd_set_vf_vlan_insert_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_vf_vlan_insert_result *res = parsed_result;
	int ret = -ENOTSUP;

	if (port_id_is_invalid(res->port_id, ENABLED_WARN))
		return;

#ifdef RTE_LIBRTE_IXGBE_PMD
	if (ret == -ENOTSUP)
		ret = rte_pmd_ixgbe_set_vf_vlan_insert(res->port_id, res->vf_id,
			res->vlan_id);
#endif
#ifdef RTE_LIBRTE_I40E_PMD
	if (ret == -ENOTSUP)
		ret = rte_pmd_i40e_set_vf_vlan_insert(res->port_id, res->vf_id,
			res->vlan_id);
#endif
#ifdef RTE_LIBRTE_BNXT_PMD
	if (ret == -ENOTSUP)
		ret = rte_pmd_bnxt_set_vf_vlan_insert(res->port_id, res->vf_id,
			res->vlan_id);
#endif

	switch (ret) {
	case 0:
		break;
	case -EINVAL:
		printf("invalid vf_id %d or vlan_id %d\n", res->vf_id, res->vlan_id);
		break;
	case -ENODEV:
		printf("invalid port_id %d\n", res->port_id);
		break;
	case -ENOTSUP:
		printf("function not implemented\n");
		break;
	default:
		printf("programming error: (%s)\n", strerror(-ret));
	}
}

cmdline_parse_inst_t cmd_set_vf_vlan_insert = {
	.f = cmd_set_vf_vlan_insert_parsed,
	.data = NULL,
	.help_str = "set vf vlan insert <port_id> <vf_id> <vlan_id>",
	.tokens = {
		(void *)&cmd_vf_vlan_insert_set,
		(void *)&cmd_vf_vlan_insert_vf,
		(void *)&cmd_vf_vlan_insert_vlan,
		(void *)&cmd_vf_vlan_insert_insert,
		(void *)&cmd_vf_vlan_insert_port_id,
		(void *)&cmd_vf_vlan_insert_vf_id,
		(void *)&cmd_vf_vlan_insert_vlan_id,
		NULL,
	},
};

/* tx loopback configuration */

/* Common result structure for tx loopback */
struct cmd_tx_loopback_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t tx;
	cmdline_fixed_string_t loopback;
	portid_t port_id;
	cmdline_fixed_string_t on_off;
};

/* Common CLI fields for tx loopback enable disable */
cmdline_parse_token_string_t cmd_tx_loopback_set =
	TOKEN_STRING_INITIALIZER
		(struct cmd_tx_loopback_result,
		 set, "set");
cmdline_parse_token_string_t cmd_tx_loopback_tx =
	TOKEN_STRING_INITIALIZER
		(struct cmd_tx_loopback_result,
		 tx, "tx");
cmdline_parse_token_string_t cmd_tx_loopback_loopback =
	TOKEN_STRING_INITIALIZER
		(struct cmd_tx_loopback_result,
		 loopback, "loopback");
cmdline_parse_token_num_t cmd_tx_loopback_port_id =
	TOKEN_NUM_INITIALIZER
		(struct cmd_tx_loopback_result,
		 port_id, UINT16);
cmdline_parse_token_string_t cmd_tx_loopback_on_off =
	TOKEN_STRING_INITIALIZER
		(struct cmd_tx_loopback_result,
		 on_off, "on#off");

static void
cmd_set_tx_loopback_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_tx_loopback_result *res = parsed_result;
	int ret = -ENOTSUP;

	__rte_unused int is_on = (strcmp(res->on_off, "on") == 0) ? 1 : 0;

	if (port_id_is_invalid(res->port_id, ENABLED_WARN))
		return;

#ifdef RTE_LIBRTE_IXGBE_PMD
	if (ret == -ENOTSUP)
		ret = rte_pmd_ixgbe_set_tx_loopback(res->port_id, is_on);
#endif
#ifdef RTE_LIBRTE_I40E_PMD
	if (ret == -ENOTSUP)
		ret = rte_pmd_i40e_set_tx_loopback(res->port_id, is_on);
#endif
#ifdef RTE_LIBRTE_BNXT_PMD
	if (ret == -ENOTSUP)
		ret = rte_pmd_bnxt_set_tx_loopback(res->port_id, is_on);
#endif
#if defined RTE_LIBRTE_DPAA_BUS && defined RTE_LIBRTE_DPAA_PMD
	if (ret == -ENOTSUP)
		ret = rte_pmd_dpaa_set_tx_loopback(res->port_id, is_on);
#endif

	switch (ret) {
	case 0:
		break;
	case -EINVAL:
		printf("invalid is_on %d\n", is_on);
		break;
	case -ENODEV:
		printf("invalid port_id %d\n", res->port_id);
		break;
	case -ENOTSUP:
		printf("function not implemented\n");
		break;
	default:
		printf("programming error: (%s)\n", strerror(-ret));
	}
}

cmdline_parse_inst_t cmd_set_tx_loopback = {
	.f = cmd_set_tx_loopback_parsed,
	.data = NULL,
	.help_str = "set tx loopback <port_id> on|off",
	.tokens = {
		(void *)&cmd_tx_loopback_set,
		(void *)&cmd_tx_loopback_tx,
		(void *)&cmd_tx_loopback_loopback,
		(void *)&cmd_tx_loopback_port_id,
		(void *)&cmd_tx_loopback_on_off,
		NULL,
	},
};

/* all queues drop enable configuration */

/* Common result structure for all queues drop enable */
struct cmd_all_queues_drop_en_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t all;
	cmdline_fixed_string_t queues;
	cmdline_fixed_string_t drop;
	portid_t port_id;
	cmdline_fixed_string_t on_off;
};

/* Common CLI fields for tx loopback enable disable */
cmdline_parse_token_string_t cmd_all_queues_drop_en_set =
	TOKEN_STRING_INITIALIZER
		(struct cmd_all_queues_drop_en_result,
		 set, "set");
cmdline_parse_token_string_t cmd_all_queues_drop_en_all =
	TOKEN_STRING_INITIALIZER
		(struct cmd_all_queues_drop_en_result,
		 all, "all");
cmdline_parse_token_string_t cmd_all_queues_drop_en_queues =
	TOKEN_STRING_INITIALIZER
		(struct cmd_all_queues_drop_en_result,
		 queues, "queues");
cmdline_parse_token_string_t cmd_all_queues_drop_en_drop =
	TOKEN_STRING_INITIALIZER
		(struct cmd_all_queues_drop_en_result,
		 drop, "drop");
cmdline_parse_token_num_t cmd_all_queues_drop_en_port_id =
	TOKEN_NUM_INITIALIZER
		(struct cmd_all_queues_drop_en_result,
		 port_id, UINT16);
cmdline_parse_token_string_t cmd_all_queues_drop_en_on_off =
	TOKEN_STRING_INITIALIZER
		(struct cmd_all_queues_drop_en_result,
		 on_off, "on#off");

static void
cmd_set_all_queues_drop_en_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_all_queues_drop_en_result *res = parsed_result;
	int ret = -ENOTSUP;
	int is_on = (strcmp(res->on_off, "on") == 0) ? 1 : 0;

	if (port_id_is_invalid(res->port_id, ENABLED_WARN))
		return;

#ifdef RTE_LIBRTE_IXGBE_PMD
	if (ret == -ENOTSUP)
		ret = rte_pmd_ixgbe_set_all_queues_drop_en(res->port_id, is_on);
#endif
#ifdef RTE_LIBRTE_BNXT_PMD
	if (ret == -ENOTSUP)
		ret = rte_pmd_bnxt_set_all_queues_drop_en(res->port_id, is_on);
#endif
	switch (ret) {
	case 0:
		break;
	case -EINVAL:
		printf("invalid is_on %d\n", is_on);
		break;
	case -ENODEV:
		printf("invalid port_id %d\n", res->port_id);
		break;
	case -ENOTSUP:
		printf("function not implemented\n");
		break;
	default:
		printf("programming error: (%s)\n", strerror(-ret));
	}
}

cmdline_parse_inst_t cmd_set_all_queues_drop_en = {
	.f = cmd_set_all_queues_drop_en_parsed,
	.data = NULL,
	.help_str = "set all queues drop <port_id> on|off",
	.tokens = {
		(void *)&cmd_all_queues_drop_en_set,
		(void *)&cmd_all_queues_drop_en_all,
		(void *)&cmd_all_queues_drop_en_queues,
		(void *)&cmd_all_queues_drop_en_drop,
		(void *)&cmd_all_queues_drop_en_port_id,
		(void *)&cmd_all_queues_drop_en_on_off,
		NULL,
	},
};

/* vf split drop enable configuration */

/* Common result structure for vf split drop enable */
struct cmd_vf_split_drop_en_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t vf;
	cmdline_fixed_string_t split;
	cmdline_fixed_string_t drop;
	portid_t port_id;
	uint16_t vf_id;
	cmdline_fixed_string_t on_off;
};

/* Common CLI fields for vf split drop enable disable */
cmdline_parse_token_string_t cmd_vf_split_drop_en_set =
	TOKEN_STRING_INITIALIZER
		(struct cmd_vf_split_drop_en_result,
		 set, "set");
cmdline_parse_token_string_t cmd_vf_split_drop_en_vf =
	TOKEN_STRING_INITIALIZER
		(struct cmd_vf_split_drop_en_result,
		 vf, "vf");
cmdline_parse_token_string_t cmd_vf_split_drop_en_split =
	TOKEN_STRING_INITIALIZER
		(struct cmd_vf_split_drop_en_result,
		 split, "split");
cmdline_parse_token_string_t cmd_vf_split_drop_en_drop =
	TOKEN_STRING_INITIALIZER
		(struct cmd_vf_split_drop_en_result,
		 drop, "drop");
cmdline_parse_token_num_t cmd_vf_split_drop_en_port_id =
	TOKEN_NUM_INITIALIZER
		(struct cmd_vf_split_drop_en_result,
		 port_id, UINT16);
cmdline_parse_token_num_t cmd_vf_split_drop_en_vf_id =
	TOKEN_NUM_INITIALIZER
		(struct cmd_vf_split_drop_en_result,
		 vf_id, UINT16);
cmdline_parse_token_string_t cmd_vf_split_drop_en_on_off =
	TOKEN_STRING_INITIALIZER
		(struct cmd_vf_split_drop_en_result,
		 on_off, "on#off");

static void
cmd_set_vf_split_drop_en_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_vf_split_drop_en_result *res = parsed_result;
	int ret = -ENOTSUP;
	int is_on = (strcmp(res->on_off, "on") == 0) ? 1 : 0;

	if (port_id_is_invalid(res->port_id, ENABLED_WARN))
		return;

#ifdef RTE_LIBRTE_IXGBE_PMD
	ret = rte_pmd_ixgbe_set_vf_split_drop_en(res->port_id, res->vf_id,
			is_on);
#endif
	switch (ret) {
	case 0:
		break;
	case -EINVAL:
		printf("invalid vf_id %d or is_on %d\n", res->vf_id, is_on);
		break;
	case -ENODEV:
		printf("invalid port_id %d\n", res->port_id);
		break;
	case -ENOTSUP:
		printf("not supported on port %d\n", res->port_id);
		break;
	default:
		printf("programming error: (%s)\n", strerror(-ret));
	}
}

cmdline_parse_inst_t cmd_set_vf_split_drop_en = {
	.f = cmd_set_vf_split_drop_en_parsed,
	.data = NULL,
	.help_str = "set vf split drop <port_id> <vf_id> on|off",
	.tokens = {
		(void *)&cmd_vf_split_drop_en_set,
		(void *)&cmd_vf_split_drop_en_vf,
		(void *)&cmd_vf_split_drop_en_split,
		(void *)&cmd_vf_split_drop_en_drop,
		(void *)&cmd_vf_split_drop_en_port_id,
		(void *)&cmd_vf_split_drop_en_vf_id,
		(void *)&cmd_vf_split_drop_en_on_off,
		NULL,
	},
};

/* vf mac address configuration */

/* Common result structure for vf mac address */
struct cmd_set_vf_mac_addr_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t vf;
	cmdline_fixed_string_t mac;
	cmdline_fixed_string_t addr;
	portid_t port_id;
	uint16_t vf_id;
	struct ether_addr mac_addr;

};

/* Common CLI fields for vf split drop enable disable */
cmdline_parse_token_string_t cmd_set_vf_mac_addr_set =
	TOKEN_STRING_INITIALIZER
		(struct cmd_set_vf_mac_addr_result,
		 set, "set");
cmdline_parse_token_string_t cmd_set_vf_mac_addr_vf =
	TOKEN_STRING_INITIALIZER
		(struct cmd_set_vf_mac_addr_result,
		 vf, "vf");
cmdline_parse_token_string_t cmd_set_vf_mac_addr_mac =
	TOKEN_STRING_INITIALIZER
		(struct cmd_set_vf_mac_addr_result,
		 mac, "mac");
cmdline_parse_token_string_t cmd_set_vf_mac_addr_addr =
	TOKEN_STRING_INITIALIZER
		(struct cmd_set_vf_mac_addr_result,
		 addr, "addr");
cmdline_parse_token_num_t cmd_set_vf_mac_addr_port_id =
	TOKEN_NUM_INITIALIZER
		(struct cmd_set_vf_mac_addr_result,
		 port_id, UINT16);
cmdline_parse_token_num_t cmd_set_vf_mac_addr_vf_id =
	TOKEN_NUM_INITIALIZER
		(struct cmd_set_vf_mac_addr_result,
		 vf_id, UINT16);
cmdline_parse_token_etheraddr_t cmd_set_vf_mac_addr_mac_addr =
	TOKEN_ETHERADDR_INITIALIZER(struct cmd_set_vf_mac_addr_result,
		 mac_addr);

static void
cmd_set_vf_mac_addr_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_set_vf_mac_addr_result *res = parsed_result;
	int ret = -ENOTSUP;

	if (port_id_is_invalid(res->port_id, ENABLED_WARN))
		return;

#ifdef RTE_LIBRTE_IXGBE_PMD
	if (ret == -ENOTSUP)
		ret = rte_pmd_ixgbe_set_vf_mac_addr(res->port_id, res->vf_id,
				&res->mac_addr);
#endif
#ifdef RTE_LIBRTE_I40E_PMD
	if (ret == -ENOTSUP)
		ret = rte_pmd_i40e_set_vf_mac_addr(res->port_id, res->vf_id,
				&res->mac_addr);
#endif
#ifdef RTE_LIBRTE_BNXT_PMD
	if (ret == -ENOTSUP)
		ret = rte_pmd_bnxt_set_vf_mac_addr(res->port_id, res->vf_id,
				&res->mac_addr);
#endif

	switch (ret) {
	case 0:
		break;
	case -EINVAL:
		printf("invalid vf_id %d or mac_addr\n", res->vf_id);
		break;
	case -ENODEV:
		printf("invalid port_id %d\n", res->port_id);
		break;
	case -ENOTSUP:
		printf("function not implemented\n");
		break;
	default:
		printf("programming error: (%s)\n", strerror(-ret));
	}
}

cmdline_parse_inst_t cmd_set_vf_mac_addr = {
	.f = cmd_set_vf_mac_addr_parsed,
	.data = NULL,
	.help_str = "set vf mac addr <port_id> <vf_id> <mac_addr>",
	.tokens = {
		(void *)&cmd_set_vf_mac_addr_set,
		(void *)&cmd_set_vf_mac_addr_vf,
		(void *)&cmd_set_vf_mac_addr_mac,
		(void *)&cmd_set_vf_mac_addr_addr,
		(void *)&cmd_set_vf_mac_addr_port_id,
		(void *)&cmd_set_vf_mac_addr_vf_id,
		(void *)&cmd_set_vf_mac_addr_mac_addr,
		NULL,
	},
};

/* MACsec configuration */

/* Common result structure for MACsec offload enable */
struct cmd_macsec_offload_on_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t macsec;
	cmdline_fixed_string_t offload;
	portid_t port_id;
	cmdline_fixed_string_t on;
	cmdline_fixed_string_t encrypt;
	cmdline_fixed_string_t en_on_off;
	cmdline_fixed_string_t replay_protect;
	cmdline_fixed_string_t rp_on_off;
};

/* Common CLI fields for MACsec offload disable */
cmdline_parse_token_string_t cmd_macsec_offload_on_set =
	TOKEN_STRING_INITIALIZER
		(struct cmd_macsec_offload_on_result,
		 set, "set");
cmdline_parse_token_string_t cmd_macsec_offload_on_macsec =
	TOKEN_STRING_INITIALIZER
		(struct cmd_macsec_offload_on_result,
		 macsec, "macsec");
cmdline_parse_token_string_t cmd_macsec_offload_on_offload =
	TOKEN_STRING_INITIALIZER
		(struct cmd_macsec_offload_on_result,
		 offload, "offload");
cmdline_parse_token_num_t cmd_macsec_offload_on_port_id =
	TOKEN_NUM_INITIALIZER
		(struct cmd_macsec_offload_on_result,
		 port_id, UINT16);
cmdline_parse_token_string_t cmd_macsec_offload_on_on =
	TOKEN_STRING_INITIALIZER
		(struct cmd_macsec_offload_on_result,
		 on, "on");
cmdline_parse_token_string_t cmd_macsec_offload_on_encrypt =
	TOKEN_STRING_INITIALIZER
		(struct cmd_macsec_offload_on_result,
		 encrypt, "encrypt");
cmdline_parse_token_string_t cmd_macsec_offload_on_en_on_off =
	TOKEN_STRING_INITIALIZER
		(struct cmd_macsec_offload_on_result,
		 en_on_off, "on#off");
cmdline_parse_token_string_t cmd_macsec_offload_on_replay_protect =
	TOKEN_STRING_INITIALIZER
		(struct cmd_macsec_offload_on_result,
		 replay_protect, "replay-protect");
cmdline_parse_token_string_t cmd_macsec_offload_on_rp_on_off =
	TOKEN_STRING_INITIALIZER
		(struct cmd_macsec_offload_on_result,
		 rp_on_off, "on#off");

static void
cmd_set_macsec_offload_on_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_macsec_offload_on_result *res = parsed_result;
	int ret = -ENOTSUP;
	portid_t port_id = res->port_id;
	int en = (strcmp(res->en_on_off, "on") == 0) ? 1 : 0;
	int rp = (strcmp(res->rp_on_off, "on") == 0) ? 1 : 0;
	struct rte_eth_dev_info dev_info;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;
	if (!port_is_stopped(port_id)) {
		printf("Please stop port %d first\n", port_id);
		return;
	}

	rte_eth_dev_info_get(port_id, &dev_info);
	if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MACSEC_INSERT) {
#ifdef RTE_LIBRTE_IXGBE_PMD
		ret = rte_pmd_ixgbe_macsec_enable(port_id, en, rp);
#endif
	}
	RTE_SET_USED(en);
	RTE_SET_USED(rp);

	switch (ret) {
	case 0:
		ports[port_id].dev_conf.txmode.offloads |=
						DEV_TX_OFFLOAD_MACSEC_INSERT;
		cmd_reconfig_device_queue(port_id, 1, 1);
		break;
	case -ENODEV:
		printf("invalid port_id %d\n", port_id);
		break;
	case -ENOTSUP:
		printf("not supported on port %d\n", port_id);
		break;
	default:
		printf("programming error: (%s)\n", strerror(-ret));
	}
}

cmdline_parse_inst_t cmd_set_macsec_offload_on = {
	.f = cmd_set_macsec_offload_on_parsed,
	.data = NULL,
	.help_str = "set macsec offload <port_id> on "
		"encrypt on|off replay-protect on|off",
	.tokens = {
		(void *)&cmd_macsec_offload_on_set,
		(void *)&cmd_macsec_offload_on_macsec,
		(void *)&cmd_macsec_offload_on_offload,
		(void *)&cmd_macsec_offload_on_port_id,
		(void *)&cmd_macsec_offload_on_on,
		(void *)&cmd_macsec_offload_on_encrypt,
		(void *)&cmd_macsec_offload_on_en_on_off,
		(void *)&cmd_macsec_offload_on_replay_protect,
		(void *)&cmd_macsec_offload_on_rp_on_off,
		NULL,
	},
};

/* Common result structure for MACsec offload disable */
struct cmd_macsec_offload_off_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t macsec;
	cmdline_fixed_string_t offload;
	portid_t port_id;
	cmdline_fixed_string_t off;
};

/* Common CLI fields for MACsec offload disable */
cmdline_parse_token_string_t cmd_macsec_offload_off_set =
	TOKEN_STRING_INITIALIZER
		(struct cmd_macsec_offload_off_result,
		 set, "set");
cmdline_parse_token_string_t cmd_macsec_offload_off_macsec =
	TOKEN_STRING_INITIALIZER
		(struct cmd_macsec_offload_off_result,
		 macsec, "macsec");
cmdline_parse_token_string_t cmd_macsec_offload_off_offload =
	TOKEN_STRING_INITIALIZER
		(struct cmd_macsec_offload_off_result,
		 offload, "offload");
cmdline_parse_token_num_t cmd_macsec_offload_off_port_id =
	TOKEN_NUM_INITIALIZER
		(struct cmd_macsec_offload_off_result,
		 port_id, UINT16);
cmdline_parse_token_string_t cmd_macsec_offload_off_off =
	TOKEN_STRING_INITIALIZER
		(struct cmd_macsec_offload_off_result,
		 off, "off");

static void
cmd_set_macsec_offload_off_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_macsec_offload_off_result *res = parsed_result;
	int ret = -ENOTSUP;
	struct rte_eth_dev_info dev_info;
	portid_t port_id = res->port_id;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;
	if (!port_is_stopped(port_id)) {
		printf("Please stop port %d first\n", port_id);
		return;
	}

	rte_eth_dev_info_get(port_id, &dev_info);
	if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MACSEC_INSERT) {
#ifdef RTE_LIBRTE_IXGBE_PMD
		ret = rte_pmd_ixgbe_macsec_disable(port_id);
#endif
	}
	switch (ret) {
	case 0:
		ports[port_id].dev_conf.txmode.offloads &=
						~DEV_TX_OFFLOAD_MACSEC_INSERT;
		cmd_reconfig_device_queue(port_id, 1, 1);
		break;
	case -ENODEV:
		printf("invalid port_id %d\n", port_id);
		break;
	case -ENOTSUP:
		printf("not supported on port %d\n", port_id);
		break;
	default:
		printf("programming error: (%s)\n", strerror(-ret));
	}
}

cmdline_parse_inst_t cmd_set_macsec_offload_off = {
	.f = cmd_set_macsec_offload_off_parsed,
	.data = NULL,
	.help_str = "set macsec offload <port_id> off",
	.tokens = {
		(void *)&cmd_macsec_offload_off_set,
		(void *)&cmd_macsec_offload_off_macsec,
		(void *)&cmd_macsec_offload_off_offload,
		(void *)&cmd_macsec_offload_off_port_id,
		(void *)&cmd_macsec_offload_off_off,
		NULL,
	},
};

/* Common result structure for MACsec secure connection configure */
struct cmd_macsec_sc_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t macsec;
	cmdline_fixed_string_t sc;
	cmdline_fixed_string_t tx_rx;
	portid_t port_id;
	struct ether_addr mac;
	uint16_t pi;
};

/* Common CLI fields for MACsec secure connection configure */
cmdline_parse_token_string_t cmd_macsec_sc_set =
	TOKEN_STRING_INITIALIZER
		(struct cmd_macsec_sc_result,
		 set, "set");
cmdline_parse_token_string_t cmd_macsec_sc_macsec =
	TOKEN_STRING_INITIALIZER
		(struct cmd_macsec_sc_result,
		 macsec, "macsec");
cmdline_parse_token_string_t cmd_macsec_sc_sc =
	TOKEN_STRING_INITIALIZER
		(struct cmd_macsec_sc_result,
		 sc, "sc");
cmdline_parse_token_string_t cmd_macsec_sc_tx_rx =
	TOKEN_STRING_INITIALIZER
		(struct cmd_macsec_sc_result,
		 tx_rx, "tx#rx");
cmdline_parse_token_num_t cmd_macsec_sc_port_id =
	TOKEN_NUM_INITIALIZER
		(struct cmd_macsec_sc_result,
		 port_id, UINT16);
cmdline_parse_token_etheraddr_t cmd_macsec_sc_mac =
	TOKEN_ETHERADDR_INITIALIZER
		(struct cmd_macsec_sc_result,
		 mac);
cmdline_parse_token_num_t cmd_macsec_sc_pi =
	TOKEN_NUM_INITIALIZER
		(struct cmd_macsec_sc_result,
		 pi, UINT16);

static void
cmd_set_macsec_sc_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_macsec_sc_result *res = parsed_result;
	int ret = -ENOTSUP;
	int is_tx = (strcmp(res->tx_rx, "tx") == 0) ? 1 : 0;

#ifdef RTE_LIBRTE_IXGBE_PMD
	ret = is_tx ?
		rte_pmd_ixgbe_macsec_config_txsc(res->port_id,
				res->mac.addr_bytes) :
		rte_pmd_ixgbe_macsec_config_rxsc(res->port_id,
				res->mac.addr_bytes, res->pi);
#endif
	RTE_SET_USED(is_tx);

	switch (ret) {
	case 0:
		break;
	case -ENODEV:
		printf("invalid port_id %d\n", res->port_id);
		break;
	case -ENOTSUP:
		printf("not supported on port %d\n", res->port_id);
		break;
	default:
		printf("programming error: (%s)\n", strerror(-ret));
	}
}

cmdline_parse_inst_t cmd_set_macsec_sc = {
	.f = cmd_set_macsec_sc_parsed,
	.data = NULL,
	.help_str = "set macsec sc tx|rx <port_id> <mac> <pi>",
	.tokens = {
		(void *)&cmd_macsec_sc_set,
		(void *)&cmd_macsec_sc_macsec,
		(void *)&cmd_macsec_sc_sc,
		(void *)&cmd_macsec_sc_tx_rx,
		(void *)&cmd_macsec_sc_port_id,
		(void *)&cmd_macsec_sc_mac,
		(void *)&cmd_macsec_sc_pi,
		NULL,
	},
};

/* Common result structure for MACsec secure connection configure */
struct cmd_macsec_sa_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t macsec;
	cmdline_fixed_string_t sa;
	cmdline_fixed_string_t tx_rx;
	portid_t port_id;
	uint8_t idx;
	uint8_t an;
	uint32_t pn;
	cmdline_fixed_string_t key;
};

/* Common CLI fields for MACsec secure connection configure */
cmdline_parse_token_string_t cmd_macsec_sa_set =
	TOKEN_STRING_INITIALIZER
		(struct cmd_macsec_sa_result,
		 set, "set");
cmdline_parse_token_string_t cmd_macsec_sa_macsec =
	TOKEN_STRING_INITIALIZER
		(struct cmd_macsec_sa_result,
		 macsec, "macsec");
cmdline_parse_token_string_t cmd_macsec_sa_sa =
	TOKEN_STRING_INITIALIZER
		(struct cmd_macsec_sa_result,
		 sa, "sa");
cmdline_parse_token_string_t cmd_macsec_sa_tx_rx =
	TOKEN_STRING_INITIALIZER
		(struct cmd_macsec_sa_result,
		 tx_rx, "tx#rx");
cmdline_parse_token_num_t cmd_macsec_sa_port_id =
	TOKEN_NUM_INITIALIZER
		(struct cmd_macsec_sa_result,
		 port_id, UINT16);
cmdline_parse_token_num_t cmd_macsec_sa_idx =
	TOKEN_NUM_INITIALIZER
		(struct cmd_macsec_sa_result,
		 idx, UINT8);
cmdline_parse_token_num_t cmd_macsec_sa_an =
	TOKEN_NUM_INITIALIZER
		(struct cmd_macsec_sa_result,
		 an, UINT8);
cmdline_parse_token_num_t cmd_macsec_sa_pn =
	TOKEN_NUM_INITIALIZER
		(struct cmd_macsec_sa_result,
		 pn, UINT32);
cmdline_parse_token_string_t cmd_macsec_sa_key =
	TOKEN_STRING_INITIALIZER
		(struct cmd_macsec_sa_result,
		 key, NULL);

static void
cmd_set_macsec_sa_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_macsec_sa_result *res = parsed_result;
	int ret = -ENOTSUP;
	int is_tx = (strcmp(res->tx_rx, "tx") == 0) ? 1 : 0;
	uint8_t key[16] = { 0 };
	uint8_t xdgt0;
	uint8_t xdgt1;
	int key_len;
	int i;

	key_len = strlen(res->key) / 2;
	if (key_len > 16)
		key_len = 16;

	for (i = 0; i < key_len; i++) {
		xdgt0 = parse_and_check_key_hexa_digit(res->key, (i * 2));
		if (xdgt0 == 0xFF)
			return;
		xdgt1 = parse_and_check_key_hexa_digit(res->key, (i * 2) + 1);
		if (xdgt1 == 0xFF)
			return;
		key[i] = (uint8_t) ((xdgt0 * 16) + xdgt1);
	}

#ifdef RTE_LIBRTE_IXGBE_PMD
	ret = is_tx ?
		rte_pmd_ixgbe_macsec_select_txsa(res->port_id,
			res->idx, res->an, res->pn, key) :
		rte_pmd_ixgbe_macsec_select_rxsa(res->port_id,
			res->idx, res->an, res->pn, key);
#endif
	RTE_SET_USED(is_tx);
	RTE_SET_USED(key);

	switch (ret) {
	case 0:
		break;
	case -EINVAL:
		printf("invalid idx %d or an %d\n", res->idx, res->an);
		break;
	case -ENODEV:
		printf("invalid port_id %d\n", res->port_id);
		break;
	case -ENOTSUP:
		printf("not supported on port %d\n", res->port_id);
		break;
	default:
		printf("programming error: (%s)\n", strerror(-ret));
	}
}

cmdline_parse_inst_t cmd_set_macsec_sa = {
	.f = cmd_set_macsec_sa_parsed,
	.data = NULL,
	.help_str = "set macsec sa tx|rx <port_id> <idx> <an> <pn> <key>",
	.tokens = {
		(void *)&cmd_macsec_sa_set,
		(void *)&cmd_macsec_sa_macsec,
		(void *)&cmd_macsec_sa_sa,
		(void *)&cmd_macsec_sa_tx_rx,
		(void *)&cmd_macsec_sa_port_id,
		(void *)&cmd_macsec_sa_idx,
		(void *)&cmd_macsec_sa_an,
		(void *)&cmd_macsec_sa_pn,
		(void *)&cmd_macsec_sa_key,
		NULL,
	},
};

/* VF unicast promiscuous mode configuration */

/* Common result structure for VF unicast promiscuous mode */
struct cmd_vf_promisc_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t vf;
	cmdline_fixed_string_t promisc;
	portid_t port_id;
	uint32_t vf_id;
	cmdline_fixed_string_t on_off;
};

/* Common CLI fields for VF unicast promiscuous mode enable disable */
cmdline_parse_token_string_t cmd_vf_promisc_set =
	TOKEN_STRING_INITIALIZER
		(struct cmd_vf_promisc_result,
		 set, "set");
cmdline_parse_token_string_t cmd_vf_promisc_vf =
	TOKEN_STRING_INITIALIZER
		(struct cmd_vf_promisc_result,
		 vf, "vf");
cmdline_parse_token_string_t cmd_vf_promisc_promisc =
	TOKEN_STRING_INITIALIZER
		(struct cmd_vf_promisc_result,
		 promisc, "promisc");
cmdline_parse_token_num_t cmd_vf_promisc_port_id =
	TOKEN_NUM_INITIALIZER
		(struct cmd_vf_promisc_result,
		 port_id, UINT16);
cmdline_parse_token_num_t cmd_vf_promisc_vf_id =
	TOKEN_NUM_INITIALIZER
		(struct cmd_vf_promisc_result,
		 vf_id, UINT32);
cmdline_parse_token_string_t cmd_vf_promisc_on_off =
	TOKEN_STRING_INITIALIZER
		(struct cmd_vf_promisc_result,
		 on_off, "on#off");

static void
cmd_set_vf_promisc_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_vf_promisc_result *res = parsed_result;
	int ret = -ENOTSUP;

	__rte_unused int is_on = (strcmp(res->on_off, "on") == 0) ? 1 : 0;

	if (port_id_is_invalid(res->port_id, ENABLED_WARN))
		return;

#ifdef RTE_LIBRTE_I40E_PMD
	ret = rte_pmd_i40e_set_vf_unicast_promisc(res->port_id,
						  res->vf_id, is_on);
#endif

	switch (ret) {
	case 0:
		break;
	case -EINVAL:
		printf("invalid vf_id %d\n", res->vf_id);
		break;
	case -ENODEV:
		printf("invalid port_id %d\n", res->port_id);
		break;
	case -ENOTSUP:
		printf("function not implemented\n");
		break;
	default:
		printf("programming error: (%s)\n", strerror(-ret));
	}
}

cmdline_parse_inst_t cmd_set_vf_promisc = {
	.f = cmd_set_vf_promisc_parsed,
	.data = NULL,
	.help_str = "set vf promisc <port_id> <vf_id> on|off: "
		"Set unicast promiscuous mode for a VF from the PF",
	.tokens = {
		(void *)&cmd_vf_promisc_set,
		(void *)&cmd_vf_promisc_vf,
		(void *)&cmd_vf_promisc_promisc,
		(void *)&cmd_vf_promisc_port_id,
		(void *)&cmd_vf_promisc_vf_id,
		(void *)&cmd_vf_promisc_on_off,
		NULL,
	},
};

/* VF multicast promiscuous mode configuration */

/* Common result structure for VF multicast promiscuous mode */
struct cmd_vf_allmulti_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t vf;
	cmdline_fixed_string_t allmulti;
	portid_t port_id;
	uint32_t vf_id;
	cmdline_fixed_string_t on_off;
};

/* Common CLI fields for VF multicast promiscuous mode enable disable */
cmdline_parse_token_string_t cmd_vf_allmulti_set =
	TOKEN_STRING_INITIALIZER
		(struct cmd_vf_allmulti_result,
		 set, "set");
cmdline_parse_token_string_t cmd_vf_allmulti_vf =
	TOKEN_STRING_INITIALIZER
		(struct cmd_vf_allmulti_result,
		 vf, "vf");
cmdline_parse_token_string_t cmd_vf_allmulti_allmulti =
	TOKEN_STRING_INITIALIZER
		(struct cmd_vf_allmulti_result,
		 allmulti, "allmulti");
cmdline_parse_token_num_t cmd_vf_allmulti_port_id =
	TOKEN_NUM_INITIALIZER
		(struct cmd_vf_allmulti_result,
		 port_id, UINT16);
cmdline_parse_token_num_t cmd_vf_allmulti_vf_id =
	TOKEN_NUM_INITIALIZER
		(struct cmd_vf_allmulti_result,
		 vf_id, UINT32);
cmdline_parse_token_string_t cmd_vf_allmulti_on_off =
	TOKEN_STRING_INITIALIZER
		(struct cmd_vf_allmulti_result,
		 on_off, "on#off");

static void
cmd_set_vf_allmulti_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_vf_allmulti_result *res = parsed_result;
	int ret = -ENOTSUP;

	__rte_unused int is_on = (strcmp(res->on_off, "on") == 0) ? 1 : 0;

	if (port_id_is_invalid(res->port_id, ENABLED_WARN))
		return;

#ifdef RTE_LIBRTE_I40E_PMD
	ret = rte_pmd_i40e_set_vf_multicast_promisc(res->port_id,
						    res->vf_id, is_on);
#endif

	switch (ret) {
	case 0:
		break;
	case -EINVAL:
		printf("invalid vf_id %d\n", res->vf_id);
		break;
	case -ENODEV:
		printf("invalid port_id %d\n", res->port_id);
		break;
	case -ENOTSUP:
		printf("function not implemented\n");
		break;
	default:
		printf("programming error: (%s)\n", strerror(-ret));
	}
}

cmdline_parse_inst_t cmd_set_vf_allmulti = {
	.f = cmd_set_vf_allmulti_parsed,
	.data = NULL,
	.help_str = "set vf allmulti <port_id> <vf_id> on|off: "
		"Set multicast promiscuous mode for a VF from the PF",
	.tokens = {
		(void *)&cmd_vf_allmulti_set,
		(void *)&cmd_vf_allmulti_vf,
		(void *)&cmd_vf_allmulti_allmulti,
		(void *)&cmd_vf_allmulti_port_id,
		(void *)&cmd_vf_allmulti_vf_id,
		(void *)&cmd_vf_allmulti_on_off,
		NULL,
	},
};

/* vf broadcast mode configuration */

/* Common result structure for vf broadcast */
struct cmd_set_vf_broadcast_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t vf;
	cmdline_fixed_string_t broadcast;
	portid_t port_id;
	uint16_t vf_id;
	cmdline_fixed_string_t on_off;
};

/* Common CLI fields for vf broadcast enable disable */
cmdline_parse_token_string_t cmd_set_vf_broadcast_set =
	TOKEN_STRING_INITIALIZER
		(struct cmd_set_vf_broadcast_result,
		 set, "set");
cmdline_parse_token_string_t cmd_set_vf_broadcast_vf =
	TOKEN_STRING_INITIALIZER
		(struct cmd_set_vf_broadcast_result,
		 vf, "vf");
cmdline_parse_token_string_t cmd_set_vf_broadcast_broadcast =
	TOKEN_STRING_INITIALIZER
		(struct cmd_set_vf_broadcast_result,
		 broadcast, "broadcast");
cmdline_parse_token_num_t cmd_set_vf_broadcast_port_id =
	TOKEN_NUM_INITIALIZER
		(struct cmd_set_vf_broadcast_result,
		 port_id, UINT16);
cmdline_parse_token_num_t cmd_set_vf_broadcast_vf_id =
	TOKEN_NUM_INITIALIZER
		(struct cmd_set_vf_broadcast_result,
		 vf_id, UINT16);
cmdline_parse_token_string_t cmd_set_vf_broadcast_on_off =
	TOKEN_STRING_INITIALIZER
		(struct cmd_set_vf_broadcast_result,
		 on_off, "on#off");

static void
cmd_set_vf_broadcast_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_set_vf_broadcast_result *res = parsed_result;
	int ret = -ENOTSUP;

	__rte_unused int is_on = (strcmp(res->on_off, "on") == 0) ? 1 : 0;

	if (port_id_is_invalid(res->port_id, ENABLED_WARN))
		return;

#ifdef RTE_LIBRTE_I40E_PMD
	ret = rte_pmd_i40e_set_vf_broadcast(res->port_id,
					    res->vf_id, is_on);
#endif

	switch (ret) {
	case 0:
		break;
	case -EINVAL:
		printf("invalid vf_id %d or is_on %d\n", res->vf_id, is_on);
		break;
	case -ENODEV:
		printf("invalid port_id %d\n", res->port_id);
		break;
	case -ENOTSUP:
		printf("function not implemented\n");
		break;
	default:
		printf("programming error: (%s)\n", strerror(-ret));
	}
}

cmdline_parse_inst_t cmd_set_vf_broadcast = {
	.f = cmd_set_vf_broadcast_parsed,
	.data = NULL,
	.help_str = "set vf broadcast <port_id> <vf_id> on|off",
	.tokens = {
		(void *)&cmd_set_vf_broadcast_set,
		(void *)&cmd_set_vf_broadcast_vf,
		(void *)&cmd_set_vf_broadcast_broadcast,
		(void *)&cmd_set_vf_broadcast_port_id,
		(void *)&cmd_set_vf_broadcast_vf_id,
		(void *)&cmd_set_vf_broadcast_on_off,
		NULL,
	},
};

/* vf vlan tag configuration */

/* Common result structure for vf vlan tag */
struct cmd_set_vf_vlan_tag_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t vf;
	cmdline_fixed_string_t vlan;
	cmdline_fixed_string_t tag;
	portid_t port_id;
	uint16_t vf_id;
	cmdline_fixed_string_t on_off;
};

/* Common CLI fields for vf vlan tag enable disable */
cmdline_parse_token_string_t cmd_set_vf_vlan_tag_set =
	TOKEN_STRING_INITIALIZER
		(struct cmd_set_vf_vlan_tag_result,
		 set, "set");
cmdline_parse_token_string_t cmd_set_vf_vlan_tag_vf =
	TOKEN_STRING_INITIALIZER
		(struct cmd_set_vf_vlan_tag_result,
		 vf, "vf");
cmdline_parse_token_string_t cmd_set_vf_vlan_tag_vlan =
	TOKEN_STRING_INITIALIZER
		(struct cmd_set_vf_vlan_tag_result,
		 vlan, "vlan");
cmdline_parse_token_string_t cmd_set_vf_vlan_tag_tag =
	TOKEN_STRING_INITIALIZER
		(struct cmd_set_vf_vlan_tag_result,
		 tag, "tag");
cmdline_parse_token_num_t cmd_set_vf_vlan_tag_port_id =
	TOKEN_NUM_INITIALIZER
		(struct cmd_set_vf_vlan_tag_result,
		 port_id, UINT16);
cmdline_parse_token_num_t cmd_set_vf_vlan_tag_vf_id =
	TOKEN_NUM_INITIALIZER
		(struct cmd_set_vf_vlan_tag_result,
		 vf_id, UINT16);
cmdline_parse_token_string_t cmd_set_vf_vlan_tag_on_off =
	TOKEN_STRING_INITIALIZER
		(struct cmd_set_vf_vlan_tag_result,
		 on_off, "on#off");

static void
cmd_set_vf_vlan_tag_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_set_vf_vlan_tag_result *res = parsed_result;
	int ret = -ENOTSUP;

	__rte_unused int is_on = (strcmp(res->on_off, "on") == 0) ? 1 : 0;

	if (port_id_is_invalid(res->port_id, ENABLED_WARN))
		return;

#ifdef RTE_LIBRTE_I40E_PMD
	ret = rte_pmd_i40e_set_vf_vlan_tag(res->port_id,
					   res->vf_id, is_on);
#endif

	switch (ret) {
	case 0:
		break;
	case -EINVAL:
		printf("invalid vf_id %d or is_on %d\n", res->vf_id, is_on);
		break;
	case -ENODEV:
		printf("invalid port_id %d\n", res->port_id);
		break;
	case -ENOTSUP:
		printf("function not implemented\n");
		break;
	default:
		printf("programming error: (%s)\n", strerror(-ret));
	}
}

cmdline_parse_inst_t cmd_set_vf_vlan_tag = {
	.f = cmd_set_vf_vlan_tag_parsed,
	.data = NULL,
	.help_str = "set vf vlan tag <port_id> <vf_id> on|off",
	.tokens = {
		(void *)&cmd_set_vf_vlan_tag_set,
		(void *)&cmd_set_vf_vlan_tag_vf,
		(void *)&cmd_set_vf_vlan_tag_vlan,
		(void *)&cmd_set_vf_vlan_tag_tag,
		(void *)&cmd_set_vf_vlan_tag_port_id,
		(void *)&cmd_set_vf_vlan_tag_vf_id,
		(void *)&cmd_set_vf_vlan_tag_on_off,
		NULL,
	},
};

/* Common definition of VF and TC TX bandwidth configuration */
struct cmd_vf_tc_bw_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t vf;
	cmdline_fixed_string_t tc;
	cmdline_fixed_string_t tx;
	cmdline_fixed_string_t min_bw;
	cmdline_fixed_string_t max_bw;
	cmdline_fixed_string_t strict_link_prio;
	portid_t port_id;
	uint16_t vf_id;
	uint8_t tc_no;
	uint32_t bw;
	cmdline_fixed_string_t bw_list;
	uint8_t tc_map;
};

cmdline_parse_token_string_t cmd_vf_tc_bw_set =
	TOKEN_STRING_INITIALIZER
		(struct cmd_vf_tc_bw_result,
		 set, "set");
cmdline_parse_token_string_t cmd_vf_tc_bw_vf =
	TOKEN_STRING_INITIALIZER
		(struct cmd_vf_tc_bw_result,
		 vf, "vf");
cmdline_parse_token_string_t cmd_vf_tc_bw_tc =
	TOKEN_STRING_INITIALIZER
		(struct cmd_vf_tc_bw_result,
		 tc, "tc");
cmdline_parse_token_string_t cmd_vf_tc_bw_tx =
	TOKEN_STRING_INITIALIZER
		(struct cmd_vf_tc_bw_result,
		 tx, "tx");
cmdline_parse_token_string_t cmd_vf_tc_bw_strict_link_prio =
	TOKEN_STRING_INITIALIZER
		(struct cmd_vf_tc_bw_result,
		 strict_link_prio, "strict-link-priority");
cmdline_parse_token_string_t cmd_vf_tc_bw_min_bw =
	TOKEN_STRING_INITIALIZER
		(struct cmd_vf_tc_bw_result,
		 min_bw, "min-bandwidth");
cmdline_parse_token_string_t cmd_vf_tc_bw_max_bw =
	TOKEN_STRING_INITIALIZER
		(struct cmd_vf_tc_bw_result,
		 max_bw, "max-bandwidth");
cmdline_parse_token_num_t cmd_vf_tc_bw_port_id =
	TOKEN_NUM_INITIALIZER
		(struct cmd_vf_tc_bw_result,
		 port_id, UINT16);
cmdline_parse_token_num_t cmd_vf_tc_bw_vf_id =
	TOKEN_NUM_INITIALIZER
		(struct cmd_vf_tc_bw_result,
		 vf_id, UINT16);
cmdline_parse_token_num_t cmd_vf_tc_bw_tc_no =
	TOKEN_NUM_INITIALIZER
		(struct cmd_vf_tc_bw_result,
		 tc_no, UINT8);
cmdline_parse_token_num_t cmd_vf_tc_bw_bw =
	TOKEN_NUM_INITIALIZER
		(struct cmd_vf_tc_bw_result,
		 bw, UINT32);
cmdline_parse_token_string_t cmd_vf_tc_bw_bw_list =
	TOKEN_STRING_INITIALIZER
		(struct cmd_vf_tc_bw_result,
		 bw_list, NULL);
cmdline_parse_token_num_t cmd_vf_tc_bw_tc_map =
	TOKEN_NUM_INITIALIZER
		(struct cmd_vf_tc_bw_result,
		 tc_map, UINT8);

/* VF max bandwidth setting */
static void
cmd_vf_max_bw_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_vf_tc_bw_result *res = parsed_result;
	int ret = -ENOTSUP;

	if (port_id_is_invalid(res->port_id, ENABLED_WARN))
		return;

#ifdef RTE_LIBRTE_I40E_PMD
	ret = rte_pmd_i40e_set_vf_max_bw(res->port_id,
					 res->vf_id, res->bw);
#endif

	switch (ret) {
	case 0:
		break;
	case -EINVAL:
		printf("invalid vf_id %d or bandwidth %d\n",
		       res->vf_id, res->bw);
		break;
	case -ENODEV:
		printf("invalid port_id %d\n", res->port_id);
		break;
	case -ENOTSUP:
		printf("function not implemented\n");
		break;
	default:
		printf("programming error: (%s)\n", strerror(-ret));
	}
}

cmdline_parse_inst_t cmd_vf_max_bw = {
	.f = cmd_vf_max_bw_parsed,
	.data = NULL,
	.help_str = "set vf tx max-bandwidth <port_id> <vf_id> <bandwidth>",
	.tokens = {
		(void *)&cmd_vf_tc_bw_set,
		(void *)&cmd_vf_tc_bw_vf,
		(void *)&cmd_vf_tc_bw_tx,
		(void *)&cmd_vf_tc_bw_max_bw,
		(void *)&cmd_vf_tc_bw_port_id,
		(void *)&cmd_vf_tc_bw_vf_id,
		(void *)&cmd_vf_tc_bw_bw,
		NULL,
	},
};

static int
vf_tc_min_bw_parse_bw_list(uint8_t *bw_list,
			   uint8_t *tc_num,
			   char *str)
{
	uint32_t size;
	const char *p, *p0 = str;
	char s[256];
	char *end;
	char *str_fld[16];
	uint16_t i;
	int ret;

	p = strchr(p0, '(');
	if (p == NULL) {
		printf("The bandwidth-list should be '(bw1, bw2, ...)'\n");
		return -1;
	}
	p++;
	p0 = strchr(p, ')');
	if (p0 == NULL) {
		printf("The bandwidth-list should be '(bw1, bw2, ...)'\n");
		return -1;
	}
	size = p0 - p;
	if (size >= sizeof(s)) {
		printf("The string size exceeds the internal buffer size\n");
		return -1;
	}
	snprintf(s, sizeof(s), "%.*s", size, p);
	ret = rte_strsplit(s, sizeof(s), str_fld, 16, ',');
	if (ret <= 0) {
		printf("Failed to get the bandwidth list. ");
		return -1;
	}
	*tc_num = ret;
	for (i = 0; i < ret; i++)
		bw_list[i] = (uint8_t)strtoul(str_fld[i], &end, 0);

	return 0;
}

/* TC min bandwidth setting */
static void
cmd_vf_tc_min_bw_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_vf_tc_bw_result *res = parsed_result;
	uint8_t tc_num;
	uint8_t bw[16];
	int ret = -ENOTSUP;

	if (port_id_is_invalid(res->port_id, ENABLED_WARN))
		return;

	ret = vf_tc_min_bw_parse_bw_list(bw, &tc_num, res->bw_list);
	if (ret)
		return;

#ifdef RTE_LIBRTE_I40E_PMD
	ret = rte_pmd_i40e_set_vf_tc_bw_alloc(res->port_id, res->vf_id,
					      tc_num, bw);
#endif

	switch (ret) {
	case 0:
		break;
	case -EINVAL:
		printf("invalid vf_id %d or bandwidth\n", res->vf_id);
		break;
	case -ENODEV:
		printf("invalid port_id %d\n", res->port_id);
		break;
	case -ENOTSUP:
		printf("function not implemented\n");
		break;
	default:
		printf("programming error: (%s)\n", strerror(-ret));
	}
}

cmdline_parse_inst_t cmd_vf_tc_min_bw = {
	.f = cmd_vf_tc_min_bw_parsed,
	.data = NULL,
	.help_str = "set vf tc tx min-bandwidth <port_id> <vf_id>"
		    " <bw1, bw2, ...>",
	.tokens = {
		(void *)&cmd_vf_tc_bw_set,
		(void *)&cmd_vf_tc_bw_vf,
		(void *)&cmd_vf_tc_bw_tc,
		(void *)&cmd_vf_tc_bw_tx,
		(void *)&cmd_vf_tc_bw_min_bw,
		(void *)&cmd_vf_tc_bw_port_id,
		(void *)&cmd_vf_tc_bw_vf_id,
		(void *)&cmd_vf_tc_bw_bw_list,
		NULL,
	},
};

static void
cmd_tc_min_bw_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_vf_tc_bw_result *res = parsed_result;
	struct rte_port *port;
	uint8_t tc_num;
	uint8_t bw[16];
	int ret = -ENOTSUP;

	if (port_id_is_invalid(res->port_id, ENABLED_WARN))
		return;

	port = &ports[res->port_id];
	/** Check if the port is not started **/
	if (port->port_status != RTE_PORT_STOPPED) {
		printf("Please stop port %d first\n", res->port_id);
		return;
	}

	ret = vf_tc_min_bw_parse_bw_list(bw, &tc_num, res->bw_list);
	if (ret)
		return;

#ifdef RTE_LIBRTE_IXGBE_PMD
	ret = rte_pmd_ixgbe_set_tc_bw_alloc(res->port_id, tc_num, bw);
#endif

	switch (ret) {
	case 0:
		break;
	case -EINVAL:
		printf("invalid bandwidth\n");
		break;
	case -ENODEV:
		printf("invalid port_id %d\n", res->port_id);
		break;
	case -ENOTSUP:
		printf("function not implemented\n");
		break;
	default:
		printf("programming error: (%s)\n", strerror(-ret));
	}
}

cmdline_parse_inst_t cmd_tc_min_bw = {
	.f = cmd_tc_min_bw_parsed,
	.data = NULL,
	.help_str = "set tc tx min-bandwidth <port_id> <bw1, bw2, ...>",
	.tokens = {
		(void *)&cmd_vf_tc_bw_set,
		(void *)&cmd_vf_tc_bw_tc,
		(void *)&cmd_vf_tc_bw_tx,
		(void *)&cmd_vf_tc_bw_min_bw,
		(void *)&cmd_vf_tc_bw_port_id,
		(void *)&cmd_vf_tc_bw_bw_list,
		NULL,
	},
};

/* TC max bandwidth setting */
static void
cmd_vf_tc_max_bw_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_vf_tc_bw_result *res = parsed_result;
	int ret = -ENOTSUP;

	if (port_id_is_invalid(res->port_id, ENABLED_WARN))
		return;

#ifdef RTE_LIBRTE_I40E_PMD
	ret = rte_pmd_i40e_set_vf_tc_max_bw(res->port_id, res->vf_id,
					    res->tc_no, res->bw);
#endif

	switch (ret) {
	case 0:
		break;
	case -EINVAL:
		printf("invalid vf_id %d, tc_no %d or bandwidth %d\n",
		       res->vf_id, res->tc_no, res->bw);
		break;
	case -ENODEV:
		printf("invalid port_id %d\n", res->port_id);
		break;
	case -ENOTSUP:
		printf("function not implemented\n");
		break;
	default:
		printf("programming error: (%s)\n", strerror(-ret));
	}
}

cmdline_parse_inst_t cmd_vf_tc_max_bw = {
	.f = cmd_vf_tc_max_bw_parsed,
	.data = NULL,
	.help_str = "set vf tc tx max-bandwidth <port_id> <vf_id> <tc_no>"
		    " <bandwidth>",
	.tokens = {
		(void *)&cmd_vf_tc_bw_set,
		(void *)&cmd_vf_tc_bw_vf,
		(void *)&cmd_vf_tc_bw_tc,
		(void *)&cmd_vf_tc_bw_tx,
		(void *)&cmd_vf_tc_bw_max_bw,
		(void *)&cmd_vf_tc_bw_port_id,
		(void *)&cmd_vf_tc_bw_vf_id,
		(void *)&cmd_vf_tc_bw_tc_no,
		(void *)&cmd_vf_tc_bw_bw,
		NULL,
	},
};


#if defined RTE_LIBRTE_PMD_SOFTNIC && defined RTE_LIBRTE_SCHED

/* *** Set Port default Traffic Management Hierarchy *** */
struct cmd_set_port_tm_hierarchy_default_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t tm;
	cmdline_fixed_string_t hierarchy;
	cmdline_fixed_string_t def;
	portid_t port_id;
};

cmdline_parse_token_string_t cmd_set_port_tm_hierarchy_default_set =
	TOKEN_STRING_INITIALIZER(
		struct cmd_set_port_tm_hierarchy_default_result, set, "set");
cmdline_parse_token_string_t cmd_set_port_tm_hierarchy_default_port =
	TOKEN_STRING_INITIALIZER(
		struct cmd_set_port_tm_hierarchy_default_result, port, "port");
cmdline_parse_token_string_t cmd_set_port_tm_hierarchy_default_tm =
	TOKEN_STRING_INITIALIZER(
		struct cmd_set_port_tm_hierarchy_default_result, tm, "tm");
cmdline_parse_token_string_t cmd_set_port_tm_hierarchy_default_hierarchy =
	TOKEN_STRING_INITIALIZER(
		struct cmd_set_port_tm_hierarchy_default_result,
			hierarchy, "hierarchy");
cmdline_parse_token_string_t cmd_set_port_tm_hierarchy_default_default =
	TOKEN_STRING_INITIALIZER(
		struct cmd_set_port_tm_hierarchy_default_result,
			def, "default");
cmdline_parse_token_num_t cmd_set_port_tm_hierarchy_default_port_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_set_port_tm_hierarchy_default_result,
			port_id, UINT16);

static void cmd_set_port_tm_hierarchy_default_parsed(void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_set_port_tm_hierarchy_default_result *res = parsed_result;
	struct rte_port *p;
	portid_t port_id = res->port_id;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;

	p = &ports[port_id];

	/* Forward mode: tm */
	if (strcmp(cur_fwd_config.fwd_eng->fwd_mode_name, "softnic")) {
		printf("  softnicfwd mode not enabled(error)\n");
		return;
	}

	/* Set the default tm hierarchy */
	p->softport.default_tm_hierarchy_enable = 1;
}

cmdline_parse_inst_t cmd_set_port_tm_hierarchy_default = {
	.f = cmd_set_port_tm_hierarchy_default_parsed,
	.data = NULL,
	.help_str = "set port tm hierarchy default <port_id>",
	.tokens = {
		(void *)&cmd_set_port_tm_hierarchy_default_set,
		(void *)&cmd_set_port_tm_hierarchy_default_port,
		(void *)&cmd_set_port_tm_hierarchy_default_tm,
		(void *)&cmd_set_port_tm_hierarchy_default_hierarchy,
		(void *)&cmd_set_port_tm_hierarchy_default_default,
		(void *)&cmd_set_port_tm_hierarchy_default_port_id,
		NULL,
	},
};
#endif

/** Set VXLAN encapsulation details */
struct cmd_set_vxlan_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t vxlan;
	cmdline_fixed_string_t pos_token;
	cmdline_fixed_string_t ip_version;
	uint32_t vlan_present:1;
	uint32_t vni;
	uint16_t udp_src;
	uint16_t udp_dst;
	cmdline_ipaddr_t ip_src;
	cmdline_ipaddr_t ip_dst;
	uint16_t tci;
	struct ether_addr eth_src;
	struct ether_addr eth_dst;
};

cmdline_parse_token_string_t cmd_set_vxlan_set =
	TOKEN_STRING_INITIALIZER(struct cmd_set_vxlan_result, set, "set");
cmdline_parse_token_string_t cmd_set_vxlan_vxlan =
	TOKEN_STRING_INITIALIZER(struct cmd_set_vxlan_result, vxlan, "vxlan");
cmdline_parse_token_string_t cmd_set_vxlan_vxlan_with_vlan =
	TOKEN_STRING_INITIALIZER(struct cmd_set_vxlan_result, vxlan,
				 "vxlan-with-vlan");
cmdline_parse_token_string_t cmd_set_vxlan_ip_version =
	TOKEN_STRING_INITIALIZER(struct cmd_set_vxlan_result, pos_token,
				 "ip-version");
cmdline_parse_token_string_t cmd_set_vxlan_ip_version_value =
	TOKEN_STRING_INITIALIZER(struct cmd_set_vxlan_result, ip_version,
				 "ipv4#ipv6");
cmdline_parse_token_string_t cmd_set_vxlan_vni =
	TOKEN_STRING_INITIALIZER(struct cmd_set_vxlan_result, pos_token,
				 "vni");
cmdline_parse_token_num_t cmd_set_vxlan_vni_value =
	TOKEN_NUM_INITIALIZER(struct cmd_set_vxlan_result, vni, UINT32);
cmdline_parse_token_string_t cmd_set_vxlan_udp_src =
	TOKEN_STRING_INITIALIZER(struct cmd_set_vxlan_result, pos_token,
				 "udp-src");
cmdline_parse_token_num_t cmd_set_vxlan_udp_src_value =
	TOKEN_NUM_INITIALIZER(struct cmd_set_vxlan_result, udp_src, UINT16);
cmdline_parse_token_string_t cmd_set_vxlan_udp_dst =
	TOKEN_STRING_INITIALIZER(struct cmd_set_vxlan_result, pos_token,
				 "udp-dst");
cmdline_parse_token_num_t cmd_set_vxlan_udp_dst_value =
	TOKEN_NUM_INITIALIZER(struct cmd_set_vxlan_result, udp_dst, UINT16);
cmdline_parse_token_string_t cmd_set_vxlan_ip_src =
	TOKEN_STRING_INITIALIZER(struct cmd_set_vxlan_result, pos_token,
				 "ip-src");
cmdline_parse_token_ipaddr_t cmd_set_vxlan_ip_src_value =
	TOKEN_IPADDR_INITIALIZER(struct cmd_set_vxlan_result, ip_src);
cmdline_parse_token_string_t cmd_set_vxlan_ip_dst =
	TOKEN_STRING_INITIALIZER(struct cmd_set_vxlan_result, pos_token,
				 "ip-dst");
cmdline_parse_token_ipaddr_t cmd_set_vxlan_ip_dst_value =
	TOKEN_IPADDR_INITIALIZER(struct cmd_set_vxlan_result, ip_dst);
cmdline_parse_token_string_t cmd_set_vxlan_vlan =
	TOKEN_STRING_INITIALIZER(struct cmd_set_vxlan_result, pos_token,
				 "vlan-tci");
cmdline_parse_token_num_t cmd_set_vxlan_vlan_value =
	TOKEN_NUM_INITIALIZER(struct cmd_set_vxlan_result, tci, UINT16);
cmdline_parse_token_string_t cmd_set_vxlan_eth_src =
	TOKEN_STRING_INITIALIZER(struct cmd_set_vxlan_result, pos_token,
				 "eth-src");
cmdline_parse_token_etheraddr_t cmd_set_vxlan_eth_src_value =
	TOKEN_ETHERADDR_INITIALIZER(struct cmd_set_vxlan_result, eth_src);
cmdline_parse_token_string_t cmd_set_vxlan_eth_dst =
	TOKEN_STRING_INITIALIZER(struct cmd_set_vxlan_result, pos_token,
				 "eth-dst");
cmdline_parse_token_etheraddr_t cmd_set_vxlan_eth_dst_value =
	TOKEN_ETHERADDR_INITIALIZER(struct cmd_set_vxlan_result, eth_dst);

static void cmd_set_vxlan_parsed(void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_set_vxlan_result *res = parsed_result;
	union {
		uint32_t vxlan_id;
		uint8_t vni[4];
	} id = {
		.vxlan_id = rte_cpu_to_be_32(res->vni) & RTE_BE32(0x00ffffff),
	};

	if (strcmp(res->vxlan, "vxlan") == 0)
		vxlan_encap_conf.select_vlan = 0;
	else if (strcmp(res->vxlan, "vxlan-with-vlan") == 0)
		vxlan_encap_conf.select_vlan = 1;
	if (strcmp(res->ip_version, "ipv4") == 0)
		vxlan_encap_conf.select_ipv4 = 1;
	else if (strcmp(res->ip_version, "ipv6") == 0)
		vxlan_encap_conf.select_ipv4 = 0;
	else
		return;
	rte_memcpy(vxlan_encap_conf.vni, &id.vni[1], 3);
	vxlan_encap_conf.udp_src = rte_cpu_to_be_16(res->udp_src);
	vxlan_encap_conf.udp_dst = rte_cpu_to_be_16(res->udp_dst);
	if (vxlan_encap_conf.select_ipv4) {
		IPV4_ADDR_TO_UINT(res->ip_src, vxlan_encap_conf.ipv4_src);
		IPV4_ADDR_TO_UINT(res->ip_dst, vxlan_encap_conf.ipv4_dst);
	} else {
		IPV6_ADDR_TO_ARRAY(res->ip_src, vxlan_encap_conf.ipv6_src);
		IPV6_ADDR_TO_ARRAY(res->ip_dst, vxlan_encap_conf.ipv6_dst);
	}
	if (vxlan_encap_conf.select_vlan)
		vxlan_encap_conf.vlan_tci = rte_cpu_to_be_16(res->tci);
	rte_memcpy(vxlan_encap_conf.eth_src, res->eth_src.addr_bytes,
		   ETHER_ADDR_LEN);
	rte_memcpy(vxlan_encap_conf.eth_dst, res->eth_dst.addr_bytes,
		   ETHER_ADDR_LEN);
}

cmdline_parse_inst_t cmd_set_vxlan = {
	.f = cmd_set_vxlan_parsed,
	.data = NULL,
	.help_str = "set vxlan ip-version ipv4|ipv6 vni <vni> udp-src"
		" <udp-src> udp-dst <udp-dst> ip-src <ip-src> ip-dst <ip-dst>"
		" eth-src <eth-src> eth-dst <eth-dst>",
	.tokens = {
		(void *)&cmd_set_vxlan_set,
		(void *)&cmd_set_vxlan_vxlan,
		(void *)&cmd_set_vxlan_ip_version,
		(void *)&cmd_set_vxlan_ip_version_value,
		(void *)&cmd_set_vxlan_vni,
		(void *)&cmd_set_vxlan_vni_value,
		(void *)&cmd_set_vxlan_udp_src,
		(void *)&cmd_set_vxlan_udp_src_value,
		(void *)&cmd_set_vxlan_udp_dst,
		(void *)&cmd_set_vxlan_udp_dst_value,
		(void *)&cmd_set_vxlan_ip_src,
		(void *)&cmd_set_vxlan_ip_src_value,
		(void *)&cmd_set_vxlan_ip_dst,
		(void *)&cmd_set_vxlan_ip_dst_value,
		(void *)&cmd_set_vxlan_eth_src,
		(void *)&cmd_set_vxlan_eth_src_value,
		(void *)&cmd_set_vxlan_eth_dst,
		(void *)&cmd_set_vxlan_eth_dst_value,
		NULL,
	},
};

cmdline_parse_inst_t cmd_set_vxlan_with_vlan = {
	.f = cmd_set_vxlan_parsed,
	.data = NULL,
	.help_str = "set vxlan-with-vlan ip-version ipv4|ipv6 vni <vni>"
		" udp-src <udp-src> udp-dst <udp-dst> ip-src <ip-src> ip-dst"
		" <ip-dst> vlan-tci <vlan-tci> eth-src <eth-src> eth-dst"
		" <eth-dst>",
	.tokens = {
		(void *)&cmd_set_vxlan_set,
		(void *)&cmd_set_vxlan_vxlan_with_vlan,
		(void *)&cmd_set_vxlan_ip_version,
		(void *)&cmd_set_vxlan_ip_version_value,
		(void *)&cmd_set_vxlan_vni,
		(void *)&cmd_set_vxlan_vni_value,
		(void *)&cmd_set_vxlan_udp_src,
		(void *)&cmd_set_vxlan_udp_src_value,
		(void *)&cmd_set_vxlan_udp_dst,
		(void *)&cmd_set_vxlan_udp_dst_value,
		(void *)&cmd_set_vxlan_ip_src,
		(void *)&cmd_set_vxlan_ip_src_value,
		(void *)&cmd_set_vxlan_ip_dst,
		(void *)&cmd_set_vxlan_ip_dst_value,
		(void *)&cmd_set_vxlan_vlan,
		(void *)&cmd_set_vxlan_vlan_value,
		(void *)&cmd_set_vxlan_eth_src,
		(void *)&cmd_set_vxlan_eth_src_value,
		(void *)&cmd_set_vxlan_eth_dst,
		(void *)&cmd_set_vxlan_eth_dst_value,
		NULL,
	},
};

/** Set NVGRE encapsulation details */
struct cmd_set_nvgre_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t nvgre;
	cmdline_fixed_string_t pos_token;
	cmdline_fixed_string_t ip_version;
	uint32_t tni;
	cmdline_ipaddr_t ip_src;
	cmdline_ipaddr_t ip_dst;
	uint16_t tci;
	struct ether_addr eth_src;
	struct ether_addr eth_dst;
};

cmdline_parse_token_string_t cmd_set_nvgre_set =
	TOKEN_STRING_INITIALIZER(struct cmd_set_nvgre_result, set, "set");
cmdline_parse_token_string_t cmd_set_nvgre_nvgre =
	TOKEN_STRING_INITIALIZER(struct cmd_set_nvgre_result, nvgre, "nvgre");
cmdline_parse_token_string_t cmd_set_nvgre_nvgre_with_vlan =
	TOKEN_STRING_INITIALIZER(struct cmd_set_nvgre_result, nvgre,
				 "nvgre-with-vlan");
cmdline_parse_token_string_t cmd_set_nvgre_ip_version =
	TOKEN_STRING_INITIALIZER(struct cmd_set_nvgre_result, pos_token,
				 "ip-version");
cmdline_parse_token_string_t cmd_set_nvgre_ip_version_value =
	TOKEN_STRING_INITIALIZER(struct cmd_set_nvgre_result, ip_version,
				 "ipv4#ipv6");
cmdline_parse_token_string_t cmd_set_nvgre_tni =
	TOKEN_STRING_INITIALIZER(struct cmd_set_nvgre_result, pos_token,
				 "tni");
cmdline_parse_token_num_t cmd_set_nvgre_tni_value =
	TOKEN_NUM_INITIALIZER(struct cmd_set_nvgre_result, tni, UINT32);
cmdline_parse_token_string_t cmd_set_nvgre_ip_src =
	TOKEN_STRING_INITIALIZER(struct cmd_set_nvgre_result, pos_token,
				 "ip-src");
cmdline_parse_token_num_t cmd_set_nvgre_ip_src_value =
	TOKEN_IPADDR_INITIALIZER(struct cmd_set_nvgre_result, ip_src);
cmdline_parse_token_string_t cmd_set_nvgre_ip_dst =
	TOKEN_STRING_INITIALIZER(struct cmd_set_nvgre_result, pos_token,
				 "ip-dst");
cmdline_parse_token_ipaddr_t cmd_set_nvgre_ip_dst_value =
	TOKEN_IPADDR_INITIALIZER(struct cmd_set_nvgre_result, ip_dst);
cmdline_parse_token_string_t cmd_set_nvgre_vlan =
	TOKEN_STRING_INITIALIZER(struct cmd_set_nvgre_result, pos_token,
				 "vlan-tci");
cmdline_parse_token_num_t cmd_set_nvgre_vlan_value =
	TOKEN_NUM_INITIALIZER(struct cmd_set_nvgre_result, tci, UINT16);
cmdline_parse_token_string_t cmd_set_nvgre_eth_src =
	TOKEN_STRING_INITIALIZER(struct cmd_set_nvgre_result, pos_token,
				 "eth-src");
cmdline_parse_token_etheraddr_t cmd_set_nvgre_eth_src_value =
	TOKEN_ETHERADDR_INITIALIZER(struct cmd_set_nvgre_result, eth_src);
cmdline_parse_token_string_t cmd_set_nvgre_eth_dst =
	TOKEN_STRING_INITIALIZER(struct cmd_set_nvgre_result, pos_token,
				 "eth-dst");
cmdline_parse_token_etheraddr_t cmd_set_nvgre_eth_dst_value =
	TOKEN_ETHERADDR_INITIALIZER(struct cmd_set_nvgre_result, eth_dst);

static void cmd_set_nvgre_parsed(void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_set_nvgre_result *res = parsed_result;
	union {
		uint32_t nvgre_tni;
		uint8_t tni[4];
	} id = {
		.nvgre_tni = rte_cpu_to_be_32(res->tni) & RTE_BE32(0x00ffffff),
	};

	if (strcmp(res->nvgre, "nvgre") == 0)
		nvgre_encap_conf.select_vlan = 0;
	else if (strcmp(res->nvgre, "nvgre-with-vlan") == 0)
		nvgre_encap_conf.select_vlan = 1;
	if (strcmp(res->ip_version, "ipv4") == 0)
		nvgre_encap_conf.select_ipv4 = 1;
	else if (strcmp(res->ip_version, "ipv6") == 0)
		nvgre_encap_conf.select_ipv4 = 0;
	else
		return;
	rte_memcpy(nvgre_encap_conf.tni, &id.tni[1], 3);
	if (nvgre_encap_conf.select_ipv4) {
		IPV4_ADDR_TO_UINT(res->ip_src, nvgre_encap_conf.ipv4_src);
		IPV4_ADDR_TO_UINT(res->ip_dst, nvgre_encap_conf.ipv4_dst);
	} else {
		IPV6_ADDR_TO_ARRAY(res->ip_src, nvgre_encap_conf.ipv6_src);
		IPV6_ADDR_TO_ARRAY(res->ip_dst, nvgre_encap_conf.ipv6_dst);
	}
	if (nvgre_encap_conf.select_vlan)
		nvgre_encap_conf.vlan_tci = rte_cpu_to_be_16(res->tci);
	rte_memcpy(nvgre_encap_conf.eth_src, res->eth_src.addr_bytes,
		   ETHER_ADDR_LEN);
	rte_memcpy(nvgre_encap_conf.eth_dst, res->eth_dst.addr_bytes,
		   ETHER_ADDR_LEN);
}

cmdline_parse_inst_t cmd_set_nvgre = {
	.f = cmd_set_nvgre_parsed,
	.data = NULL,
	.help_str = "set nvgre ip-version <ipv4|ipv6> tni <tni> ip-src"
		" <ip-src> ip-dst <ip-dst> eth-src <eth-src>"
		" eth-dst <eth-dst>",
	.tokens = {
		(void *)&cmd_set_nvgre_set,
		(void *)&cmd_set_nvgre_nvgre,
		(void *)&cmd_set_nvgre_ip_version,
		(void *)&cmd_set_nvgre_ip_version_value,
		(void *)&cmd_set_nvgre_tni,
		(void *)&cmd_set_nvgre_tni_value,
		(void *)&cmd_set_nvgre_ip_src,
		(void *)&cmd_set_nvgre_ip_src_value,
		(void *)&cmd_set_nvgre_ip_dst,
		(void *)&cmd_set_nvgre_ip_dst_value,
		(void *)&cmd_set_nvgre_eth_src,
		(void *)&cmd_set_nvgre_eth_src_value,
		(void *)&cmd_set_nvgre_eth_dst,
		(void *)&cmd_set_nvgre_eth_dst_value,
		NULL,
	},
};

cmdline_parse_inst_t cmd_set_nvgre_with_vlan = {
	.f = cmd_set_nvgre_parsed,
	.data = NULL,
	.help_str = "set nvgre-with-vlan ip-version <ipv4|ipv6> tni <tni>"
		" ip-src <ip-src> ip-dst <ip-dst> vlan-tci <vlan-tci>"
		" eth-src <eth-src> eth-dst <eth-dst>",
	.tokens = {
		(void *)&cmd_set_nvgre_set,
		(void *)&cmd_set_nvgre_nvgre_with_vlan,
		(void *)&cmd_set_nvgre_ip_version,
		(void *)&cmd_set_nvgre_ip_version_value,
		(void *)&cmd_set_nvgre_tni,
		(void *)&cmd_set_nvgre_tni_value,
		(void *)&cmd_set_nvgre_ip_src,
		(void *)&cmd_set_nvgre_ip_src_value,
		(void *)&cmd_set_nvgre_ip_dst,
		(void *)&cmd_set_nvgre_ip_dst_value,
		(void *)&cmd_set_nvgre_vlan,
		(void *)&cmd_set_nvgre_vlan_value,
		(void *)&cmd_set_nvgre_eth_src,
		(void *)&cmd_set_nvgre_eth_src_value,
		(void *)&cmd_set_nvgre_eth_dst,
		(void *)&cmd_set_nvgre_eth_dst_value,
		NULL,
	},
};

/** Set L2 encapsulation details */
struct cmd_set_l2_encap_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t l2_encap;
	cmdline_fixed_string_t pos_token;
	cmdline_fixed_string_t ip_version;
	uint32_t vlan_present:1;
	uint16_t tci;
	struct ether_addr eth_src;
	struct ether_addr eth_dst;
};

cmdline_parse_token_string_t cmd_set_l2_encap_set =
	TOKEN_STRING_INITIALIZER(struct cmd_set_l2_encap_result, set, "set");
cmdline_parse_token_string_t cmd_set_l2_encap_l2_encap =
	TOKEN_STRING_INITIALIZER(struct cmd_set_l2_encap_result, l2_encap, "l2_encap");
cmdline_parse_token_string_t cmd_set_l2_encap_l2_encap_with_vlan =
	TOKEN_STRING_INITIALIZER(struct cmd_set_l2_encap_result, l2_encap,
				 "l2_encap-with-vlan");
cmdline_parse_token_string_t cmd_set_l2_encap_ip_version =
	TOKEN_STRING_INITIALIZER(struct cmd_set_l2_encap_result, pos_token,
				 "ip-version");
cmdline_parse_token_string_t cmd_set_l2_encap_ip_version_value =
	TOKEN_STRING_INITIALIZER(struct cmd_set_l2_encap_result, ip_version,
				 "ipv4#ipv6");
cmdline_parse_token_string_t cmd_set_l2_encap_vlan =
	TOKEN_STRING_INITIALIZER(struct cmd_set_l2_encap_result, pos_token,
				 "vlan-tci");
cmdline_parse_token_num_t cmd_set_l2_encap_vlan_value =
	TOKEN_NUM_INITIALIZER(struct cmd_set_l2_encap_result, tci, UINT16);
cmdline_parse_token_string_t cmd_set_l2_encap_eth_src =
	TOKEN_STRING_INITIALIZER(struct cmd_set_l2_encap_result, pos_token,
				 "eth-src");
cmdline_parse_token_etheraddr_t cmd_set_l2_encap_eth_src_value =
	TOKEN_ETHERADDR_INITIALIZER(struct cmd_set_l2_encap_result, eth_src);
cmdline_parse_token_string_t cmd_set_l2_encap_eth_dst =
	TOKEN_STRING_INITIALIZER(struct cmd_set_l2_encap_result, pos_token,
				 "eth-dst");
cmdline_parse_token_etheraddr_t cmd_set_l2_encap_eth_dst_value =
	TOKEN_ETHERADDR_INITIALIZER(struct cmd_set_l2_encap_result, eth_dst);

static void cmd_set_l2_encap_parsed(void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_set_l2_encap_result *res = parsed_result;

	if (strcmp(res->l2_encap, "l2_encap") == 0)
		l2_encap_conf.select_vlan = 0;
	else if (strcmp(res->l2_encap, "l2_encap-with-vlan") == 0)
		l2_encap_conf.select_vlan = 1;
	if (strcmp(res->ip_version, "ipv4") == 0)
		l2_encap_conf.select_ipv4 = 1;
	else if (strcmp(res->ip_version, "ipv6") == 0)
		l2_encap_conf.select_ipv4 = 0;
	else
		return;
	if (l2_encap_conf.select_vlan)
		l2_encap_conf.vlan_tci = rte_cpu_to_be_16(res->tci);
	rte_memcpy(l2_encap_conf.eth_src, res->eth_src.addr_bytes,
		   ETHER_ADDR_LEN);
	rte_memcpy(l2_encap_conf.eth_dst, res->eth_dst.addr_bytes,
		   ETHER_ADDR_LEN);
}

cmdline_parse_inst_t cmd_set_l2_encap = {
	.f = cmd_set_l2_encap_parsed,
	.data = NULL,
	.help_str = "set l2_encap ip-version ipv4|ipv6"
		" eth-src <eth-src> eth-dst <eth-dst>",
	.tokens = {
		(void *)&cmd_set_l2_encap_set,
		(void *)&cmd_set_l2_encap_l2_encap,
		(void *)&cmd_set_l2_encap_ip_version,
		(void *)&cmd_set_l2_encap_ip_version_value,
		(void *)&cmd_set_l2_encap_eth_src,
		(void *)&cmd_set_l2_encap_eth_src_value,
		(void *)&cmd_set_l2_encap_eth_dst,
		(void *)&cmd_set_l2_encap_eth_dst_value,
		NULL,
	},
};

cmdline_parse_inst_t cmd_set_l2_encap_with_vlan = {
	.f = cmd_set_l2_encap_parsed,
	.data = NULL,
	.help_str = "set l2_encap-with-vlan ip-version ipv4|ipv6"
		" vlan-tci <vlan-tci> eth-src <eth-src> eth-dst <eth-dst>",
	.tokens = {
		(void *)&cmd_set_l2_encap_set,
		(void *)&cmd_set_l2_encap_l2_encap_with_vlan,
		(void *)&cmd_set_l2_encap_ip_version,
		(void *)&cmd_set_l2_encap_ip_version_value,
		(void *)&cmd_set_l2_encap_vlan,
		(void *)&cmd_set_l2_encap_vlan_value,
		(void *)&cmd_set_l2_encap_eth_src,
		(void *)&cmd_set_l2_encap_eth_src_value,
		(void *)&cmd_set_l2_encap_eth_dst,
		(void *)&cmd_set_l2_encap_eth_dst_value,
		NULL,
	},
};

/** Set L2 decapsulation details */
struct cmd_set_l2_decap_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t l2_decap;
	cmdline_fixed_string_t pos_token;
	uint32_t vlan_present:1;
};

cmdline_parse_token_string_t cmd_set_l2_decap_set =
	TOKEN_STRING_INITIALIZER(struct cmd_set_l2_decap_result, set, "set");
cmdline_parse_token_string_t cmd_set_l2_decap_l2_decap =
	TOKEN_STRING_INITIALIZER(struct cmd_set_l2_decap_result, l2_decap,
				 "l2_decap");
cmdline_parse_token_string_t cmd_set_l2_decap_l2_decap_with_vlan =
	TOKEN_STRING_INITIALIZER(struct cmd_set_l2_decap_result, l2_decap,
				 "l2_decap-with-vlan");

static void cmd_set_l2_decap_parsed(void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_set_l2_decap_result *res = parsed_result;

	if (strcmp(res->l2_decap, "l2_decap") == 0)
		l2_decap_conf.select_vlan = 0;
	else if (strcmp(res->l2_decap, "l2_decap-with-vlan") == 0)
		l2_decap_conf.select_vlan = 1;
}

cmdline_parse_inst_t cmd_set_l2_decap = {
	.f = cmd_set_l2_decap_parsed,
	.data = NULL,
	.help_str = "set l2_decap",
	.tokens = {
		(void *)&cmd_set_l2_decap_set,
		(void *)&cmd_set_l2_decap_l2_decap,
		NULL,
	},
};

cmdline_parse_inst_t cmd_set_l2_decap_with_vlan = {
	.f = cmd_set_l2_decap_parsed,
	.data = NULL,
	.help_str = "set l2_decap-with-vlan",
	.tokens = {
		(void *)&cmd_set_l2_decap_set,
		(void *)&cmd_set_l2_decap_l2_decap_with_vlan,
		NULL,
	},
};

/** Set MPLSoGRE encapsulation details */
struct cmd_set_mplsogre_encap_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t mplsogre;
	cmdline_fixed_string_t pos_token;
	cmdline_fixed_string_t ip_version;
	uint32_t vlan_present:1;
	uint32_t label;
	cmdline_ipaddr_t ip_src;
	cmdline_ipaddr_t ip_dst;
	uint16_t tci;
	struct ether_addr eth_src;
	struct ether_addr eth_dst;
};

cmdline_parse_token_string_t cmd_set_mplsogre_encap_set =
	TOKEN_STRING_INITIALIZER(struct cmd_set_mplsogre_encap_result, set,
				 "set");
cmdline_parse_token_string_t cmd_set_mplsogre_encap_mplsogre_encap =
	TOKEN_STRING_INITIALIZER(struct cmd_set_mplsogre_encap_result, mplsogre,
				 "mplsogre_encap");
cmdline_parse_token_string_t cmd_set_mplsogre_encap_mplsogre_encap_with_vlan =
	TOKEN_STRING_INITIALIZER(struct cmd_set_mplsogre_encap_result,
				 mplsogre, "mplsogre_encap-with-vlan");
cmdline_parse_token_string_t cmd_set_mplsogre_encap_ip_version =
	TOKEN_STRING_INITIALIZER(struct cmd_set_mplsogre_encap_result,
				 pos_token, "ip-version");
cmdline_parse_token_string_t cmd_set_mplsogre_encap_ip_version_value =
	TOKEN_STRING_INITIALIZER(struct cmd_set_mplsogre_encap_result,
				 ip_version, "ipv4#ipv6");
cmdline_parse_token_string_t cmd_set_mplsogre_encap_label =
	TOKEN_STRING_INITIALIZER(struct cmd_set_mplsogre_encap_result,
				 pos_token, "label");
cmdline_parse_token_num_t cmd_set_mplsogre_encap_label_value =
	TOKEN_NUM_INITIALIZER(struct cmd_set_mplsogre_encap_result, label,
			      UINT32);
cmdline_parse_token_string_t cmd_set_mplsogre_encap_ip_src =
	TOKEN_STRING_INITIALIZER(struct cmd_set_mplsogre_encap_result,
				 pos_token, "ip-src");
cmdline_parse_token_ipaddr_t cmd_set_mplsogre_encap_ip_src_value =
	TOKEN_IPADDR_INITIALIZER(struct cmd_set_mplsogre_encap_result, ip_src);
cmdline_parse_token_string_t cmd_set_mplsogre_encap_ip_dst =
	TOKEN_STRING_INITIALIZER(struct cmd_set_mplsogre_encap_result,
				 pos_token, "ip-dst");
cmdline_parse_token_ipaddr_t cmd_set_mplsogre_encap_ip_dst_value =
	TOKEN_IPADDR_INITIALIZER(struct cmd_set_mplsogre_encap_result, ip_dst);
cmdline_parse_token_string_t cmd_set_mplsogre_encap_vlan =
	TOKEN_STRING_INITIALIZER(struct cmd_set_mplsogre_encap_result,
				 pos_token, "vlan-tci");
cmdline_parse_token_num_t cmd_set_mplsogre_encap_vlan_value =
	TOKEN_NUM_INITIALIZER(struct cmd_set_mplsogre_encap_result, tci,
			      UINT16);
cmdline_parse_token_string_t cmd_set_mplsogre_encap_eth_src =
	TOKEN_STRING_INITIALIZER(struct cmd_set_mplsogre_encap_result,
				 pos_token, "eth-src");
cmdline_parse_token_etheraddr_t cmd_set_mplsogre_encap_eth_src_value =
	TOKEN_ETHERADDR_INITIALIZER(struct cmd_set_mplsogre_encap_result,
				    eth_src);
cmdline_parse_token_string_t cmd_set_mplsogre_encap_eth_dst =
	TOKEN_STRING_INITIALIZER(struct cmd_set_mplsogre_encap_result,
				 pos_token, "eth-dst");
cmdline_parse_token_etheraddr_t cmd_set_mplsogre_encap_eth_dst_value =
	TOKEN_ETHERADDR_INITIALIZER(struct cmd_set_mplsogre_encap_result,
				    eth_dst);

static void cmd_set_mplsogre_encap_parsed(void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_set_mplsogre_encap_result *res = parsed_result;
	union {
		uint32_t mplsogre_label;
		uint8_t label[4];
	} id = {
		.mplsogre_label = rte_cpu_to_be_32(res->label<<12),
	};

	if (strcmp(res->mplsogre, "mplsogre_encap") == 0)
		mplsogre_encap_conf.select_vlan = 0;
	else if (strcmp(res->mplsogre, "mplsogre_encap-with-vlan") == 0)
		mplsogre_encap_conf.select_vlan = 1;
	if (strcmp(res->ip_version, "ipv4") == 0)
		mplsogre_encap_conf.select_ipv4 = 1;
	else if (strcmp(res->ip_version, "ipv6") == 0)
		mplsogre_encap_conf.select_ipv4 = 0;
	else
		return;
	rte_memcpy(mplsogre_encap_conf.label, &id.label, 3);
	if (mplsogre_encap_conf.select_ipv4) {
		IPV4_ADDR_TO_UINT(res->ip_src, mplsogre_encap_conf.ipv4_src);
		IPV4_ADDR_TO_UINT(res->ip_dst, mplsogre_encap_conf.ipv4_dst);
	} else {
		IPV6_ADDR_TO_ARRAY(res->ip_src, mplsogre_encap_conf.ipv6_src);
		IPV6_ADDR_TO_ARRAY(res->ip_dst, mplsogre_encap_conf.ipv6_dst);
	}
	if (mplsogre_encap_conf.select_vlan)
		mplsogre_encap_conf.vlan_tci = rte_cpu_to_be_16(res->tci);
	rte_memcpy(mplsogre_encap_conf.eth_src, res->eth_src.addr_bytes,
		   ETHER_ADDR_LEN);
	rte_memcpy(mplsogre_encap_conf.eth_dst, res->eth_dst.addr_bytes,
		   ETHER_ADDR_LEN);
}

cmdline_parse_inst_t cmd_set_mplsogre_encap = {
	.f = cmd_set_mplsogre_encap_parsed,
	.data = NULL,
	.help_str = "set mplsogre_encap ip-version ipv4|ipv6 label <label>"
		" ip-src <ip-src> ip-dst <ip-dst> eth-src <eth-src>"
		" eth-dst <eth-dst>",
	.tokens = {
		(void *)&cmd_set_mplsogre_encap_set,
		(void *)&cmd_set_mplsogre_encap_mplsogre_encap,
		(void *)&cmd_set_mplsogre_encap_ip_version,
		(void *)&cmd_set_mplsogre_encap_ip_version_value,
		(void *)&cmd_set_mplsogre_encap_label,
		(void *)&cmd_set_mplsogre_encap_label_value,
		(void *)&cmd_set_mplsogre_encap_ip_src,
		(void *)&cmd_set_mplsogre_encap_ip_src_value,
		(void *)&cmd_set_mplsogre_encap_ip_dst,
		(void *)&cmd_set_mplsogre_encap_ip_dst_value,
		(void *)&cmd_set_mplsogre_encap_eth_src,
		(void *)&cmd_set_mplsogre_encap_eth_src_value,
		(void *)&cmd_set_mplsogre_encap_eth_dst,
		(void *)&cmd_set_mplsogre_encap_eth_dst_value,
		NULL,
	},
};

cmdline_parse_inst_t cmd_set_mplsogre_encap_with_vlan = {
	.f = cmd_set_mplsogre_encap_parsed,
	.data = NULL,
	.help_str = "set mplsogre_encap-with-vlan ip-version ipv4|ipv6"
		" label <label> ip-src <ip-src> ip-dst <ip-dst>"
		" vlan-tci <vlan-tci> eth-src <eth-src> eth-dst <eth-dst>",
	.tokens = {
		(void *)&cmd_set_mplsogre_encap_set,
		(void *)&cmd_set_mplsogre_encap_mplsogre_encap_with_vlan,
		(void *)&cmd_set_mplsogre_encap_ip_version,
		(void *)&cmd_set_mplsogre_encap_ip_version_value,
		(void *)&cmd_set_mplsogre_encap_label,
		(void *)&cmd_set_mplsogre_encap_label_value,
		(void *)&cmd_set_mplsogre_encap_ip_src,
		(void *)&cmd_set_mplsogre_encap_ip_src_value,
		(void *)&cmd_set_mplsogre_encap_ip_dst,
		(void *)&cmd_set_mplsogre_encap_ip_dst_value,
		(void *)&cmd_set_mplsogre_encap_vlan,
		(void *)&cmd_set_mplsogre_encap_vlan_value,
		(void *)&cmd_set_mplsogre_encap_eth_src,
		(void *)&cmd_set_mplsogre_encap_eth_src_value,
		(void *)&cmd_set_mplsogre_encap_eth_dst,
		(void *)&cmd_set_mplsogre_encap_eth_dst_value,
		NULL,
	},
};

/** Set MPLSoGRE decapsulation details */
struct cmd_set_mplsogre_decap_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t mplsogre;
	cmdline_fixed_string_t pos_token;
	cmdline_fixed_string_t ip_version;
	uint32_t vlan_present:1;
};

cmdline_parse_token_string_t cmd_set_mplsogre_decap_set =
	TOKEN_STRING_INITIALIZER(struct cmd_set_mplsogre_decap_result, set,
				 "set");
cmdline_parse_token_string_t cmd_set_mplsogre_decap_mplsogre_decap =
	TOKEN_STRING_INITIALIZER(struct cmd_set_mplsogre_decap_result, mplsogre,
				 "mplsogre_decap");
cmdline_parse_token_string_t cmd_set_mplsogre_decap_mplsogre_decap_with_vlan =
	TOKEN_STRING_INITIALIZER(struct cmd_set_mplsogre_decap_result,
				 mplsogre, "mplsogre_decap-with-vlan");
cmdline_parse_token_string_t cmd_set_mplsogre_decap_ip_version =
	TOKEN_STRING_INITIALIZER(struct cmd_set_mplsogre_decap_result,
				 pos_token, "ip-version");
cmdline_parse_token_string_t cmd_set_mplsogre_decap_ip_version_value =
	TOKEN_STRING_INITIALIZER(struct cmd_set_mplsogre_decap_result,
				 ip_version, "ipv4#ipv6");

static void cmd_set_mplsogre_decap_parsed(void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_set_mplsogre_decap_result *res = parsed_result;

	if (strcmp(res->mplsogre, "mplsogre_decap") == 0)
		mplsogre_decap_conf.select_vlan = 0;
	else if (strcmp(res->mplsogre, "mplsogre_decap-with-vlan") == 0)
		mplsogre_decap_conf.select_vlan = 1;
	if (strcmp(res->ip_version, "ipv4") == 0)
		mplsogre_decap_conf.select_ipv4 = 1;
	else if (strcmp(res->ip_version, "ipv6") == 0)
		mplsogre_decap_conf.select_ipv4 = 0;
}

cmdline_parse_inst_t cmd_set_mplsogre_decap = {
	.f = cmd_set_mplsogre_decap_parsed,
	.data = NULL,
	.help_str = "set mplsogre_decap ip-version ipv4|ipv6",
	.tokens = {
		(void *)&cmd_set_mplsogre_decap_set,
		(void *)&cmd_set_mplsogre_decap_mplsogre_decap,
		(void *)&cmd_set_mplsogre_decap_ip_version,
		(void *)&cmd_set_mplsogre_decap_ip_version_value,
		NULL,
	},
};

cmdline_parse_inst_t cmd_set_mplsogre_decap_with_vlan = {
	.f = cmd_set_mplsogre_decap_parsed,
	.data = NULL,
	.help_str = "set mplsogre_decap-with-vlan ip-version ipv4|ipv6",
	.tokens = {
		(void *)&cmd_set_mplsogre_decap_set,
		(void *)&cmd_set_mplsogre_decap_mplsogre_decap_with_vlan,
		(void *)&cmd_set_mplsogre_decap_ip_version,
		(void *)&cmd_set_mplsogre_decap_ip_version_value,
		NULL,
	},
};

/** Set MPLSoUDP encapsulation details */
struct cmd_set_mplsoudp_encap_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t mplsoudp;
	cmdline_fixed_string_t pos_token;
	cmdline_fixed_string_t ip_version;
	uint32_t vlan_present:1;
	uint32_t label;
	uint16_t udp_src;
	uint16_t udp_dst;
	cmdline_ipaddr_t ip_src;
	cmdline_ipaddr_t ip_dst;
	uint16_t tci;
	struct ether_addr eth_src;
	struct ether_addr eth_dst;
};

cmdline_parse_token_string_t cmd_set_mplsoudp_encap_set =
	TOKEN_STRING_INITIALIZER(struct cmd_set_mplsoudp_encap_result, set,
				 "set");
cmdline_parse_token_string_t cmd_set_mplsoudp_encap_mplsoudp_encap =
	TOKEN_STRING_INITIALIZER(struct cmd_set_mplsoudp_encap_result, mplsoudp,
				 "mplsoudp_encap");
cmdline_parse_token_string_t cmd_set_mplsoudp_encap_mplsoudp_encap_with_vlan =
	TOKEN_STRING_INITIALIZER(struct cmd_set_mplsoudp_encap_result,
				 mplsoudp, "mplsoudp_encap-with-vlan");
cmdline_parse_token_string_t cmd_set_mplsoudp_encap_ip_version =
	TOKEN_STRING_INITIALIZER(struct cmd_set_mplsoudp_encap_result,
				 pos_token, "ip-version");
cmdline_parse_token_string_t cmd_set_mplsoudp_encap_ip_version_value =
	TOKEN_STRING_INITIALIZER(struct cmd_set_mplsoudp_encap_result,
				 ip_version, "ipv4#ipv6");
cmdline_parse_token_string_t cmd_set_mplsoudp_encap_label =
	TOKEN_STRING_INITIALIZER(struct cmd_set_mplsoudp_encap_result,
				 pos_token, "label");
cmdline_parse_token_num_t cmd_set_mplsoudp_encap_label_value =
	TOKEN_NUM_INITIALIZER(struct cmd_set_mplsoudp_encap_result, label,
			      UINT32);
cmdline_parse_token_string_t cmd_set_mplsoudp_encap_udp_src =
	TOKEN_STRING_INITIALIZER(struct cmd_set_mplsoudp_encap_result,
				 pos_token, "udp-src");
cmdline_parse_token_num_t cmd_set_mplsoudp_encap_udp_src_value =
	TOKEN_NUM_INITIALIZER(struct cmd_set_mplsoudp_encap_result, udp_src,
			      UINT16);
cmdline_parse_token_string_t cmd_set_mplsoudp_encap_udp_dst =
	TOKEN_STRING_INITIALIZER(struct cmd_set_mplsoudp_encap_result,
				 pos_token, "udp-dst");
cmdline_parse_token_num_t cmd_set_mplsoudp_encap_udp_dst_value =
	TOKEN_NUM_INITIALIZER(struct cmd_set_mplsoudp_encap_result, udp_dst,
			      UINT16);
cmdline_parse_token_string_t cmd_set_mplsoudp_encap_ip_src =
	TOKEN_STRING_INITIALIZER(struct cmd_set_mplsoudp_encap_result,
				 pos_token, "ip-src");
cmdline_parse_token_ipaddr_t cmd_set_mplsoudp_encap_ip_src_value =
	TOKEN_IPADDR_INITIALIZER(struct cmd_set_mplsoudp_encap_result, ip_src);
cmdline_parse_token_string_t cmd_set_mplsoudp_encap_ip_dst =
	TOKEN_STRING_INITIALIZER(struct cmd_set_mplsoudp_encap_result,
				 pos_token, "ip-dst");
cmdline_parse_token_ipaddr_t cmd_set_mplsoudp_encap_ip_dst_value =
	TOKEN_IPADDR_INITIALIZER(struct cmd_set_mplsoudp_encap_result, ip_dst);
cmdline_parse_token_string_t cmd_set_mplsoudp_encap_vlan =
	TOKEN_STRING_INITIALIZER(struct cmd_set_mplsoudp_encap_result,
				 pos_token, "vlan-tci");
cmdline_parse_token_num_t cmd_set_mplsoudp_encap_vlan_value =
	TOKEN_NUM_INITIALIZER(struct cmd_set_mplsoudp_encap_result, tci,
			      UINT16);
cmdline_parse_token_string_t cmd_set_mplsoudp_encap_eth_src =
	TOKEN_STRING_INITIALIZER(struct cmd_set_mplsoudp_encap_result,
				 pos_token, "eth-src");
cmdline_parse_token_etheraddr_t cmd_set_mplsoudp_encap_eth_src_value =
	TOKEN_ETHERADDR_INITIALIZER(struct cmd_set_mplsoudp_encap_result,
				    eth_src);
cmdline_parse_token_string_t cmd_set_mplsoudp_encap_eth_dst =
	TOKEN_STRING_INITIALIZER(struct cmd_set_mplsoudp_encap_result,
				 pos_token, "eth-dst");
cmdline_parse_token_etheraddr_t cmd_set_mplsoudp_encap_eth_dst_value =
	TOKEN_ETHERADDR_INITIALIZER(struct cmd_set_mplsoudp_encap_result,
				    eth_dst);

static void cmd_set_mplsoudp_encap_parsed(void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_set_mplsoudp_encap_result *res = parsed_result;
	union {
		uint32_t mplsoudp_label;
		uint8_t label[4];
	} id = {
		.mplsoudp_label = rte_cpu_to_be_32(res->label<<12),
	};

	if (strcmp(res->mplsoudp, "mplsoudp_encap") == 0)
		mplsoudp_encap_conf.select_vlan = 0;
	else if (strcmp(res->mplsoudp, "mplsoudp_encap-with-vlan") == 0)
		mplsoudp_encap_conf.select_vlan = 1;
	if (strcmp(res->ip_version, "ipv4") == 0)
		mplsoudp_encap_conf.select_ipv4 = 1;
	else if (strcmp(res->ip_version, "ipv6") == 0)
		mplsoudp_encap_conf.select_ipv4 = 0;
	else
		return;
	rte_memcpy(mplsoudp_encap_conf.label, &id.label, 3);
	mplsoudp_encap_conf.udp_src = rte_cpu_to_be_16(res->udp_src);
	mplsoudp_encap_conf.udp_dst = rte_cpu_to_be_16(res->udp_dst);
	if (mplsoudp_encap_conf.select_ipv4) {
		IPV4_ADDR_TO_UINT(res->ip_src, mplsoudp_encap_conf.ipv4_src);
		IPV4_ADDR_TO_UINT(res->ip_dst, mplsoudp_encap_conf.ipv4_dst);
	} else {
		IPV6_ADDR_TO_ARRAY(res->ip_src, mplsoudp_encap_conf.ipv6_src);
		IPV6_ADDR_TO_ARRAY(res->ip_dst, mplsoudp_encap_conf.ipv6_dst);
	}
	if (mplsoudp_encap_conf.select_vlan)
		mplsoudp_encap_conf.vlan_tci = rte_cpu_to_be_16(res->tci);
	rte_memcpy(mplsoudp_encap_conf.eth_src, res->eth_src.addr_bytes,
		   ETHER_ADDR_LEN);
	rte_memcpy(mplsoudp_encap_conf.eth_dst, res->eth_dst.addr_bytes,
		   ETHER_ADDR_LEN);
}

cmdline_parse_inst_t cmd_set_mplsoudp_encap = {
	.f = cmd_set_mplsoudp_encap_parsed,
	.data = NULL,
	.help_str = "set mplsoudp_encap ip-version ipv4|ipv6 label <label>"
		" udp-src <udp-src> udp-dst <udp-dst> ip-src <ip-src>"
		" ip-dst <ip-dst> eth-src <eth-src> eth-dst <eth-dst>",
	.tokens = {
		(void *)&cmd_set_mplsoudp_encap_set,
		(void *)&cmd_set_mplsoudp_encap_mplsoudp_encap,
		(void *)&cmd_set_mplsoudp_encap_ip_version,
		(void *)&cmd_set_mplsoudp_encap_ip_version_value,
		(void *)&cmd_set_mplsoudp_encap_label,
		(void *)&cmd_set_mplsoudp_encap_label_value,
		(void *)&cmd_set_mplsoudp_encap_udp_src,
		(void *)&cmd_set_mplsoudp_encap_udp_src_value,
		(void *)&cmd_set_mplsoudp_encap_udp_dst,
		(void *)&cmd_set_mplsoudp_encap_udp_dst_value,
		(void *)&cmd_set_mplsoudp_encap_ip_src,
		(void *)&cmd_set_mplsoudp_encap_ip_src_value,
		(void *)&cmd_set_mplsoudp_encap_ip_dst,
		(void *)&cmd_set_mplsoudp_encap_ip_dst_value,
		(void *)&cmd_set_mplsoudp_encap_eth_src,
		(void *)&cmd_set_mplsoudp_encap_eth_src_value,
		(void *)&cmd_set_mplsoudp_encap_eth_dst,
		(void *)&cmd_set_mplsoudp_encap_eth_dst_value,
		NULL,
	},
};

cmdline_parse_inst_t cmd_set_mplsoudp_encap_with_vlan = {
	.f = cmd_set_mplsoudp_encap_parsed,
	.data = NULL,
	.help_str = "set mplsoudp_encap-with-vlan ip-version ipv4|ipv6"
		" label <label> udp-src <udp-src> udp-dst <udp-dst>"
		" ip-src <ip-src> ip-dst <ip-dst> vlan-tci <vlan-tci>"
		" eth-src <eth-src> eth-dst <eth-dst>",
	.tokens = {
		(void *)&cmd_set_mplsoudp_encap_set,
		(void *)&cmd_set_mplsoudp_encap_mplsoudp_encap_with_vlan,
		(void *)&cmd_set_mplsoudp_encap_ip_version,
		(void *)&cmd_set_mplsoudp_encap_ip_version_value,
		(void *)&cmd_set_mplsoudp_encap_label,
		(void *)&cmd_set_mplsoudp_encap_label_value,
		(void *)&cmd_set_mplsoudp_encap_udp_src,
		(void *)&cmd_set_mplsoudp_encap_udp_src_value,
		(void *)&cmd_set_mplsoudp_encap_udp_dst,
		(void *)&cmd_set_mplsoudp_encap_udp_dst_value,
		(void *)&cmd_set_mplsoudp_encap_ip_src,
		(void *)&cmd_set_mplsoudp_encap_ip_src_value,
		(void *)&cmd_set_mplsoudp_encap_ip_dst,
		(void *)&cmd_set_mplsoudp_encap_ip_dst_value,
		(void *)&cmd_set_mplsoudp_encap_vlan,
		(void *)&cmd_set_mplsoudp_encap_vlan_value,
		(void *)&cmd_set_mplsoudp_encap_eth_src,
		(void *)&cmd_set_mplsoudp_encap_eth_src_value,
		(void *)&cmd_set_mplsoudp_encap_eth_dst,
		(void *)&cmd_set_mplsoudp_encap_eth_dst_value,
		NULL,
	},
};

/** Set MPLSoUDP decapsulation details */
struct cmd_set_mplsoudp_decap_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t mplsoudp;
	cmdline_fixed_string_t pos_token;
	cmdline_fixed_string_t ip_version;
	uint32_t vlan_present:1;
};

cmdline_parse_token_string_t cmd_set_mplsoudp_decap_set =
	TOKEN_STRING_INITIALIZER(struct cmd_set_mplsoudp_decap_result, set,
				 "set");
cmdline_parse_token_string_t cmd_set_mplsoudp_decap_mplsoudp_decap =
	TOKEN_STRING_INITIALIZER(struct cmd_set_mplsoudp_decap_result, mplsoudp,
				 "mplsoudp_decap");
cmdline_parse_token_string_t cmd_set_mplsoudp_decap_mplsoudp_decap_with_vlan =
	TOKEN_STRING_INITIALIZER(struct cmd_set_mplsoudp_decap_result,
				 mplsoudp, "mplsoudp_decap-with-vlan");
cmdline_parse_token_string_t cmd_set_mplsoudp_decap_ip_version =
	TOKEN_STRING_INITIALIZER(struct cmd_set_mplsoudp_decap_result,
				 pos_token, "ip-version");
cmdline_parse_token_string_t cmd_set_mplsoudp_decap_ip_version_value =
	TOKEN_STRING_INITIALIZER(struct cmd_set_mplsoudp_decap_result,
				 ip_version, "ipv4#ipv6");

static void cmd_set_mplsoudp_decap_parsed(void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_set_mplsoudp_decap_result *res = parsed_result;

	if (strcmp(res->mplsoudp, "mplsoudp_decap") == 0)
		mplsoudp_decap_conf.select_vlan = 0;
	else if (strcmp(res->mplsoudp, "mplsoudp_decap-with-vlan") == 0)
		mplsoudp_decap_conf.select_vlan = 1;
	if (strcmp(res->ip_version, "ipv4") == 0)
		mplsoudp_decap_conf.select_ipv4 = 1;
	else if (strcmp(res->ip_version, "ipv6") == 0)
		mplsoudp_decap_conf.select_ipv4 = 0;
}

cmdline_parse_inst_t cmd_set_mplsoudp_decap = {
	.f = cmd_set_mplsoudp_decap_parsed,
	.data = NULL,
	.help_str = "set mplsoudp_decap ip-version ipv4|ipv6",
	.tokens = {
		(void *)&cmd_set_mplsoudp_decap_set,
		(void *)&cmd_set_mplsoudp_decap_mplsoudp_decap,
		(void *)&cmd_set_mplsoudp_decap_ip_version,
		(void *)&cmd_set_mplsoudp_decap_ip_version_value,
		NULL,
	},
};

cmdline_parse_inst_t cmd_set_mplsoudp_decap_with_vlan = {
	.f = cmd_set_mplsoudp_decap_parsed,
	.data = NULL,
	.help_str = "set mplsoudp_decap-with-vlan ip-version ipv4|ipv6",
	.tokens = {
		(void *)&cmd_set_mplsoudp_decap_set,
		(void *)&cmd_set_mplsoudp_decap_mplsoudp_decap_with_vlan,
		(void *)&cmd_set_mplsoudp_decap_ip_version,
		(void *)&cmd_set_mplsoudp_decap_ip_version_value,
		NULL,
	},
};

/* Strict link priority scheduling mode setting */
static void
cmd_strict_link_prio_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_vf_tc_bw_result *res = parsed_result;
	int ret = -ENOTSUP;

	if (port_id_is_invalid(res->port_id, ENABLED_WARN))
		return;

#ifdef RTE_LIBRTE_I40E_PMD
	ret = rte_pmd_i40e_set_tc_strict_prio(res->port_id, res->tc_map);
#endif

	switch (ret) {
	case 0:
		break;
	case -EINVAL:
		printf("invalid tc_bitmap 0x%x\n", res->tc_map);
		break;
	case -ENODEV:
		printf("invalid port_id %d\n", res->port_id);
		break;
	case -ENOTSUP:
		printf("function not implemented\n");
		break;
	default:
		printf("programming error: (%s)\n", strerror(-ret));
	}
}

cmdline_parse_inst_t cmd_strict_link_prio = {
	.f = cmd_strict_link_prio_parsed,
	.data = NULL,
	.help_str = "set tx strict-link-priority <port_id> <tc_bitmap>",
	.tokens = {
		(void *)&cmd_vf_tc_bw_set,
		(void *)&cmd_vf_tc_bw_tx,
		(void *)&cmd_vf_tc_bw_strict_link_prio,
		(void *)&cmd_vf_tc_bw_port_id,
		(void *)&cmd_vf_tc_bw_tc_map,
		NULL,
	},
};

/* Load dynamic device personalization*/
struct cmd_ddp_add_result {
	cmdline_fixed_string_t ddp;
	cmdline_fixed_string_t add;
	portid_t port_id;
	char filepath[];
};

cmdline_parse_token_string_t cmd_ddp_add_ddp =
	TOKEN_STRING_INITIALIZER(struct cmd_ddp_add_result, ddp, "ddp");
cmdline_parse_token_string_t cmd_ddp_add_add =
	TOKEN_STRING_INITIALIZER(struct cmd_ddp_add_result, add, "add");
cmdline_parse_token_num_t cmd_ddp_add_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_ddp_add_result, port_id, UINT16);
cmdline_parse_token_string_t cmd_ddp_add_filepath =
	TOKEN_STRING_INITIALIZER(struct cmd_ddp_add_result, filepath, NULL);

static void
cmd_ddp_add_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_ddp_add_result *res = parsed_result;
	uint8_t *buff;
	uint32_t size;
	char *filepath;
	char *file_fld[2];
	int file_num;
	int ret = -ENOTSUP;

	if (!all_ports_stopped()) {
		printf("Please stop all ports first\n");
		return;
	}

	filepath = strdup(res->filepath);
	if (filepath == NULL) {
		printf("Failed to allocate memory\n");
		return;
	}
	file_num = rte_strsplit(filepath, strlen(filepath), file_fld, 2, ',');

	buff = open_file(file_fld[0], &size);
	if (!buff) {
		free((void *)filepath);
		return;
	}

#ifdef RTE_LIBRTE_I40E_PMD
	if (ret == -ENOTSUP)
		ret = rte_pmd_i40e_process_ddp_package(res->port_id,
					       buff, size,
					       RTE_PMD_I40E_PKG_OP_WR_ADD);
#endif

	if (ret == -EEXIST)
		printf("Profile has already existed.\n");
	else if (ret < 0)
		printf("Failed to load profile.\n");
	else if (file_num == 2)
		save_file(file_fld[1], buff, size);

	close_file(buff);
	free((void *)filepath);
}

cmdline_parse_inst_t cmd_ddp_add = {
	.f = cmd_ddp_add_parsed,
	.data = NULL,
	.help_str = "ddp add <port_id> <profile_path[,backup_profile_path]>",
	.tokens = {
		(void *)&cmd_ddp_add_ddp,
		(void *)&cmd_ddp_add_add,
		(void *)&cmd_ddp_add_port_id,
		(void *)&cmd_ddp_add_filepath,
		NULL,
	},
};

/* Delete dynamic device personalization*/
struct cmd_ddp_del_result {
	cmdline_fixed_string_t ddp;
	cmdline_fixed_string_t del;
	portid_t port_id;
	char filepath[];
};

cmdline_parse_token_string_t cmd_ddp_del_ddp =
	TOKEN_STRING_INITIALIZER(struct cmd_ddp_del_result, ddp, "ddp");
cmdline_parse_token_string_t cmd_ddp_del_del =
	TOKEN_STRING_INITIALIZER(struct cmd_ddp_del_result, del, "del");
cmdline_parse_token_num_t cmd_ddp_del_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_ddp_del_result, port_id, UINT16);
cmdline_parse_token_string_t cmd_ddp_del_filepath =
	TOKEN_STRING_INITIALIZER(struct cmd_ddp_del_result, filepath, NULL);

static void
cmd_ddp_del_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_ddp_del_result *res = parsed_result;
	uint8_t *buff;
	uint32_t size;
	int ret = -ENOTSUP;

	if (!all_ports_stopped()) {
		printf("Please stop all ports first\n");
		return;
	}

	buff = open_file(res->filepath, &size);
	if (!buff)
		return;

#ifdef RTE_LIBRTE_I40E_PMD
	if (ret == -ENOTSUP)
		ret = rte_pmd_i40e_process_ddp_package(res->port_id,
					       buff, size,
					       RTE_PMD_I40E_PKG_OP_WR_DEL);
#endif

	if (ret == -EACCES)
		printf("Profile does not exist.\n");
	else if (ret < 0)
		printf("Failed to delete profile.\n");

	close_file(buff);
}

cmdline_parse_inst_t cmd_ddp_del = {
	.f = cmd_ddp_del_parsed,
	.data = NULL,
	.help_str = "ddp del <port_id> <backup_profile_path>",
	.tokens = {
		(void *)&cmd_ddp_del_ddp,
		(void *)&cmd_ddp_del_del,
		(void *)&cmd_ddp_del_port_id,
		(void *)&cmd_ddp_del_filepath,
		NULL,
	},
};

/* Get dynamic device personalization profile info */
struct cmd_ddp_info_result {
	cmdline_fixed_string_t ddp;
	cmdline_fixed_string_t get;
	cmdline_fixed_string_t info;
	char filepath[];
};

cmdline_parse_token_string_t cmd_ddp_info_ddp =
	TOKEN_STRING_INITIALIZER(struct cmd_ddp_info_result, ddp, "ddp");
cmdline_parse_token_string_t cmd_ddp_info_get =
	TOKEN_STRING_INITIALIZER(struct cmd_ddp_info_result, get, "get");
cmdline_parse_token_string_t cmd_ddp_info_info =
	TOKEN_STRING_INITIALIZER(struct cmd_ddp_info_result, info, "info");
cmdline_parse_token_string_t cmd_ddp_info_filepath =
	TOKEN_STRING_INITIALIZER(struct cmd_ddp_info_result, filepath, NULL);

static void
cmd_ddp_info_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_ddp_info_result *res = parsed_result;
	uint8_t *pkg;
	uint32_t pkg_size;
	int ret = -ENOTSUP;
#ifdef RTE_LIBRTE_I40E_PMD
	uint32_t i, j, n;
	uint8_t *buff;
	uint32_t buff_size = 0;
	struct rte_pmd_i40e_profile_info info;
	uint32_t dev_num = 0;
	struct rte_pmd_i40e_ddp_device_id *devs;
	uint32_t proto_num = 0;
	struct rte_pmd_i40e_proto_info *proto = NULL;
	uint32_t pctype_num = 0;
	struct rte_pmd_i40e_ptype_info *pctype;
	uint32_t ptype_num = 0;
	struct rte_pmd_i40e_ptype_info *ptype;
	uint8_t proto_id;

#endif

	pkg = open_file(res->filepath, &pkg_size);
	if (!pkg)
		return;

#ifdef RTE_LIBRTE_I40E_PMD
	ret = rte_pmd_i40e_get_ddp_info(pkg, pkg_size,
				(uint8_t *)&info, sizeof(info),
				RTE_PMD_I40E_PKG_INFO_GLOBAL_HEADER);
	if (!ret) {
		printf("Global Track id:       0x%x\n", info.track_id);
		printf("Global Version:        %d.%d.%d.%d\n",
			info.version.major,
			info.version.minor,
			info.version.update,
			info.version.draft);
		printf("Global Package name:   %s\n\n", info.name);
	}

	ret = rte_pmd_i40e_get_ddp_info(pkg, pkg_size,
				(uint8_t *)&info, sizeof(info),
				RTE_PMD_I40E_PKG_INFO_HEADER);
	if (!ret) {
		printf("i40e Profile Track id: 0x%x\n", info.track_id);
		printf("i40e Profile Version:  %d.%d.%d.%d\n",
			info.version.major,
			info.version.minor,
			info.version.update,
			info.version.draft);
		printf("i40e Profile name:     %s\n\n", info.name);
	}

	ret = rte_pmd_i40e_get_ddp_info(pkg, pkg_size,
				(uint8_t *)&buff_size, sizeof(buff_size),
				RTE_PMD_I40E_PKG_INFO_GLOBAL_NOTES_SIZE);
	if (!ret && buff_size) {
		buff = (uint8_t *)malloc(buff_size);
		if (buff) {
			ret = rte_pmd_i40e_get_ddp_info(pkg, pkg_size,
						buff, buff_size,
						RTE_PMD_I40E_PKG_INFO_GLOBAL_NOTES);
			if (!ret)
				printf("Package Notes:\n%s\n\n", buff);
			free(buff);
		}
	}

	ret = rte_pmd_i40e_get_ddp_info(pkg, pkg_size,
				(uint8_t *)&dev_num, sizeof(dev_num),
				RTE_PMD_I40E_PKG_INFO_DEVID_NUM);
	if (!ret && dev_num) {
		buff_size = dev_num * sizeof(struct rte_pmd_i40e_ddp_device_id);
		devs = (struct rte_pmd_i40e_ddp_device_id *)malloc(buff_size);
		if (devs) {
			ret = rte_pmd_i40e_get_ddp_info(pkg, pkg_size,
						(uint8_t *)devs, buff_size,
						RTE_PMD_I40E_PKG_INFO_DEVID_LIST);
			if (!ret) {
				printf("List of supported devices:\n");
				for (i = 0; i < dev_num; i++) {
					printf("  %04X:%04X %04X:%04X\n",
						devs[i].vendor_dev_id >> 16,
						devs[i].vendor_dev_id & 0xFFFF,
						devs[i].sub_vendor_dev_id >> 16,
						devs[i].sub_vendor_dev_id & 0xFFFF);
				}
				printf("\n");
			}
			free(devs);
		}
	}

	/* get information about protocols and packet types */
	ret = rte_pmd_i40e_get_ddp_info(pkg, pkg_size,
		(uint8_t *)&proto_num, sizeof(proto_num),
		RTE_PMD_I40E_PKG_INFO_PROTOCOL_NUM);
	if (ret || !proto_num)
		goto no_print_return;

	buff_size = proto_num * sizeof(struct rte_pmd_i40e_proto_info);
	proto = (struct rte_pmd_i40e_proto_info *)malloc(buff_size);
	if (!proto)
		goto no_print_return;

	ret = rte_pmd_i40e_get_ddp_info(pkg, pkg_size, (uint8_t *)proto,
					buff_size,
					RTE_PMD_I40E_PKG_INFO_PROTOCOL_LIST);
	if (!ret) {
		printf("List of used protocols:\n");
		for (i = 0; i < proto_num; i++)
			printf("  %2u: %s\n", proto[i].proto_id,
			       proto[i].name);
		printf("\n");
	}
	ret = rte_pmd_i40e_get_ddp_info(pkg, pkg_size,
		(uint8_t *)&pctype_num, sizeof(pctype_num),
		RTE_PMD_I40E_PKG_INFO_PCTYPE_NUM);
	if (ret || !pctype_num)
		goto no_print_pctypes;

	buff_size = pctype_num * sizeof(struct rte_pmd_i40e_ptype_info);
	pctype = (struct rte_pmd_i40e_ptype_info *)malloc(buff_size);
	if (!pctype)
		goto no_print_pctypes;

	ret = rte_pmd_i40e_get_ddp_info(pkg, pkg_size, (uint8_t *)pctype,
					buff_size,
					RTE_PMD_I40E_PKG_INFO_PCTYPE_LIST);
	if (ret) {
		free(pctype);
		goto no_print_pctypes;
	}

	printf("List of defined packet classification types:\n");
	for (i = 0; i < pctype_num; i++) {
		printf("  %2u:", pctype[i].ptype_id);
		for (j = 0; j < RTE_PMD_I40E_PROTO_NUM; j++) {
			proto_id = pctype[i].protocols[j];
			if (proto_id != RTE_PMD_I40E_PROTO_UNUSED) {
				for (n = 0; n < proto_num; n++) {
					if (proto[n].proto_id == proto_id) {
						printf(" %s", proto[n].name);
						break;
					}
				}
			}
		}
		printf("\n");
	}
	printf("\n");
	free(pctype);

no_print_pctypes:

	ret = rte_pmd_i40e_get_ddp_info(pkg, pkg_size, (uint8_t *)&ptype_num,
					sizeof(ptype_num),
					RTE_PMD_I40E_PKG_INFO_PTYPE_NUM);
	if (ret || !ptype_num)
		goto no_print_return;

	buff_size = ptype_num * sizeof(struct rte_pmd_i40e_ptype_info);
	ptype = (struct rte_pmd_i40e_ptype_info *)malloc(buff_size);
	if (!ptype)
		goto no_print_return;

	ret = rte_pmd_i40e_get_ddp_info(pkg, pkg_size, (uint8_t *)ptype,
					buff_size,
					RTE_PMD_I40E_PKG_INFO_PTYPE_LIST);
	if (ret) {
		free(ptype);
		goto no_print_return;
	}
	printf("List of defined packet types:\n");
	for (i = 0; i < ptype_num; i++) {
		printf("  %2u:", ptype[i].ptype_id);
		for (j = 0; j < RTE_PMD_I40E_PROTO_NUM; j++) {
			proto_id = ptype[i].protocols[j];
			if (proto_id != RTE_PMD_I40E_PROTO_UNUSED) {
				for (n = 0; n < proto_num; n++) {
					if (proto[n].proto_id == proto_id) {
						printf(" %s", proto[n].name);
						break;
					}
				}
			}
		}
		printf("\n");
	}
	free(ptype);
	printf("\n");

	ret = 0;
no_print_return:
	if (proto)
		free(proto);
#endif
	if (ret == -ENOTSUP)
		printf("Function not supported in PMD driver\n");
	close_file(pkg);
}

cmdline_parse_inst_t cmd_ddp_get_info = {
	.f = cmd_ddp_info_parsed,
	.data = NULL,
	.help_str = "ddp get info <profile_path>",
	.tokens = {
		(void *)&cmd_ddp_info_ddp,
		(void *)&cmd_ddp_info_get,
		(void *)&cmd_ddp_info_info,
		(void *)&cmd_ddp_info_filepath,
		NULL,
	},
};

/* Get dynamic device personalization profile info list*/
#define PROFILE_INFO_SIZE 48
#define MAX_PROFILE_NUM 16

struct cmd_ddp_get_list_result {
	cmdline_fixed_string_t ddp;
	cmdline_fixed_string_t get;
	cmdline_fixed_string_t list;
	portid_t port_id;
};

cmdline_parse_token_string_t cmd_ddp_get_list_ddp =
	TOKEN_STRING_INITIALIZER(struct cmd_ddp_get_list_result, ddp, "ddp");
cmdline_parse_token_string_t cmd_ddp_get_list_get =
	TOKEN_STRING_INITIALIZER(struct cmd_ddp_get_list_result, get, "get");
cmdline_parse_token_string_t cmd_ddp_get_list_list =
	TOKEN_STRING_INITIALIZER(struct cmd_ddp_get_list_result, list, "list");
cmdline_parse_token_num_t cmd_ddp_get_list_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_ddp_get_list_result, port_id, UINT16);

static void
cmd_ddp_get_list_parsed(
	__attribute__((unused)) void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
#ifdef RTE_LIBRTE_I40E_PMD
	struct cmd_ddp_get_list_result *res = parsed_result;
	struct rte_pmd_i40e_profile_list *p_list;
	struct rte_pmd_i40e_profile_info *p_info;
	uint32_t p_num;
	uint32_t size;
	uint32_t i;
#endif
	int ret = -ENOTSUP;

#ifdef RTE_LIBRTE_I40E_PMD
	size = PROFILE_INFO_SIZE * MAX_PROFILE_NUM + 4;
	p_list = (struct rte_pmd_i40e_profile_list *)malloc(size);
	if (!p_list)
		printf("%s: Failed to malloc buffer\n", __func__);

	if (ret == -ENOTSUP)
		ret = rte_pmd_i40e_get_ddp_list(res->port_id,
						(uint8_t *)p_list, size);

	if (!ret) {
		p_num = p_list->p_count;
		printf("Profile number is: %d\n\n", p_num);

		for (i = 0; i < p_num; i++) {
			p_info = &p_list->p_info[i];
			printf("Profile %d:\n", i);
			printf("Track id:     0x%x\n", p_info->track_id);
			printf("Version:      %d.%d.%d.%d\n",
			       p_info->version.major,
			       p_info->version.minor,
			       p_info->version.update,
			       p_info->version.draft);
			printf("Profile name: %s\n\n", p_info->name);
		}
	}

	free(p_list);
#endif

	if (ret < 0)
		printf("Failed to get ddp list\n");
}

cmdline_parse_inst_t cmd_ddp_get_list = {
	.f = cmd_ddp_get_list_parsed,
	.data = NULL,
	.help_str = "ddp get list <port_id>",
	.tokens = {
		(void *)&cmd_ddp_get_list_ddp,
		(void *)&cmd_ddp_get_list_get,
		(void *)&cmd_ddp_get_list_list,
		(void *)&cmd_ddp_get_list_port_id,
		NULL,
	},
};

/* Configure input set */
struct cmd_cfg_input_set_result {
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t cfg;
	portid_t port_id;
	cmdline_fixed_string_t pctype;
	uint8_t pctype_id;
	cmdline_fixed_string_t inset_type;
	cmdline_fixed_string_t opt;
	cmdline_fixed_string_t field;
	uint8_t field_idx;
};

static void
cmd_cfg_input_set_parsed(
	__attribute__((unused)) void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
#ifdef RTE_LIBRTE_I40E_PMD
	struct cmd_cfg_input_set_result *res = parsed_result;
	enum rte_pmd_i40e_inset_type inset_type = INSET_NONE;
	struct rte_pmd_i40e_inset inset;
#endif
	int ret = -ENOTSUP;

	if (!all_ports_stopped()) {
		printf("Please stop all ports first\n");
		return;
	}

#ifdef RTE_LIBRTE_I40E_PMD
	if (!strcmp(res->inset_type, "hash_inset"))
		inset_type = INSET_HASH;
	else if (!strcmp(res->inset_type, "fdir_inset"))
		inset_type = INSET_FDIR;
	else if (!strcmp(res->inset_type, "fdir_flx_inset"))
		inset_type = INSET_FDIR_FLX;
	ret = rte_pmd_i40e_inset_get(res->port_id, res->pctype_id,
				     &inset, inset_type);
	if (ret) {
		printf("Failed to get input set.\n");
		return;
	}

	if (!strcmp(res->opt, "get")) {
		ret = rte_pmd_i40e_inset_field_get(inset.inset,
						   res->field_idx);
		if (ret)
			printf("Field index %d is enabled.\n", res->field_idx);
		else
			printf("Field index %d is disabled.\n", res->field_idx);
		return;
	} else if (!strcmp(res->opt, "set"))
		ret = rte_pmd_i40e_inset_field_set(&inset.inset,
						   res->field_idx);
	else if (!strcmp(res->opt, "clear"))
		ret = rte_pmd_i40e_inset_field_clear(&inset.inset,
						     res->field_idx);
	if (ret) {
		printf("Failed to configure input set field.\n");
		return;
	}

	ret = rte_pmd_i40e_inset_set(res->port_id, res->pctype_id,
				     &inset, inset_type);
	if (ret) {
		printf("Failed to set input set.\n");
		return;
	}
#endif

	if (ret == -ENOTSUP)
		printf("Function not supported\n");
}

cmdline_parse_token_string_t cmd_cfg_input_set_port =
	TOKEN_STRING_INITIALIZER(struct cmd_cfg_input_set_result,
				 port, "port");
cmdline_parse_token_string_t cmd_cfg_input_set_cfg =
	TOKEN_STRING_INITIALIZER(struct cmd_cfg_input_set_result,
				 cfg, "config");
cmdline_parse_token_num_t cmd_cfg_input_set_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_cfg_input_set_result,
			      port_id, UINT16);
cmdline_parse_token_string_t cmd_cfg_input_set_pctype =
	TOKEN_STRING_INITIALIZER(struct cmd_cfg_input_set_result,
				 pctype, "pctype");
cmdline_parse_token_num_t cmd_cfg_input_set_pctype_id =
	TOKEN_NUM_INITIALIZER(struct cmd_cfg_input_set_result,
			      pctype_id, UINT8);
cmdline_parse_token_string_t cmd_cfg_input_set_inset_type =
	TOKEN_STRING_INITIALIZER(struct cmd_cfg_input_set_result,
				 inset_type,
				 "hash_inset#fdir_inset#fdir_flx_inset");
cmdline_parse_token_string_t cmd_cfg_input_set_opt =
	TOKEN_STRING_INITIALIZER(struct cmd_cfg_input_set_result,
				 opt, "get#set#clear");
cmdline_parse_token_string_t cmd_cfg_input_set_field =
	TOKEN_STRING_INITIALIZER(struct cmd_cfg_input_set_result,
				 field, "field");
cmdline_parse_token_num_t cmd_cfg_input_set_field_idx =
	TOKEN_NUM_INITIALIZER(struct cmd_cfg_input_set_result,
			      field_idx, UINT8);

cmdline_parse_inst_t cmd_cfg_input_set = {
	.f = cmd_cfg_input_set_parsed,
	.data = NULL,
	.help_str = "port config <port_id> pctype <pctype_id> hash_inset|"
		    "fdir_inset|fdir_flx_inset get|set|clear field <field_idx>",
	.tokens = {
		(void *)&cmd_cfg_input_set_port,
		(void *)&cmd_cfg_input_set_cfg,
		(void *)&cmd_cfg_input_set_port_id,
		(void *)&cmd_cfg_input_set_pctype,
		(void *)&cmd_cfg_input_set_pctype_id,
		(void *)&cmd_cfg_input_set_inset_type,
		(void *)&cmd_cfg_input_set_opt,
		(void *)&cmd_cfg_input_set_field,
		(void *)&cmd_cfg_input_set_field_idx,
		NULL,
	},
};

/* Clear input set */
struct cmd_clear_input_set_result {
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t cfg;
	portid_t port_id;
	cmdline_fixed_string_t pctype;
	uint8_t pctype_id;
	cmdline_fixed_string_t inset_type;
	cmdline_fixed_string_t clear;
	cmdline_fixed_string_t all;
};

static void
cmd_clear_input_set_parsed(
	__attribute__((unused)) void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
#ifdef RTE_LIBRTE_I40E_PMD
	struct cmd_clear_input_set_result *res = parsed_result;
	enum rte_pmd_i40e_inset_type inset_type = INSET_NONE;
	struct rte_pmd_i40e_inset inset;
#endif
	int ret = -ENOTSUP;

	if (!all_ports_stopped()) {
		printf("Please stop all ports first\n");
		return;
	}

#ifdef RTE_LIBRTE_I40E_PMD
	if (!strcmp(res->inset_type, "hash_inset"))
		inset_type = INSET_HASH;
	else if (!strcmp(res->inset_type, "fdir_inset"))
		inset_type = INSET_FDIR;
	else if (!strcmp(res->inset_type, "fdir_flx_inset"))
		inset_type = INSET_FDIR_FLX;

	memset(&inset, 0, sizeof(inset));

	ret = rte_pmd_i40e_inset_set(res->port_id, res->pctype_id,
				     &inset, inset_type);
	if (ret) {
		printf("Failed to clear input set.\n");
		return;
	}

#endif

	if (ret == -ENOTSUP)
		printf("Function not supported\n");
}

cmdline_parse_token_string_t cmd_clear_input_set_port =
	TOKEN_STRING_INITIALIZER(struct cmd_clear_input_set_result,
				 port, "port");
cmdline_parse_token_string_t cmd_clear_input_set_cfg =
	TOKEN_STRING_INITIALIZER(struct cmd_clear_input_set_result,
				 cfg, "config");
cmdline_parse_token_num_t cmd_clear_input_set_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_clear_input_set_result,
			      port_id, UINT16);
cmdline_parse_token_string_t cmd_clear_input_set_pctype =
	TOKEN_STRING_INITIALIZER(struct cmd_clear_input_set_result,
				 pctype, "pctype");
cmdline_parse_token_num_t cmd_clear_input_set_pctype_id =
	TOKEN_NUM_INITIALIZER(struct cmd_clear_input_set_result,
			      pctype_id, UINT8);
cmdline_parse_token_string_t cmd_clear_input_set_inset_type =
	TOKEN_STRING_INITIALIZER(struct cmd_clear_input_set_result,
				 inset_type,
				 "hash_inset#fdir_inset#fdir_flx_inset");
cmdline_parse_token_string_t cmd_clear_input_set_clear =
	TOKEN_STRING_INITIALIZER(struct cmd_clear_input_set_result,
				 clear, "clear");
cmdline_parse_token_string_t cmd_clear_input_set_all =
	TOKEN_STRING_INITIALIZER(struct cmd_clear_input_set_result,
				 all, "all");

cmdline_parse_inst_t cmd_clear_input_set = {
	.f = cmd_clear_input_set_parsed,
	.data = NULL,
	.help_str = "port config <port_id> pctype <pctype_id> hash_inset|"
		    "fdir_inset|fdir_flx_inset clear all",
	.tokens = {
		(void *)&cmd_clear_input_set_port,
		(void *)&cmd_clear_input_set_cfg,
		(void *)&cmd_clear_input_set_port_id,
		(void *)&cmd_clear_input_set_pctype,
		(void *)&cmd_clear_input_set_pctype_id,
		(void *)&cmd_clear_input_set_inset_type,
		(void *)&cmd_clear_input_set_clear,
		(void *)&cmd_clear_input_set_all,
		NULL,
	},
};

/* show vf stats */

/* Common result structure for show vf stats */
struct cmd_show_vf_stats_result {
	cmdline_fixed_string_t show;
	cmdline_fixed_string_t vf;
	cmdline_fixed_string_t stats;
	portid_t port_id;
	uint16_t vf_id;
};

/* Common CLI fields show vf stats*/
cmdline_parse_token_string_t cmd_show_vf_stats_show =
	TOKEN_STRING_INITIALIZER
		(struct cmd_show_vf_stats_result,
		 show, "show");
cmdline_parse_token_string_t cmd_show_vf_stats_vf =
	TOKEN_STRING_INITIALIZER
		(struct cmd_show_vf_stats_result,
		 vf, "vf");
cmdline_parse_token_string_t cmd_show_vf_stats_stats =
	TOKEN_STRING_INITIALIZER
		(struct cmd_show_vf_stats_result,
		 stats, "stats");
cmdline_parse_token_num_t cmd_show_vf_stats_port_id =
	TOKEN_NUM_INITIALIZER
		(struct cmd_show_vf_stats_result,
		 port_id, UINT16);
cmdline_parse_token_num_t cmd_show_vf_stats_vf_id =
	TOKEN_NUM_INITIALIZER
		(struct cmd_show_vf_stats_result,
		 vf_id, UINT16);

static void
cmd_show_vf_stats_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_show_vf_stats_result *res = parsed_result;
	struct rte_eth_stats stats;
	int ret = -ENOTSUP;
	static const char *nic_stats_border = "########################";

	if (port_id_is_invalid(res->port_id, ENABLED_WARN))
		return;

	memset(&stats, 0, sizeof(stats));

#ifdef RTE_LIBRTE_I40E_PMD
	if (ret == -ENOTSUP)
		ret = rte_pmd_i40e_get_vf_stats(res->port_id,
						res->vf_id,
						&stats);
#endif
#ifdef RTE_LIBRTE_BNXT_PMD
	if (ret == -ENOTSUP)
		ret = rte_pmd_bnxt_get_vf_stats(res->port_id,
						res->vf_id,
						&stats);
#endif

	switch (ret) {
	case 0:
		break;
	case -EINVAL:
		printf("invalid vf_id %d\n", res->vf_id);
		break;
	case -ENODEV:
		printf("invalid port_id %d\n", res->port_id);
		break;
	case -ENOTSUP:
		printf("function not implemented\n");
		break;
	default:
		printf("programming error: (%s)\n", strerror(-ret));
	}

	printf("\n  %s NIC statistics for port %-2d vf %-2d %s\n",
		nic_stats_border, res->port_id, res->vf_id, nic_stats_border);

	printf("  RX-packets: %-10"PRIu64" RX-missed: %-10"PRIu64" RX-bytes:  "
	       "%-"PRIu64"\n",
	       stats.ipackets, stats.imissed, stats.ibytes);
	printf("  RX-errors: %-"PRIu64"\n", stats.ierrors);
	printf("  RX-nombuf:  %-10"PRIu64"\n",
	       stats.rx_nombuf);
	printf("  TX-packets: %-10"PRIu64" TX-errors: %-10"PRIu64" TX-bytes:  "
	       "%-"PRIu64"\n",
	       stats.opackets, stats.oerrors, stats.obytes);

	printf("  %s############################%s\n",
			       nic_stats_border, nic_stats_border);
}

cmdline_parse_inst_t cmd_show_vf_stats = {
	.f = cmd_show_vf_stats_parsed,
	.data = NULL,
	.help_str = "show vf stats <port_id> <vf_id>",
	.tokens = {
		(void *)&cmd_show_vf_stats_show,
		(void *)&cmd_show_vf_stats_vf,
		(void *)&cmd_show_vf_stats_stats,
		(void *)&cmd_show_vf_stats_port_id,
		(void *)&cmd_show_vf_stats_vf_id,
		NULL,
	},
};

/* clear vf stats */

/* Common result structure for clear vf stats */
struct cmd_clear_vf_stats_result {
	cmdline_fixed_string_t clear;
	cmdline_fixed_string_t vf;
	cmdline_fixed_string_t stats;
	portid_t port_id;
	uint16_t vf_id;
};

/* Common CLI fields clear vf stats*/
cmdline_parse_token_string_t cmd_clear_vf_stats_clear =
	TOKEN_STRING_INITIALIZER
		(struct cmd_clear_vf_stats_result,
		 clear, "clear");
cmdline_parse_token_string_t cmd_clear_vf_stats_vf =
	TOKEN_STRING_INITIALIZER
		(struct cmd_clear_vf_stats_result,
		 vf, "vf");
cmdline_parse_token_string_t cmd_clear_vf_stats_stats =
	TOKEN_STRING_INITIALIZER
		(struct cmd_clear_vf_stats_result,
		 stats, "stats");
cmdline_parse_token_num_t cmd_clear_vf_stats_port_id =
	TOKEN_NUM_INITIALIZER
		(struct cmd_clear_vf_stats_result,
		 port_id, UINT16);
cmdline_parse_token_num_t cmd_clear_vf_stats_vf_id =
	TOKEN_NUM_INITIALIZER
		(struct cmd_clear_vf_stats_result,
		 vf_id, UINT16);

static void
cmd_clear_vf_stats_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_clear_vf_stats_result *res = parsed_result;
	int ret = -ENOTSUP;

	if (port_id_is_invalid(res->port_id, ENABLED_WARN))
		return;

#ifdef RTE_LIBRTE_I40E_PMD
	if (ret == -ENOTSUP)
		ret = rte_pmd_i40e_reset_vf_stats(res->port_id,
						  res->vf_id);
#endif
#ifdef RTE_LIBRTE_BNXT_PMD
	if (ret == -ENOTSUP)
		ret = rte_pmd_bnxt_reset_vf_stats(res->port_id,
						  res->vf_id);
#endif

	switch (ret) {
	case 0:
		break;
	case -EINVAL:
		printf("invalid vf_id %d\n", res->vf_id);
		break;
	case -ENODEV:
		printf("invalid port_id %d\n", res->port_id);
		break;
	case -ENOTSUP:
		printf("function not implemented\n");
		break;
	default:
		printf("programming error: (%s)\n", strerror(-ret));
	}
}

cmdline_parse_inst_t cmd_clear_vf_stats = {
	.f = cmd_clear_vf_stats_parsed,
	.data = NULL,
	.help_str = "clear vf stats <port_id> <vf_id>",
	.tokens = {
		(void *)&cmd_clear_vf_stats_clear,
		(void *)&cmd_clear_vf_stats_vf,
		(void *)&cmd_clear_vf_stats_stats,
		(void *)&cmd_clear_vf_stats_port_id,
		(void *)&cmd_clear_vf_stats_vf_id,
		NULL,
	},
};

/* port config pctype mapping reset */

/* Common result structure for port config pctype mapping reset */
struct cmd_pctype_mapping_reset_result {
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t config;
	portid_t port_id;
	cmdline_fixed_string_t pctype;
	cmdline_fixed_string_t mapping;
	cmdline_fixed_string_t reset;
};

/* Common CLI fields for port config pctype mapping reset*/
cmdline_parse_token_string_t cmd_pctype_mapping_reset_port =
	TOKEN_STRING_INITIALIZER
		(struct cmd_pctype_mapping_reset_result,
		 port, "port");
cmdline_parse_token_string_t cmd_pctype_mapping_reset_config =
	TOKEN_STRING_INITIALIZER
		(struct cmd_pctype_mapping_reset_result,
		 config, "config");
cmdline_parse_token_num_t cmd_pctype_mapping_reset_port_id =
	TOKEN_NUM_INITIALIZER
		(struct cmd_pctype_mapping_reset_result,
		 port_id, UINT16);
cmdline_parse_token_string_t cmd_pctype_mapping_reset_pctype =
	TOKEN_STRING_INITIALIZER
		(struct cmd_pctype_mapping_reset_result,
		 pctype, "pctype");
cmdline_parse_token_string_t cmd_pctype_mapping_reset_mapping =
	TOKEN_STRING_INITIALIZER
		(struct cmd_pctype_mapping_reset_result,
		 mapping, "mapping");
cmdline_parse_token_string_t cmd_pctype_mapping_reset_reset =
	TOKEN_STRING_INITIALIZER
		(struct cmd_pctype_mapping_reset_result,
		 reset, "reset");

static void
cmd_pctype_mapping_reset_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_pctype_mapping_reset_result *res = parsed_result;
	int ret = -ENOTSUP;

	if (port_id_is_invalid(res->port_id, ENABLED_WARN))
		return;

#ifdef RTE_LIBRTE_I40E_PMD
	ret = rte_pmd_i40e_flow_type_mapping_reset(res->port_id);
#endif

	switch (ret) {
	case 0:
		break;
	case -ENODEV:
		printf("invalid port_id %d\n", res->port_id);
		break;
	case -ENOTSUP:
		printf("function not implemented\n");
		break;
	default:
		printf("programming error: (%s)\n", strerror(-ret));
	}
}

cmdline_parse_inst_t cmd_pctype_mapping_reset = {
	.f = cmd_pctype_mapping_reset_parsed,
	.data = NULL,
	.help_str = "port config <port_id> pctype mapping reset",
	.tokens = {
		(void *)&cmd_pctype_mapping_reset_port,
		(void *)&cmd_pctype_mapping_reset_config,
		(void *)&cmd_pctype_mapping_reset_port_id,
		(void *)&cmd_pctype_mapping_reset_pctype,
		(void *)&cmd_pctype_mapping_reset_mapping,
		(void *)&cmd_pctype_mapping_reset_reset,
		NULL,
	},
};

/* show port pctype mapping */

/* Common result structure for show port pctype mapping */
struct cmd_pctype_mapping_get_result {
	cmdline_fixed_string_t show;
	cmdline_fixed_string_t port;
	portid_t port_id;
	cmdline_fixed_string_t pctype;
	cmdline_fixed_string_t mapping;
};

/* Common CLI fields for pctype mapping get */
cmdline_parse_token_string_t cmd_pctype_mapping_get_show =
	TOKEN_STRING_INITIALIZER
		(struct cmd_pctype_mapping_get_result,
		 show, "show");
cmdline_parse_token_string_t cmd_pctype_mapping_get_port =
	TOKEN_STRING_INITIALIZER
		(struct cmd_pctype_mapping_get_result,
		 port, "port");
cmdline_parse_token_num_t cmd_pctype_mapping_get_port_id =
	TOKEN_NUM_INITIALIZER
		(struct cmd_pctype_mapping_get_result,
		 port_id, UINT16);
cmdline_parse_token_string_t cmd_pctype_mapping_get_pctype =
	TOKEN_STRING_INITIALIZER
		(struct cmd_pctype_mapping_get_result,
		 pctype, "pctype");
cmdline_parse_token_string_t cmd_pctype_mapping_get_mapping =
	TOKEN_STRING_INITIALIZER
		(struct cmd_pctype_mapping_get_result,
		 mapping, "mapping");

static void
cmd_pctype_mapping_get_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_pctype_mapping_get_result *res = parsed_result;
	int ret = -ENOTSUP;
#ifdef RTE_LIBRTE_I40E_PMD
	struct rte_pmd_i40e_flow_type_mapping
				mapping[RTE_PMD_I40E_FLOW_TYPE_MAX];
	int i, j, first_pctype;
#endif

	if (port_id_is_invalid(res->port_id, ENABLED_WARN))
		return;

#ifdef RTE_LIBRTE_I40E_PMD
	ret = rte_pmd_i40e_flow_type_mapping_get(res->port_id, mapping);
#endif

	switch (ret) {
	case 0:
		break;
	case -ENODEV:
		printf("invalid port_id %d\n", res->port_id);
		return;
	case -ENOTSUP:
		printf("function not implemented\n");
		return;
	default:
		printf("programming error: (%s)\n", strerror(-ret));
		return;
	}

#ifdef RTE_LIBRTE_I40E_PMD
	for (i = 0; i < RTE_PMD_I40E_FLOW_TYPE_MAX; i++) {
		if (mapping[i].pctype != 0ULL) {
			first_pctype = 1;

			printf("pctype: ");
			for (j = 0; j < RTE_PMD_I40E_PCTYPE_MAX; j++) {
				if (mapping[i].pctype & (1ULL << j)) {
					printf(first_pctype ?
					       "%02d" : ",%02d", j);
					first_pctype = 0;
				}
			}
			printf("  ->  flowtype: %02d\n", mapping[i].flow_type);
		}
	}
#endif
}

cmdline_parse_inst_t cmd_pctype_mapping_get = {
	.f = cmd_pctype_mapping_get_parsed,
	.data = NULL,
	.help_str = "show port <port_id> pctype mapping",
	.tokens = {
		(void *)&cmd_pctype_mapping_get_show,
		(void *)&cmd_pctype_mapping_get_port,
		(void *)&cmd_pctype_mapping_get_port_id,
		(void *)&cmd_pctype_mapping_get_pctype,
		(void *)&cmd_pctype_mapping_get_mapping,
		NULL,
	},
};

/* port config pctype mapping update */

/* Common result structure for port config pctype mapping update */
struct cmd_pctype_mapping_update_result {
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t config;
	portid_t port_id;
	cmdline_fixed_string_t pctype;
	cmdline_fixed_string_t mapping;
	cmdline_fixed_string_t update;
	cmdline_fixed_string_t pctype_list;
	uint16_t flow_type;
};

/* Common CLI fields for pctype mapping update*/
cmdline_parse_token_string_t cmd_pctype_mapping_update_port =
	TOKEN_STRING_INITIALIZER
		(struct cmd_pctype_mapping_update_result,
		 port, "port");
cmdline_parse_token_string_t cmd_pctype_mapping_update_config =
	TOKEN_STRING_INITIALIZER
		(struct cmd_pctype_mapping_update_result,
		 config, "config");
cmdline_parse_token_num_t cmd_pctype_mapping_update_port_id =
	TOKEN_NUM_INITIALIZER
		(struct cmd_pctype_mapping_update_result,
		 port_id, UINT16);
cmdline_parse_token_string_t cmd_pctype_mapping_update_pctype =
	TOKEN_STRING_INITIALIZER
		(struct cmd_pctype_mapping_update_result,
		 pctype, "pctype");
cmdline_parse_token_string_t cmd_pctype_mapping_update_mapping =
	TOKEN_STRING_INITIALIZER
		(struct cmd_pctype_mapping_update_result,
		 mapping, "mapping");
cmdline_parse_token_string_t cmd_pctype_mapping_update_update =
	TOKEN_STRING_INITIALIZER
		(struct cmd_pctype_mapping_update_result,
		 update, "update");
cmdline_parse_token_string_t cmd_pctype_mapping_update_pc_type =
	TOKEN_STRING_INITIALIZER
		(struct cmd_pctype_mapping_update_result,
		 pctype_list, NULL);
cmdline_parse_token_num_t cmd_pctype_mapping_update_flow_type =
	TOKEN_NUM_INITIALIZER
		(struct cmd_pctype_mapping_update_result,
		 flow_type, UINT16);

static void
cmd_pctype_mapping_update_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_pctype_mapping_update_result *res = parsed_result;
	int ret = -ENOTSUP;
#ifdef RTE_LIBRTE_I40E_PMD
	struct rte_pmd_i40e_flow_type_mapping mapping;
	unsigned int i;
	unsigned int nb_item;
	unsigned int pctype_list[RTE_PMD_I40E_PCTYPE_MAX];
#endif

	if (port_id_is_invalid(res->port_id, ENABLED_WARN))
		return;

#ifdef RTE_LIBRTE_I40E_PMD
	nb_item = parse_item_list(res->pctype_list, "pctypes",
				  RTE_PMD_I40E_PCTYPE_MAX, pctype_list, 1);
	mapping.flow_type = res->flow_type;
	for (i = 0, mapping.pctype = 0ULL; i < nb_item; i++)
		mapping.pctype |= (1ULL << pctype_list[i]);
	ret = rte_pmd_i40e_flow_type_mapping_update(res->port_id,
						&mapping,
						1,
						0);
#endif

	switch (ret) {
	case 0:
		break;
	case -EINVAL:
		printf("invalid pctype or flow type\n");
		break;
	case -ENODEV:
		printf("invalid port_id %d\n", res->port_id);
		break;
	case -ENOTSUP:
		printf("function not implemented\n");
		break;
	default:
		printf("programming error: (%s)\n", strerror(-ret));
	}
}

cmdline_parse_inst_t cmd_pctype_mapping_update = {
	.f = cmd_pctype_mapping_update_parsed,
	.data = NULL,
	.help_str = "port config <port_id> pctype mapping update"
	" <pctype_id_0,[pctype_id_1]*> <flowtype_id>",
	.tokens = {
		(void *)&cmd_pctype_mapping_update_port,
		(void *)&cmd_pctype_mapping_update_config,
		(void *)&cmd_pctype_mapping_update_port_id,
		(void *)&cmd_pctype_mapping_update_pctype,
		(void *)&cmd_pctype_mapping_update_mapping,
		(void *)&cmd_pctype_mapping_update_update,
		(void *)&cmd_pctype_mapping_update_pc_type,
		(void *)&cmd_pctype_mapping_update_flow_type,
		NULL,
	},
};

/* ptype mapping get */

/* Common result structure for ptype mapping get */
struct cmd_ptype_mapping_get_result {
	cmdline_fixed_string_t ptype;
	cmdline_fixed_string_t mapping;
	cmdline_fixed_string_t get;
	portid_t port_id;
	uint8_t valid_only;
};

/* Common CLI fields for ptype mapping get */
cmdline_parse_token_string_t cmd_ptype_mapping_get_ptype =
	TOKEN_STRING_INITIALIZER
		(struct cmd_ptype_mapping_get_result,
		 ptype, "ptype");
cmdline_parse_token_string_t cmd_ptype_mapping_get_mapping =
	TOKEN_STRING_INITIALIZER
		(struct cmd_ptype_mapping_get_result,
		 mapping, "mapping");
cmdline_parse_token_string_t cmd_ptype_mapping_get_get =
	TOKEN_STRING_INITIALIZER
		(struct cmd_ptype_mapping_get_result,
		 get, "get");
cmdline_parse_token_num_t cmd_ptype_mapping_get_port_id =
	TOKEN_NUM_INITIALIZER
		(struct cmd_ptype_mapping_get_result,
		 port_id, UINT16);
cmdline_parse_token_num_t cmd_ptype_mapping_get_valid_only =
	TOKEN_NUM_INITIALIZER
		(struct cmd_ptype_mapping_get_result,
		 valid_only, UINT8);

static void
cmd_ptype_mapping_get_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_ptype_mapping_get_result *res = parsed_result;
	int ret = -ENOTSUP;
#ifdef RTE_LIBRTE_I40E_PMD
	int max_ptype_num = 256;
	struct rte_pmd_i40e_ptype_mapping mapping[max_ptype_num];
	uint16_t count;
	int i;
#endif

	if (port_id_is_invalid(res->port_id, ENABLED_WARN))
		return;

#ifdef RTE_LIBRTE_I40E_PMD
	ret = rte_pmd_i40e_ptype_mapping_get(res->port_id,
					mapping,
					max_ptype_num,
					&count,
					res->valid_only);
#endif

	switch (ret) {
	case 0:
		break;
	case -ENODEV:
		printf("invalid port_id %d\n", res->port_id);
		break;
	case -ENOTSUP:
		printf("function not implemented\n");
		break;
	default:
		printf("programming error: (%s)\n", strerror(-ret));
	}

#ifdef RTE_LIBRTE_I40E_PMD
	if (!ret) {
		for (i = 0; i < count; i++)
			printf("%3d\t0x%08x\n",
				mapping[i].hw_ptype, mapping[i].sw_ptype);
	}
#endif
}

cmdline_parse_inst_t cmd_ptype_mapping_get = {
	.f = cmd_ptype_mapping_get_parsed,
	.data = NULL,
	.help_str = "ptype mapping get <port_id> <valid_only>",
	.tokens = {
		(void *)&cmd_ptype_mapping_get_ptype,
		(void *)&cmd_ptype_mapping_get_mapping,
		(void *)&cmd_ptype_mapping_get_get,
		(void *)&cmd_ptype_mapping_get_port_id,
		(void *)&cmd_ptype_mapping_get_valid_only,
		NULL,
	},
};

/* ptype mapping replace */

/* Common result structure for ptype mapping replace */
struct cmd_ptype_mapping_replace_result {
	cmdline_fixed_string_t ptype;
	cmdline_fixed_string_t mapping;
	cmdline_fixed_string_t replace;
	portid_t port_id;
	uint32_t target;
	uint8_t mask;
	uint32_t pkt_type;
};

/* Common CLI fields for ptype mapping replace */
cmdline_parse_token_string_t cmd_ptype_mapping_replace_ptype =
	TOKEN_STRING_INITIALIZER
		(struct cmd_ptype_mapping_replace_result,
		 ptype, "ptype");
cmdline_parse_token_string_t cmd_ptype_mapping_replace_mapping =
	TOKEN_STRING_INITIALIZER
		(struct cmd_ptype_mapping_replace_result,
		 mapping, "mapping");
cmdline_parse_token_string_t cmd_ptype_mapping_replace_replace =
	TOKEN_STRING_INITIALIZER
		(struct cmd_ptype_mapping_replace_result,
		 replace, "replace");
cmdline_parse_token_num_t cmd_ptype_mapping_replace_port_id =
	TOKEN_NUM_INITIALIZER
		(struct cmd_ptype_mapping_replace_result,
		 port_id, UINT16);
cmdline_parse_token_num_t cmd_ptype_mapping_replace_target =
	TOKEN_NUM_INITIALIZER
		(struct cmd_ptype_mapping_replace_result,
		 target, UINT32);
cmdline_parse_token_num_t cmd_ptype_mapping_replace_mask =
	TOKEN_NUM_INITIALIZER
		(struct cmd_ptype_mapping_replace_result,
		 mask, UINT8);
cmdline_parse_token_num_t cmd_ptype_mapping_replace_pkt_type =
	TOKEN_NUM_INITIALIZER
		(struct cmd_ptype_mapping_replace_result,
		 pkt_type, UINT32);

static void
cmd_ptype_mapping_replace_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_ptype_mapping_replace_result *res = parsed_result;
	int ret = -ENOTSUP;

	if (port_id_is_invalid(res->port_id, ENABLED_WARN))
		return;

#ifdef RTE_LIBRTE_I40E_PMD
	ret = rte_pmd_i40e_ptype_mapping_replace(res->port_id,
					res->target,
					res->mask,
					res->pkt_type);
#endif

	switch (ret) {
	case 0:
		break;
	case -EINVAL:
		printf("invalid ptype 0x%8x or 0x%8x\n",
				res->target, res->pkt_type);
		break;
	case -ENODEV:
		printf("invalid port_id %d\n", res->port_id);
		break;
	case -ENOTSUP:
		printf("function not implemented\n");
		break;
	default:
		printf("programming error: (%s)\n", strerror(-ret));
	}
}

cmdline_parse_inst_t cmd_ptype_mapping_replace = {
	.f = cmd_ptype_mapping_replace_parsed,
	.data = NULL,
	.help_str =
		"ptype mapping replace <port_id> <target> <mask> <pkt_type>",
	.tokens = {
		(void *)&cmd_ptype_mapping_replace_ptype,
		(void *)&cmd_ptype_mapping_replace_mapping,
		(void *)&cmd_ptype_mapping_replace_replace,
		(void *)&cmd_ptype_mapping_replace_port_id,
		(void *)&cmd_ptype_mapping_replace_target,
		(void *)&cmd_ptype_mapping_replace_mask,
		(void *)&cmd_ptype_mapping_replace_pkt_type,
		NULL,
	},
};

/* ptype mapping reset */

/* Common result structure for ptype mapping reset */
struct cmd_ptype_mapping_reset_result {
	cmdline_fixed_string_t ptype;
	cmdline_fixed_string_t mapping;
	cmdline_fixed_string_t reset;
	portid_t port_id;
};

/* Common CLI fields for ptype mapping reset*/
cmdline_parse_token_string_t cmd_ptype_mapping_reset_ptype =
	TOKEN_STRING_INITIALIZER
		(struct cmd_ptype_mapping_reset_result,
		 ptype, "ptype");
cmdline_parse_token_string_t cmd_ptype_mapping_reset_mapping =
	TOKEN_STRING_INITIALIZER
		(struct cmd_ptype_mapping_reset_result,
		 mapping, "mapping");
cmdline_parse_token_string_t cmd_ptype_mapping_reset_reset =
	TOKEN_STRING_INITIALIZER
		(struct cmd_ptype_mapping_reset_result,
		 reset, "reset");
cmdline_parse_token_num_t cmd_ptype_mapping_reset_port_id =
	TOKEN_NUM_INITIALIZER
		(struct cmd_ptype_mapping_reset_result,
		 port_id, UINT16);

static void
cmd_ptype_mapping_reset_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_ptype_mapping_reset_result *res = parsed_result;
	int ret = -ENOTSUP;

	if (port_id_is_invalid(res->port_id, ENABLED_WARN))
		return;

#ifdef RTE_LIBRTE_I40E_PMD
	ret = rte_pmd_i40e_ptype_mapping_reset(res->port_id);
#endif

	switch (ret) {
	case 0:
		break;
	case -ENODEV:
		printf("invalid port_id %d\n", res->port_id);
		break;
	case -ENOTSUP:
		printf("function not implemented\n");
		break;
	default:
		printf("programming error: (%s)\n", strerror(-ret));
	}
}

cmdline_parse_inst_t cmd_ptype_mapping_reset = {
	.f = cmd_ptype_mapping_reset_parsed,
	.data = NULL,
	.help_str = "ptype mapping reset <port_id>",
	.tokens = {
		(void *)&cmd_ptype_mapping_reset_ptype,
		(void *)&cmd_ptype_mapping_reset_mapping,
		(void *)&cmd_ptype_mapping_reset_reset,
		(void *)&cmd_ptype_mapping_reset_port_id,
		NULL,
	},
};

/* ptype mapping update */

/* Common result structure for ptype mapping update */
struct cmd_ptype_mapping_update_result {
	cmdline_fixed_string_t ptype;
	cmdline_fixed_string_t mapping;
	cmdline_fixed_string_t reset;
	portid_t port_id;
	uint8_t hw_ptype;
	uint32_t sw_ptype;
};

/* Common CLI fields for ptype mapping update*/
cmdline_parse_token_string_t cmd_ptype_mapping_update_ptype =
	TOKEN_STRING_INITIALIZER
		(struct cmd_ptype_mapping_update_result,
		 ptype, "ptype");
cmdline_parse_token_string_t cmd_ptype_mapping_update_mapping =
	TOKEN_STRING_INITIALIZER
		(struct cmd_ptype_mapping_update_result,
		 mapping, "mapping");
cmdline_parse_token_string_t cmd_ptype_mapping_update_update =
	TOKEN_STRING_INITIALIZER
		(struct cmd_ptype_mapping_update_result,
		 reset, "update");
cmdline_parse_token_num_t cmd_ptype_mapping_update_port_id =
	TOKEN_NUM_INITIALIZER
		(struct cmd_ptype_mapping_update_result,
		 port_id, UINT16);
cmdline_parse_token_num_t cmd_ptype_mapping_update_hw_ptype =
	TOKEN_NUM_INITIALIZER
		(struct cmd_ptype_mapping_update_result,
		 hw_ptype, UINT8);
cmdline_parse_token_num_t cmd_ptype_mapping_update_sw_ptype =
	TOKEN_NUM_INITIALIZER
		(struct cmd_ptype_mapping_update_result,
		 sw_ptype, UINT32);

static void
cmd_ptype_mapping_update_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_ptype_mapping_update_result *res = parsed_result;
	int ret = -ENOTSUP;
#ifdef RTE_LIBRTE_I40E_PMD
	struct rte_pmd_i40e_ptype_mapping mapping;
#endif
	if (port_id_is_invalid(res->port_id, ENABLED_WARN))
		return;

#ifdef RTE_LIBRTE_I40E_PMD
	mapping.hw_ptype = res->hw_ptype;
	mapping.sw_ptype = res->sw_ptype;
	ret = rte_pmd_i40e_ptype_mapping_update(res->port_id,
						&mapping,
						1,
						0);
#endif

	switch (ret) {
	case 0:
		break;
	case -EINVAL:
		printf("invalid ptype 0x%8x\n", res->sw_ptype);
		break;
	case -ENODEV:
		printf("invalid port_id %d\n", res->port_id);
		break;
	case -ENOTSUP:
		printf("function not implemented\n");
		break;
	default:
		printf("programming error: (%s)\n", strerror(-ret));
	}
}

cmdline_parse_inst_t cmd_ptype_mapping_update = {
	.f = cmd_ptype_mapping_update_parsed,
	.data = NULL,
	.help_str = "ptype mapping update <port_id> <hw_ptype> <sw_ptype>",
	.tokens = {
		(void *)&cmd_ptype_mapping_update_ptype,
		(void *)&cmd_ptype_mapping_update_mapping,
		(void *)&cmd_ptype_mapping_update_update,
		(void *)&cmd_ptype_mapping_update_port_id,
		(void *)&cmd_ptype_mapping_update_hw_ptype,
		(void *)&cmd_ptype_mapping_update_sw_ptype,
		NULL,
	},
};

/* Common result structure for file commands */
struct cmd_cmdfile_result {
	cmdline_fixed_string_t load;
	cmdline_fixed_string_t filename;
};

/* Common CLI fields for file commands */
cmdline_parse_token_string_t cmd_load_cmdfile =
	TOKEN_STRING_INITIALIZER(struct cmd_cmdfile_result, load, "load");
cmdline_parse_token_string_t cmd_load_cmdfile_filename =
	TOKEN_STRING_INITIALIZER(struct cmd_cmdfile_result, filename, NULL);

static void
cmd_load_from_file_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_cmdfile_result *res = parsed_result;

	cmdline_read_from_file(res->filename);
}

cmdline_parse_inst_t cmd_load_from_file = {
	.f = cmd_load_from_file_parsed,
	.data = NULL,
	.help_str = "load <filename>",
	.tokens = {
		(void *)&cmd_load_cmdfile,
		(void *)&cmd_load_cmdfile_filename,
		NULL,
	},
};

/* Get Rx offloads capabilities */
struct cmd_rx_offload_get_capa_result {
	cmdline_fixed_string_t show;
	cmdline_fixed_string_t port;
	portid_t port_id;
	cmdline_fixed_string_t rx_offload;
	cmdline_fixed_string_t capabilities;
};

cmdline_parse_token_string_t cmd_rx_offload_get_capa_show =
	TOKEN_STRING_INITIALIZER
		(struct cmd_rx_offload_get_capa_result,
		 show, "show");
cmdline_parse_token_string_t cmd_rx_offload_get_capa_port =
	TOKEN_STRING_INITIALIZER
		(struct cmd_rx_offload_get_capa_result,
		 port, "port");
cmdline_parse_token_num_t cmd_rx_offload_get_capa_port_id =
	TOKEN_NUM_INITIALIZER
		(struct cmd_rx_offload_get_capa_result,
		 port_id, UINT16);
cmdline_parse_token_string_t cmd_rx_offload_get_capa_rx_offload =
	TOKEN_STRING_INITIALIZER
		(struct cmd_rx_offload_get_capa_result,
		 rx_offload, "rx_offload");
cmdline_parse_token_string_t cmd_rx_offload_get_capa_capabilities =
	TOKEN_STRING_INITIALIZER
		(struct cmd_rx_offload_get_capa_result,
		 capabilities, "capabilities");

static void
print_rx_offloads(uint64_t offloads)
{
	uint64_t single_offload;
	int begin;
	int end;
	int bit;

	if (offloads == 0)
		return;

	begin = __builtin_ctzll(offloads);
	end = sizeof(offloads) * CHAR_BIT - __builtin_clzll(offloads);

	single_offload = 1ULL << begin;
	for (bit = begin; bit < end; bit++) {
		if (offloads & single_offload)
			printf(" %s",
			       rte_eth_dev_rx_offload_name(single_offload));
		single_offload <<= 1;
	}
}

static void
cmd_rx_offload_get_capa_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_rx_offload_get_capa_result *res = parsed_result;
	struct rte_eth_dev_info dev_info;
	portid_t port_id = res->port_id;
	uint64_t queue_offloads;
	uint64_t port_offloads;

	rte_eth_dev_info_get(port_id, &dev_info);
	queue_offloads = dev_info.rx_queue_offload_capa;
	port_offloads = dev_info.rx_offload_capa ^ queue_offloads;

	printf("Rx Offloading Capabilities of port %d :\n", port_id);
	printf("  Per Queue :");
	print_rx_offloads(queue_offloads);

	printf("\n");
	printf("  Per Port  :");
	print_rx_offloads(port_offloads);
	printf("\n\n");
}

cmdline_parse_inst_t cmd_rx_offload_get_capa = {
	.f = cmd_rx_offload_get_capa_parsed,
	.data = NULL,
	.help_str = "show port <port_id> rx_offload capabilities",
	.tokens = {
		(void *)&cmd_rx_offload_get_capa_show,
		(void *)&cmd_rx_offload_get_capa_port,
		(void *)&cmd_rx_offload_get_capa_port_id,
		(void *)&cmd_rx_offload_get_capa_rx_offload,
		(void *)&cmd_rx_offload_get_capa_capabilities,
		NULL,
	}
};

/* Get Rx offloads configuration */
struct cmd_rx_offload_get_configuration_result {
	cmdline_fixed_string_t show;
	cmdline_fixed_string_t port;
	portid_t port_id;
	cmdline_fixed_string_t rx_offload;
	cmdline_fixed_string_t configuration;
};

cmdline_parse_token_string_t cmd_rx_offload_get_configuration_show =
	TOKEN_STRING_INITIALIZER
		(struct cmd_rx_offload_get_configuration_result,
		 show, "show");
cmdline_parse_token_string_t cmd_rx_offload_get_configuration_port =
	TOKEN_STRING_INITIALIZER
		(struct cmd_rx_offload_get_configuration_result,
		 port, "port");
cmdline_parse_token_num_t cmd_rx_offload_get_configuration_port_id =
	TOKEN_NUM_INITIALIZER
		(struct cmd_rx_offload_get_configuration_result,
		 port_id, UINT16);
cmdline_parse_token_string_t cmd_rx_offload_get_configuration_rx_offload =
	TOKEN_STRING_INITIALIZER
		(struct cmd_rx_offload_get_configuration_result,
		 rx_offload, "rx_offload");
cmdline_parse_token_string_t cmd_rx_offload_get_configuration_configuration =
	TOKEN_STRING_INITIALIZER
		(struct cmd_rx_offload_get_configuration_result,
		 configuration, "configuration");

static void
cmd_rx_offload_get_configuration_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_rx_offload_get_configuration_result *res = parsed_result;
	struct rte_eth_dev_info dev_info;
	portid_t port_id = res->port_id;
	struct rte_port *port = &ports[port_id];
	uint64_t port_offloads;
	uint64_t queue_offloads;
	uint16_t nb_rx_queues;
	int q;

	printf("Rx Offloading Configuration of port %d :\n", port_id);

	port_offloads = port->dev_conf.rxmode.offloads;
	printf("  Port :");
	print_rx_offloads(port_offloads);
	printf("\n");

	rte_eth_dev_info_get(port_id, &dev_info);
	nb_rx_queues = dev_info.nb_rx_queues;
	for (q = 0; q < nb_rx_queues; q++) {
		queue_offloads = port->rx_conf[q].offloads;
		printf("  Queue[%2d] :", q);
		print_rx_offloads(queue_offloads);
		printf("\n");
	}
	printf("\n");
}

cmdline_parse_inst_t cmd_rx_offload_get_configuration = {
	.f = cmd_rx_offload_get_configuration_parsed,
	.data = NULL,
	.help_str = "show port <port_id> rx_offload configuration",
	.tokens = {
		(void *)&cmd_rx_offload_get_configuration_show,
		(void *)&cmd_rx_offload_get_configuration_port,
		(void *)&cmd_rx_offload_get_configuration_port_id,
		(void *)&cmd_rx_offload_get_configuration_rx_offload,
		(void *)&cmd_rx_offload_get_configuration_configuration,
		NULL,
	}
};

/* Enable/Disable a per port offloading */
struct cmd_config_per_port_rx_offload_result {
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t config;
	portid_t port_id;
	cmdline_fixed_string_t rx_offload;
	cmdline_fixed_string_t offload;
	cmdline_fixed_string_t on_off;
};

cmdline_parse_token_string_t cmd_config_per_port_rx_offload_result_port =
	TOKEN_STRING_INITIALIZER
		(struct cmd_config_per_port_rx_offload_result,
		 port, "port");
cmdline_parse_token_string_t cmd_config_per_port_rx_offload_result_config =
	TOKEN_STRING_INITIALIZER
		(struct cmd_config_per_port_rx_offload_result,
		 config, "config");
cmdline_parse_token_num_t cmd_config_per_port_rx_offload_result_port_id =
	TOKEN_NUM_INITIALIZER
		(struct cmd_config_per_port_rx_offload_result,
		 port_id, UINT16);
cmdline_parse_token_string_t cmd_config_per_port_rx_offload_result_rx_offload =
	TOKEN_STRING_INITIALIZER
		(struct cmd_config_per_port_rx_offload_result,
		 rx_offload, "rx_offload");
cmdline_parse_token_string_t cmd_config_per_port_rx_offload_result_offload =
	TOKEN_STRING_INITIALIZER
		(struct cmd_config_per_port_rx_offload_result,
		 offload, "vlan_strip#ipv4_cksum#udp_cksum#tcp_cksum#tcp_lro#"
			   "qinq_strip#outer_ipv4_cksum#macsec_strip#"
			   "header_split#vlan_filter#vlan_extend#jumbo_frame#"
			   "crc_strip#scatter#timestamp#security#keep_crc");
cmdline_parse_token_string_t cmd_config_per_port_rx_offload_result_on_off =
	TOKEN_STRING_INITIALIZER
		(struct cmd_config_per_port_rx_offload_result,
		 on_off, "on#off");

static uint64_t
search_rx_offload(const char *name)
{
	uint64_t single_offload;
	const char *single_name;
	int found = 0;
	unsigned int bit;

	single_offload = 1;
	for (bit = 0; bit < sizeof(single_offload) * CHAR_BIT; bit++) {
		single_name = rte_eth_dev_rx_offload_name(single_offload);
		if (!strcasecmp(single_name, name)) {
			found = 1;
			break;
		}
		single_offload <<= 1;
	}

	if (found)
		return single_offload;

	return 0;
}

static void
cmd_config_per_port_rx_offload_parsed(void *parsed_result,
				__attribute__((unused)) struct cmdline *cl,
				__attribute__((unused)) void *data)
{
	struct cmd_config_per_port_rx_offload_result *res = parsed_result;
	portid_t port_id = res->port_id;
	struct rte_eth_dev_info dev_info;
	struct rte_port *port = &ports[port_id];
	uint64_t single_offload;
	uint16_t nb_rx_queues;
	int q;

	if (port->port_status != RTE_PORT_STOPPED) {
		printf("Error: Can't config offload when Port %d "
		       "is not stopped\n", port_id);
		return;
	}

	single_offload = search_rx_offload(res->offload);
	if (single_offload == 0) {
		printf("Unknown offload name: %s\n", res->offload);
		return;
	}

	rte_eth_dev_info_get(port_id, &dev_info);
	nb_rx_queues = dev_info.nb_rx_queues;
	if (!strcmp(res->on_off, "on")) {
		port->dev_conf.rxmode.offloads |= single_offload;
		for (q = 0; q < nb_rx_queues; q++)
			port->rx_conf[q].offloads |= single_offload;
	} else {
		port->dev_conf.rxmode.offloads &= ~single_offload;
		for (q = 0; q < nb_rx_queues; q++)
			port->rx_conf[q].offloads &= ~single_offload;
	}

	cmd_reconfig_device_queue(port_id, 1, 1);
}

cmdline_parse_inst_t cmd_config_per_port_rx_offload = {
	.f = cmd_config_per_port_rx_offload_parsed,
	.data = NULL,
	.help_str = "port config <port_id> rx_offload vlan_strip|ipv4_cksum|"
		    "udp_cksum|tcp_cksum|tcp_lro|qinq_strip|outer_ipv4_cksum|"
		    "macsec_strip|header_split|vlan_filter|vlan_extend|"
		    "jumbo_frame|crc_strip|scatter|timestamp|security|keep_crc "
		    "on|off",
	.tokens = {
		(void *)&cmd_config_per_port_rx_offload_result_port,
		(void *)&cmd_config_per_port_rx_offload_result_config,
		(void *)&cmd_config_per_port_rx_offload_result_port_id,
		(void *)&cmd_config_per_port_rx_offload_result_rx_offload,
		(void *)&cmd_config_per_port_rx_offload_result_offload,
		(void *)&cmd_config_per_port_rx_offload_result_on_off,
		NULL,
	}
};

/* Enable/Disable a per queue offloading */
struct cmd_config_per_queue_rx_offload_result {
	cmdline_fixed_string_t port;
	portid_t port_id;
	cmdline_fixed_string_t rxq;
	uint16_t queue_id;
	cmdline_fixed_string_t rx_offload;
	cmdline_fixed_string_t offload;
	cmdline_fixed_string_t on_off;
};

cmdline_parse_token_string_t cmd_config_per_queue_rx_offload_result_port =
	TOKEN_STRING_INITIALIZER
		(struct cmd_config_per_queue_rx_offload_result,
		 port, "port");
cmdline_parse_token_num_t cmd_config_per_queue_rx_offload_result_port_id =
	TOKEN_NUM_INITIALIZER
		(struct cmd_config_per_queue_rx_offload_result,
		 port_id, UINT16);
cmdline_parse_token_string_t cmd_config_per_queue_rx_offload_result_rxq =
	TOKEN_STRING_INITIALIZER
		(struct cmd_config_per_queue_rx_offload_result,
		 rxq, "rxq");
cmdline_parse_token_num_t cmd_config_per_queue_rx_offload_result_queue_id =
	TOKEN_NUM_INITIALIZER
		(struct cmd_config_per_queue_rx_offload_result,
		 queue_id, UINT16);
cmdline_parse_token_string_t cmd_config_per_queue_rx_offload_result_rxoffload =
	TOKEN_STRING_INITIALIZER
		(struct cmd_config_per_queue_rx_offload_result,
		 rx_offload, "rx_offload");
cmdline_parse_token_string_t cmd_config_per_queue_rx_offload_result_offload =
	TOKEN_STRING_INITIALIZER
		(struct cmd_config_per_queue_rx_offload_result,
		 offload, "vlan_strip#ipv4_cksum#udp_cksum#tcp_cksum#tcp_lro#"
			   "qinq_strip#outer_ipv4_cksum#macsec_strip#"
			   "header_split#vlan_filter#vlan_extend#jumbo_frame#"
			   "crc_strip#scatter#timestamp#security#keep_crc");
cmdline_parse_token_string_t cmd_config_per_queue_rx_offload_result_on_off =
	TOKEN_STRING_INITIALIZER
		(struct cmd_config_per_queue_rx_offload_result,
		 on_off, "on#off");

static void
cmd_config_per_queue_rx_offload_parsed(void *parsed_result,
				__attribute__((unused)) struct cmdline *cl,
				__attribute__((unused)) void *data)
{
	struct cmd_config_per_queue_rx_offload_result *res = parsed_result;
	struct rte_eth_dev_info dev_info;
	portid_t port_id = res->port_id;
	uint16_t queue_id = res->queue_id;
	struct rte_port *port = &ports[port_id];
	uint64_t single_offload;

	if (port->port_status != RTE_PORT_STOPPED) {
		printf("Error: Can't config offload when Port %d "
		       "is not stopped\n", port_id);
		return;
	}

	rte_eth_dev_info_get(port_id, &dev_info);
	if (queue_id >= dev_info.nb_rx_queues) {
		printf("Error: input queue_id should be 0 ... "
		       "%d\n", dev_info.nb_rx_queues - 1);
		return;
	}

	single_offload = search_rx_offload(res->offload);
	if (single_offload == 0) {
		printf("Unknown offload name: %s\n", res->offload);
		return;
	}

	if (!strcmp(res->on_off, "on"))
		port->rx_conf[queue_id].offloads |= single_offload;
	else
		port->rx_conf[queue_id].offloads &= ~single_offload;

	cmd_reconfig_device_queue(port_id, 1, 1);
}

cmdline_parse_inst_t cmd_config_per_queue_rx_offload = {
	.f = cmd_config_per_queue_rx_offload_parsed,
	.data = NULL,
	.help_str = "port <port_id> rxq <queue_id> rx_offload "
		    "vlan_strip|ipv4_cksum|"
		    "udp_cksum|tcp_cksum|tcp_lro|qinq_strip|outer_ipv4_cksum|"
		    "macsec_strip|header_split|vlan_filter|vlan_extend|"
		    "jumbo_frame|crc_strip|scatter|timestamp|security|keep_crc "
		    "on|off",
	.tokens = {
		(void *)&cmd_config_per_queue_rx_offload_result_port,
		(void *)&cmd_config_per_queue_rx_offload_result_port_id,
		(void *)&cmd_config_per_queue_rx_offload_result_rxq,
		(void *)&cmd_config_per_queue_rx_offload_result_queue_id,
		(void *)&cmd_config_per_queue_rx_offload_result_rxoffload,
		(void *)&cmd_config_per_queue_rx_offload_result_offload,
		(void *)&cmd_config_per_queue_rx_offload_result_on_off,
		NULL,
	}
};

/* Get Tx offloads capabilities */
struct cmd_tx_offload_get_capa_result {
	cmdline_fixed_string_t show;
	cmdline_fixed_string_t port;
	portid_t port_id;
	cmdline_fixed_string_t tx_offload;
	cmdline_fixed_string_t capabilities;
};

cmdline_parse_token_string_t cmd_tx_offload_get_capa_show =
	TOKEN_STRING_INITIALIZER
		(struct cmd_tx_offload_get_capa_result,
		 show, "show");
cmdline_parse_token_string_t cmd_tx_offload_get_capa_port =
	TOKEN_STRING_INITIALIZER
		(struct cmd_tx_offload_get_capa_result,
		 port, "port");
cmdline_parse_token_num_t cmd_tx_offload_get_capa_port_id =
	TOKEN_NUM_INITIALIZER
		(struct cmd_tx_offload_get_capa_result,
		 port_id, UINT16);
cmdline_parse_token_string_t cmd_tx_offload_get_capa_tx_offload =
	TOKEN_STRING_INITIALIZER
		(struct cmd_tx_offload_get_capa_result,
		 tx_offload, "tx_offload");
cmdline_parse_token_string_t cmd_tx_offload_get_capa_capabilities =
	TOKEN_STRING_INITIALIZER
		(struct cmd_tx_offload_get_capa_result,
		 capabilities, "capabilities");

static void
print_tx_offloads(uint64_t offloads)
{
	uint64_t single_offload;
	int begin;
	int end;
	int bit;

	if (offloads == 0)
		return;

	begin = __builtin_ctzll(offloads);
	end = sizeof(offloads) * CHAR_BIT - __builtin_clzll(offloads);

	single_offload = 1ULL << begin;
	for (bit = begin; bit < end; bit++) {
		if (offloads & single_offload)
			printf(" %s",
			       rte_eth_dev_tx_offload_name(single_offload));
		single_offload <<= 1;
	}
}

static void
cmd_tx_offload_get_capa_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_tx_offload_get_capa_result *res = parsed_result;
	struct rte_eth_dev_info dev_info;
	portid_t port_id = res->port_id;
	uint64_t queue_offloads;
	uint64_t port_offloads;

	rte_eth_dev_info_get(port_id, &dev_info);
	queue_offloads = dev_info.tx_queue_offload_capa;
	port_offloads = dev_info.tx_offload_capa ^ queue_offloads;

	printf("Tx Offloading Capabilities of port %d :\n", port_id);
	printf("  Per Queue :");
	print_tx_offloads(queue_offloads);

	printf("\n");
	printf("  Per Port  :");
	print_tx_offloads(port_offloads);
	printf("\n\n");
}

cmdline_parse_inst_t cmd_tx_offload_get_capa = {
	.f = cmd_tx_offload_get_capa_parsed,
	.data = NULL,
	.help_str = "show port <port_id> tx_offload capabilities",
	.tokens = {
		(void *)&cmd_tx_offload_get_capa_show,
		(void *)&cmd_tx_offload_get_capa_port,
		(void *)&cmd_tx_offload_get_capa_port_id,
		(void *)&cmd_tx_offload_get_capa_tx_offload,
		(void *)&cmd_tx_offload_get_capa_capabilities,
		NULL,
	}
};

/* Get Tx offloads configuration */
struct cmd_tx_offload_get_configuration_result {
	cmdline_fixed_string_t show;
	cmdline_fixed_string_t port;
	portid_t port_id;
	cmdline_fixed_string_t tx_offload;
	cmdline_fixed_string_t configuration;
};

cmdline_parse_token_string_t cmd_tx_offload_get_configuration_show =
	TOKEN_STRING_INITIALIZER
		(struct cmd_tx_offload_get_configuration_result,
		 show, "show");
cmdline_parse_token_string_t cmd_tx_offload_get_configuration_port =
	TOKEN_STRING_INITIALIZER
		(struct cmd_tx_offload_get_configuration_result,
		 port, "port");
cmdline_parse_token_num_t cmd_tx_offload_get_configuration_port_id =
	TOKEN_NUM_INITIALIZER
		(struct cmd_tx_offload_get_configuration_result,
		 port_id, UINT16);
cmdline_parse_token_string_t cmd_tx_offload_get_configuration_tx_offload =
	TOKEN_STRING_INITIALIZER
		(struct cmd_tx_offload_get_configuration_result,
		 tx_offload, "tx_offload");
cmdline_parse_token_string_t cmd_tx_offload_get_configuration_configuration =
	TOKEN_STRING_INITIALIZER
		(struct cmd_tx_offload_get_configuration_result,
		 configuration, "configuration");

static void
cmd_tx_offload_get_configuration_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_tx_offload_get_configuration_result *res = parsed_result;
	struct rte_eth_dev_info dev_info;
	portid_t port_id = res->port_id;
	struct rte_port *port = &ports[port_id];
	uint64_t port_offloads;
	uint64_t queue_offloads;
	uint16_t nb_tx_queues;
	int q;

	printf("Tx Offloading Configuration of port %d :\n", port_id);

	port_offloads = port->dev_conf.txmode.offloads;
	printf("  Port :");
	print_tx_offloads(port_offloads);
	printf("\n");

	rte_eth_dev_info_get(port_id, &dev_info);
	nb_tx_queues = dev_info.nb_tx_queues;
	for (q = 0; q < nb_tx_queues; q++) {
		queue_offloads = port->tx_conf[q].offloads;
		printf("  Queue[%2d] :", q);
		print_tx_offloads(queue_offloads);
		printf("\n");
	}
	printf("\n");
}

cmdline_parse_inst_t cmd_tx_offload_get_configuration = {
	.f = cmd_tx_offload_get_configuration_parsed,
	.data = NULL,
	.help_str = "show port <port_id> tx_offload configuration",
	.tokens = {
		(void *)&cmd_tx_offload_get_configuration_show,
		(void *)&cmd_tx_offload_get_configuration_port,
		(void *)&cmd_tx_offload_get_configuration_port_id,
		(void *)&cmd_tx_offload_get_configuration_tx_offload,
		(void *)&cmd_tx_offload_get_configuration_configuration,
		NULL,
	}
};

/* Enable/Disable a per port offloading */
struct cmd_config_per_port_tx_offload_result {
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t config;
	portid_t port_id;
	cmdline_fixed_string_t tx_offload;
	cmdline_fixed_string_t offload;
	cmdline_fixed_string_t on_off;
};

cmdline_parse_token_string_t cmd_config_per_port_tx_offload_result_port =
	TOKEN_STRING_INITIALIZER
		(struct cmd_config_per_port_tx_offload_result,
		 port, "port");
cmdline_parse_token_string_t cmd_config_per_port_tx_offload_result_config =
	TOKEN_STRING_INITIALIZER
		(struct cmd_config_per_port_tx_offload_result,
		 config, "config");
cmdline_parse_token_num_t cmd_config_per_port_tx_offload_result_port_id =
	TOKEN_NUM_INITIALIZER
		(struct cmd_config_per_port_tx_offload_result,
		 port_id, UINT16);
cmdline_parse_token_string_t cmd_config_per_port_tx_offload_result_tx_offload =
	TOKEN_STRING_INITIALIZER
		(struct cmd_config_per_port_tx_offload_result,
		 tx_offload, "tx_offload");
cmdline_parse_token_string_t cmd_config_per_port_tx_offload_result_offload =
	TOKEN_STRING_INITIALIZER
		(struct cmd_config_per_port_tx_offload_result,
		 offload, "vlan_insert#ipv4_cksum#udp_cksum#tcp_cksum#"
			  "sctp_cksum#tcp_tso#udp_tso#outer_ipv4_cksum#"
			  "qinq_insert#vxlan_tnl_tso#gre_tnl_tso#"
			  "ipip_tnl_tso#geneve_tnl_tso#macsec_insert#"
			  "mt_lockfree#multi_segs#mbuf_fast_free#security#"
			  "match_metadata");
cmdline_parse_token_string_t cmd_config_per_port_tx_offload_result_on_off =
	TOKEN_STRING_INITIALIZER
		(struct cmd_config_per_port_tx_offload_result,
		 on_off, "on#off");

static uint64_t
search_tx_offload(const char *name)
{
	uint64_t single_offload;
	const char *single_name;
	int found = 0;
	unsigned int bit;

	single_offload = 1;
	for (bit = 0; bit < sizeof(single_offload) * CHAR_BIT; bit++) {
		single_name = rte_eth_dev_tx_offload_name(single_offload);
		if (single_name == NULL)
			break;
		if (!strcasecmp(single_name, name)) {
			found = 1;
			break;
		} else if (!strcasecmp(single_name, "UNKNOWN"))
			break;
		single_offload <<= 1;
	}

	if (found)
		return single_offload;

	return 0;
}

static void
cmd_config_per_port_tx_offload_parsed(void *parsed_result,
				__attribute__((unused)) struct cmdline *cl,
				__attribute__((unused)) void *data)
{
	struct cmd_config_per_port_tx_offload_result *res = parsed_result;
	portid_t port_id = res->port_id;
	struct rte_eth_dev_info dev_info;
	struct rte_port *port = &ports[port_id];
	uint64_t single_offload;
	uint16_t nb_tx_queues;
	int q;

	if (port->port_status != RTE_PORT_STOPPED) {
		printf("Error: Can't config offload when Port %d "
		       "is not stopped\n", port_id);
		return;
	}

	single_offload = search_tx_offload(res->offload);
	if (single_offload == 0) {
		printf("Unknown offload name: %s\n", res->offload);
		return;
	}

	rte_eth_dev_info_get(port_id, &dev_info);
	nb_tx_queues = dev_info.nb_tx_queues;
	if (!strcmp(res->on_off, "on")) {
		port->dev_conf.txmode.offloads |= single_offload;
		for (q = 0; q < nb_tx_queues; q++)
			port->tx_conf[q].offloads |= single_offload;
	} else {
		port->dev_conf.txmode.offloads &= ~single_offload;
		for (q = 0; q < nb_tx_queues; q++)
			port->tx_conf[q].offloads &= ~single_offload;
	}

	cmd_reconfig_device_queue(port_id, 1, 1);
}

cmdline_parse_inst_t cmd_config_per_port_tx_offload = {
	.f = cmd_config_per_port_tx_offload_parsed,
	.data = NULL,
	.help_str = "port config <port_id> tx_offload "
		    "vlan_insert|ipv4_cksum|udp_cksum|tcp_cksum|"
		    "sctp_cksum|tcp_tso|udp_tso|outer_ipv4_cksum|"
		    "qinq_insert|vxlan_tnl_tso|gre_tnl_tso|"
		    "ipip_tnl_tso|geneve_tnl_tso|macsec_insert|"
		    "mt_lockfree|multi_segs|mbuf_fast_free|security|"
		    "match_metadata on|off",
	.tokens = {
		(void *)&cmd_config_per_port_tx_offload_result_port,
		(void *)&cmd_config_per_port_tx_offload_result_config,
		(void *)&cmd_config_per_port_tx_offload_result_port_id,
		(void *)&cmd_config_per_port_tx_offload_result_tx_offload,
		(void *)&cmd_config_per_port_tx_offload_result_offload,
		(void *)&cmd_config_per_port_tx_offload_result_on_off,
		NULL,
	}
};

/* Enable/Disable a per queue offloading */
struct cmd_config_per_queue_tx_offload_result {
	cmdline_fixed_string_t port;
	portid_t port_id;
	cmdline_fixed_string_t txq;
	uint16_t queue_id;
	cmdline_fixed_string_t tx_offload;
	cmdline_fixed_string_t offload;
	cmdline_fixed_string_t on_off;
};

cmdline_parse_token_string_t cmd_config_per_queue_tx_offload_result_port =
	TOKEN_STRING_INITIALIZER
		(struct cmd_config_per_queue_tx_offload_result,
		 port, "port");
cmdline_parse_token_num_t cmd_config_per_queue_tx_offload_result_port_id =
	TOKEN_NUM_INITIALIZER
		(struct cmd_config_per_queue_tx_offload_result,
		 port_id, UINT16);
cmdline_parse_token_string_t cmd_config_per_queue_tx_offload_result_txq =
	TOKEN_STRING_INITIALIZER
		(struct cmd_config_per_queue_tx_offload_result,
		 txq, "txq");
cmdline_parse_token_num_t cmd_config_per_queue_tx_offload_result_queue_id =
	TOKEN_NUM_INITIALIZER
		(struct cmd_config_per_queue_tx_offload_result,
		 queue_id, UINT16);
cmdline_parse_token_string_t cmd_config_per_queue_tx_offload_result_txoffload =
	TOKEN_STRING_INITIALIZER
		(struct cmd_config_per_queue_tx_offload_result,
		 tx_offload, "tx_offload");
cmdline_parse_token_string_t cmd_config_per_queue_tx_offload_result_offload =
	TOKEN_STRING_INITIALIZER
		(struct cmd_config_per_queue_tx_offload_result,
		 offload, "vlan_insert#ipv4_cksum#udp_cksum#tcp_cksum#"
			  "sctp_cksum#tcp_tso#udp_tso#outer_ipv4_cksum#"
			  "qinq_insert#vxlan_tnl_tso#gre_tnl_tso#"
			  "ipip_tnl_tso#geneve_tnl_tso#macsec_insert#"
			  "mt_lockfree#multi_segs#mbuf_fast_free#security");
cmdline_parse_token_string_t cmd_config_per_queue_tx_offload_result_on_off =
	TOKEN_STRING_INITIALIZER
		(struct cmd_config_per_queue_tx_offload_result,
		 on_off, "on#off");

static void
cmd_config_per_queue_tx_offload_parsed(void *parsed_result,
				__attribute__((unused)) struct cmdline *cl,
				__attribute__((unused)) void *data)
{
	struct cmd_config_per_queue_tx_offload_result *res = parsed_result;
	struct rte_eth_dev_info dev_info;
	portid_t port_id = res->port_id;
	uint16_t queue_id = res->queue_id;
	struct rte_port *port = &ports[port_id];
	uint64_t single_offload;

	if (port->port_status != RTE_PORT_STOPPED) {
		printf("Error: Can't config offload when Port %d "
		       "is not stopped\n", port_id);
		return;
	}

	rte_eth_dev_info_get(port_id, &dev_info);
	if (queue_id >= dev_info.nb_tx_queues) {
		printf("Error: input queue_id should be 0 ... "
		       "%d\n", dev_info.nb_tx_queues - 1);
		return;
	}

	single_offload = search_tx_offload(res->offload);
	if (single_offload == 0) {
		printf("Unknown offload name: %s\n", res->offload);
		return;
	}

	if (!strcmp(res->on_off, "on"))
		port->tx_conf[queue_id].offloads |= single_offload;
	else
		port->tx_conf[queue_id].offloads &= ~single_offload;

	cmd_reconfig_device_queue(port_id, 1, 1);
}

cmdline_parse_inst_t cmd_config_per_queue_tx_offload = {
	.f = cmd_config_per_queue_tx_offload_parsed,
	.data = NULL,
	.help_str = "port <port_id> txq <queue_id> tx_offload "
		    "vlan_insert|ipv4_cksum|udp_cksum|tcp_cksum|"
		    "sctp_cksum|tcp_tso|udp_tso|outer_ipv4_cksum|"
		    "qinq_insert|vxlan_tnl_tso|gre_tnl_tso|"
		    "ipip_tnl_tso|geneve_tnl_tso|macsec_insert|"
		    "mt_lockfree|multi_segs|mbuf_fast_free|security "
		    "on|off",
	.tokens = {
		(void *)&cmd_config_per_queue_tx_offload_result_port,
		(void *)&cmd_config_per_queue_tx_offload_result_port_id,
		(void *)&cmd_config_per_queue_tx_offload_result_txq,
		(void *)&cmd_config_per_queue_tx_offload_result_queue_id,
		(void *)&cmd_config_per_queue_tx_offload_result_txoffload,
		(void *)&cmd_config_per_queue_tx_offload_result_offload,
		(void *)&cmd_config_per_queue_tx_offload_result_on_off,
		NULL,
	}
};

/* *** configure tx_metadata for specific port *** */
struct cmd_config_tx_metadata_specific_result {
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t keyword;
	uint16_t port_id;
	cmdline_fixed_string_t item;
	uint32_t value;
};

static void
cmd_config_tx_metadata_specific_parsed(void *parsed_result,
				__attribute__((unused)) struct cmdline *cl,
				__attribute__((unused)) void *data)
{
	struct cmd_config_tx_metadata_specific_result *res = parsed_result;

	if (port_id_is_invalid(res->port_id, ENABLED_WARN))
		return;
	ports[res->port_id].tx_metadata = rte_cpu_to_be_32(res->value);
	/* Add/remove callback to insert valid metadata in every Tx packet. */
	if (ports[res->port_id].tx_metadata)
		add_tx_md_callback(res->port_id);
	else
		remove_tx_md_callback(res->port_id);
}

cmdline_parse_token_string_t cmd_config_tx_metadata_specific_port =
	TOKEN_STRING_INITIALIZER(struct cmd_config_tx_metadata_specific_result,
			port, "port");
cmdline_parse_token_string_t cmd_config_tx_metadata_specific_keyword =
	TOKEN_STRING_INITIALIZER(struct cmd_config_tx_metadata_specific_result,
			keyword, "config");
cmdline_parse_token_num_t cmd_config_tx_metadata_specific_id =
	TOKEN_NUM_INITIALIZER(struct cmd_config_tx_metadata_specific_result,
			port_id, UINT16);
cmdline_parse_token_string_t cmd_config_tx_metadata_specific_item =
	TOKEN_STRING_INITIALIZER(struct cmd_config_tx_metadata_specific_result,
			item, "tx_metadata");
cmdline_parse_token_num_t cmd_config_tx_metadata_specific_value =
	TOKEN_NUM_INITIALIZER(struct cmd_config_tx_metadata_specific_result,
			value, UINT32);

cmdline_parse_inst_t cmd_config_tx_metadata_specific = {
	.f = cmd_config_tx_metadata_specific_parsed,
	.data = NULL,
	.help_str = "port config <port_id> tx_metadata <value>",
	.tokens = {
		(void *)&cmd_config_tx_metadata_specific_port,
		(void *)&cmd_config_tx_metadata_specific_keyword,
		(void *)&cmd_config_tx_metadata_specific_id,
		(void *)&cmd_config_tx_metadata_specific_item,
		(void *)&cmd_config_tx_metadata_specific_value,
		NULL,
	},
};

/* *** display tx_metadata per port configuration *** */
struct cmd_show_tx_metadata_result {
	cmdline_fixed_string_t cmd_show;
	cmdline_fixed_string_t cmd_port;
	cmdline_fixed_string_t cmd_keyword;
	portid_t cmd_pid;
};

static void
cmd_show_tx_metadata_parsed(void *parsed_result,
		__attribute__((unused)) struct cmdline *cl,
		__attribute__((unused)) void *data)
{
	struct cmd_show_tx_metadata_result *res = parsed_result;

	if (!rte_eth_dev_is_valid_port(res->cmd_pid)) {
		printf("invalid port id %u\n", res->cmd_pid);
		return;
	}
	if (!strcmp(res->cmd_keyword, "tx_metadata")) {
		printf("Port %u tx_metadata: %u\n", res->cmd_pid,
			rte_be_to_cpu_32(ports[res->cmd_pid].tx_metadata));
	}
}

cmdline_parse_token_string_t cmd_show_tx_metadata_show =
	TOKEN_STRING_INITIALIZER(struct cmd_show_tx_metadata_result,
			cmd_show, "show");
cmdline_parse_token_string_t cmd_show_tx_metadata_port =
	TOKEN_STRING_INITIALIZER(struct cmd_show_tx_metadata_result,
			cmd_port, "port");
cmdline_parse_token_num_t cmd_show_tx_metadata_pid =
	TOKEN_NUM_INITIALIZER(struct cmd_show_tx_metadata_result,
			cmd_pid, UINT16);
cmdline_parse_token_string_t cmd_show_tx_metadata_keyword =
	TOKEN_STRING_INITIALIZER(struct cmd_show_tx_metadata_result,
			cmd_keyword, "tx_metadata");

cmdline_parse_inst_t cmd_show_tx_metadata = {
	.f = cmd_show_tx_metadata_parsed,
	.data = NULL,
	.help_str = "show port <port_id> tx_metadata",
	.tokens = {
		(void *)&cmd_show_tx_metadata_show,
		(void *)&cmd_show_tx_metadata_port,
		(void *)&cmd_show_tx_metadata_pid,
		(void *)&cmd_show_tx_metadata_keyword,
		NULL,
	},
};

/* ******************************************************************************** */

/* list of instructions */
cmdline_parse_ctx_t main_ctx[] = {
	(cmdline_parse_inst_t *)&cmd_help_brief,
	(cmdline_parse_inst_t *)&cmd_help_long,
	(cmdline_parse_inst_t *)&cmd_quit,
	(cmdline_parse_inst_t *)&cmd_load_from_file,
	(cmdline_parse_inst_t *)&cmd_showport,
	(cmdline_parse_inst_t *)&cmd_showqueue,
	(cmdline_parse_inst_t *)&cmd_showportall,
	(cmdline_parse_inst_t *)&cmd_showcfg,
	(cmdline_parse_inst_t *)&cmd_start,
	(cmdline_parse_inst_t *)&cmd_start_tx_first,
	(cmdline_parse_inst_t *)&cmd_start_tx_first_n,
	(cmdline_parse_inst_t *)&cmd_set_link_up,
	(cmdline_parse_inst_t *)&cmd_set_link_down,
	(cmdline_parse_inst_t *)&cmd_reset,
	(cmdline_parse_inst_t *)&cmd_set_numbers,
	(cmdline_parse_inst_t *)&cmd_set_log,
	(cmdline_parse_inst_t *)&cmd_set_txpkts,
	(cmdline_parse_inst_t *)&cmd_set_txsplit,
	(cmdline_parse_inst_t *)&cmd_set_fwd_list,
	(cmdline_parse_inst_t *)&cmd_set_fwd_mask,
	(cmdline_parse_inst_t *)&cmd_set_fwd_mode,
	(cmdline_parse_inst_t *)&cmd_set_fwd_retry_mode,
	(cmdline_parse_inst_t *)&cmd_set_burst_tx_retry,
	(cmdline_parse_inst_t *)&cmd_set_promisc_mode_one,
	(cmdline_parse_inst_t *)&cmd_set_promisc_mode_all,
	(cmdline_parse_inst_t *)&cmd_set_allmulti_mode_one,
	(cmdline_parse_inst_t *)&cmd_set_allmulti_mode_all,
	(cmdline_parse_inst_t *)&cmd_set_flush_rx,
	(cmdline_parse_inst_t *)&cmd_set_link_check,
	(cmdline_parse_inst_t *)&cmd_set_bypass_mode,
	(cmdline_parse_inst_t *)&cmd_set_bypass_event,
	(cmdline_parse_inst_t *)&cmd_set_bypass_timeout,
	(cmdline_parse_inst_t *)&cmd_show_bypass_config,
#ifdef RTE_LIBRTE_PMD_BOND
	(cmdline_parse_inst_t *) &cmd_set_bonding_mode,
	(cmdline_parse_inst_t *) &cmd_show_bonding_config,
	(cmdline_parse_inst_t *) &cmd_set_bonding_primary,
	(cmdline_parse_inst_t *) &cmd_add_bonding_slave,
	(cmdline_parse_inst_t *) &cmd_remove_bonding_slave,
	(cmdline_parse_inst_t *) &cmd_create_bonded_device,
	(cmdline_parse_inst_t *) &cmd_set_bond_mac_addr,
	(cmdline_parse_inst_t *) &cmd_set_balance_xmit_policy,
	(cmdline_parse_inst_t *) &cmd_set_bond_mon_period,
	(cmdline_parse_inst_t *) &cmd_set_lacp_dedicated_queues,
	(cmdline_parse_inst_t *) &cmd_set_bonding_agg_mode_policy,
#endif
	(cmdline_parse_inst_t *)&cmd_vlan_offload,
	(cmdline_parse_inst_t *)&cmd_vlan_tpid,
	(cmdline_parse_inst_t *)&cmd_rx_vlan_filter_all,
	(cmdline_parse_inst_t *)&cmd_rx_vlan_filter,
	(cmdline_parse_inst_t *)&cmd_tx_vlan_set,
	(cmdline_parse_inst_t *)&cmd_tx_vlan_set_qinq,
	(cmdline_parse_inst_t *)&cmd_tx_vlan_reset,
	(cmdline_parse_inst_t *)&cmd_tx_vlan_set_pvid,
	(cmdline_parse_inst_t *)&cmd_csum_set,
	(cmdline_parse_inst_t *)&cmd_csum_show,
	(cmdline_parse_inst_t *)&cmd_csum_tunnel,
	(cmdline_parse_inst_t *)&cmd_tso_set,
	(cmdline_parse_inst_t *)&cmd_tso_show,
	(cmdline_parse_inst_t *)&cmd_tunnel_tso_set,
	(cmdline_parse_inst_t *)&cmd_tunnel_tso_show,
	(cmdline_parse_inst_t *)&cmd_gro_enable,
	(cmdline_parse_inst_t *)&cmd_gro_flush,
	(cmdline_parse_inst_t *)&cmd_gro_show,
	(cmdline_parse_inst_t *)&cmd_gso_enable,
	(cmdline_parse_inst_t *)&cmd_gso_size,
	(cmdline_parse_inst_t *)&cmd_gso_show,
	(cmdline_parse_inst_t *)&cmd_link_flow_control_set,
	(cmdline_parse_inst_t *)&cmd_link_flow_control_set_rx,
	(cmdline_parse_inst_t *)&cmd_link_flow_control_set_tx,
	(cmdline_parse_inst_t *)&cmd_link_flow_control_set_hw,
	(cmdline_parse_inst_t *)&cmd_link_flow_control_set_lw,
	(cmdline_parse_inst_t *)&cmd_link_flow_control_set_pt,
	(cmdline_parse_inst_t *)&cmd_link_flow_control_set_xon,
	(cmdline_parse_inst_t *)&cmd_link_flow_control_set_macfwd,
	(cmdline_parse_inst_t *)&cmd_link_flow_control_set_autoneg,
	(cmdline_parse_inst_t *)&cmd_priority_flow_control_set,
	(cmdline_parse_inst_t *)&cmd_config_dcb,
	(cmdline_parse_inst_t *)&cmd_read_reg,
	(cmdline_parse_inst_t *)&cmd_read_reg_bit_field,
	(cmdline_parse_inst_t *)&cmd_read_reg_bit,
	(cmdline_parse_inst_t *)&cmd_write_reg,
	(cmdline_parse_inst_t *)&cmd_write_reg_bit_field,
	(cmdline_parse_inst_t *)&cmd_write_reg_bit,
	(cmdline_parse_inst_t *)&cmd_read_rxd_txd,
	(cmdline_parse_inst_t *)&cmd_stop,
	(cmdline_parse_inst_t *)&cmd_mac_addr,
	(cmdline_parse_inst_t *)&cmd_set_fwd_eth_peer,
	(cmdline_parse_inst_t *)&cmd_set_qmap,
	(cmdline_parse_inst_t *)&cmd_set_xstats_hide_zero,
	(cmdline_parse_inst_t *)&cmd_operate_port,
	(cmdline_parse_inst_t *)&cmd_operate_specific_port,
	(cmdline_parse_inst_t *)&cmd_operate_attach_port,
	(cmdline_parse_inst_t *)&cmd_operate_detach_port,
	(cmdline_parse_inst_t *)&cmd_set_port_setup_on,
	(cmdline_parse_inst_t *)&cmd_config_speed_all,
	(cmdline_parse_inst_t *)&cmd_config_speed_specific,
	(cmdline_parse_inst_t *)&cmd_config_loopback_all,
	(cmdline_parse_inst_t *)&cmd_config_loopback_specific,
	(cmdline_parse_inst_t *)&cmd_config_rx_tx,
	(cmdline_parse_inst_t *)&cmd_config_mtu,
	(cmdline_parse_inst_t *)&cmd_config_max_pkt_len,
	(cmdline_parse_inst_t *)&cmd_config_rx_mode_flag,
	(cmdline_parse_inst_t *)&cmd_config_rss,
	(cmdline_parse_inst_t *)&cmd_config_rxtx_ring_size,
	(cmdline_parse_inst_t *)&cmd_config_rxtx_queue,
	(cmdline_parse_inst_t *)&cmd_config_deferred_start_rxtx_queue,
	(cmdline_parse_inst_t *)&cmd_setup_rxtx_queue,
	(cmdline_parse_inst_t *)&cmd_config_rss_reta,
	(cmdline_parse_inst_t *)&cmd_showport_reta,
	(cmdline_parse_inst_t *)&cmd_config_burst,
	(cmdline_parse_inst_t *)&cmd_config_thresh,
	(cmdline_parse_inst_t *)&cmd_config_threshold,
	(cmdline_parse_inst_t *)&cmd_set_uc_hash_filter,
	(cmdline_parse_inst_t *)&cmd_set_uc_all_hash_filter,
	(cmdline_parse_inst_t *)&cmd_vf_mac_addr_filter,
	(cmdline_parse_inst_t *)&cmd_set_vf_macvlan_filter,
	(cmdline_parse_inst_t *)&cmd_queue_rate_limit,
	(cmdline_parse_inst_t *)&cmd_tunnel_filter,
	(cmdline_parse_inst_t *)&cmd_tunnel_udp_config,
	(cmdline_parse_inst_t *)&cmd_global_config,
	(cmdline_parse_inst_t *)&cmd_set_mirror_mask,
	(cmdline_parse_inst_t *)&cmd_set_mirror_link,
	(cmdline_parse_inst_t *)&cmd_reset_mirror_rule,
	(cmdline_parse_inst_t *)&cmd_showport_rss_hash,
	(cmdline_parse_inst_t *)&cmd_showport_rss_hash_key,
	(cmdline_parse_inst_t *)&cmd_config_rss_hash_key,
	(cmdline_parse_inst_t *)&cmd_dump,
	(cmdline_parse_inst_t *)&cmd_dump_one,
	(cmdline_parse_inst_t *)&cmd_ethertype_filter,
	(cmdline_parse_inst_t *)&cmd_syn_filter,
	(cmdline_parse_inst_t *)&cmd_2tuple_filter,
	(cmdline_parse_inst_t *)&cmd_5tuple_filter,
	(cmdline_parse_inst_t *)&cmd_flex_filter,
	(cmdline_parse_inst_t *)&cmd_add_del_ip_flow_director,
	(cmdline_parse_inst_t *)&cmd_add_del_udp_flow_director,
	(cmdline_parse_inst_t *)&cmd_add_del_sctp_flow_director,
	(cmdline_parse_inst_t *)&cmd_add_del_l2_flow_director,
	(cmdline_parse_inst_t *)&cmd_add_del_mac_vlan_flow_director,
	(cmdline_parse_inst_t *)&cmd_add_del_tunnel_flow_director,
	(cmdline_parse_inst_t *)&cmd_add_del_raw_flow_director,
	(cmdline_parse_inst_t *)&cmd_flush_flow_director,
	(cmdline_parse_inst_t *)&cmd_set_flow_director_ip_mask,
	(cmdline_parse_inst_t *)&cmd_set_flow_director_mac_vlan_mask,
	(cmdline_parse_inst_t *)&cmd_set_flow_director_tunnel_mask,
	(cmdline_parse_inst_t *)&cmd_set_flow_director_flex_mask,
	(cmdline_parse_inst_t *)&cmd_set_flow_director_flex_payload,
	(cmdline_parse_inst_t *)&cmd_get_sym_hash_ena_per_port,
	(cmdline_parse_inst_t *)&cmd_set_sym_hash_ena_per_port,
	(cmdline_parse_inst_t *)&cmd_get_hash_global_config,
	(cmdline_parse_inst_t *)&cmd_set_hash_global_config,
	(cmdline_parse_inst_t *)&cmd_set_hash_input_set,
	(cmdline_parse_inst_t *)&cmd_set_fdir_input_set,
	(cmdline_parse_inst_t *)&cmd_flow,
	(cmdline_parse_inst_t *)&cmd_show_port_meter_cap,
	(cmdline_parse_inst_t *)&cmd_add_port_meter_profile_srtcm,
	(cmdline_parse_inst_t *)&cmd_add_port_meter_profile_trtcm,
	(cmdline_parse_inst_t *)&cmd_del_port_meter_profile,
	(cmdline_parse_inst_t *)&cmd_create_port_meter,
	(cmdline_parse_inst_t *)&cmd_enable_port_meter,
	(cmdline_parse_inst_t *)&cmd_disable_port_meter,
	(cmdline_parse_inst_t *)&cmd_del_port_meter,
	(cmdline_parse_inst_t *)&cmd_set_port_meter_profile,
	(cmdline_parse_inst_t *)&cmd_set_port_meter_dscp_table,
	(cmdline_parse_inst_t *)&cmd_set_port_meter_policer_action,
	(cmdline_parse_inst_t *)&cmd_set_port_meter_stats_mask,
	(cmdline_parse_inst_t *)&cmd_show_port_meter_stats,
	(cmdline_parse_inst_t *)&cmd_mcast_addr,
	(cmdline_parse_inst_t *)&cmd_config_l2_tunnel_eth_type_all,
	(cmdline_parse_inst_t *)&cmd_config_l2_tunnel_eth_type_specific,
	(cmdline_parse_inst_t *)&cmd_config_l2_tunnel_en_dis_all,
	(cmdline_parse_inst_t *)&cmd_config_l2_tunnel_en_dis_specific,
	(cmdline_parse_inst_t *)&cmd_config_e_tag_insertion_en,
	(cmdline_parse_inst_t *)&cmd_config_e_tag_insertion_dis,
	(cmdline_parse_inst_t *)&cmd_config_e_tag_stripping_en_dis,
	(cmdline_parse_inst_t *)&cmd_config_e_tag_forwarding_en_dis,
	(cmdline_parse_inst_t *)&cmd_config_e_tag_filter_add,
	(cmdline_parse_inst_t *)&cmd_config_e_tag_filter_del,
	(cmdline_parse_inst_t *)&cmd_set_vf_vlan_anti_spoof,
	(cmdline_parse_inst_t *)&cmd_set_vf_mac_anti_spoof,
	(cmdline_parse_inst_t *)&cmd_set_vf_vlan_stripq,
	(cmdline_parse_inst_t *)&cmd_set_vf_vlan_insert,
	(cmdline_parse_inst_t *)&cmd_set_tx_loopback,
	(cmdline_parse_inst_t *)&cmd_set_all_queues_drop_en,
	(cmdline_parse_inst_t *)&cmd_set_vf_split_drop_en,
	(cmdline_parse_inst_t *)&cmd_set_macsec_offload_on,
	(cmdline_parse_inst_t *)&cmd_set_macsec_offload_off,
	(cmdline_parse_inst_t *)&cmd_set_macsec_sc,
	(cmdline_parse_inst_t *)&cmd_set_macsec_sa,
	(cmdline_parse_inst_t *)&cmd_set_vf_traffic,
	(cmdline_parse_inst_t *)&cmd_set_vf_rxmode,
	(cmdline_parse_inst_t *)&cmd_vf_rate_limit,
	(cmdline_parse_inst_t *)&cmd_vf_rxvlan_filter,
	(cmdline_parse_inst_t *)&cmd_set_vf_mac_addr,
	(cmdline_parse_inst_t *)&cmd_set_vf_promisc,
	(cmdline_parse_inst_t *)&cmd_set_vf_allmulti,
	(cmdline_parse_inst_t *)&cmd_set_vf_broadcast,
	(cmdline_parse_inst_t *)&cmd_set_vf_vlan_tag,
	(cmdline_parse_inst_t *)&cmd_vf_max_bw,
	(cmdline_parse_inst_t *)&cmd_vf_tc_min_bw,
	(cmdline_parse_inst_t *)&cmd_vf_tc_max_bw,
	(cmdline_parse_inst_t *)&cmd_strict_link_prio,
	(cmdline_parse_inst_t *)&cmd_tc_min_bw,
#if defined RTE_LIBRTE_PMD_SOFTNIC && defined RTE_LIBRTE_SCHED
	(cmdline_parse_inst_t *)&cmd_set_port_tm_hierarchy_default,
#endif
	(cmdline_parse_inst_t *)&cmd_set_vxlan,
	(cmdline_parse_inst_t *)&cmd_set_vxlan_with_vlan,
	(cmdline_parse_inst_t *)&cmd_set_nvgre,
	(cmdline_parse_inst_t *)&cmd_set_nvgre_with_vlan,
	(cmdline_parse_inst_t *)&cmd_set_l2_encap,
	(cmdline_parse_inst_t *)&cmd_set_l2_encap_with_vlan,
	(cmdline_parse_inst_t *)&cmd_set_l2_decap,
	(cmdline_parse_inst_t *)&cmd_set_l2_decap_with_vlan,
	(cmdline_parse_inst_t *)&cmd_set_mplsogre_encap,
	(cmdline_parse_inst_t *)&cmd_set_mplsogre_encap_with_vlan,
	(cmdline_parse_inst_t *)&cmd_set_mplsogre_decap,
	(cmdline_parse_inst_t *)&cmd_set_mplsogre_decap_with_vlan,
	(cmdline_parse_inst_t *)&cmd_set_mplsoudp_encap,
	(cmdline_parse_inst_t *)&cmd_set_mplsoudp_encap_with_vlan,
	(cmdline_parse_inst_t *)&cmd_set_mplsoudp_decap,
	(cmdline_parse_inst_t *)&cmd_set_mplsoudp_decap_with_vlan,
	(cmdline_parse_inst_t *)&cmd_ddp_add,
	(cmdline_parse_inst_t *)&cmd_ddp_del,
	(cmdline_parse_inst_t *)&cmd_ddp_get_list,
	(cmdline_parse_inst_t *)&cmd_ddp_get_info,
	(cmdline_parse_inst_t *)&cmd_cfg_input_set,
	(cmdline_parse_inst_t *)&cmd_clear_input_set,
	(cmdline_parse_inst_t *)&cmd_show_vf_stats,
	(cmdline_parse_inst_t *)&cmd_clear_vf_stats,
	(cmdline_parse_inst_t *)&cmd_ptype_mapping_get,
	(cmdline_parse_inst_t *)&cmd_ptype_mapping_replace,
	(cmdline_parse_inst_t *)&cmd_ptype_mapping_reset,
	(cmdline_parse_inst_t *)&cmd_ptype_mapping_update,

	(cmdline_parse_inst_t *)&cmd_pctype_mapping_get,
	(cmdline_parse_inst_t *)&cmd_pctype_mapping_reset,
	(cmdline_parse_inst_t *)&cmd_pctype_mapping_update,
	(cmdline_parse_inst_t *)&cmd_queue_region,
	(cmdline_parse_inst_t *)&cmd_region_flowtype,
	(cmdline_parse_inst_t *)&cmd_user_priority_region,
	(cmdline_parse_inst_t *)&cmd_flush_queue_region,
	(cmdline_parse_inst_t *)&cmd_show_queue_region_info_all,
	(cmdline_parse_inst_t *)&cmd_show_port_tm_cap,
	(cmdline_parse_inst_t *)&cmd_show_port_tm_level_cap,
	(cmdline_parse_inst_t *)&cmd_show_port_tm_node_cap,
	(cmdline_parse_inst_t *)&cmd_show_port_tm_node_type,
	(cmdline_parse_inst_t *)&cmd_show_port_tm_node_stats,
	(cmdline_parse_inst_t *)&cmd_add_port_tm_node_shaper_profile,
	(cmdline_parse_inst_t *)&cmd_del_port_tm_node_shaper_profile,
	(cmdline_parse_inst_t *)&cmd_add_port_tm_node_shared_shaper,
	(cmdline_parse_inst_t *)&cmd_del_port_tm_node_shared_shaper,
	(cmdline_parse_inst_t *)&cmd_add_port_tm_node_wred_profile,
	(cmdline_parse_inst_t *)&cmd_del_port_tm_node_wred_profile,
	(cmdline_parse_inst_t *)&cmd_set_port_tm_node_shaper_profile,
	(cmdline_parse_inst_t *)&cmd_add_port_tm_nonleaf_node,
	(cmdline_parse_inst_t *)&cmd_add_port_tm_leaf_node,
	(cmdline_parse_inst_t *)&cmd_del_port_tm_node,
	(cmdline_parse_inst_t *)&cmd_set_port_tm_node_parent,
	(cmdline_parse_inst_t *)&cmd_suspend_port_tm_node,
	(cmdline_parse_inst_t *)&cmd_resume_port_tm_node,
	(cmdline_parse_inst_t *)&cmd_port_tm_hierarchy_commit,
	(cmdline_parse_inst_t *)&cmd_port_tm_mark_ip_ecn,
	(cmdline_parse_inst_t *)&cmd_port_tm_mark_ip_dscp,
	(cmdline_parse_inst_t *)&cmd_port_tm_mark_vlan_dei,
	(cmdline_parse_inst_t *)&cmd_cfg_tunnel_udp_port,
	(cmdline_parse_inst_t *)&cmd_rx_offload_get_capa,
	(cmdline_parse_inst_t *)&cmd_rx_offload_get_configuration,
	(cmdline_parse_inst_t *)&cmd_config_per_port_rx_offload,
	(cmdline_parse_inst_t *)&cmd_config_per_queue_rx_offload,
	(cmdline_parse_inst_t *)&cmd_tx_offload_get_capa,
	(cmdline_parse_inst_t *)&cmd_tx_offload_get_configuration,
	(cmdline_parse_inst_t *)&cmd_config_per_port_tx_offload,
	(cmdline_parse_inst_t *)&cmd_config_per_queue_tx_offload,
#ifdef RTE_LIBRTE_BPF
	(cmdline_parse_inst_t *)&cmd_operate_bpf_ld_parse,
	(cmdline_parse_inst_t *)&cmd_operate_bpf_unld_parse,
#endif
	(cmdline_parse_inst_t *)&cmd_config_tx_metadata_specific,
	(cmdline_parse_inst_t *)&cmd_show_tx_metadata,
	NULL,
};

/* read cmdline commands from file */
void
cmdline_read_from_file(const char *filename)
{
	struct cmdline *cl;

	cl = cmdline_file_new(main_ctx, "testpmd> ", filename);
	if (cl == NULL) {
		printf("Failed to create file based cmdline context: %s\n",
		       filename);
		return;
	}

	cmdline_interact(cl);
	cmdline_quit(cl);

	cmdline_free(cl);

	printf("Read CLI commands from %s\n", filename);
}

/* prompt function, called from main on MASTER lcore */
void
prompt(void)
{
	/* initialize non-constant commands */
	cmd_set_fwd_mode_init();
	cmd_set_fwd_retry_mode_init();

	testpmd_cl = cmdline_stdin_new(main_ctx, "testpmd> ");
	if (testpmd_cl == NULL)
		return;
	cmdline_interact(testpmd_cl);
	cmdline_stdin_exit(testpmd_cl);
}

void
prompt_exit(void)
{
	if (testpmd_cl != NULL)
		cmdline_quit(testpmd_cl);
}

static void
cmd_reconfig_device_queue(portid_t id, uint8_t dev, uint8_t queue)
{
	if (id == (portid_t)RTE_PORT_ALL) {
		portid_t pid;

		RTE_ETH_FOREACH_DEV(pid) {
			/* check if need_reconfig has been set to 1 */
			if (ports[pid].need_reconfig == 0)
				ports[pid].need_reconfig = dev;
			/* check if need_reconfig_queues has been set to 1 */
			if (ports[pid].need_reconfig_queues == 0)
				ports[pid].need_reconfig_queues = queue;
		}
	} else if (!port_id_is_invalid(id, DISABLED_WARN)) {
		/* check if need_reconfig has been set to 1 */
		if (ports[id].need_reconfig == 0)
			ports[id].need_reconfig = dev;
		/* check if need_reconfig_queues has been set to 1 */
		if (ports[id].need_reconfig_queues == 0)
			ports[id].need_reconfig_queues = queue;
	}
}
