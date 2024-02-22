#include "standard_common.h"
#include "onvm_common.h"

#include <inttypes.h>
#include <rte_common.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

struct port_info *ports;

const struct rte_eth_conf port_conf_default = {
	.rxmode = {
		.max_rx_pkt_len = RTE_ETHER_MAX_LEN,
	},
};

uint16_t
get_available_port_id(void) {
        uint16_t port_id;
        RTE_ETH_FOREACH_DEV(port_id) {
                uint16_t use = rte_eth_find_next(port_id);
                if (use != RTE_MAX_ETHPORTS)
                        return use;
        }
        return RTE_MAX_ETHPORTS;
}

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
int
port_init(uint16_t port, struct rte_mempool *mbuf_pool, const struct rte_eth_conf* port_conf_customize)
{
	struct rte_eth_conf port_conf;
	if (port_conf_customize != NULL)
		port_conf = *port_conf_customize;
	else
		port_conf = port_conf_default;

	const uint16_t rx_rings = 1, tx_rings = 1;
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;
	int retval;
	uint16_t q;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;

	retval = rte_eth_dev_info_get(port, &dev_info);
	if (retval != 0) {
		printf("Error during getting device (port %u) info: %s\n",
				port, strerror(-retval));
		return retval;
	}

	if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |=
			DEV_TX_OFFLOAD_MBUF_FAST_FREE;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
				rte_eth_dev_socket_id(port), &txconf);
		if (retval < 0)
			return retval;
	}

	/* Start the Ethernet port. */
	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	struct rte_ether_addr addr;
	retval = rte_eth_macaddr_get(port, &addr);
	if (retval != 0)
		return retval;

	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			port,
			addr.addr_bytes[0], addr.addr_bytes[1],
			addr.addr_bytes[2], addr.addr_bytes[3],
			addr.addr_bytes[4], addr.addr_bytes[5]);

	/* Enable RX in promiscuous mode for the Ethernet device. */
	retval = rte_eth_promiscuous_enable(port);
	if (retval != 0)
		return retval;

	return 0;
}

/**
 * The ports to be used by the application are passed in
 * the form of a bitmask. This function parses the bitmask
 * and places the port numbers to be used into the port[]
 * array variable
 */
int
parse_portmask(const char *portmask)
{
	char *end = NULL;
	unsigned long long pm;
	uint16_t id;

	if (portmask == NULL || *portmask == '\0')
		return -1;

	/* convert parameter to a number and verify */
	errno = 0;
	pm = strtoull(portmask, &end, 16);
	if (errno != 0 || end == NULL || *end != '\0')
		return -1;

	RTE_ETH_FOREACH_DEV(id) {
		unsigned long msk = 1u << id;

		if ((pm & msk) == 0)
			continue;

		pm &= ~msk;
		ports->id[ports->num_ports++] = id;
	}

	if (pm != 0) {
		printf("WARNING: leftover ports in mask %#llx - ignoring\n",
		       pm);
	}

	return 0;
}
