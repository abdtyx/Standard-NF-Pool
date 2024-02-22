/*********************************************************************
 *                     openNetVM
 *              https://sdnfv.github.io
 *
 *   BSD LICENSE
 *
 *   Copyright(c)
 *            2015-2019 George Washington University
 *            2015-2019 University of California Riverside
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * The name of the author may not be used to endorse or promote
 *       products derived from this software without specific prior
 *       written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * flow_table.c - a simple flow table NF
 ********************************************************************/

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_ether.h>
#include <rte_hash.h>
#include <rte_ip.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_ring.h>
#include <rte_tcp.h>
#include <rte_malloc.h>

#ifdef LIBPCAP
#include <pcap.h>
#endif

#include "flow_table.h"
#include "onvm_flow_dir.h"
#include "onvm_flow_table.h"
#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"
#include "onvm_sc_common.h"
#include "sdn.h"
#include "standard_common.h"

#define NF_TAG "flow_table"

#define MEMPOOL_CACHE_SIZE 256
#define MAX_PKT_BURST 32
#define NF_PKTMBUF_POOL_NAME "flow_table_pktmbuf_pool"

struct rte_ring *ring_to_sdn;
struct rte_ring *ring_from_sdn;
#define SDN_RING_SIZE 65536

/* number of package between each print */
static uint32_t print_delay = 10000;

static uint32_t destination;

uint16_t def_destination;
static uint32_t total_flows;

struct rte_mempool *flow_table_pktmbuf_pool = NULL;
uint16_t port_id;
struct rte_eth_dev_tx_buffer* pkts_tx_buffer;

/* Break the infinite loop */
static volatile bool force_quit;

/*
 * Variables needed to replay a pcap file
 */
const char *pcap_filename = "sample.pcap";

/* Setup rings to hold buffered packets destined for SDN controller */
static void
setup_rings(void) {
        /* Remove old ring buffers */
        ring_to_sdn = rte_ring_lookup("ring_to_sdn");
        ring_from_sdn = rte_ring_lookup("ring_from_sdn");
        if (ring_to_sdn) {
                rte_ring_free(ring_to_sdn);
        }
        if (ring_from_sdn) {
                rte_ring_free(ring_from_sdn);
        }

        ring_to_sdn = rte_ring_create("ring_to_sdn", SDN_RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
        ring_from_sdn = rte_ring_create("ring_from_sdn", SDN_RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
        if (ring_to_sdn == NULL || ring_from_sdn == NULL) {
                rte_exit(EXIT_FAILURE, "Unable to create SDN rings\n");
        }
}

/* Clear out rings on exit. Requires DPDK v2.2.0+ */
static void
cleanup(void) {
        printf("Freeing memory for SDN rings.\n");
        rte_ring_free(ring_to_sdn);
        rte_ring_free(ring_from_sdn);
        printf("Freeing memory for hash table.\n");
        rte_hash_free(sdn_ft->hash);
}

static int
parse_app_args(int argc, char *argv[]) {
        const char *progname = argv[0];
        int c;

        opterr = 0;

        while ((c = getopt(argc, argv, "d:p:")) != -1)
                switch (c) {
                        case 'd':
                                destination = strtoul(optarg, NULL, 10);
                                break;
                        case 'p':
                                print_delay = strtoul(optarg, NULL, 10);
                                break;
                        case '?':
                                usage(progname);
                                if (optopt == 'p')
                                        fprintf(stderr, "Option -%c requires an argument.\n", optopt);
                                else if (isprint(optopt))
                                        fprintf(stderr, "Unknown option `-%c'.\n", optopt);
                                else
                                        fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
                                return -1;
                        default:
                                return -1;
                }
        return optind;
}

static void
do_stats_display(struct rte_mbuf *pkt, int32_t tbl_index) {
        const char clr[] = {27, '[', '2', 'J', '\0'};
        const char topLeft[] = {27, '[', '1', ';', '1', 'H', '\0'};
        static uint64_t total_pkts = 0;
        /* Fix unused variable warnings: */
        (void)pkt;

        struct onvm_flow_entry *flow_entry = (struct onvm_flow_entry *)onvm_ft_get_data(sdn_ft, tbl_index);
        total_pkts += print_delay;

        /* Clear screen and move to top left */
        printf("%s%s", clr, topLeft);

        printf("FLOW TABLE NF\n");
        printf("-----\n");
        printf("Total pkts   : %" PRIu64 "\n", total_pkts);
        printf("Total flows  : %d\n", total_flows);
        printf("Flow ID      : %d\n", tbl_index);
        printf("Flow pkts    : %" PRIu64 "\n", flow_entry->packet_count);
        // printf("Flow Action  : %d\n", flow_entry->action);
        // printf("Flow Dest    : %d\n", flow_entry->destination);
        printf("\n\n");

#ifdef DEBUG_PRINT
        struct rte_ipv4_hdr *ip;
        ip = onvm_pkt_ipv4_hdr(pkt);
        if (ip != NULL) {
                onvm_pkt_print(pkt);
        } else {
                printf("Not an IP4 packet\n");
        }
#endif
}

static int
flow_table_hit(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta) {
        (void)pkt;
        meta->chain_index = 0;
        meta->action = ONVM_NF_ACTION_NEXT;
        meta->destination = 0;

        return 0;
}

static int
flow_table_miss(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta) {
        int ret;

        /* Buffer new flows until we get response from SDN controller. */
        ret = rte_ring_enqueue(ring_to_sdn, pkt);
        if (ret != 0) {
                printf("ERROR enqueing to SDN ring\n");
                meta->action = ONVM_NF_ACTION_DROP;
                meta->destination = 0;
                return 0;
        }

        return 1;
}

static int
packet_handler(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta,
               __attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx) {
        static uint32_t counter = 0;

        int32_t tbl_index;
        int action;
        struct onvm_flow_entry *flow_entry;

        if (!onvm_pkt_is_ipv4(pkt)) {
                printf("Non-ipv4 packet\n");
                meta->action = ONVM_NF_ACTION_TONF;
                meta->destination = def_destination;
                return 0;
        }

        tbl_index = onvm_flow_dir_get_pkt(pkt, &flow_entry);
        if (tbl_index >= 0) {
#ifdef DEBUG_PRINT
                printf("Found existing flow %d\n", tbl_index);
#endif
                /* Existing flow */
                action = flow_table_hit(pkt, meta);
        } else if (tbl_index == -ENOENT) {
#ifdef DEBUG_PRINT
                printf("Unkown flow\n");
#endif
                /* New flow */
                action = flow_table_miss(pkt, meta);
        } else {
#ifdef DEBUG_PRINT
                printf("Error in flow lookup: %d (ENOENT=%d, EINVAL=%d)\n", tbl_index, ENOENT, EINVAL);
                onvm_pkt_print(pkt);
#endif
                rte_exit(EXIT_FAILURE, "Error in flow lookup\n");
        }

        if (++counter == print_delay && print_delay != 0) {
                if (tbl_index >= 0) {
                        do_stats_display(pkt, tbl_index);
                        counter = 0;
                }
        }

        return action;
}

/* main processing loop */
static void
flow_table_main_loop(void) {
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	struct rte_mbuf *m;

        while (!force_quit) {
                unsigned int nb_rx = rte_eth_rx_burst(port_id, 0, pkts_burst, MAX_PKT_BURST);
                for (unsigned i = 0; i < nb_rx; i++) {
                        m = pkts_burst[i];
                        rte_prefetch0(rte_pktmbuf_mtod(m, void *));
                        packet_handler(m, onvm_get_pkt_meta(m), NULL);
                        if (onvm_get_pkt_meta(m)->action != ONVM_NF_ACTION_DROP) {
                                rte_eth_tx_buffer(port_id, 0, pkts_tx_buffer, m);
                        }
                }
                rte_eth_tx_buffer_flush(port_id, 0, pkts_tx_buffer);
        }
}

static int
flow_table_launch_one_lcore(__rte_unused void* dummy) {
        flow_table_main_loop();
        return 0;
}

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n",
				signum);
		force_quit = true;
	}
}

int
main(int argc, char *argv[]) {
        unsigned sdn_core = 0;

        int ret = rte_eal_init(argc, argv);
        if (ret < 0) {
                rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
        }
        argc -= ret;
        argv += ret;

        force_quit = false;
        // signal handler
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

        unsigned int nb_mbufs = 8192U;
        // create membuf
	flow_table_pktmbuf_pool = rte_pktmbuf_pool_create(NF_PKTMBUF_POOL_NAME, nb_mbufs,
		MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
		rte_socket_id());
	if (flow_table_pktmbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

        // bind NIC device
        ret = rte_eth_dev_count_avail();
        if (ret == 0)
                rte_exit(EXIT_FAILURE, "No available port\n");

        // port_id
        port_id = get_available_port_id();
        if (port_id == RTE_MAX_ETHPORTS)
                rte_exit(EXIT_FAILURE, "No available port\n");

        // init port
        if (port_init(port_id, flow_table_pktmbuf_pool, NULL) != 0)
                rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n", port_id);

        // malloc tx buffer
        pkts_tx_buffer = rte_zmalloc_socket("tx_buffer", RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST), 0, rte_eth_dev_socket_id(port_id));
        if (pkts_tx_buffer == NULL)
                rte_exit(EXIT_FAILURE, "Cannot allocate buffer for tx on port %u\n", port_id);

        // init tx buffer
        ret = rte_eth_tx_buffer_init(pkts_tx_buffer, MAX_PKT_BURST);
        if (ret != 0)
                rte_exit(EXIT_FAILURE, "Cannot init transmit buffer: %d\n", ret);

        if (parse_app_args(argc, argv) < 0) {
                rte_exit(EXIT_FAILURE, "Invalid command-line arguments\n");
        }
        printf("Flow table running on %d\n", rte_lcore_id());

        def_destination = destination + 1;
        printf("Setting up hash table with default destination: %d\n", def_destination);
        total_flows = 0;

        /* Setup the SDN connection thread */
        printf("Setting up SDN rings and thread.\n");
        setup_rings();
        sdn_core = rte_lcore_id();
        sdn_core = rte_get_next_lcore(sdn_core, 1, 1);
        rte_eal_remote_launch(setup_securechannel, NULL, sdn_core);

        /* Map sdn_ft table */
        onvm_flow_dir_init();
        onvm_flow_dir_nf_init();
        printf("Starting packet handler.\n");
#ifdef LIBPCAP
        pcap_t *pcap;
        char errbuf[PCAP_ERRBUF_SIZE];
        const unsigned char *packet;
        struct pcap_pkthdr header;

        if (pcap_filename != NULL) {
                printf("Replaying %s pcap file\n", pcap_filename);

                pcap = pcap_open_offline(pcap_filename, errbuf);
                if (pcap == NULL) {
                        fprintf(stderr, "Error reading pcap file: %s\n", errbuf);
                        rte_exit(EXIT_FAILURE, "Cannot open pcap file\n");
                }

                // packet_number = (use_custom_pkt_count ? packet_number : MAX_PKT_NUM);
                // struct rte_mbuf *pkts[packet_number];

                // i = 0;

                /* 
                 * max_elt_size is the maximum preallocated memory size permitted for each packet, 
                 * adjusted for the memory offset of the rte_mbuf struct and header/tail lengths
                 */
                
                // max_elt_size = pktmbuf_pool->elt_size - sizeof(struct rte_mbuf) - pktmbuf_pool->header_size - pktmbuf_pool->trailer_size;

                // Read from file, not manager
                struct rte_mbuf *pkt;
                while (((packet = pcap_next(pcap, &header)) != NULL)) {
                        struct onvm_pkt_meta *pmeta;
                        struct onvm_ft_ipv4_5tuple key;

                        /* Length of the packet cannot exceed preallocated storage size */
                        // if (header.caplen > max_elt_size) {
                        //         nf_local_ctx->nf->stats.tx_drop++;
                        //         nf_local_ctx->nf->stats.act_drop++;
                        //         continue;
                        // }

                        pkt = rte_pktmbuf_alloc(flow_table_pktmbuf_pool);
                        if (pkt == NULL)
                                break;

                        pkt->pkt_len = header.caplen;
                        pkt->data_len = header.caplen;

                        /* Copy the packet into the rte_mbuf data section */
                        rte_memcpy(rte_pktmbuf_mtod(pkt, char *), packet, header.caplen);

                        pmeta = onvm_get_pkt_meta(pkt);
                        pmeta->destination = destination;
                        pmeta->action = ONVM_NF_ACTION_TONF;
                        pmeta->flags = ONVM_SET_BIT(0, 0);

                        onvm_ft_fill_key(&key, pkt);
                        pkt->hash.rss = onvm_softrss(&key);

                        /* Add packet to batch, and update counter */
                        // pkts[i++] = pkt;
                        // pkts_generated++;

                        // handler packet
                        packet_handler(pkt, onvm_get_pkt_meta(pkt), NULL);
                        // drop packet
                        rte_pktmbuf_free(pkt);
                }
                // Send pkt to mgr
                // onvm_nflib_return_pkt_bulk(nf_local_ctx->nf, pkts, pkts_generated);
        }
#else
        // dpdk loop
        unsigned lcore_id;
	rte_eal_mp_remote_launch(flow_table_launch_one_lcore, NULL, CALL_MASTER);
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0) {
			ret = -1;
			break;
		}
	}
#endif

        printf("NF exiting...\n");
        cleanup();
        return 0;
}
