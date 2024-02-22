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
 * load_generator.c - send pkts at defined rate and measure received pkts.
 ********************************************************************/

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <math.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_ring.h>
#include <rte_malloc.h>

#ifdef LIBPCAP
#include <pcap.h>
#endif

#include "onvm_flow_table.h"
#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"
#include "standard_common.h"

#define LOCAL_EXPERIMENTAL_ETHER 0x88B5
#define NF_TAG "load_generator"
#define LOAD_GEN_BIT 5
#define BATCH_LIMIT 32

#define MEMPOOL_CACHE_SIZE 256
#define MAX_PKT_BURST 32
#define NF_PKTMBUF_POOL_NAME "lg_pktmbuf_pool"

static uint64_t packet_rate = 3000000;
static uint64_t last_cycle;
static uint64_t start_cycle;
static uint64_t last_update_cycle;
static double packets_to_send = 0;
static uint64_t packets_sent = 0;
static uint64_t packets_sent_since_update = 0;
static uint64_t packets_received = 0;
static uint64_t packets_received_since_update = 0;
static uint32_t batch_size;
static double total_latency_since_update = 0;

struct rte_mempool *pktmbuf_pool;

static uint16_t packet_size = RTE_ETHER_HDR_LEN;
static uint8_t d_addr_bytes[RTE_ETHER_ADDR_LEN];

/* number of seconds between each print */
static double print_delay = 0.1;
static double time_since_print = 0;

static uint16_t destination;

static uint8_t action_out = 0;

static struct rte_ether_hdr *ehdr;

struct rte_mempool *load_generator_pktmbuf_pool = NULL;
uint16_t port_id;
struct rte_eth_dev_tx_buffer* pkts_tx_buffer;

/* Break the infinite loop */
static volatile bool force_quit;

/*
 * Variables needed to replay a pcap file
 */
const char *pcap_filename = "sample.pcap";

/* Sets up variables for the load generator */
void
nf_setup(void);

/*
 * Print a usage message
 */
static void
usage(const char *progname) {
        printf("Usage:\n");
        printf(
            "%s [EAL args] -- [NF_LIB args] -- -d <destination> [-m <dest_mac_address>] "
            "[-p <print_delay>] [-s <packet_size>] [-t <packet_rate>] [-o]\n\n",
            progname);
        printf("%s -F <CONFIG_FILE.json> [EAL args] -- [NF_LIB args] -- [NF args]\n\n", progname);
        printf("Flags:\n");
        printf(" - `-d DST`: destination service ID to foward to, or dst port if `-o` is used.\n");
        printf(
            " - `-p <print_delay>`: number of seconds between each print (e.g. `-p 0.1` prints every 0.1 seconds).\n");
        printf(
            " - `-t <packet_rate>`: the desired transmission rate for the packets (e.g. `-t 3000000 transmits 3 "
            "million packets per second). Note that the actual transmission rate may be limited based on system "
            "performance and NF configuration. If the load generator is experiencing high levels of dropped packets "
            "either transmitting or receiving, lowering the transmission rate could solve this.\n");
        printf(
            " - `-m <dest_mac>`: user specified destination MAC address (e.g. `-m aa:bb:cc:dd:ee:ff` sets the "
            "destination address within the ethernet header that is located at the start of the packet data).\n");
        printf(" - `-s <packet_size>`: the desired size of the generated packets in bytes.\n");
        printf(" - `-o`: send the packets out the NIC port.\n");
}

/*
 * Parses the application arguments.
 */
static int
parse_app_args(int argc, char *argv[], const char *progname) {
        int c, i, count, dst_flag = 0;
        int values[RTE_ETHER_ADDR_LEN];
        while ((c = getopt(argc, argv, "d:p:t:m:s:o")) != -1) {
                switch (c) {
                        case 'd':
                                destination = strtoul(optarg, NULL, 10);
                                dst_flag = 1;
                                break;
                        case 'p':
                                print_delay = strtod(optarg, NULL);
                                RTE_LOG(INFO, APP, "print_delay = %f\n", print_delay);
                                break;
                        case 't':
                                packet_rate = strtoul(optarg, NULL, 10);
                                break;
                        case 'm':
                                count = sscanf(optarg, "%x:%x:%x:%x:%x:%x", &values[0], &values[1], &values[2],
                                               &values[3], &values[4], &values[5]);
                                if (count == RTE_ETHER_ADDR_LEN) {
                                        for (i = 0; i < RTE_ETHER_ADDR_LEN; ++i) {
                                                d_addr_bytes[i] = (uint8_t)values[i];
                                        }
                                } else {
                                        usage(progname);
                                        return -1;
                                }
                                break;
                        case 's':
                                packet_size = strtoul(optarg, NULL, 10);
                                if (packet_size >= RTE_ETHER_HDR_LEN) {
                                        break;
                                } else {
                                        RTE_LOG(INFO, APP,
                                                "Load generator NF requires a packet size of at least 14.\n");
                                        return -1;
                                }
                        case 'o':
                                action_out = 1;
                                break;
                        default:
                                usage(progname);
                                return -1;
                }
        }

        if (!dst_flag) {
                RTE_LOG(INFO, APP, "Load generator NF requires a destination NF with the -d flag.\n");
                return -1;
        }

        return optind;
}

static void
do_stats_display(void) {
        const char clr[] = {27, '[', '2', 'J', '\0'};
        const char topLeft[] = {27, '[', '1', ';', '1', 'H', '\0'};

        uint64_t cur_cycle = rte_get_tsc_cycles();
        double time_elapsed = (cur_cycle - start_cycle) / (double)rte_get_timer_hz();
        double time_since_update = (cur_cycle - last_update_cycle) / (double)rte_get_timer_hz();

        double tx_rate_average = packets_sent / time_elapsed;
        double tx_rate_current = packets_sent_since_update / time_since_update;

        double rx_rate_average = packets_received / time_elapsed;
        double rx_rate_current = packets_received_since_update / time_since_update;

        double latency_current_mean =
            total_latency_since_update / (double)packets_received_since_update / (double)(rte_get_timer_hz() / 1000000);

        last_update_cycle = cur_cycle;
        packets_sent_since_update = 0;
        packets_received_since_update = 0;
        total_latency_since_update = 0;

        /* Clear screen and move to top left */
        printf("%s%s", clr, topLeft);

        printf("Time elapsed: %.2f\n", time_elapsed);

        printf("\n");
        printf("Tx total packets: %" PRIu64 "\n", packets_sent);
        printf("Tx packets sent this iteration: %" PRIu32 "\n", batch_size);
        printf("Tx rate (set): %" PRIu64 "\n", packet_rate);
        printf("Tx rate (average): %.2f\n", tx_rate_average);
        printf("Tx rate (current): %.2f\n", tx_rate_current);

        printf("\n");
        printf("Rx total packets: %" PRIu64 " \n", packets_received);
        printf("Rx rate (average): %.2f\n", rx_rate_average);
        printf("Rx rate (current): %.2f\n", rx_rate_current);
        printf("Latency (current mean): %.2f us\n", latency_current_mean);

        printf("\n\n");
}

static int
packet_handler(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta,
               __attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx) {
        uint64_t *timestamp;

        if (!ONVM_CHECK_BIT(meta->flags, LOAD_GEN_BIT)) {
                meta->action = ONVM_NF_ACTION_DROP;
                return 0;
        }

        timestamp = (uint64_t *)(rte_pktmbuf_mtod(pkt, uint8_t *) + packet_size);
        total_latency_since_update += rte_get_tsc_cycles() - *timestamp;

        packets_received++;
        packets_received_since_update++;

        meta->action = ONVM_NF_ACTION_DROP;
        return 0;
}

static int
callback_handler(__attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx) {
        uint32_t i;
        uint64_t cur_cycle = rte_get_tsc_cycles();
        double time_delta = (cur_cycle - last_cycle) / (double)rte_get_timer_hz();
        packets_to_send += time_delta * packet_rate;
        last_cycle = cur_cycle;

        if (packets_to_send >= 1) {
                batch_size = (packets_to_send <= BATCH_LIMIT) ? (int)packets_to_send : BATCH_LIMIT;
                struct rte_mbuf *pkts[batch_size];
                for (i = 0; i < batch_size; i++) {
                        struct rte_ether_hdr *pkt_ehdr;
                        struct rte_mbuf *pkt = rte_pktmbuf_alloc(pktmbuf_pool);
                        uint64_t *timestamp;

                        if (pkt == NULL) {
                                printf("Failed to allocate packets\n");
                                break;
                        }

                        /* Append and copy ether header */
                        pkt_ehdr = (struct rte_ether_hdr *)rte_pktmbuf_append(pkt, packet_size);
                        rte_memcpy(pkt_ehdr, ehdr, sizeof(struct rte_ether_hdr));

                        struct onvm_pkt_meta *pmeta = onvm_get_pkt_meta(pkt);
                        pmeta->destination = destination;
                        pmeta->flags |= ONVM_SET_BIT(0, LOAD_GEN_BIT);
                        if (action_out) {
                                pmeta->action = ONVM_NF_ACTION_OUT;
                        } else {
                                pmeta->action = ONVM_NF_ACTION_TONF;
                        }

                        /* Add data to measure latency */
                        timestamp = (uint64_t *)rte_pktmbuf_append(pkt, sizeof(uint64_t));
                        *timestamp = rte_get_tsc_cycles();

                        pkts[i] = pkt;

                        packets_sent++;
                        packets_sent_since_update++;
                        packets_to_send--;
                }
                rte_eth_tx_burst(port_id, 0, pkts, batch_size);
                rte_eth_tx_buffer_flush(port_id, 0, pkts_tx_buffer);
        }

        time_since_print += time_delta;
        if (time_since_print > print_delay) {
                do_stats_display();
                time_since_print = 0;
        }

        return 0;
}

/*
 * Sets up load generator values
 */
void
nf_setup(void) {
        int j;

        start_cycle = rte_get_tsc_cycles();
        last_cycle = rte_get_tsc_cycles();
        last_update_cycle = rte_get_tsc_cycles();

        pktmbuf_pool = rte_mempool_lookup(NF_PKTMBUF_POOL_NAME);
        if (pktmbuf_pool == NULL) {
                rte_exit(EXIT_FAILURE, "Cannot find mbuf pool!\n");
        }

        ehdr = (struct rte_ether_hdr *)malloc(sizeof(struct rte_ether_hdr));
        if (ehdr == NULL) {
                rte_exit(EXIT_FAILURE, "Failed to allocate common ehdr\n");
        }

        if (onvm_get_macaddr(0, &ehdr->s_addr) == -1) {
                RTE_LOG(INFO, APP, "Using fake MAC address\n");
                onvm_get_fake_macaddr(&ehdr->s_addr);
        }
        for (j = 0; j < RTE_ETHER_ADDR_LEN; ++j) {
                ehdr->d_addr.addr_bytes[j] = d_addr_bytes[j];
        }
        ehdr->ether_type = rte_cpu_to_be_16(LOCAL_EXPERIMENTAL_ETHER);
}

/* main processing loop */
static void
load_generator_main_loop(void) {
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

                // optional user actions
                if (callback_handler(NULL))
                        return;
        }
}

static int
load_generator_launch_one_lcore(__rte_unused void* dummy) {
        load_generator_main_loop();
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
        const char *progname = argv[0];

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
	load_generator_pktmbuf_pool = rte_pktmbuf_pool_create(NF_PKTMBUF_POOL_NAME, nb_mbufs,
		MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
		rte_socket_id());
	if (load_generator_pktmbuf_pool == NULL)
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
        if (port_init(port_id, load_generator_pktmbuf_pool, NULL) != 0)
                rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n", port_id);

        // malloc tx buffer
        pkts_tx_buffer = rte_zmalloc_socket("tx_buffer", RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST), 0, rte_eth_dev_socket_id(port_id));
        if (pkts_tx_buffer == NULL)
                rte_exit(EXIT_FAILURE, "Cannot allocate buffer for tx on port %u\n", port_id);

        // init tx buffer
        ret = rte_eth_tx_buffer_init(pkts_tx_buffer, MAX_PKT_BURST);
        if (ret != 0)
                rte_exit(EXIT_FAILURE, "Cannot init transmit buffer: %d\n", ret);

        if (parse_app_args(argc, argv, progname) < 0) {
                rte_exit(EXIT_FAILURE, "Invalid command-line arguments\n");
        }

        nf_setup();

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

                        pkt = rte_pktmbuf_alloc(load_generator_pktmbuf_pool);
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
                        // optional user actions
                        if (callback_handler(NULL))
                                break;
                        // drop packet
                        rte_pktmbuf_free(pkt);
                }
                // Send pkt to mgr
                // onvm_nflib_return_pkt_bulk(nf_local_ctx->nf, pkts, pkts_generated);
        }
#else
        // dpdk loop
        unsigned lcore_id;
	rte_eal_mp_remote_launch(load_generator_launch_one_lcore, NULL, CALL_MASTER);
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0) {
			ret = -1;
			break;
		}
	}
#endif

        free(ehdr);

        printf("If we reach here, program is ending\n");
        return 0;
}
