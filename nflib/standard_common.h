#ifndef _STANDARD_COMMON_H_
#define _STANDARD_COMMON_H_

#include <inttypes.h>
#include <rte_common.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>

uint16_t
get_available_port_id(void);

int
port_init(uint16_t port, struct rte_mempool *mbuf_pool, const struct rte_eth_conf* port_conf_customize);

int
parse_portmask(const char *portmask);

#endif // _STANDARD_COMMON_H_