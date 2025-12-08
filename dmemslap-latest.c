#include <generic/rte_cycles.h>
#include <inttypes.h>
#include <rte_byteorder.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <math.h>
#include <time.h>
#include <rte_arp.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_atomic.h>
#include <getopt.h>

#define DEBUG_ARGS 1
#define FILE_PATH_MAX 512

#define MAX_TX_RX_QUEUE 16
#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */
#define MEMPOOL_CACHE_SIZE 256

#define MAX_BURST_SIZE 32
#define MAX_SAMPLES ((uint64_t)100000000)
#define RANDOM_US 10

#define CLIENT_IP "192.168.1.2"
#define MAX_KEY_LEN 16
#define MAX_VALUE_LEN 32
#define ZIPF_KEYSPACE_SIZE 65536 // 64K keys
// 16 bytes fixed key
#define FIXED_KEY "0000000000000001"

// Custom RSS key to ensure consistent hashing for TCP flows
static uint8_t rss_key[] = {
  0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
  0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
  0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
  0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
  0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
};

static const struct rte_eth_conf port_conf_default = {
  .rxmode = {
    .mq_mode = RTE_ETH_MQ_RX_RSS,
  },
  .rx_adv_conf = {
    .rss_conf = {
      .rss_key = rss_key,
      .rss_key_len = sizeof(rss_key),
      .rss_hf = RTE_ETH_RSS_NONFRAG_IPV4_TCP | RTE_ETH_RSS_NONFRAG_IPV6_TCP |
                RTE_ETH_RSS_NONFRAG_IPV4_UDP | RTE_ETH_RSS_NONFRAG_IPV6_UDP,
    },
  },
  .txmode = {
    .offloads = RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE | RTE_ETH_TX_OFFLOAD_IPV4_CKSUM |
                RTE_ETH_TX_OFFLOAD_UDP_CKSUM,
  },
};

#define MAKE_IP_ADDR(a, b, c, d)      \
  (((uint32_t) a << 24) | ((uint32_t) b << 16) |  \
   ((uint32_t) c << 8) | (uint32_t) d)

uint32_t kMagic = 0x6e626368; // 'nbch'

struct nbench_req {
  uint32_t magic;
  int nports;
};

struct nbench_resp {
  uint32_t magic;
  int nports;
  uint16_t ports[];
};

struct main_loop_arg {
  struct rte_ether_addr *eth_addr;
  uint8_t queue_id;
};

struct port_statistics {
  uint64_t tx;
  uint64_t rx;
  uint64_t dropped;
} __rte_cache_aligned;

struct port_statistics port_statistics[MAX_TX_RX_QUEUE];

struct tcp_connection_state {
  bool established;
  uint32_t next_seq;
  uint32_t recv_next;
  uint16_t src_port;
} __rte_cache_aligned tcp_connections[MAX_TX_RX_QUEUE];

static unsigned int dpdk_port = 1;
struct rte_mempool *rx_mbuf_pool;
struct rte_mempool *tx_mbuf_pool;
static struct rte_ether_addr my_eth;
static struct rte_ether_addr server_eth;
static uint32_t server_ip;
static uint32_t client_ip;
static int seconds;
static unsigned int server_port = 11211;
static unsigned int client_port = 38500; // Will be randomized at startup
static unsigned int num_queues;

static inline uint16_t
tcp_src_port_for_queue(uint8_t queue_id)
{
  return (uint16_t)(client_port + queue_id);
}

static inline int
queue_id_from_tcp_port(uint16_t port)
{
  if (port < client_port)
    return -1;

  unsigned int idx = port - client_port;
  if (idx >= num_queues)
    return -1;

  return (int)idx;
}

struct rte_ether_addr zero_mac = {
    .addr_bytes = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
};
struct rte_ether_addr broadcast_mac = {
    .addr_bytes = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
};

static unsigned int batch_size = 1;
static unsigned int send_pps = 1000000;
static float set_ratio = 0.5;
static double zipf_skew = 0.0;
static bool use_zipf_keys = false;
static bool use_fixed_key = false;
static bool use_open_loop = false;
static double *zipf_cdf = NULL;
static uint32_t zipf_keyspace = ZIPF_KEYSPACE_SIZE;
static char *mem_key = NULL;
static char *mem_val = NULL;

static uint64_t *diff_times;

static struct arr_index {
  uint64_t index;
} __rte_cache_aligned arr_index[MAX_TX_RX_QUEUE];

static struct container_rrt {
  uint64_t *rtt;
} __rte_cache_aligned rtt_times[MAX_TX_RX_QUEUE];

struct xorshift64_state {
    uint64_t a;
} __rte_cache_aligned rand_state[MAX_TX_RX_QUEUE];

static void handle_tcp_packet(struct rte_mbuf *buf, int q_id,
    struct rte_ether_addr *server_eth);

uint64_t xorshift64(struct xorshift64_state *state)
{
  uint64_t x = state->a;
  x ^= x << 13;
  x ^= x >> 7;
  x ^= x << 17;
  return state->a = x;
}

static int str_to_ip(const char *str, uint32_t *addr)
{
  uint8_t a, b, c, d;
  if(sscanf(str, "%hhu.%hhu.%hhu.%hhu", &a, &b, &c, &d) != 4) {
    return -EINVAL;
  }

  *addr = MAKE_IP_ADDR(a, b, c, d);
  return 0;
}

void print_ip_u32(uint32_t ip)
{
  printf("%d.%d.%d.%d\n", (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
}

void print_ip_be_u32(uint32_t ip)
{
  ip = rte_be_to_cpu_32(ip);
  printf("%d.%d.%d.%d\n", (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
}

static int str_to_long(const char *str, long *val)
{
  char *endptr;

  *val = strtol(str, &endptr, 10);
  if (endptr == str || (*endptr != '\0' && *endptr != '\n') ||
      ((*val == LONG_MIN || *val == LONG_MAX) && errno == ERANGE))
    return -EINVAL;
  return 0;
}

void print_mac(struct rte_ether_addr *mac) {
  printf("%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8
         ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8,
      mac->addr_bytes[0], mac->addr_bytes[1],
      mac->addr_bytes[2], mac->addr_bytes[3],
      mac->addr_bytes[4], mac->addr_bytes[5]);
}

int comp(const void *a, const void *b) {
  uint64_t ua = *((uint64_t *)a);
  uint64_t ub = *((uint64_t *)b);

  if (ua > ub) return 1;
  if (ua < ub) return -1;

  return 0;
}

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
static inline int
port_init(uint8_t port, struct rte_mempool *mbuf_pool, unsigned int n_queues)
{
  struct rte_eth_conf port_conf = port_conf_default;
  const uint16_t rx_rings = n_queues, tx_rings = n_queues;
  uint16_t nb_rxd = RX_RING_SIZE;
  uint16_t nb_txd = TX_RING_SIZE;
  int retval;
  uint16_t q;
  struct rte_eth_dev_info dev_info;
  struct rte_eth_txconf *txconf;

  printf("initializing with %u queues\n", n_queues);

  if (!rte_eth_dev_is_valid_port(port)){
    printf("port valid\n");
    return -1;

  }

  /* Configure the Ethernet device. */
  retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
  if (retval != 0){
    printf("port config\n");
    return retval;

  }

  /* Get device info for RSS configuration */
  retval = rte_eth_dev_info_get(port, &dev_info);
  if (retval != 0) {
    printf("Failed to get device info\n");
    return retval;
  }

  printf("RSS configuration:\n");
  printf("  Hash key size: %u\n", dev_info.hash_key_size);
  printf("  RETA size: %u\n", dev_info.reta_size);
  printf("  Flow type RSS offloads: 0x%lx\n", dev_info.flow_type_rss_offloads);

  /* Configure RSS indirection table to distribute flows across queues */
  if (dev_info.reta_size > 0 && n_queues > 1) {
    struct rte_eth_rss_reta_entry64 reta_conf[512 / RTE_ETH_RETA_GROUP_SIZE];
    memset(reta_conf, 0, sizeof(reta_conf));
    
    for (uint16_t i = 0; i < dev_info.reta_size; i++) {
      uint16_t idx = i / RTE_ETH_RETA_GROUP_SIZE;
      uint16_t shift = i % RTE_ETH_RETA_GROUP_SIZE;
      reta_conf[idx].mask |= (1ULL << shift);
      reta_conf[idx].reta[shift] = i % n_queues;
    }
    
    retval = rte_eth_dev_rss_reta_update(port, reta_conf,
                                         dev_info.reta_size);
    if (retval != 0) {
      printf("Warning: Failed to update RSS RETA table: %d\n", retval);
      printf("Continuing anyway - RSS may not distribute evenly\n");
    } else {
      printf("RSS RETA table configured for %u queues\n", n_queues);
    }
  }

  retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
  if (retval != 0)
    return retval;

  /* Allocate and set up RX queues */
  for (q = 0; q < rx_rings; q++) {
    retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
                                        rte_eth_dev_socket_id(port), NULL,
                                        mbuf_pool);
    if (retval < 0)
      return retval;
  }

  /* Enable TX offloading */
  txconf = &dev_info.default_txconf;
  txconf->offloads = port_conf.txmode.offloads;

  /* Allocate and set up TX queues */
  for (q = 0; q < tx_rings; q++) {
    retval = rte_eth_tx_queue_setup(port, q, nb_txd,
                                        rte_eth_dev_socket_id(port), txconf);
    if (retval < 0)
      return retval;
  }

  /* Start the Ethernet port. */
  retval = rte_eth_dev_start(port);
  if (retval < 0)
    return retval;

  /* Display the port MAC address. */
  rte_eth_macaddr_get(port, &my_eth);
  printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
         " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
      (unsigned)port,
      my_eth.addr_bytes[0], my_eth.addr_bytes[1],
      my_eth.addr_bytes[2], my_eth.addr_bytes[3],
      my_eth.addr_bytes[4], my_eth.addr_bytes[5]);

  /* Enable RX in promiscuous mode for the Ethernet device. */
  rte_eth_promiscuous_enable(port);

  return 0;
}

/*
 * Send out an arp.
 */
static void send_arp(uint16_t op, struct rte_ether_addr dst_eth, uint32_t dst_ip)
{
  struct rte_mbuf *buf;
  char *buf_ptr;
  struct rte_ether_hdr *eth_hdr;
  struct rte_arp_hdr *a_hdr;
  int nb_tx;

  buf = rte_pktmbuf_alloc(tx_mbuf_pool);
  if (buf == NULL)
    printf("error allocating arp mbuf\n");

  /* ethernet header */
  buf_ptr = rte_pktmbuf_append(buf, RTE_ETHER_HDR_LEN);
  eth_hdr = (struct rte_ether_hdr *) buf_ptr;

  rte_ether_addr_copy(&my_eth, &eth_hdr->src_addr);
  rte_ether_addr_copy(&dst_eth, &eth_hdr->dst_addr);
  eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);

  /* arp header */
  buf_ptr = rte_pktmbuf_append(buf, sizeof(struct rte_arp_hdr));
  a_hdr = (struct rte_arp_hdr *) buf_ptr;
  a_hdr->arp_hardware = rte_cpu_to_be_16(RTE_ARP_HRD_ETHER);
  a_hdr->arp_protocol = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
  a_hdr->arp_hlen = RTE_ETHER_ADDR_LEN;
  a_hdr->arp_plen = 4;
  a_hdr->arp_opcode = rte_cpu_to_be_16(op);

  rte_ether_addr_copy(&my_eth, &a_hdr->arp_data.arp_sha);
  a_hdr->arp_data.arp_sip = rte_cpu_to_be_32(client_ip);
  rte_ether_addr_copy(&dst_eth, &a_hdr->arp_data.arp_tha);
  a_hdr->arp_data.arp_tip = rte_cpu_to_be_32(dst_ip);

  nb_tx = rte_eth_tx_burst(dpdk_port, 0, &buf, 1);
  if (unlikely(nb_tx != 1)) {
    printf("error: could not send arp packet\n");
  }
}

/*
 * Validate this ethernet header. Return true if this packet is for higher
 * layers, false otherwise.
 */
static bool check_eth_hdr(struct rte_mbuf *buf)
{
  struct rte_ether_hdr *ptr_mac_hdr;
  struct rte_arp_hdr *a_hdr;
  struct rte_ether_addr *serv_eth;

  ptr_mac_hdr = rte_pktmbuf_mtod(buf, struct rte_ether_hdr *);
  serv_eth = &ptr_mac_hdr->src_addr;
  if (!rte_is_same_ether_addr(&ptr_mac_hdr->dst_addr, &my_eth) &&
      !rte_is_broadcast_ether_addr(&ptr_mac_hdr->dst_addr)) {
    //print ether addr
    // printf("MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
    //      " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
    //   serv_eth->addr_bytes[0], serv_eth->addr_bytes[1],
    //   serv_eth->addr_bytes[2], serv_eth->addr_bytes[3],
    //   serv_eth->addr_bytes[4], serv_eth->addr_bytes[5]);

    /* packet not to our ethernet addr */
    return false;
  }

  if (ptr_mac_hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {
    /* reply to ARP if necessary */
    a_hdr = rte_pktmbuf_mtod_offset(buf, struct rte_arp_hdr *,
        sizeof(struct rte_ether_hdr));
    if (a_hdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REQUEST)
        && a_hdr->arp_data.arp_tip == rte_cpu_to_be_32(client_ip))
      send_arp(RTE_ARP_OP_REPLY, a_hdr->arp_data.arp_sha,
          rte_be_to_cpu_32(a_hdr->arp_data.arp_sip));
    return false;
  }

  if (ptr_mac_hdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
    /* packet not IPv4 */
    return false;

  return true;
}

/*
 * Return true if this IP packet is to us and contains a UDP packet,
 * false otherwise.
 */
static bool check_ip_hdr(struct rte_mbuf *buf)
{
  struct rte_ipv4_hdr *ipv4_hdr;

  ipv4_hdr = rte_pktmbuf_mtod_offset(buf, struct rte_ipv4_hdr *,
      RTE_ETHER_HDR_LEN);

  if (ipv4_hdr->dst_addr == client_ip
      && ipv4_hdr->next_proto_id == IPPROTO_UDP) {
    
    return true;
  }
  
  return false;
}

/*
 * Resolve mac
 */

void get_server_mac(struct rte_ether_addr *server_eth) {
  struct rte_mbuf *bufs[MAX_BURST_SIZE];
  struct rte_mbuf *buf;
  struct rte_ether_hdr *ptr_mac_hdr;
  struct rte_arp_hdr *a_hdr;
  int nb_rx, nb_tx, i;

  /* get the mac address of the server via ARP */
  while (true) {
    send_arp(RTE_ARP_OP_REQUEST, broadcast_mac, server_ip);
    sleep(1);

    nb_rx = rte_eth_rx_burst(dpdk_port, 0, bufs, MAX_BURST_SIZE);
    if (nb_rx == 0) {
      printf("No ARP reply\n");
      continue;
    }
    printf("ARP reply found\n");

    for (i = 0; i < nb_rx; i++) {
      buf = bufs[i];

      ptr_mac_hdr = rte_pktmbuf_mtod(buf, struct rte_ether_hdr *);
      if (!rte_is_same_ether_addr(&ptr_mac_hdr->dst_addr, &my_eth)) {
          /* packet not to our ethernet addr */
          printf("Same address!\n");
          continue;
      }

      if (ptr_mac_hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {
        /* this is an ARP */
        a_hdr = rte_pktmbuf_mtod_offset(buf, struct rte_arp_hdr *,
            sizeof(struct rte_ether_hdr));
        if (a_hdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REPLY) &&
            rte_is_same_ether_addr(&a_hdr->arp_data.arp_tha, &my_eth) &&
            a_hdr->arp_data.arp_tip == rte_cpu_to_be_32(client_ip)) {
          /* got a response from server! */
          rte_ether_addr_copy(&a_hdr->arp_data.arp_sha, server_eth);
          return;
        }
      }
    }
  }
}

static struct rte_mbuf *
build_tcp_packet(struct rte_ether_addr *server_eth, uint16_t src_port,
    uint8_t flags, uint32_t seq, uint32_t ack_num,
    const char *payload, uint16_t payload_len)
{
  struct rte_mbuf *buf = rte_pktmbuf_alloc(tx_mbuf_pool);
  if (buf == NULL)
    return NULL;

  char *buf_ptr = rte_pktmbuf_append(buf, RTE_ETHER_HDR_LEN);
  struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)buf_ptr;
  rte_ether_addr_copy(&my_eth, &eth_hdr->src_addr);
  rte_ether_addr_copy(server_eth, &eth_hdr->dst_addr);
  eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

  buf_ptr = rte_pktmbuf_append(buf, sizeof(struct rte_ipv4_hdr));
  struct rte_ipv4_hdr *ipv4_hdr = (struct rte_ipv4_hdr *)buf_ptr;
  ipv4_hdr->version_ihl = 0x45;
  ipv4_hdr->type_of_service = 0;
  uint16_t ip_hdr_len = sizeof(struct rte_ipv4_hdr);
  uint16_t total_len = ip_hdr_len + sizeof(struct rte_tcp_hdr) + payload_len;
  ipv4_hdr->total_length = rte_cpu_to_be_16(total_len);
  ipv4_hdr->packet_id = 0;
  ipv4_hdr->fragment_offset = 0;
  ipv4_hdr->time_to_live = 64;
  ipv4_hdr->next_proto_id = IPPROTO_TCP;
  ipv4_hdr->hdr_checksum = 0;
  ipv4_hdr->src_addr = client_ip;
  ipv4_hdr->dst_addr = server_ip;

  buf_ptr = rte_pktmbuf_append(buf, sizeof(struct rte_tcp_hdr) + payload_len);
  struct rte_tcp_hdr *tcp_hdr = (struct rte_tcp_hdr *)buf_ptr;
  tcp_hdr->src_port = rte_cpu_to_be_16(src_port);
  tcp_hdr->dst_port = rte_cpu_to_be_16(server_port);
  tcp_hdr->sent_seq = rte_cpu_to_be_32(seq);
  tcp_hdr->recv_ack = rte_cpu_to_be_32(ack_num);
  tcp_hdr->data_off = (sizeof(struct rte_tcp_hdr) / 4) << 4;
  tcp_hdr->tcp_flags = flags;
  tcp_hdr->rx_win = rte_cpu_to_be_16(65535);
  tcp_hdr->cksum = 0;
  tcp_hdr->tcp_urp = 0;

  if (payload_len > 0 && payload != NULL) {
    char *data_ptr = buf_ptr + sizeof(struct rte_tcp_hdr);
    memcpy(data_ptr, payload, payload_len);
  }

  tcp_hdr->cksum = rte_ipv4_udptcp_cksum(ipv4_hdr, tcp_hdr);
  ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);

  buf->l2_len = RTE_ETHER_HDR_LEN;
  buf->l3_len = sizeof(struct rte_ipv4_hdr);
  buf->l4_len = sizeof(struct rte_tcp_hdr);
  buf->ol_flags = RTE_MBUF_F_TX_IPV4;

  return buf;
}

static int
transmit_single(struct rte_mbuf *packet, uint8_t queue_id)
{
  if (packet == NULL)
    return -1;

  struct rte_mbuf *pkts[1] = { packet };
  int nb_tx = rte_eth_tx_burst(dpdk_port, queue_id, pkts, 1);
  if (nb_tx != 1) {
    rte_pktmbuf_free(packet);
    return -1;
  }
  return 0;
}

static int
setup_tcp_connection(struct rte_ether_addr *server_eth, int q_id)
{
  struct tcp_connection_state *conn = &tcp_connections[q_id];
  if (conn->established)
    return 0;

  conn->src_port = tcp_src_port_for_queue(q_id);
  uint32_t isn = (uint32_t)xorshift64(&rand_state[q_id]);
  struct rte_mbuf *syn_pkt = build_tcp_packet(server_eth, conn->src_port,
      RTE_TCP_SYN_FLAG, isn, 0, NULL, 0);
  if (syn_pkt == NULL)
    return -1;

  if (transmit_single(syn_pkt, (uint8_t)q_id) != 0)
    return -1;

  conn->next_seq = isn + 1;

  uint64_t start = rte_get_timer_cycles();
  const uint64_t timeout = rte_get_timer_hz(); // 1 second
  int total_packets_seen = 0;
  int tcp_packets_seen = 0;

  while (rte_get_timer_cycles() - start < timeout) {
    for (unsigned int rx_q = 0; rx_q < num_queues; rx_q++) {
      struct rte_mbuf *bufs[MAX_BURST_SIZE];
      int nb_rx = rte_eth_rx_burst(dpdk_port, rx_q, bufs, MAX_BURST_SIZE);
      if (nb_rx == 0)
        continue;

      total_packets_seen += nb_rx;

      for (int i = 0; i < nb_rx; i++) {
        struct rte_mbuf *buf = bufs[i];
        if (!check_eth_hdr(buf)) {
          rte_pktmbuf_free(buf);
          continue;
        }

        struct rte_ipv4_hdr *ipv4_hdr = rte_pktmbuf_mtod_offset(buf,
            struct rte_ipv4_hdr *, RTE_ETHER_HDR_LEN);
        if (ipv4_hdr->dst_addr != client_ip ||
            ipv4_hdr->src_addr != server_ip ||
            ipv4_hdr->next_proto_id != IPPROTO_TCP) {
          rte_pktmbuf_free(buf);
          continue;
        }

        tcp_packets_seen++;
        uint16_t ip_hdr_len = (uint16_t)((ipv4_hdr->version_ihl & 0x0F) * 4);
        struct rte_tcp_hdr *tcp_hdr = (struct rte_tcp_hdr *)((char *)ipv4_hdr + ip_hdr_len);

        int target_queue = queue_id_from_tcp_port(rte_be_to_cpu_16(tcp_hdr->dst_port));
        if (target_queue < 0) {
          rte_pktmbuf_free(buf);
          continue;
        }

        if ((unsigned int)target_queue != q_id) {
          handle_tcp_packet(buf, target_queue, server_eth);
          continue;
        }

        if (tcp_hdr->src_port != rte_cpu_to_be_16(server_port)) {
          rte_pktmbuf_free(buf);
          continue;
        }

        // Check for SYN-ACK
        uint8_t flags = tcp_hdr->tcp_flags;
        if ((flags & (RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG)) ==
            (RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG)) {
          uint32_t ack = rte_be_to_cpu_32(tcp_hdr->recv_ack);
          if (ack != conn->next_seq) {
            rte_pktmbuf_free(buf);
            continue;
          }

          uint32_t server_seq = rte_be_to_cpu_32(tcp_hdr->sent_seq);
          conn->recv_next = server_seq + 1;

          struct rte_mbuf *ack_pkt = build_tcp_packet(server_eth,
              conn->src_port, RTE_TCP_ACK_FLAG, conn->next_seq,
              conn->recv_next, NULL, 0);
          if (ack_pkt != NULL)
            transmit_single(ack_pkt, (uint8_t)q_id);

          conn->established = true;
          printf("TCP handshake established on queue %d\n", q_id);
          fflush(stdout);
          rte_pktmbuf_free(buf);

          for (int j = i + 1; j < nb_rx; j++)
            rte_pktmbuf_free(bufs[j]);

          return 0;
        }

        rte_pktmbuf_free(buf);
      }
    }
  }

  printf("TCP handshake timed out on queue %d\n", q_id);
  conn->established = false;
  return -1;
}

static void
teardown_tcp_connection(struct rte_ether_addr *server_eth, int q_id)
{
  struct tcp_connection_state *conn = &tcp_connections[q_id];
  if (!conn->established || conn->src_port == 0)
    return;

  struct rte_mbuf *fin_pkt = build_tcp_packet(server_eth, conn->src_port,
      (uint8_t)(RTE_TCP_FIN_FLAG | RTE_TCP_ACK_FLAG), conn->next_seq,
      conn->recv_next, NULL, 0);
  if (fin_pkt != NULL && transmit_single(fin_pkt, (uint8_t)q_id) == 0)
    conn->next_seq += 1;

  struct rte_mbuf *bufs[MAX_BURST_SIZE];
  uint64_t start = rte_get_timer_cycles();
  const uint64_t timeout = rte_get_timer_hz() / 2;

  while (conn->established && (rte_get_timer_cycles() - start) < timeout) {
    int nb_rx = rte_eth_rx_burst(dpdk_port, q_id, bufs, MAX_BURST_SIZE);
    if (nb_rx == 0)
      continue;

    for (int i = 0; i < nb_rx; i++) {
      struct rte_mbuf *buf = bufs[i];
      if (!check_eth_hdr(buf)) {
        rte_pktmbuf_free(buf);
        continue;
      }

      struct rte_ipv4_hdr *ipv4_hdr = rte_pktmbuf_mtod_offset(buf,
          struct rte_ipv4_hdr *, RTE_ETHER_HDR_LEN);

      if (ipv4_hdr->dst_addr != client_ip) {
        rte_pktmbuf_free(buf);
        continue;
      }

      if (ipv4_hdr->next_proto_id == IPPROTO_TCP) {
        handle_tcp_packet(buf, q_id, server_eth);
      } else if (ipv4_hdr->next_proto_id == IPPROTO_UDP) {
        rte_pktmbuf_free(buf);
      } else {
        rte_pktmbuf_free(buf);
      }
    }
  }

  conn->established = false;
  conn->src_port = 0;
}

static void
establish_tcp_connections(struct rte_ether_addr *server_eth)
{
  if (set_ratio <= 0.0f)
    return;

  for (unsigned int q = 0; q < num_queues; q++) {
    if (setup_tcp_connection(server_eth, (int)q) != 0)
      rte_exit(EXIT_FAILURE,
          "Failed to establish TCP connection on queue %u\n", q);
  }
}

static void
handle_tcp_packet(struct rte_mbuf *buf, int q_id,
    struct rte_ether_addr *server_eth)
{
  struct tcp_connection_state *conn = &tcp_connections[q_id];
  struct rte_ipv4_hdr *ipv4_hdr = rte_pktmbuf_mtod_offset(buf,
      struct rte_ipv4_hdr *, RTE_ETHER_HDR_LEN);

  if (ipv4_hdr->dst_addr != client_ip || ipv4_hdr->src_addr != server_ip) {
    rte_pktmbuf_free(buf);
    return;
  }

  uint16_t ip_hdr_len = (uint16_t)((ipv4_hdr->version_ihl & 0x0F) * 4);
  struct rte_tcp_hdr *tcp_hdr = (struct rte_tcp_hdr *)((char *)ipv4_hdr + ip_hdr_len);
  if (conn->src_port == 0) {
    rte_pktmbuf_free(buf);
    return;
  }
  if (tcp_hdr->dst_port != rte_cpu_to_be_16(conn->src_port) ||
      tcp_hdr->src_port != rte_cpu_to_be_16(server_port)) {
    rte_pktmbuf_free(buf);
    return;
  }

  uint16_t tcp_hdr_len = (uint16_t)(((tcp_hdr->data_off & 0xF0) >> 4) * 4);
  uint16_t total_len = rte_be_to_cpu_16(ipv4_hdr->total_length);
  uint16_t payload_len = 0;

  if (total_len >= ip_hdr_len + tcp_hdr_len)
    payload_len = total_len - ip_hdr_len - tcp_hdr_len;

  uint32_t seq = rte_be_to_cpu_32(tcp_hdr->sent_seq);
  uint8_t flags = tcp_hdr->tcp_flags;

  if ((flags & RTE_TCP_RST_FLAG) != 0) {
    conn->established = false;
    rte_pktmbuf_free(buf);
    return;
  }

  if (!conn->established &&
      (flags & (RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG)) ==
          (RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG)) {
    conn->recv_next = seq + 1;
    conn->established = true;
    struct rte_mbuf *ack_pkt = build_tcp_packet(server_eth, conn->src_port,
        RTE_TCP_ACK_FLAG, conn->next_seq, conn->recv_next, NULL, 0);
    if (ack_pkt != NULL)
      transmit_single(ack_pkt, (uint8_t)q_id);
    rte_pktmbuf_free(buf);
    return;
  }

  if (payload_len > 0 || (flags & RTE_TCP_FIN_FLAG)) {
    uint32_t advance = payload_len;
    if ((flags & RTE_TCP_SYN_FLAG) != 0)
      advance += 1;
    if ((flags & RTE_TCP_FIN_FLAG) != 0)
      advance += 1;

    if (seq == conn->recv_next)
      conn->recv_next += advance;

    struct rte_mbuf *ack_pkt = build_tcp_packet(server_eth, conn->src_port,
        RTE_TCP_ACK_FLAG, conn->next_seq, conn->recv_next, NULL, 0);
    if (ack_pkt != NULL)
      transmit_single(ack_pkt, (uint8_t)q_id);

    if ((flags & RTE_TCP_FIN_FLAG) != 0) {
      conn->established = false;
      conn->src_port = 0;
    }
  }

  rte_pktmbuf_free(buf);
}

void report_stats() {
  uint64_t included_samples = 0;
  uint64_t total_cycles = 0;

  for (uint64_t j = 0; j < num_queues; j++) {
    for (uint64_t i = arr_index[j].index * 0.1; i < arr_index[j].index * 0.9; i++) {
      total_cycles += rtt_times[j].rtt[i];
      diff_times[included_samples++] = rtt_times[j].rtt[i];
    }
  }
  
  // Measure p50 and p99 latency 
  qsort(diff_times, included_samples, sizeof(uint64_t), comp);
  uint64_t p50_cycles = diff_times[(uint64_t)(included_samples * 0.5)];
  uint64_t p99_cycles = diff_times[(uint64_t)(included_samples * 0.99)];

  printf("mean latency (us): %f\n", (float) total_cycles *
    1000 * 1000 / (included_samples * rte_get_timer_hz()));
  printf("median latency (us): %f\n", (p50_cycles * 1000.0 * 1000.0) / rte_get_timer_hz());
  printf("99th latency (us): %f\n", (p99_cycles * 1000.0 * 1000.0) / rte_get_timer_hz());
}

struct memcache_udp_header {
    uint16_t request_id;
    uint16_t sequence_id;
    uint16_t total_datagrams;
    uint16_t reserved;
} __attribute__((__packed__));

static void gen_random_string(struct xorshift64_state *state, int len, char *buf) {
  static const char alphanum[] =
      "0123456789"
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
      "abcdefghijklmnopqrstuvwxyz";
  for (int i = 0; i < len; ++i) {
    buf[i] = alphanum[xorshift64(state) % (sizeof(alphanum) - 1)];
  }
  buf[len] = 0;
}

static void init_zipf_generator(void)
{
  if (!use_zipf_keys || zipf_cdf != NULL)
    return;

  zipf_cdf = (double *)malloc(sizeof(double) * zipf_keyspace);
  if (!zipf_cdf)
    rte_exit(EXIT_FAILURE, "Cannot allocate memory for zipf_cdf\n");

  double normalizer = 0.0;
  for (uint32_t i = 1; i <= zipf_keyspace; ++i) {
    normalizer += pow((double)i, -zipf_skew);
  }

  double cumulative = 0.0;
  for (uint32_t i = 1; i <= zipf_keyspace; ++i) {
    cumulative += pow((double)i, -zipf_skew) / normalizer;
    zipf_cdf[i - 1] = cumulative;
  }
  zipf_cdf[zipf_keyspace - 1] = 1.0;
}

static inline double next_uniform(struct xorshift64_state *state)
{
  return ((double)xorshift64(state) + 1.0) / ((double)UINT64_MAX + 1.0);
}

static inline uint32_t sample_zipf_key(struct xorshift64_state *state)
{
  double u = next_uniform(state);
  uint32_t left = 0;
  uint32_t right = zipf_keyspace - 1;

  while (left < right) {
    uint32_t mid = left + ((right - left) >> 1);
    if (u <= zipf_cdf[mid])
      right = mid;
    else
      left = mid + 1;
  }

  return left;
}

static inline void fill_request_key(uint8_t q_id, char *buf)
{
  if (use_zipf_keys) {
    uint32_t idx = sample_zipf_key(&rand_state[q_id]);
    snprintf(buf, MAX_KEY_LEN + 1, "%0*" PRIx32, MAX_KEY_LEN, idx);
  } else {
    gen_random_string(&rand_state[q_id], MAX_KEY_LEN, buf);
  }
}

/*
 * Allocate a packet
 */

struct rte_mbuf *allocate_pkt(struct rte_ether_addr *server_eth, int q_id,
    uint32_t *tcp_payload_len) {
  struct rte_mbuf *buf;
  struct rte_ether_hdr *eth_hdr;
  struct rte_ipv4_hdr *ipv4_hdr;
  struct rte_udp_hdr *rte_udp_hdr;
  char *buf_ptr;

  char payload[MAX_VALUE_LEN + MAX_KEY_LEN + 64];
  int payload_len;
  bool is_set = (xorshift64(&rand_state[q_id]) % 100) < (set_ratio * 100);

  if (tcp_payload_len != NULL)
    *tcp_payload_len = 0;

  if (!use_fixed_key)
    fill_request_key(q_id, mem_key);

  if (is_set) {
      payload_len = snprintf(payload, sizeof(payload), "set %s 0 0 %u\r\n", mem_key, MAX_VALUE_LEN);
      if (payload_len < 0 || payload_len >= (int)sizeof(payload)) {
          return NULL;
      }
      
      if ((int)(payload_len + MAX_VALUE_LEN + 2) >= (int)sizeof(payload)) {
          return NULL;
      }
      
      gen_random_string(&rand_state[q_id], MAX_VALUE_LEN, mem_val);
      memcpy(payload + payload_len, mem_val, MAX_VALUE_LEN);
      payload_len += MAX_VALUE_LEN;
      payload[payload_len++] = '\r';
      payload[payload_len++] = '\n';
  } else {
      payload_len = snprintf(payload, sizeof(payload), "get %s\r\n", mem_key);
      if (payload_len < 0 || payload_len >= (int)sizeof(payload)) {
          return NULL;
      }
  }

  struct tcp_connection_state *conn = NULL;
  if (is_set) {
    conn = &tcp_connections[q_id];
    if (!conn->established) {
      if (setup_tcp_connection(server_eth, q_id) != 0)
        return NULL;
    }
  }

  buf = rte_pktmbuf_alloc(tx_mbuf_pool);
  if (buf == NULL) {
    printf("error allocating tx mbuf\n");
    return NULL;
  }

  /* ethernet header */
  buf_ptr = rte_pktmbuf_append(buf, RTE_ETHER_HDR_LEN);
  eth_hdr = (struct rte_ether_hdr *) buf_ptr;

  rte_ether_addr_copy(&my_eth, &eth_hdr->src_addr);
  rte_ether_addr_copy(server_eth, &eth_hdr->dst_addr);
  eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

  /* IPv4 header */
  buf_ptr = rte_pktmbuf_append(buf, sizeof(struct rte_ipv4_hdr));
  ipv4_hdr = (struct rte_ipv4_hdr *) buf_ptr;
  ipv4_hdr->version_ihl = 0x45;
  ipv4_hdr->type_of_service = 0;
  ipv4_hdr->packet_id = 0;
  ipv4_hdr->fragment_offset = 0;
  ipv4_hdr->time_to_live = 64;
  // If get then UDP else TCP
  if (!is_set)
    ipv4_hdr->next_proto_id = IPPROTO_UDP;
  else
    ipv4_hdr->next_proto_id = IPPROTO_TCP;
  
  ipv4_hdr->hdr_checksum = 0; // Checksum offloaded to hardware
  ipv4_hdr->src_addr = client_ip;
  ipv4_hdr->dst_addr = server_ip;

  uint16_t l4_len = 0;
  uint64_t ol_flags = 0;

  /* UDP header + data */
  if (!is_set) {
    ipv4_hdr->total_length = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) +
      sizeof(struct rte_udp_hdr) + sizeof(struct memcache_udp_header) + payload_len);
    
    buf_ptr = rte_pktmbuf_append(buf,
        sizeof(struct rte_udp_hdr) + sizeof(struct memcache_udp_header) + payload_len);
    rte_udp_hdr = (struct rte_udp_hdr *) buf_ptr;
    rte_udp_hdr->src_port = rte_cpu_to_be_16(client_port);
    rte_udp_hdr->dst_port = rte_cpu_to_be_16(server_port);
    rte_udp_hdr->dgram_len = rte_cpu_to_be_16(sizeof(struct rte_udp_hdr)
        + sizeof(struct memcache_udp_header) + payload_len);
    rte_udp_hdr->dgram_cksum = 0; // Checksum offloaded to hardware

    // Set memcached udp header
    struct memcache_udp_header *mc_udp_hdr = (struct memcache_udp_header *)(buf_ptr + sizeof(struct rte_udp_hdr));
    mc_udp_hdr->request_id = rte_cpu_to_be_16(0);
    mc_udp_hdr->sequence_id = rte_cpu_to_be_16(0);
    mc_udp_hdr->total_datagrams = rte_cpu_to_be_16(1);
    mc_udp_hdr->reserved = rte_cpu_to_be_16(0);

    // Set payload
    char *data_ptr = buf_ptr + sizeof(struct rte_udp_hdr) + sizeof(struct memcache_udp_header);
    memcpy(data_ptr, payload, payload_len);
    l4_len = sizeof(struct rte_udp_hdr);
    ol_flags = RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_UDP_CKSUM;
  }
  else {
    uint16_t total_len = sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr) + payload_len;
    ipv4_hdr->total_length = rte_cpu_to_be_16(total_len);

    buf_ptr = rte_pktmbuf_append(buf, sizeof(struct rte_tcp_hdr) + payload_len);
    struct rte_tcp_hdr *tcp_hdr = (struct rte_tcp_hdr *)buf_ptr;
    tcp_hdr->src_port = rte_cpu_to_be_16(conn->src_port);
    tcp_hdr->dst_port = rte_cpu_to_be_16(server_port);
    tcp_hdr->sent_seq = rte_cpu_to_be_32(conn->next_seq);
    tcp_hdr->recv_ack = rte_cpu_to_be_32(conn->recv_next);
    tcp_hdr->data_off = (sizeof(struct rte_tcp_hdr) / 4) << 4;
    tcp_hdr->tcp_flags = RTE_TCP_PSH_FLAG | RTE_TCP_ACK_FLAG;
    tcp_hdr->rx_win = rte_cpu_to_be_16(65535);
    tcp_hdr->cksum = 0;
    tcp_hdr->tcp_urp = 0;

    char *data_ptr = buf_ptr + sizeof(struct rte_tcp_hdr);
    memcpy(data_ptr, payload, payload_len);

    ipv4_hdr->hdr_checksum = 0;
    tcp_hdr->cksum = rte_ipv4_udptcp_cksum(ipv4_hdr, tcp_hdr);
    ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);

    l4_len = sizeof(struct rte_tcp_hdr);
    ol_flags = RTE_MBUF_F_TX_IPV4;

    conn->next_seq += payload_len;
    if (tcp_hdr->tcp_flags & RTE_TCP_FIN_FLAG)
      conn->next_seq += 1;

    if (tcp_payload_len != NULL)
      *tcp_payload_len = (uint32_t)payload_len;
  }

  buf->l2_len = RTE_ETHER_HDR_LEN;
  buf->l3_len = sizeof(struct rte_ipv4_hdr);
  buf->l4_len = l4_len;
  buf->ol_flags = ol_flags;
  
  return buf;
}

static int open_loop(void *arg) {
  struct rte_mbuf *rx_bufs[MAX_BURST_SIZE];
  struct rte_mbuf *buf;
  uint64_t start_time, prev_time, curr_time;
  int32_t nb_tx, nb_rx;
  uint64_t total_tx = 0, total_rx = 0;
  struct main_loop_arg *args = (struct main_loop_arg *)arg;
  uint8_t q_id = args->queue_id;
  struct rte_ether_addr *server_eth = args->eth_addr;
  
  printf("Open loop client starting\n");
  
  if (rte_eth_dev_socket_id(dpdk_port) != (int)rte_socket_id())
    printf("WARNING, port %u (socket %d) is on remote NUMA node to polling thread (socket %d).\n\t"
           "Performance will not be optimal.\n", dpdk_port, rte_eth_dev_socket_id(dpdk_port), rte_socket_id());

  printf("\nCore %d\tQueue: %d\n", rte_lcore_id(), q_id);
  printf("Server MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
         " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
      server_eth->addr_bytes[0], server_eth->addr_bytes[1],
      server_eth->addr_bytes[2], server_eth->addr_bytes[3],
      server_eth->addr_bytes[4], server_eth->addr_bytes[5]);

  if (set_ratio > 0.0f) {
    if (setup_tcp_connection(server_eth, q_id) != 0) {
      printf("WARNING: TCP connection failed on queue %d - SET requests will be dropped\n", q_id);
      // Don't fail in open-loop - just continue without SETs
    }
  }
  
  /* Calculate timing for fixed rate sending */
  uint64_t hz = rte_get_timer_hz();
  uint64_t pps_per_queue = send_pps / num_queues;
  uint64_t cycles_per_packet = hz / pps_per_queue;
  
  printf("Target rate: %lu pps per queue (%lu cycles between packets)\n", 
         pps_per_queue, cycles_per_packet);
  
  start_time = rte_get_timer_cycles();
  prev_time = start_time;
  uint64_t next_send_time = start_time;
  
  while (rte_get_timer_cycles() < (start_time + seconds * hz)) {
    curr_time = rte_get_timer_cycles();
    
    /* Send packets at fixed rate */
    if (curr_time >= next_send_time) {
      struct rte_mbuf *tx_bufs[batch_size];
      uint32_t tcp_payload_lengths[batch_size];
      
      int prepared = 0;
      while (prepared < batch_size) {
        buf = allocate_pkt(server_eth, q_id, &tcp_payload_lengths[prepared]);
        if (buf == NULL)
          continue;
        tx_bufs[prepared++] = buf;
      }
      
      nb_tx = rte_eth_tx_burst(dpdk_port, q_id, tx_bufs, batch_size);
      total_tx += nb_tx;
      port_statistics[q_id].tx += nb_tx;
      
      /* Handle unsent packets */
      if (unlikely(nb_tx < batch_size)) {
        for (int i = nb_tx; i < batch_size; i++) {
          struct rte_mbuf *unsent = tx_bufs[i];
          uint32_t payload_len = tcp_payload_lengths[i];
          if (unsent != NULL && payload_len > 0) {
            struct tcp_connection_state *conn = &tcp_connections[q_id];
            conn->next_seq -= payload_len;
          }
          rte_pktmbuf_free(unsent);
        }
      }
      
      next_send_time += cycles_per_packet * batch_size;
    }
    
    /* Receive packets (non-blocking) */
    nb_rx = rte_eth_rx_burst(dpdk_port, q_id, rx_bufs, MAX_BURST_SIZE);
    if (nb_rx > 0) {
      total_rx += nb_rx;
      
      for (int i = 0; i < nb_rx; i++) {
        buf = rx_bufs[i];
        
        if (!check_eth_hdr(buf)) {
          rte_pktmbuf_free(buf);
          continue;
        }

        struct rte_ipv4_hdr *rx_ipv4_hdr = rte_pktmbuf_mtod_offset(buf,
            struct rte_ipv4_hdr *, RTE_ETHER_HDR_LEN);

        if (rx_ipv4_hdr->dst_addr != client_ip) {
          rte_pktmbuf_free(buf);
          continue;
        }

        if (rx_ipv4_hdr->next_proto_id == IPPROTO_TCP) {
          handle_tcp_packet(buf, q_id, server_eth);
        } else if (rx_ipv4_hdr->next_proto_id == IPPROTO_UDP) {
          port_statistics[q_id].rx++;
          rte_pktmbuf_free(buf);
        } else {
          rte_pktmbuf_free(buf);
        }
      }
    }
  }
  
  uint64_t end_time = rte_get_timer_cycles();
  double elapsed = (double)(end_time - start_time) / hz;
  
  printf("Sent: %lu\tReceived: %lu\tMissing: %lu\n",
         total_tx, total_rx, total_tx > total_rx ? total_tx - total_rx : 0);
  printf("Sent: %.6f Mpps\tReceived: %.6f Mpps\n",
         total_tx / elapsed / 1e6, total_rx / elapsed / 1e6);
  
  return 0;
}

static int close_loop(void *arg) {
  struct rte_mbuf *bufs[MAX_BURST_SIZE];
  struct rte_mbuf *buf;
  uint64_t start_time;
  int32_t nb_tx, nb_rx;
  uint64_t total_rx = 0;
  int packets_to_send = batch_size;
  struct main_loop_arg *args = (struct main_loop_arg *)arg;
  uint8_t q_id = args->queue_id;
  struct rte_ether_addr *server_eth = args->eth_addr;
  uint64_t total_pkt = 8; // debugging
  printf("Close loop client starting\n");
  
  /*
   * Check that the port is on the same NUMA node as the polling thread
   * for best performance.
   */
  if (rte_eth_dev_socket_id(dpdk_port) != (int)rte_socket_id())
        printf("WARNING, port %u (socket %d) is on remote NUMA node to polling thread (socket %d).\n\t"
               "Performance will not be optimal.\n", dpdk_port, rte_eth_dev_socket_id(dpdk_port), rte_socket_id());

  printf("\nCore %d\tQueue: %d\n",
      rte_lcore_id(), q_id);
  
  printf("Server MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
         " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
      server_eth->addr_bytes[0], server_eth->addr_bytes[1],
      server_eth->addr_bytes[2], server_eth->addr_bytes[3],
      server_eth->addr_bytes[4], server_eth->addr_bytes[5]);

  if (set_ratio > 0.0f) {
    if (setup_tcp_connection(server_eth, q_id) != 0) {
      printf("Failed to establish TCP connection on queue %d\n", q_id);
      return -1;
    }
  }
  
  start_time = rte_get_timer_cycles();
  
  while (rte_get_timer_cycles() < (start_time + seconds * rte_get_timer_hz())) {
    struct rte_mbuf *send_tx_bufs[batch_size];
    uint32_t tcp_payload_lengths[batch_size];
    
    int prepared = 0;
    while (prepared < packets_to_send) {
      buf = allocate_pkt(server_eth, q_id, &tcp_payload_lengths[prepared]);
      if (buf == NULL)
        continue;
      send_tx_bufs[prepared++] = buf;
    }
    
    // assert(port_statistics[q_id].tx + packets_to_send < (MAX_SAMPLES / num_queues));
    
    nb_tx = rte_eth_tx_burst(dpdk_port, q_id, send_tx_bufs, packets_to_send);
    port_statistics[q_id].tx += nb_tx;

    if (unlikely(nb_tx < packets_to_send)) {
      for (int i = nb_tx; i < packets_to_send; i++) {
        struct rte_mbuf *unsent = send_tx_bufs[i];
        uint32_t payload_len = tcp_payload_lengths[i];
        if (unsent != NULL && payload_len > 0) {
          struct tcp_connection_state *conn = &tcp_connections[q_id];
          conn->next_seq -= payload_len;
        }
        rte_pktmbuf_free(unsent);
      }
    }

    total_rx = 0;
    while(total_rx < nb_tx) {
      nb_rx = rte_eth_rx_burst(dpdk_port, q_id, bufs, MAX_BURST_SIZE);
      if (nb_rx == 0)
        continue;
      for (int i = 0; i < nb_rx; i++) {
        buf = bufs[i];
        
        if (!check_eth_hdr(buf)) {
          // printf("error: eth header check failed\n");
          rte_pktmbuf_free(buf);
          continue;
        }

        struct rte_ipv4_hdr *rx_ipv4_hdr = rte_pktmbuf_mtod_offset(buf,
            struct rte_ipv4_hdr *, RTE_ETHER_HDR_LEN);

        if (rx_ipv4_hdr->dst_addr != client_ip) {
          rte_pktmbuf_free(buf);
          continue;
        }

        if (rx_ipv4_hdr->next_proto_id == IPPROTO_UDP) {
          total_rx += 1;
          port_statistics[q_id].rx += 1;
          rte_pktmbuf_free(buf);
        } else if (rx_ipv4_hdr->next_proto_id == IPPROTO_TCP) {
          handle_tcp_packet(buf, q_id, server_eth);
          total_rx += 1;
          port_statistics[q_id].rx += 1;
        } else {
          rte_pktmbuf_free(buf);
        }
      }
    }

    // Debugging
    if (port_statistics[q_id].rx == total_pkt) {
      break;
    }
  }

  if (set_ratio > 0.0f)
    teardown_tcp_connection(server_eth, q_id);

  return 0;
}


/*
 * Run a dnetperf client
 */
static void do_client(uint8_t port)
{
  uint64_t send_end_time, send_start_time;
  
  unsigned lcore_id = rte_lcore_id();
  struct main_loop_arg args[num_queues];

  establish_tcp_connections(&server_eth);

  send_start_time = rte_get_timer_cycles();
  // comment/uncomment if sendera and receiver are on the same thread 
  // 8<----------------------------------------------------------------
  // Select loop function based on mode
  int (*loop_func)(void *) = use_open_loop ? open_loop : close_loop;
  
  // launch remote cores
  for (int i = 1; i < rte_lcore_count(); i++) {
    args[i].eth_addr = &server_eth;
    args[i].queue_id = i;
    lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
    rte_eal_remote_launch(loop_func, &args[i], lcore_id);
  }
  
  // run on main core
  args[0].eth_addr = &server_eth;
  args[0].queue_id = 0;
  loop_func(&args[0]);

  rte_eal_mp_wait_lcore();
  send_end_time = rte_get_timer_cycles();

  uint64_t total_pkt_sent = 0;
  uint64_t total_pkt_recv = 0;

  for (int i = 0; i < num_queues; i++) {
    total_pkt_sent += port_statistics[i].tx;
    total_pkt_recv += port_statistics[i].rx;
  }

  if (seconds != 0) {
    printf("Sent: %lu\tReceived: %lu\tMissing: %lu\n", total_pkt_sent, total_pkt_recv, total_pkt_sent - total_pkt_recv);
    // FIXME: DPDK 24.11 show illegal instruction here
    printf("Sent: %f Mpps\tReceived: %f Mpp\tMissing: %f Mpps\n", 
      (double) total_pkt_sent / (send_end_time - send_start_time) * rte_get_timer_hz() / 1000000,
      (double) total_pkt_recv / (send_end_time - send_start_time) * rte_get_timer_hz() / 1000000,
      (double) (total_pkt_sent - total_pkt_recv) / (send_end_time - send_start_time) * rte_get_timer_hz() / 1000000);
    // report_stats();
  }
}

/*
 * Initialize dpdk.
 */
static int dpdk_init(int argc, char *argv[])
{
  int args_parsed;
  int nb_ports = 1;
  int nb_rxd = RX_RING_SIZE;
  int nb_txd = TX_RING_SIZE;
  int nb_lcores = rte_lcore_count();
  unsigned int nb_mbufs;

  /* Initialize the Environment Abstraction Layer (EAL). */
  args_parsed = rte_eal_init(argc, argv);
  if (args_parsed < 0)
    rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

  /* Check that there is a port to send/receive on. */
  if (!rte_eth_dev_is_valid_port(0))
    rte_exit(EXIT_FAILURE, "Error: no available ports\n");
  
  nb_mbufs = RTE_MAX(nb_ports * (nb_rxd + nb_txd + MAX_BURST_SIZE +
    nb_lcores * MEMPOOL_CACHE_SIZE), 8192U);
  printf("Creating mbuf pool with %u mbufs\n", nb_mbufs);

  /* Creates a new mempool in memory to hold the mbufs. */
  rx_mbuf_pool = rte_pktmbuf_pool_create("MBUF_RX_POOL", nb_mbufs,
    MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

  if (rx_mbuf_pool == NULL)
    rte_exit(EXIT_FAILURE, "Cannot create rx mbuf pool\n");

  /* Creates a new mempool in memory to hold the mbufs. */
  tx_mbuf_pool = rte_pktmbuf_pool_create("MBUF_TX_POOL", nb_mbufs,
    MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

  if (tx_mbuf_pool == NULL)
    rte_exit(EXIT_FAILURE, "Cannot create tx mbuf pool\n");

  return args_parsed;
}

typedef struct {
    struct rte_ether_addr server_eth;
    char     server_ip[64];
    uint16_t server_port;
    unsigned duration_s;
    unsigned batch_size;
    unsigned pps;
    double   skew;
    bool     fixed_key;
    bool     open_loop;
    double   ratio;
    // presence tracking
    bool have_ip, have_port, have_duration,
         have_batch, have_pps, have_skew, have_ratio;
} config_t;

static void usage(const char *prog) {
    fprintf(stderr,
      "usage: %s [EAL options] -- \n"
      "  -E, --host-eth <mac>      Server MAC address (required)\n"
      "  -H, --host-ip <ip>        Server IP address (required)\n"
      "  -p, --port <port>         Server port (required)\n"
  "  -d, --duration <seconds>  Duration of the test in seconds (required, default: 10)\n"
  "  -b, --batch <num>         Number of requests to send in a batch (default: 1)\n"
  "  -o, --pps <num>           For open-loop mode: Fixed packets per second to send (default: 1000000)\n"
  "  -O, --open-loop           Use open-loop mode (fire-and-forget at fixed rate)\n"
  "  -R, --ratio <float>       Fraction of GET requests (0.0-1.0, default: 0.5)\n"
  "  -S, --skew <float>        Zipfian skew parameter (0 for uniform keys, default: 0)\n"
  "  -F, --fixed               Generate single fixed key (zipf skew will be ignored)\n"
  "  -h, --help                Show this help message\n",
  prog
);
}

static void die_usage(const char *prog, const char *msg) {
    if (msg && *msg) fprintf(stderr, "Error: %s\n\n", msg);
    usage(prog);
    exit(EXIT_FAILURE);
}

static bool parse_uint_in_range(const char *s, unsigned long min, unsigned long max, unsigned *out) {
    errno = 0;
    char *end = NULL;
    unsigned long v = strtoul(s, &end, 10);
    if (errno || end == s || *end != '\0') return false;
    if (v < min || v > max) return false;
    *out = (unsigned)v;
    return true;
}

static bool parse_double_nonneg(const char *s, double *out) {
    errno = 0;
    char *end = NULL;
    double v = strtod(s, &end);
    if (errno || end == s || *end != '\0') return false;
    if (v < 0.0) return false;
    *out = v;
    return true;
}

static bool parse_double_unit_interval(const char *s, double *out) {
    double v;
    if (!parse_double_nonneg(s, &v)) return false;
    if (v > 1.0) return false;
    *out = v;
    return true;
}

static bool parse_u16_port(const char *s, uint16_t *out) {
    unsigned v;
    if (!parse_uint_in_range(s, 1, 65535, &v)) return false;
    *out = (uint16_t)v;
    return true;
}

static bool looks_like_ip(const char *ip) {
    unsigned char buf[sizeof(struct in6_addr)];
    if (inet_pton(AF_INET,  ip, buf) == 1) return true;
    if (inet_pton(AF_INET6, ip, buf) == 1) return true;
    return false;
}

/* ---------- parser ---------- */

static config_t parse_args(int argc, char **argv) {
    const char *prog = argv[0];
    config_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    // Set defaults
    cfg.batch_size = 1;
    cfg.pps = 1000;
    cfg.duration_s = 10;
    cfg.skew = 0.0;
    cfg.ratio = 0.5;
    cfg.fixed_key = false;

    static const struct option long_opts[] = {
        {"host-eth",    required_argument, NULL, 'E'},
        {"host-ip",     required_argument, NULL, 'H'},
        {"port",        required_argument, NULL, 'p'},
        {"duration",    required_argument, NULL, 'd'},
        {"batch",       required_argument, NULL, 'b'},
        {"pps",         required_argument, NULL, 'o'},
        {"open-loop",   no_argument,       NULL, 'O'},
        {"ratio",       required_argument, NULL, 'R'},
        {"skew",        required_argument, NULL, 'S'},
        {"fixed",       no_argument,       NULL, 'F'},
        {"help",        no_argument,       NULL, 'h'},
        {0,0,0,0}
    };

    int opt, idx;
    while ((opt = getopt_long(argc, argv, "E:H:p:d:b:o:OR:S:Fh", long_opts, &idx)) != -1) {
        switch (opt) {
        case 'E':
            if (rte_ether_unformat_addr(optarg, (struct rte_ether_addr *)&cfg.server_eth))
                die_usage(prog, "Invalid --host-eth.");
            break;
        case 'H':
            if (!looks_like_ip(optarg)) die_usage(prog, "Invalid --host.");
            snprintf(cfg.server_ip, sizeof(cfg.server_ip), "%s", optarg);
            printf("Server IP: %s\n", cfg.server_ip);
            cfg.have_ip = true;
            break;
        case 'p':
            if (!parse_u16_port(optarg, &cfg.server_port))
                die_usage(prog, "Invalid --port.");
      printf("Server Port: %u\n", cfg.server_port);
            cfg.have_port = true;
            break;
        case 'd':
            if (!parse_uint_in_range(optarg, 0, UINT_MAX, &cfg.duration_s))
                die_usage(prog, "--duration must be a positive integer.");
            cfg.have_duration = true;
            break;
        case 'b':
            if (!parse_uint_in_range(optarg, 1, UINT_MAX, &cfg.batch_size))
                die_usage(prog, "--batch must be a positive integer.");
            cfg.have_batch = true;
            break;
        case 'o':
            if (!parse_uint_in_range(optarg, 1, UINT_MAX, &cfg.pps))
                die_usage(prog, "--pps must be positive.");
            cfg.have_pps = true;
            break;
        case 'O':
            cfg.open_loop = true;
            break;
        case 'R':
            if (!parse_double_unit_interval(optarg, &cfg.ratio))
                die_usage(prog, "--ratio must be between 0.0 and 1.0.");
            cfg.have_ratio = true;
            break;
        case 'S':
            if (!parse_double_nonneg(optarg, &cfg.skew))
                die_usage(prog, "--skew must be a non-negative number.");
            cfg.have_skew = true;
            break;
        case 'F':
            cfg.fixed_key = true;
            break;
        case 'h':
            usage(prog);
            exit(EXIT_SUCCESS);
        default:
            die_usage(prog, "Unknown or malformed option.");
        }
    }

    if (optind != argc) die_usage(prog, "Unexpected positional arguments.");

    // Validate common
    if (!cfg.have_ip || !cfg.have_port || !cfg.have_duration) {
        die_usage(prog, "Missing required common options.");
    }

    return cfg;
}

static int parse_netperf_args(int argc, char *argv[])
{
  long tmp;
  config_t cfg = parse_args(argc, argv);
  struct in_addr tmp_addr;
  int ret;

  server_eth = cfg.server_eth;

  ret = inet_pton(AF_INET, cfg.server_ip, &tmp_addr);
  if (ret != 1) {
    printf("Invalid server IP address: %s\n", cfg.server_ip);
    return -1;
  }
  server_ip = tmp_addr.s_addr;
  ret = inet_pton(AF_INET, CLIENT_IP, &tmp_addr);
  if (ret != 1) {
    printf("Invalid client IP address: %s\n", CLIENT_IP);
    return -1;
  }
  client_ip = tmp_addr.s_addr;
  server_port = cfg.server_port;
  seconds = cfg.duration_s;
  
  batch_size = cfg.batch_size;
  send_pps = cfg.pps;
  zipf_skew = cfg.skew;
  // if fixed key generation is used, zipf skew is ignored
  use_fixed_key = cfg.fixed_key;
  use_open_loop = cfg.open_loop;
  if (use_fixed_key)
    zipf_skew = 0.0;
  use_zipf_keys = zipf_skew > 0.0;
  set_ratio = (float)(1.0 - cfg.ratio);

  if (DEBUG_ARGS) {
    printf("DEBUG ARGS:\n");
    printf("Number of arguments: %d\n", argc);
    printf("Server mac: ");
    print_mac(&server_eth);
    printf("\n");
    printf("Server IP: ");
    print_ip_be_u32(server_ip);
    printf("Server port: %u\n", server_port);
    printf("Client IP: ");
    print_ip_be_u32(client_ip);
    printf("Run time: %u\n", seconds);
    printf("Batch size: %u\n", batch_size);
    printf("Offered pps: %u\n", send_pps);
    printf("Mode: %s\n", use_open_loop ? "open-loop" : "close-loop");
    printf("GET ratio: %.3f\n", cfg.ratio);
    printf("Use fixed key: %s\n", use_fixed_key ? "true" : "false");
    printf("Zipf skew: %.6f\n", zipf_skew);
  }

  return 0;
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
  int args_parsed, res, lcore_id;
  uint64_t i;

  /* Randomize client port to avoid stale server connections */
  srand(time(NULL));
  client_port = 38500 + (rand() % 1000); // Random port between 38500-39499
  
  /* Initialize dpdk. */
  args_parsed = dpdk_init(argc, argv);

  /* initialize our arguments */
  argc -= args_parsed;
  argv += args_parsed;
  res = parse_netperf_args(argc, argv);
  if (res < 0)
    return 0;

  // Uncomment if sender and receiver on same thread (open_loop())
  num_queues = rte_lcore_count();

  if (port_init(dpdk_port, rx_mbuf_pool, num_queues) != 0)
    rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu8 "\n", dpdk_port);
  
  /* Initialize sample arrays */
  diff_times = (uint64_t *)malloc(MAX_SAMPLES * sizeof(uint64_t));
  if (!diff_times)
    rte_exit(EXIT_FAILURE, "Cannot allocate memory for diff_times\n");

  // Initialize per queue data structures
  for (i = 0; i < num_queues; i++) {
    rtt_times[i].rtt = (uint64_t *)calloc(MAX_SAMPLES / num_queues, sizeof(uint64_t));
    if (!rtt_times[i].rtt)
      rte_exit(EXIT_FAILURE, "Cannot allocate memory for rtt_times\n");
    
    rand_state[i].a = rte_get_timer_cycles();
  }

  // Buffer for key generation
  mem_key = (char *)malloc(MAX_KEY_LEN + 1);
  if (!mem_key)
    rte_exit(EXIT_FAILURE, "Cannot allocate memory for key_buffer\n");
  memset(mem_key, 0, MAX_KEY_LEN + 1);

  // If fixed key generation is used, pre-generate the fixed key
  if (use_fixed_key)
    strncpy(mem_key, FIXED_KEY, MAX_KEY_LEN + 1);

  mem_val = (char *)malloc(MAX_VALUE_LEN + 1);
  if (!mem_val)
    rte_exit(EXIT_FAILURE, "Cannot allocate memory for value_buffer\n");

  if (use_zipf_keys)
    init_zipf_generator();

  do_client(dpdk_port);

  return 0;
}
