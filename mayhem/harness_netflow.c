// libFuzzer harness for pmacct's NetFlow v5 / v9 / IPFIX collector (nfacctd): one datagram per input,
// processed through the same process_v5_packet()/process_v9_packet() calls as nfacctd's receive loop.
#include "pmacct.h"
#include "pmacct-data.h"
#include "nfacctd.h"
#include "nfv9_template.c"

static struct packet_ptrs_vector pptrs;
static struct plugin_requests req;
static struct sockaddr_storage client;
static unsigned char dummy_packet[64]; 
static unsigned char dummy_packet_vlan[64]; 
static unsigned char dummy_packet_mpls[128]; 
static unsigned char dummy_packet_vlan_mpls[128]; 
static struct pcap_pkthdr dummy_pkthdr;
static struct pcap_pkthdr dummy_pkthdr_vlan;
static struct pcap_pkthdr dummy_pkthdr_mpls;
static struct pcap_pkthdr dummy_pkthdr_vlan_mpls;

static unsigned char dummy_packet6[92]; 
static unsigned char dummy_packet_vlan6[92]; 
static unsigned char dummy_packet_mpls6[128]; 
static unsigned char dummy_packet_vlan_mpls6[128]; 
static struct pcap_pkthdr dummy_pkthdr6;
static struct pcap_pkthdr dummy_pkthdr_vlan6;
static struct pcap_pkthdr dummy_pkthdr_mpls6;
static struct pcap_pkthdr dummy_pkthdr_vlan_mpls6;

static void setup_pptrs(void)
{
  memset(&pptrs, 0, sizeof(pptrs));
  memset(&dummy_pkthdr, 0, sizeof(dummy_pkthdr));
  memset(&dummy_pkthdr_vlan, 0, sizeof(dummy_pkthdr_vlan));
  memset(&dummy_pkthdr_mpls, 0, sizeof(dummy_pkthdr_mpls));
  memset(&dummy_pkthdr_vlan_mpls, 0, sizeof(dummy_pkthdr_vlan_mpls));
  memset(&dummy_pkthdr6, 0, sizeof(dummy_pkthdr6));
  memset(&dummy_pkthdr_vlan6, 0, sizeof(dummy_pkthdr_vlan6));
  memset(&dummy_pkthdr_mpls6, 0, sizeof(dummy_pkthdr_mpls6));
  memset(&dummy_pkthdr_vlan_mpls6, 0, sizeof(dummy_pkthdr_vlan_mpls6));
  memset(dummy_packet, 0, sizeof(dummy_packet));
  pptrs.l2.f_agent = (u_char *) &client;
  pptrs.l2.packet_ptr = dummy_packet;
  pptrs.l2.pkthdr = &dummy_pkthdr;
  Assign16(((struct eth_header *)pptrs.l2.packet_ptr)->ether_type, htons(ETHERTYPE_8021Q));
  pptrs.l2.mac_ptr = (u_char *)((struct eth_header *)pptrs.l2.packet_ptr)->ether_dhost;
  pptrs.l2.vlan_ptr = pptrs.l2.packet_ptr + ETHER_HDRLEN;
  // pptrs.l2.pkthdr->caplen = 18; /* eth_header + vlan */
  pptrs.l2.pkthdr->caplen = 35;
  pptrs.l2.pkthdr->len = 100; /* fake len */

  memset(dummy_packet, 0, sizeof(dummy_packet));
  pptrs.v4.f_agent = (u_char *) &client;
  pptrs.v4.packet_ptr = dummy_packet;
  pptrs.v4.pkthdr = &dummy_pkthdr;
  Assign16(((struct eth_header *)pptrs.v4.packet_ptr)->ether_type, htons(ETHERTYPE_IP)); /* 0x800 */
  pptrs.v4.mac_ptr = (u_char *)((struct eth_header *)pptrs.v4.packet_ptr)->ether_dhost; 
  pptrs.v4.iph_ptr = pptrs.v4.packet_ptr + ETHER_HDRLEN; 
  pptrs.v4.tlh_ptr = pptrs.v4.packet_ptr + ETHER_HDRLEN + sizeof(struct pm_iphdr); 
  Assign8(((struct pm_iphdr *)pptrs.v4.iph_ptr)->ip_vhl, 5);
  // pptrs.v4.pkthdr->caplen = 38; /* eth_header + pm_iphdr + pm_tlhdr */
  pptrs.v4.pkthdr->caplen = 55; 
  pptrs.v4.pkthdr->len = 100; /* fake len */ 
  pptrs.v4.l3_proto = ETHERTYPE_IP;

  memset(dummy_packet_vlan, 0, sizeof(dummy_packet_vlan));
  pptrs.vlan4.f_agent = (u_char *) &client;
  pptrs.vlan4.packet_ptr = dummy_packet_vlan;
  pptrs.vlan4.pkthdr = &dummy_pkthdr_vlan;
  Assign16(((struct eth_header *)pptrs.vlan4.packet_ptr)->ether_type, htons(ETHERTYPE_8021Q));
  pptrs.vlan4.mac_ptr = (u_char *)((struct eth_header *)pptrs.vlan4.packet_ptr)->ether_dhost;
  pptrs.vlan4.vlan_ptr = pptrs.vlan4.packet_ptr + ETHER_HDRLEN;
  Assign16(*(pptrs.vlan4.vlan_ptr+2), htons(ETHERTYPE_IP));
  pptrs.vlan4.iph_ptr = pptrs.vlan4.packet_ptr + ETHER_HDRLEN + IEEE8021Q_TAGLEN;
  pptrs.vlan4.tlh_ptr = pptrs.vlan4.packet_ptr + ETHER_HDRLEN + IEEE8021Q_TAGLEN + sizeof(struct pm_iphdr);
  Assign8(((struct pm_iphdr *)pptrs.vlan4.iph_ptr)->ip_vhl, 5);
  // pptrs.vlan4.pkthdr->caplen = 42; /* eth_header + vlan + pm_iphdr + pm_tlhdr */
  pptrs.vlan4.pkthdr->caplen = 59;
  pptrs.vlan4.pkthdr->len = 100; /* fake len */
  pptrs.vlan4.l3_proto = ETHERTYPE_IP;

  memset(dummy_packet_mpls, 0, sizeof(dummy_packet_mpls));
  pptrs.mpls4.f_agent = (u_char *) &client;
  pptrs.mpls4.packet_ptr = dummy_packet_mpls;
  pptrs.mpls4.pkthdr = &dummy_pkthdr_mpls;
  Assign16(((struct eth_header *)pptrs.mpls4.packet_ptr)->ether_type, htons(ETHERTYPE_MPLS));
  pptrs.mpls4.mac_ptr = (u_char *)((struct eth_header *)pptrs.mpls4.packet_ptr)->ether_dhost;
  pptrs.mpls4.mpls_ptr = pptrs.mpls4.packet_ptr + ETHER_HDRLEN;
  // pptrs.mpls4.pkthdr->caplen = 78; /* eth_header + upto 10 MPLS labels + pm_iphdr + pm_tlhdr */
  pptrs.mpls4.pkthdr->caplen = 95; 
  pptrs.mpls4.pkthdr->len = 100; /* fake len */
  pptrs.mpls4.l3_proto = ETHERTYPE_IP;

  memset(dummy_packet_vlan_mpls, 0, sizeof(dummy_packet_vlan_mpls));
  pptrs.vlanmpls4.f_agent = (u_char *) &client;
  pptrs.vlanmpls4.packet_ptr = dummy_packet_vlan_mpls;
  pptrs.vlanmpls4.pkthdr = &dummy_pkthdr_vlan_mpls;
  Assign16(((struct eth_header *)pptrs.vlanmpls4.packet_ptr)->ether_type, htons(ETHERTYPE_8021Q));
  pptrs.vlanmpls4.mac_ptr = (u_char *)((struct eth_header *)pptrs.vlanmpls4.packet_ptr)->ether_dhost;
  pptrs.vlanmpls4.vlan_ptr = pptrs.vlanmpls4.packet_ptr + ETHER_HDRLEN;
  Assign16(((struct vlan_header *)pptrs.vlanmpls4.vlan_ptr)->proto, htons(ETHERTYPE_MPLS));
  pptrs.vlanmpls4.mpls_ptr = pptrs.vlanmpls4.packet_ptr + ETHER_HDRLEN + IEEE8021Q_TAGLEN;
  // pptrs.vlanmpls4.pkthdr->caplen = 82; /* eth_header + vlan + upto 10 MPLS labels + pm_iphdr + pm_tlhdr */
  pptrs.vlanmpls4.pkthdr->caplen = 99; 
  pptrs.vlanmpls4.pkthdr->len = 100; /* fake len */
  pptrs.vlanmpls4.l3_proto = ETHERTYPE_IP;

  memset(dummy_packet6, 0, sizeof(dummy_packet6));
  pptrs.v6.f_agent = (u_char *) &client;
  pptrs.v6.packet_ptr = dummy_packet6;
  pptrs.v6.pkthdr = &dummy_pkthdr6;
  Assign16(((struct eth_header *)pptrs.v6.packet_ptr)->ether_type, htons(ETHERTYPE_IPV6)); 
  pptrs.v6.mac_ptr = (u_char *)((struct eth_header *)pptrs.v6.packet_ptr)->ether_dhost; 
  pptrs.v6.iph_ptr = pptrs.v6.packet_ptr + ETHER_HDRLEN;
  pptrs.v6.tlh_ptr = pptrs.v6.packet_ptr + ETHER_HDRLEN + sizeof(struct ip6_hdr);
  Assign16(((struct ip6_hdr *)pptrs.v6.iph_ptr)->ip6_plen, htons(100));
  ((struct ip6_hdr *)pptrs.v6.iph_ptr)->ip6_hlim = 64;
  // pptrs.v6.pkthdr->caplen = 60; /* eth_header + ip6_hdr + pm_tlhdr */
  pptrs.v6.pkthdr->caplen = 77; 
  pptrs.v6.pkthdr->len = 100; /* fake len */
  pptrs.v6.l3_proto = ETHERTYPE_IPV6;

  memset(dummy_packet_vlan6, 0, sizeof(dummy_packet_vlan6));
  pptrs.vlan6.f_agent = (u_char *) &client;
  pptrs.vlan6.packet_ptr = dummy_packet_vlan6;
  pptrs.vlan6.pkthdr = &dummy_pkthdr_vlan6;
  Assign16(((struct eth_header *)pptrs.vlan6.packet_ptr)->ether_type, htons(ETHERTYPE_8021Q));
  pptrs.vlan6.mac_ptr = (u_char *)((struct eth_header *)pptrs.vlan6.packet_ptr)->ether_dhost;
  pptrs.vlan6.vlan_ptr = pptrs.vlan6.packet_ptr + ETHER_HDRLEN;
  Assign8(*(pptrs.vlan6.vlan_ptr+2), 0x86);
  Assign8(*(pptrs.vlan6.vlan_ptr+3), 0xDD);
  pptrs.vlan6.iph_ptr = pptrs.vlan6.packet_ptr + ETHER_HDRLEN + IEEE8021Q_TAGLEN;
  pptrs.vlan6.tlh_ptr = pptrs.vlan6.packet_ptr + ETHER_HDRLEN + IEEE8021Q_TAGLEN + sizeof(struct ip6_hdr);
  Assign16(((struct ip6_hdr *)pptrs.vlan6.iph_ptr)->ip6_plen, htons(100));
  ((struct ip6_hdr *)pptrs.vlan6.iph_ptr)->ip6_hlim = 64;
  // pptrs.vlan6.pkthdr->caplen = 64; /* eth_header + vlan + ip6_hdr + pm_tlhdr */
  pptrs.vlan6.pkthdr->caplen = 81;
  pptrs.vlan6.pkthdr->len = 100; /* fake len */
  pptrs.vlan6.l3_proto = ETHERTYPE_IPV6;

  memset(dummy_packet_mpls6, 0, sizeof(dummy_packet_mpls6));
  pptrs.mpls6.f_agent = (u_char *) &client;
  pptrs.mpls6.packet_ptr = dummy_packet_mpls6;
  pptrs.mpls6.pkthdr = &dummy_pkthdr_mpls6;
  Assign16(((struct eth_header *)pptrs.mpls6.packet_ptr)->ether_type, htons(ETHERTYPE_MPLS));
  pptrs.mpls6.mac_ptr = (u_char *)((struct eth_header *)pptrs.mpls6.packet_ptr)->ether_dhost;
  pptrs.mpls6.mpls_ptr = pptrs.mpls6.packet_ptr + ETHER_HDRLEN;
  // pptrs.mpls6.pkthdr->caplen = 100; /* eth_header + upto 10 MPLS labels + ip6_hdr + pm_tlhdr */
  pptrs.mpls6.pkthdr->caplen = 117; 
  pptrs.mpls6.pkthdr->len = 128; /* fake len */
  pptrs.mpls6.l3_proto = ETHERTYPE_IPV6;

  memset(dummy_packet_vlan_mpls6, 0, sizeof(dummy_packet_vlan_mpls6));
  pptrs.vlanmpls6.f_agent = (u_char *) &client;
  pptrs.vlanmpls6.packet_ptr = dummy_packet_vlan_mpls6;
  pptrs.vlanmpls6.pkthdr = &dummy_pkthdr_vlan_mpls6;
  Assign16(((struct eth_header *)pptrs.vlanmpls6.packet_ptr)->ether_type, htons(ETHERTYPE_8021Q));
  pptrs.vlanmpls6.mac_ptr = (u_char *)((struct eth_header *)pptrs.vlanmpls6.packet_ptr)->ether_dhost;
  pptrs.vlanmpls6.vlan_ptr = pptrs.vlanmpls6.packet_ptr + ETHER_HDRLEN;
  Assign8(*(pptrs.vlanmpls6.vlan_ptr+2), 0x88);
  Assign8(*(pptrs.vlanmpls6.vlan_ptr+3), 0x47);
  pptrs.vlanmpls6.mpls_ptr = pptrs.vlanmpls6.packet_ptr + ETHER_HDRLEN + IEEE8021Q_TAGLEN;
  // pptrs.vlanmpls6.pkthdr->caplen = 104; /* eth_header + vlan + upto 10 MPLS labels + ip6_hdr + pm_tlhdr */
  pptrs.vlanmpls6.pkthdr->caplen = 121;
  pptrs.vlanmpls6.pkthdr->len = 128; /* fake len */
  pptrs.vlanmpls6.l3_proto = ETHERTYPE_IPV6;
}

static void free_value(const cdada_map_t *map, const void *key, void *val, void *opaque)
{
  free(val);
}

static void destroy_value_map(cdada_map_t *map)
{
  if (!map) return;
  cdada_map_traverse(map, free_value, NULL);
  cdada_map_destroy(map);
}

/* Template cache and exporter status are per-exporter state in nfacctd; drop them after every datagram so
   that each input is decoded on its own. */
static void reset_collector_state(void)
{
  u_int32_t idx;

  cdada_map_traverse(tpl_data_map, free_value, NULL);
  cdada_map_clear(tpl_data_map);

  for (idx = 0; idx < XFLOW_STATUS_TABLE_SZ; idx++) {
    struct xflow_status_entry *entry = xflow_status_table.t[idx], *next;

    while (entry) {
      struct xflow_status_entry_sampling *s = entry->sampling, *s_next;
      struct xflow_status_entry_class *c = entry->class, *c_next;

      for (; s; s = s_next) { s_next = s->next; free(s); }
      for (; c; c = c_next) { c_next = c->next; free(c); }
      destroy_value_map(entry->in_rd_map);
      destroy_value_map(entry->out_rd_map);
      destroy_value_map(entry->vrf_name_map);
      destroy_value_map(entry->iface_name_map);
      next = entry->next;
      free(entry);
      entry = next;
    }
  }
  memset(&xflow_status_table, 0, sizeof(xflow_status_table));
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
  struct sockaddr_in *sa4 = (struct sockaddr_in *) &client;

  config.name = "fuzz";
  config.type = "core";
  config.acct_type = ACCT_NF;
  { static char logbuf[1 << 16]; config.logfile_fd = fmemopen(logbuf, sizeof(logbuf), "w"); }

  memset(&client, 0, sizeof(client));
  sa4->sin_family = AF_INET;
  sa4->sin_port = htons(2055);
  inet_pton(AF_INET, "192.0.2.1", &sa4->sin_addr);

  /* nfacctd_main() calls this once at startup; it sets the Nf*Sz/IpFixHdrSz/HostAddrSz/UDPHdrSz/IP6*Sz size
     globals (and the P*Sz ones) that the v5/v9/IPFIX decoders' length checks compare against; all 0 without it. */
  NF_compute_once();

  memset(&xflow_status_table, 0, sizeof(xflow_status_table));
  if (init_template_cache_v2()) return -1;
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  unsigned char *datagram;
  int has_templates = 0;
  u_int16_t nfv;

  /* nfacctd reads datagrams into a NETFLOW_MSG_SIZE buffer and needs at least the 16-bit version to dispatch. */
  if (size < 2 || size > NETFLOW_MSG_SIZE) return -1;

  /* An exact-size heap copy, so a decoder read past the datagram is an ASan error instead of the previous
     input's bytes. */
  datagram = malloc(size);
  if (!datagram) return -1;
  memcpy(datagram, data, size);

  /* The decoders write into pptrs, the dummy_packet* buffers and req: rebuild them for every input. Of the
     other file-level state on this path, only xflow_status_table and tpl_data_map hold data (cleared below);
     debug_a/debug_agent_addr/debug_agent_port in nfacctd.c are log scratch, overwritten before each use. */
  memset(&req, 0, sizeof(req));
  setup_pptrs();
  pptrs.v4.f_len = size;

  nfv = ((struct struct_header_v5 *)datagram)->version = ntohs(((struct struct_header_v5 *)datagram)->version);

  reset_tag_label_status(&pptrs);
  reset_shadow_status(&pptrs);

  switch (nfv) {
  case 5:
    process_v5_packet(datagram, size, &pptrs.v4, &req, nfv, NULL);
    break;
  case 9:
  case 10:
    process_v9_packet(datagram, size, &pptrs, &req, nfv, NULL, &has_templates);
    break;
  default:
    break;
  }

  reset_collector_state();
  free(datagram);
  return 0;
}
