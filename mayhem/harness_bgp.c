// libFuzzer harness for pmacct's BGP message parser (OPEN/UPDATE/KEEPALIVE/NOTIFICATION): one fresh session per input.
#include "pmacct.h"
#include "pmacct-data.h"
#include "bgp/bgp.h"

#define FUZZ_BUF BGP_BUFFER_SIZE

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
  afi_t afi;
  safi_t safi;

  config.name = "fuzz";
  config.type = "bgp";
  { static char logbuf[1 << 16]; config.logfile_fd = fmemopen(logbuf, sizeof(logbuf), "w"); }

  bgp_prepare_thread();
  bgp_routing_db = &inter_domain_routing_dbs[FUNC_TYPE_BGP];
  memset(bgp_routing_db, 0, sizeof(struct bgp_rt_structs));

  config.bgp_daemon_max_peers = 1;
  peers = calloc(config.bgp_daemon_max_peers, sizeof(struct bgp_peer));

  config.bgp_table_attr_hash_buckets = HASHTABSIZE;
  bgp_attr_init(config.bgp_table_attr_hash_buckets, bgp_routing_db);
  config.bgp_table_peer_buckets = DEFAULT_BGP_INFO_HASH;
  config.bgp_table_per_peer_buckets = DEFAULT_BGP_INFO_PER_PEER_HASH;
  config.bgp_table_per_peer_hash = BGP_ASPATH_HASH_PATHID;
  bgp_route_info_modulo = bgp_route_info_modulo_pathid;

  for (afi = AFI_IP; afi < AFI_MAX; afi++)
    for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++)
      bgp_routing_db->rib[afi][safi] = bgp_table_init(afi, safi);

  bgp_link_misc_structs(bgp_misc_db);
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  struct bgp_peer *peer = &peers[0];
  struct host_addr neighbor;

  if (size == 0 || size > FUZZ_BUF) return -1;

  if (bgp_peer_init(peer, FUNC_TYPE_BGP, BGP_BUFFER_SIZE)) return -1;
  str_to_addr("192.0.2.1", &neighbor);
  memcpy(&peer->addr, &neighbor, sizeof(neighbor));
  addr_to_str(peer->addr_str, &neighbor);
  peer->tcp_port = 179;

  memcpy(peer->buf.base, data, size);
  peer->msglen = size;
  bgp_parse_msg(peer, 1700000000, FALSE);

  bgp_peer_close(peer, FUNC_TYPE_BGP, FALSE, FALSE, 0, 0, NULL);
  return 0;
}
