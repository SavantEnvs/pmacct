// libFuzzer harness for pmacct's BMP (RFC 7854) message parser: one fresh BMP session per input.
#include "pmacct.h"
#include "pmacct-data.h"
#include "bgp/bgp.h"
#include "bmp/bmp.h"

#define FUZZ_BUF BGP_BUFFER_SIZE

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
  afi_t afi;
  safi_t safi;

  config.name = "fuzz";
  config.type = "bmp";
  { static char logbuf[1 << 16]; config.logfile_fd = fmemopen(logbuf, sizeof(logbuf), "w"); }

  bmp_prepare_thread();
  bmp_routing_db = &inter_domain_routing_dbs[FUNC_TYPE_BMP];
  memset(bmp_routing_db, 0, sizeof(struct bgp_rt_structs));

  config.bmp_daemon_max_peers = 1;
  bmp_peers = calloc(config.bmp_daemon_max_peers, sizeof(struct bmp_peer));

  config.bmp_table_attr_hash_buckets = HASHTABSIZE;
  bgp_attr_init(config.bmp_table_attr_hash_buckets, bmp_routing_db);
  config.bmp_table_peer_buckets = DEFAULT_BGP_INFO_HASH;
  config.bmp_table_per_peer_buckets = DEFAULT_BGP_INFO_PER_PEER_HASH;
  config.bmp_table_per_peer_hash = BGP_ASPATH_HASH_PATHID;
  bmp_route_info_modulo = bmp_route_info_modulo_pathid;

  for (afi = AFI_IP; afi < AFI_MAX; afi++)
    for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++)
      bmp_routing_db->rib[afi][safi] = bgp_table_init(afi, safi);

  config.writer_id_string = DYNNAME_DEFAULT_WRITER_ID;
  dynname_tokens_prepare(config.writer_id_string, &bmp_misc_db->writer_id_tokens, DYN_STR_WRITER_ID);
  bmp_link_misc_structs(bmp_misc_db);
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  struct bmp_peer *bmpp = &bmp_peers[0];
  struct host_addr router;
  int do_term = FALSE;

  if (size == 0 || size > FUZZ_BUF) return -1;

  if (bmp_peer_init(bmpp, FUNC_TYPE_BMP)) return -1;
  str_to_addr("192.0.2.1", &router);
  memcpy(&bmpp->self.addr, &router, sizeof(router));
  addr_to_str(bmpp->self.addr_str, &router);
  bmpp->self.tcp_port = 11019;

  memcpy(bmpp->self.buf.base, data, size);
  bmpp->self.msglen = size;
  bmp_process_packet(bmpp->self.buf.base, bmpp->self.msglen, bmpp, &do_term);

  bmp_peer_close(bmpp, FUNC_TYPE_BMP);
  return 0;
}
