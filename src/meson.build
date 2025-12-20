#c source files, if adding new features add c file to this list 
srcs = files(
  'main.c',
  'ppr_control_server.c',
  'ppr_stats.c',
  'ppr_stats_rpc.c',
  'ppr_ports.c',
  'ppr_port_rpc.c',
  'ppr_pcap_loader.c',
  'ppr_pcap_loader_rpc.c',
  'ppr_tx_worker.c',
  'ppr_mbuf_fields.c',
  'ppr_log.c',
  'ppr_qsbr.c',
  'ppr_acl.c',
  'ppr_acl_db.c',
  'ppr_acl_rpc.c',
  'ppr_acl_yaml.c',
  'ppr_header_extract.c',
  'ppr_config.c'
)

executable(
  'pcap_replay_dataplane',
  srcs,
  dependencies: [dpdk,jansson,pthread,pcap, cyaml],
  include_directories: include_directories('../include'))

