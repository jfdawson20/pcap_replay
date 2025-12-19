#c source files, if adding new features add c file to this list 
srcs = files(
  'main.c',
  'ppr_control_server.c',
  'ppr_stats.c',
  'ppr_ports.c',
  'ppr_pcap_loader.c',
  'ppr_buff_worker.c',
  'ppr_tx_worker.c',
  'ppr_mbuf_fields.c',
  'ppr_flowtable.c',
  'ppr_ft_manager.c',
  'ppr_log.c',
  'ppr_qsbr.c',
  'ppr_acl.c',
  'ppr_header_extract.c',
)

executable(
  'pcap_replay_dataplane',
  srcs,
  dependencies: [dpdk,jansson,pthread,pcap],
  include_directories: include_directories('../include'))

