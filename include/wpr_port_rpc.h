#ifndef PPR_PORT_RPC_H
#define PPR_PORT_RPC_H

#include <unistd.h>
#include <jansson.h>
#include <stdio.h>
#include <string.h>
#include <stdio.h> 
#include <unistd.h>
#include <errno.h>

#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_hash.h>

#include "ppr_app_defines.h"
#include "ppr_ports.h"
#include "ppr_log.h"

int ppr_cmd_get_port_list(json_t *reply_root, json_t *args, ppr_thread_args_t *thread_args);
int ppr_port_tx_ctl(json_t *reply_root, json_t *args, ppr_thread_args_t *thread_args);
int ppr_set_port_stream_vcs(json_t *reply_root, json_t *args, ppr_thread_args_t *thread_args);

#endif // PPR_PORT_RPC_H