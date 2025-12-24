/*
SPDX-License-Identifier: MIT
Copyright (c) 2025 jfdawson20

Filename: ppr_log.c
Description: Logging in the PPR application uses a custom set of log types registered with DPDK's logging framework. This file contains the implementation for 
initializing and configuring these log types based on the application configuration. When logging in the application, the PPR_LOG macro defined in ppr_log.h 
should be used to ensure that logs are properly categorized and filtered according to the configured log levels.

*/
#define _GNU_SOURCE

#include <rte_log.h>
#include <errno.h>

#include "ppr_log.h"

/* Define custom log types for wirepath switch */
int PPR_LOG_INIT, PPR_LOG_DP, PPR_LOG_FLOW, PPR_LOG_PORTS, PPR_LOG_CFG, PPR_LOG_STATS, PPR_LOG_RPC,PPR_LOG_PKTIO, PPR_LOG_CTL, PPR_LOG_LB, PPR_LOG_NETL, PPR_LOG_ACL;

/** 
* Initialize and register all logtypes
* @param cfg
*   Pointer to the application configuration    
* @return
*   - 0 on success
*   - -EINVAL if input parameters are invalid
*   - -ENOENT if log file cannot be opened
**/
int ppr_log_init_defaults(int log_level, int default_output, const char *log_dir){
    int rc=0; ;
    
    PPR_LOG_INIT  = rte_log_register("ppr.init");
    PPR_LOG_DP    = rte_log_register("ppr.dp");
    PPR_LOG_FLOW  = rte_log_register("ppr.flow");
    PPR_LOG_PORTS = rte_log_register("ppr.ports");
    PPR_LOG_CFG   = rte_log_register("ppr.cfg");
    PPR_LOG_STATS = rte_log_register("ppr.stats");
    PPR_LOG_PKTIO = rte_log_register("ppr.pktio");
    PPR_LOG_RPC   = rte_log_register("ppr.rpc");
    PPR_LOG_CTL   = rte_log_register("ppr.ctl");
    PPR_LOG_LB    = rte_log_register("ppr.lb");
    PPR_LOG_NETL  = rte_log_register("ppr.netl");
    PPR_LOG_ACL   = rte_log_register("ppr.acl");
    
    /* Sensible defaults; CLI can override with --log-level=... */
    rc = rte_log_set_level(PPR_LOG_INIT,    log_level);
    rc = rc + rte_log_set_level(PPR_LOG_DP,    log_level);
    rc = rc + rte_log_set_level(PPR_LOG_FLOW,  log_level);
    rc = rc + rte_log_set_level(PPR_LOG_PORTS, log_level);
    rc = rc + rte_log_set_level(PPR_LOG_CFG,   log_level);
    rc = rc + rte_log_set_level(PPR_LOG_STATS, log_level);
    rc = rc + rte_log_set_level(PPR_LOG_PKTIO, log_level);
    rc = rc + rte_log_set_level(PPR_LOG_RPC,   log_level);
    rc = rc + rte_log_set_level(PPR_LOG_CTL,   log_level);
    rc = rc + rte_log_set_level(PPR_LOG_LB,    log_level);
    rc = rc + rte_log_set_level(PPR_LOG_NETL,  log_level);
    rc = rc + rte_log_set_level(PPR_LOG_ACL,   log_level);
    if (rc < 0){
        return -EINVAL;
    }
    
    if (default_output == LOG_STDOUT){
        rte_openlog_stream(stdout);
    }
    else if (default_output == LOG_FILE && log_dir != NULL){
        char logfile[256];
        snprintf(logfile, sizeof(logfile), "%s/pcap_replay.log", log_dir);
        rc = rte_openlog_stream(fopen(logfile, "w"));
        if (rc < 0){
            return -ENOENT;
        }
    }
    else {
        return -EINVAL;
    }


    return 0;
}

/** 
* Convert yaml log level to rte log level
* @param level
*   yaml log level integer
* @return
*   corresponding rte log level integer
**/
int yaml_to_rte_log_level(int level)
{
    switch (level) {
        case 0: return RTE_LOGTYPE_EAL;
        case 1: return RTE_LOG_EMERG;
        case 2: return RTE_LOG_ALERT;
        case 3: return RTE_LOG_CRIT;
        case 4: return RTE_LOG_ERR;
        case 5: return RTE_LOG_WARNING;
        case 6: return RTE_LOG_NOTICE;
        case 7: return RTE_LOG_INFO;
        case 8: return RTE_LOG_DEBUG;
        default: return RTE_LOG_INFO;
    }
}