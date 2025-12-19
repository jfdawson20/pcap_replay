/*
SPDX-License-Identifier: MIT
Copyright (c) 2025 jfdawson20

Filename: ppr_log.h
Description: Logging in the PPR application uses a custom set of log types registered with DPDK's logging framework. This file contains the implementation for 
initializing and configuring these log types based on the application configuration. When logging in the application, the PPR_LOG macro defined in ppr_log.h 
should be used to ensure that logs are properly categorized and filtered according to the configured log levels.

*/
#ifndef PPR_LOG_H
#define PPR_LOG_H

#include <rte_log.h>
#include <stdatomic.h>

/* Extern declarations (defined once in ppr_log.c) */
extern int PPR_LOG_INIT;
extern int PPR_LOG_DP;
extern int PPR_LOG_FLOW;
extern int PPR_LOG_PORTS;
extern int PPR_LOG_PKTIO;
extern int PPR_LOG_CFG;
extern int PPR_LOG_STATS;
extern int PPR_LOG_RPC;
extern int PPR_LOG_CTL;
extern int PPR_LOG_LB;
extern int PPR_LOG_NETL;
extern int PPR_LOG_ACL;

typedef enum {
    LOG_STDOUT = 0,
    LOG_FILE   = 1,
} ppr_log_mode_t;


/* Initialize and register all logtypes */
int ppr_log_init_defaults(int log_level, int default_output, const char *log_dir);
int yaml_to_rte_log_level(int level);

/* Helper macro for conditional logging */
#define PPR_LOG(logtype, level, fmt, ...)                                       \
    do {                                                                        \
        if (rte_log_can_log((logtype), (level)))                                \
            rte_log((level), (logtype), fmt, ##__VA_ARGS__);                    \
    } while (0)

#ifndef PPR_DP_LOG_ENABLE
#define PPR_DP_LOG_ENABLE 0
#endif

#if PPR_DP_LOG_ENABLE
    #define PPR_DP_LOG(logtype, level, fmt, ...) \
        PPR_LOG(logtype, level, fmt, ##__VA_ARGS__)
#else
    // Completely compiled out – no function call, no branch.
    #define PPR_DP_LOG(logtype, level, fmt, ...) \
        do { } while (0)
#endif


#endif