/*
SPDX-License-Identifier: MIT
Copyright (c) 2025 jfdawson20

Filename: stats.h
Description: contains the main entry point for the stats monitoring thread. The stats monitor is a pthread launched from the main DPDK 
core and is responsible for periodically collecting, processing, and publishing statistics about the application. The initial monitoring tasks 
includes memory, port stats, flow table, load balancer, etc. aggregation. but is the landing place for any "i need to monitor X stats" functionality.

The main thread runs in a infinite loop at a poll frequency specified at launch time. 

Note, where possible, stats structures live in a parent struct to which they are associated with (e.g. ppr_port_entry_t contains its own stats struct pointer).

Where there isn't a great landing spot for a stats struct, we place it in the global stats struct ppr_stats_all_t defined here.
*/

#ifndef PPR_STATS_H
#define PPR_STATS_H

#include <stdint.h>
#include <stdatomic.h> 
#include <pthread.h>
#include <time.h> 

#include <rte_common.h>

#include "ppr_ports.h"
#include "ppr_acl.h"

#define STATS_POLL_INTERVAL_MS 100

/* per worker or per port stat structs */
typedef struct ppr_single_port_stat_seq{
    uint64_t        rx_packets;
    uint64_t        rx_bytes;
    uint64_t        rx_bad_packets;
    uint64_t        frag_packets_rx;
    uint64_t        frag_reassembled_packets;
    uint64_t        tx_packets;
    uint64_t        tx_bytes;
    uint64_t        tx_dropped_packets;
} ppr_single_worker_stat_seq_t __rte_aligned(RTE_CACHE_LINE_SIZE);
_Static_assert(sizeof(ppr_single_worker_stat_seq_t) == RTE_CACHE_LINE_SIZE, "worker stats must be one cache line");

typedef struct ppr_worker_stats{
    pthread_mutex_t lock;
    unsigned int num_workers; 
    ppr_single_worker_stat_seq_t  *prev_worker_stats;
    ppr_single_worker_stat_seq_t  *current_worker_stats;
    ppr_single_worker_stat_seq_t  *rates_worker_stats;
    struct timespec prev_ts; 
    struct timespec curr_ts; 
} ppr_worker_stats_t;

//memory subsystem stats 
typedef struct ppr_mempool_stats{
    uint64_t available; 
    uint64_t used; 
    uint64_t total; 
} ppr_mempool_stats_t;

typedef struct ppr_all_memory_stats{
    pthread_mutex_t lock; 
    ppr_mempool_stats_t *mstats;
} ppr_all_memory_stats_t;

//main stats entry struct 
typedef struct ppr_stats_all{
    ppr_worker_stats_t      *worker_stats;
    ppr_all_memory_stats_t  *mem_stats; 
} ppr_stats_all_t;


void *run_ppr_stats_thread(void *arg);

#endif /* PPR_STATS_H */