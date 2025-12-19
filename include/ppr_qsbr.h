/*
SPDX-License-Identifier: MIT
Copyright (c) 2025 jfdawson20

Filename: ppr_qsbr.h
Description: Multiple subsystems in the ppr application require read-copy-update (RCU) style synchronization for safe concurrent access to shared data 
structures. Specifically, systems that require lock-free delete/update of shared structures that are frequently read by datapath worker threads use RCU QSBR 
(quiescent state-based reclamation) provided by DPDK to ensure safe memory reclamation of retired objects. While each specific subsystem (e.g. flow table, 
load balancer) maintains their own specific QSBR differ queue and callback reclamation logic, they all share a common RCU QSBR context structure that is used 
to register reader threads and manage the underlying DPDK RCU QSBR structure.

the ppr QSBR API provides helper functions for initializing the RCU QSBR context, registering reader threads, and marking quiescent states. This allows
multiple subsystems to share a common RCU QSBR structure while encapsulating the specific logic for each subsystem's defer queue and reclamation process.

*/

#ifndef PPR_QSBR_H
#define PPR_QSBR_H

#include <rte_rcu_qsbr.h>

typedef struct ppr_rcu_ctx {
    struct rte_rcu_qsbr *qs;
    uint32_t             num_readers;
} ppr_rcu_ctx_t;    



void ppr_ft_reader_init(ppr_rcu_ctx_t *rcu_ctx, int thread_id);
void ppr_ft_reader_destroy(ppr_rcu_ctx_t *rcu_ctx, int thread_id);
void ppr_ft_reader_idle(ppr_rcu_ctx_t *rcu_ctx, int thread_id);

#endif /* ppr_QSBR_H */