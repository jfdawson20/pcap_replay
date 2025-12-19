/*
SPDX-License-Identifier: MIT
Copyright (c) 2025 jfdawson20

Filename: ppr_flowtable.c
Description: This file contains the API for creating and managing flow tables. Flow tables store flow entries that define how packets matching specific flow keys should be processed. 
The flow table supports sharding for scalability and uses DPDK hash tables for efficient lookups. The flowtable API is designed to support concurrent 
instances of flow tables being accessed by multiple worker threads safely. The API supports two types of flow keys: IPv4/IPv6 5-tuple and L2 (MAC address based) keys
allowing for creation of IP and Non IP flowtables. 
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <rte_hash_crc.h>
#include <rte_thash.h>
#include <rte_malloc.h>
#include <rte_per_lcore.h> 
#include <rte_lcore.h> 
#include <string.h>
#include <stdatomic.h>

#include "ppr_flowtable.h"
#include "ppr_app_defines.h"
#include "ppr_log.h"
#include "ppr_acl.h"

//per lcore key/action pair caches 
RTE_DEFINE_PER_LCORE(ppr_ft_lcache_entry_t, l1)[PPR_L1_CACHE_SIZE];


/* ------------------------------ Configuration and Init functions --------------------------------------------*/

/**
    * Callback function to free retired action entries.
    *
    * @param arg
    *   Optional context argument (unused here).
    * @param entries
    *   Array of pointers to entries to free.
    * @param n
    *   Number of entries in the array. 
**/
static void ppr_ft_free_action_cb(void *arg, void *entries, unsigned int n)
{
    (void)arg; // optional context, ignore if unused
    void **arr = (void **)entries;   // array of pointers, n elements
    for (unsigned int i = 0; i < n; i++) {
        // We enqueue both action* and handle*; both were rte_zmalloc'd
        rte_free(arr[i]);
    }
}

/** 
    * Compute the next power of two greater than or equal to x.
    * @param x
    *   Input value
    * @return
    *   Next power of two >= x
**/
static inline uint32_t ppr_ft_pow2_ceiling(uint32_t x) {
    if (x <= 1) return 1;
    x--;
    x |= x >> 1; x |= x >> 2; x |= x >> 4; x |= x >> 8; x |= x >> 16;
    return x + 1;
}

/**
* Create a DPDK hash table for the flow table
* @param name
*   Name of the hash table
* @param socket_id
*   NUMA socket ID for memory allocation
* @param entries
*   Expected number of entries in the hash table
* @return
*   Pointer to the created hash table, or NULL on failure
**/
static struct rte_hash *ppr_ft_make_hash(const char *name, int socket_id, uint32_t entries, uint16_t key_size) {
    
    //create re_hash_parameters strcuture, currently configured for maximum thread safe behavior (see below)
    struct rte_hash_parameters hp = {
        .name = name, 
        .entries = entries, 
        .key_len = key_size,
        .socket_id = socket_id,
        .extra_flag = RTE_HASH_EXTRA_FLAGS_EXT_TABLE       |   //we want to use the extended hash table features
                      RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF | //readers/writers can operate on the hash table simultaneously
                      RTE_HASH_EXTRA_FLAGS_MULTI_WRITER_ADD    //allow multiple writes to safely add keys simultaneously
    };

    //return a pointer to the rte_hash structure created with the config above
    return rte_hash_create(&hp);
}


/** 
* Create a flow table structure
* @param cfg
*   Pointer to flow table configuration structure
* @return
*   Pointer to created flow table structure, or NULL on failure 
**/
ppr_flow_table_t *ppr_ft_create(const ppr_ft_cfg_t *cfg,ppr_rcu_ctx_t *rcu_ctx) {
    
    //use rte_zmalloc to reserve flowtable memory pointer, use rte zmalloc to allow use of dpdk managed memory
    ppr_flow_table_t *ft = rte_zmalloc_socket(cfg->name, sizeof(*ft), RTE_CACHE_LINE_SIZE, cfg->socket_id);
    if (!ft) 
        goto fail_ft;

    ft->cfg = *cfg;

    //set key type and size 
    ft->key_kind = cfg->key_kind;
    ft->key_size = cfg->key_size;

    ft->shards = cfg->shards > 0 ? ppr_ft_pow2_ceiling(cfg->shards) : 1; //enforce a minimum of one shard  stripe 
    ft->s = rte_zmalloc_socket("ft_shards", sizeof(ppr_ft_shard_t)*ft->shards, RTE_CACHE_LINE_SIZE, cfg->socket_id);
    if (!ft->s) 
        goto fail_ft;

    //allocate cursor to track where we are in a walk through all shards
    ft->shard_walk_iter = rte_zmalloc_socket("ft_shard_walk_iter", sizeof(uint32_t)*ft->shards, RTE_CACHE_LINE_SIZE, cfg->socket_id);
    if (!ft->shard_walk_iter)  {
        goto fail_shards;
    }

    //create the hashtable structure and assign it to each shard
    for (unsigned int i=0;i<ft->shards;i++){
        char n[64]; 
        snprintf(n,sizeof n,"%s_%d",cfg->name,i);
        uint32_t per = RTE_MAX(1u, cfg->entries / ft->shards);
        
        snprintf(ft->s[i].name,sizeof (ft->s[i].name),"%s_%d",cfg->name,i);
        ft->s[i].h = ppr_ft_make_hash(n, cfg->socket_id, per, ft->key_size);
        //if failure occurs
        if (!ft->s[i].h) {
            // unwind already-created shards
            for (unsigned int j = 0; j < i; j++) {
                rte_hash_free(ft->s[j].h);
            }
            printf("Failed to create hash table for flow table shard %d\n", i);
            goto fail_shards;
        }
    }

    ft->rcu_ctx = rcu_ctx; //assign shared rcu context

    char dq_name[RTE_RCU_QSBR_DQ_NAMESIZE];
    snprintf(dq_name, sizeof(dq_name), "%s_dq", cfg->name);
    ft->dq = rte_rcu_qsbr_dq_create(&(struct rte_rcu_qsbr_dq_parameters){
        .name = dq_name,
        .v = ft->rcu_ctx->qs,
        .size = cfg->entries*2,                                 //we always want double the size of the hash table to avoid backpressure
        .esize = sizeof(void *),
        .free_fn = ppr_ft_free_action_cb,                       // action retire free function
        .trigger_reclaim_limit = cfg->qsbr_reclaim_limit,       // start reclaim when queue reaches this
        .max_reclaim_size = cfg->qsbr_max_reclaim_size,         // max items freed per reclaim call
    });
    if (!ft->dq) {
        for (unsigned int i = 0; i < ft->shards; i++){
            rte_hash_free(ft->s[i].h);
        }
        goto fail_shards;
    }

    //assign policy epoch pointer for future use
    ft->policy_epochs = cfg->policy_epochs;
    ft->enable_multi_tenancy = cfg->enable_multi_tenancy;
    ft->multi_tenant_protocol = cfg->multi_tenant_protocol;
    ft->log_level = cfg->log_level;
    ft->default_lifetime_ms     = cfg->default_lifetime_ms;
    ft->default_idle_timeout_ms = cfg->default_idle_timeout_ms;

    //initialize flowtable level stats
    ft->total_flows = 0;    
    ft->total_active_flows = 0;
    ft->total_flows_evicted = 0;   
    ft->total_invalidated_evicted_flows = 0;                 
    ft->total_timeout_evicted_flows = 0;           
    ft->total_lifetime_evicted_flows = 0;             
    ft->total_acl_policy_epoch_evicted_flows = 0;

    //per shard stats arrays
    ft->shard_new_flows = rte_zmalloc_socket("ft_shard_new_flows", sizeof(*ft->shard_new_flows) * ft->shards, RTE_CACHE_LINE_SIZE, cfg->socket_id);
    ft->shard_total_flows = rte_zmalloc_socket("ft_shard_total_flows", sizeof(*ft->shard_total_flows) * ft->shards, RTE_CACHE_LINE_SIZE, cfg->socket_id);
    ft->shard_active_flows = rte_zmalloc_socket("ft_shard_active_flows", sizeof(*ft->shard_active_flows) * ft->shards, RTE_CACHE_LINE_SIZE, cfg->socket_id);
    ft->shard_evicted_flows = rte_zmalloc_socket("ft_shard_flows_evicted", sizeof(*ft->shard_evicted_flows) * ft->shards, RTE_CACHE_LINE_SIZE, cfg->socket_id);
    ft->shard_invalidated_evicted_flows = rte_zmalloc_socket("ft_shard_invalidated_evicted_flows", sizeof(*ft->shard_invalidated_evicted_flows) * ft->shards, RTE_CACHE_LINE_SIZE, cfg->socket_id);
    ft->shard_timeout_evicted_flows = rte_zmalloc_socket("ft_shard_timeout_evicted_flows", sizeof(*ft->shard_timeout_evicted_flows) * ft->shards, RTE_CACHE_LINE_SIZE, cfg->socket_id);
    ft->shard_lifetime_evicted_flows = rte_zmalloc_socket("ft_shard_lifetime_evicted_flows", sizeof(*ft->shard_lifetime_evicted_flows) * ft->shards, RTE_CACHE_LINE_SIZE, cfg->socket_id);
    ft->shard_acl_policy_epoch_evicted_flows = rte_zmalloc_socket("ft_shard_acl_policy_epoch_evicted_flows", sizeof(*ft->shard_acl_policy_epoch_evicted_flows) * ft->shards, RTE_CACHE_LINE_SIZE, cfg->socket_id);
    
    if(!ft->shard_new_flows || !ft->shard_total_flows || !ft->shard_active_flows || !ft->shard_evicted_flows ||
       !ft->shard_invalidated_evicted_flows || !ft->shard_timeout_evicted_flows || !ft->shard_lifetime_evicted_flows ||
       !ft->shard_acl_policy_epoch_evicted_flows) {
        rte_free(ft->shard_new_flows);
        rte_free(ft->shard_total_flows);
        rte_free(ft->shard_active_flows);
        rte_free(ft->shard_evicted_flows);
        rte_free(ft->shard_invalidated_evicted_flows);
        rte_free(ft->shard_timeout_evicted_flows);
        rte_free(ft->shard_lifetime_evicted_flows);
        rte_free(ft->shard_acl_policy_epoch_evicted_flows);
        for (unsigned int i = 0; i < ft->shards; i++) {
            rte_hash_free(ft->s[i].h);
        }
        rte_rcu_qsbr_dq_delete(ft->dq);
        goto fail_shards;
    }   

    //initialize per shard stats arrays
    for(unsigned int i=0; i < ft->shards; i++){
        atomic_fetch_add_explicit(&ft->shard_new_flows[i], 0, memory_order_relaxed);
        ft->shard_total_flows[i] = 0;
        ft->shard_active_flows[i] = 0;
        ft->shard_evicted_flows[i] = 0;
        ft->shard_invalidated_evicted_flows[i] = 0;
        ft->shard_timeout_evicted_flows[i] = 0;
        ft->shard_lifetime_evicted_flows[i] = 0;
        ft->shard_acl_policy_epoch_evicted_flows[i] = 0;    
    }

    ppr_time_bins_init(&ft->time_bins, rte_get_tsc_hz());

    //return flowtable pointer
    return ft;

fail_shards:
    rte_free(ft->s);
fail_ft:
    rte_free(ft);
    return NULL;
}


/**
* Destroy a flow table structure
* @param ft
*   Pointer to flow table structure to destroy 
**/
void ppr_ft_destroy(ppr_flow_table_t *ft) {
    
    //free stats arrays
    rte_free(ft->shard_new_flows);
    rte_free(ft->shard_total_flows);
    rte_free(ft->shard_active_flows);
    rte_free(ft->shard_evicted_flows);
    rte_free(ft->shard_invalidated_evicted_flows);
    rte_free(ft->shard_timeout_evicted_flows);
    rte_free(ft->shard_lifetime_evicted_flows);
    rte_free(ft->shard_acl_policy_epoch_evicted_flows);

    //for each shard, call rte_hash_free on it's hashtable struct
    for (unsigned int i=0;i<ft->shards;i++){ 
        rte_hash_free(ft->s[i].h);
    }

    //reclaim all outstanding retired actions
    rte_rcu_qsbr_synchronize(ft->rcu_ctx->qs, RTE_QSBR_THRID_INVALID); // wait for readers
    if(ft->dq == NULL) {
        PPR_LOG(PPR_LOG_FLOW, RTE_LOG_WARNING, "Flow table dq is NULL during destroy, skipping reclaim\n");
        return;
    }
    unsigned int freed = 0, pending= 0, avail = 0;
    do {
        rte_rcu_qsbr_dq_reclaim(ft->dq, 1, &freed, &pending, &avail);
    } while (pending);
    
    //free the qsbr differ queue
    rte_rcu_qsbr_dq_delete(ft->dq);    
    
    //free the shard array pointer
    rte_free(ft->s); 

    //free the flowtable pointer 
    rte_free(ft);
}

/** 
* helper function to validate acl runtime context in flow entry
* @param e
*   Pointer to flow entry structure
* @return
*   true if valid, false if not valid
**/
static bool ppr_ft_acl_ctx_valid(const ppr_flow_entry_t *e)
{
    return e && e->acl_runtime_ctx && e->acl_runtime_ctx->stats_shards;
}




static inline void ppr_acl_bump_start(const ppr_flow_entry_t *e)
{
    if (!e || e->authored_stage != PPR_DEF_ACL_LKP_COMPLETED) return;
    if (!ppr_ft_acl_ctx_valid(e)) return;

    ppr_acl_stats_shard_t *sh = &e->acl_runtime_ctx->stats_shards[e->thread_index];

    if (e->acl_l3_type == PPR_L3_IPV4)
        atomic_fetch_add_explicit(&sh->ip4[e->acl_policy_index].new_flows, 1, memory_order_relaxed);
    else if (e->acl_l3_type == PPR_L3_IPV6)
        atomic_fetch_add_explicit(&sh->ip6[e->acl_policy_index].new_flows, 1, memory_order_relaxed);
    else
        atomic_fetch_add_explicit(&sh->l2[e->acl_policy_index].new_flows, 1, memory_order_relaxed);
}

static inline void ppr_acl_bump_close(const ppr_flow_entry_t *e)
{
    if (!e || e->authored_stage != PPR_DEF_ACL_LKP_COMPLETED) return;
    if (!ppr_ft_acl_ctx_valid(e)) return;

    ppr_acl_stats_shard_t *sh = &e->acl_runtime_ctx->stats_shards[e->thread_index];

    if (e->acl_l3_type == PPR_L3_IPV4)
        atomic_fetch_add_explicit(&sh->ip4[e->acl_policy_index].closed_flows, 1, memory_order_relaxed);
    else if (e->acl_l3_type == PPR_L3_IPV6)
        atomic_fetch_add_explicit(&sh->ip6[e->acl_policy_index].closed_flows, 1, memory_order_relaxed);
    else
        atomic_fetch_add_explicit(&sh->l2[e->acl_policy_index].closed_flows, 1, memory_order_relaxed);
}

static inline bool ppr_acl_same_bucket(const ppr_flow_entry_t *a, const ppr_flow_entry_t *b)
{
    if (!a || !b) return false;
    if (a->authored_stage != PPR_DEF_ACL_LKP_COMPLETED) return false;
    if (b->authored_stage != PPR_DEF_ACL_LKP_COMPLETED) return false;

    return a->acl_runtime_ctx == b->acl_runtime_ctx &&
           a->thread_index    == b->thread_index &&
           a->acl_l3_type     == b->acl_l3_type &&
           a->acl_policy_index== b->acl_policy_index;
}

static void ppr_acl_reconcile_flow_stats(const ppr_flow_entry_t *old_e,
                                        const ppr_flow_entry_t *new_e)
{
    // If they map to the same rule bucket, no net change.
    if (old_e && new_e && ppr_acl_same_bucket(old_e, new_e))
        return;

    // Old contribution ends, new contribution begins.
    ppr_acl_bump_close(old_e);
    ppr_acl_bump_start(new_e);
}



/* ------------------------------------- Lookup Functions --------------------------------------------------------- */

/** 
* Common lookup function used by both prehash and non-prehash variants
* @param ft
*   Pointer to flow table structure
* @param key
*   Pointer to flow key structure
* @param sig    
*   Signature hash value
* @return
*   Pointer to flow entry structure    
**/
static inline const ppr_flow_entry_t *
ppr_ft_lookup_common(const ppr_flow_table_t *ft, const void *key, uint32_t sig)
{
    RTE_ASSERT(ft != NULL);
    RTE_ASSERT(ft->s != NULL);
    RTE_ASSERT(ft->shards >= 1 && (ft->shards & (ft->shards - 1)) == 0);

    ppr_ft_lcache_entry_t *local_l1 = RTE_PER_LCORE(l1);
    uint32_t i = sig & (PPR_L1_CACHE_SIZE - 1);

    if (likely(local_l1[i].h &&
               memcmp(local_l1[i].key_bytes, key, ft->key_size) == 0)) {

        const ppr_flow_entry_t *entry =
            atomic_load_explicit(&local_l1[i].h->ptr, memory_order_acquire);

        if (unlikely(entry == NULL || (entry->state_flags & FLOWF_INVALID))) {
            local_l1[i].h = NULL;
        } else {
            return entry;
        }
    }

    /* Miss: consult shard hash (stores handle*) */
    ppr_ft_indr_entry_handle_t *h = NULL;
    uint32_t shard = ppr_ft_shard_id(ft, sig);
    RTE_ASSERT(shard < (uint32_t)ft->shards);

    struct rte_hash *hh = ft->s[shard].h;
    RTE_ASSERT(hh != NULL);

    PPR_DP_LOG(PPR_LOG_FLOW, RTE_LOG_DEBUG,
            "Looking up flow key in shard %u, hash: 0x%x\n",
            shard, sig);

    if (rte_hash_lookup_with_hash_data(hh, key, sig, (void **)&h) >= 0 && h) {
        memcpy(local_l1[i].key_bytes, key, ft->key_size);
        local_l1[i].h = h;

        const ppr_flow_entry_t *entry =
            atomic_load_explicit(&h->ptr, memory_order_acquire);

        if (unlikely(entry == NULL || (entry->state_flags & FLOWF_INVALID))) {
            return NULL;
        }
        return entry;
    }

    return NULL;
}

/** 
* ---- extenal flow table lookup function ----
* @param ft
*   Pointer to flow table structure
* @param key
*   Pointer to flow key structure
* @return
*   Pointer to flow entry structure 
**/
const ppr_flow_entry_t *ppr_ft_lookup(const ppr_flow_table_t *ft, const void *key) {
    return ppr_ft_lookup_common(ft, key, ppr_ft_key_sig(ft, key));
}

/** 
* Perform a table lookup using a pre-provided hash function
* @param ft
*   Pointer to flow table structure
* @param key
*   Pointer to flow key structure
* @param sig    
*   Signature hash value
* @return
*   Pointer to flow entry structure
**/
const ppr_flow_entry_t *ppr_ft_lookup_prehash(const ppr_flow_table_t *ft, const void *key, uint32_t sig) {
    return ppr_ft_lookup_common(ft, key, sig);
}

/* returns a published entry or NULL if create failed */
static inline const ppr_flow_entry_t *ppr_ft_rx_lookup_or_create(ppr_flow_table_t *ft,
                    const void *key,
                    const ppr_flow_entry_t *init_template,
                    uint64_t tsc_ns)
{
    /* 1) Try fast lookup (may hit L1 or hash). */
    const ppr_flow_entry_t *fe = ppr_ft_lookup(ft, key);
    if (fe) 
        return fe;

    /* 2) Miss → try to add. May race with other cores. */
    int rc = ppr_ft_add(ft, key, init_template,tsc_ns,NULL);
    if (rc < 0 && rc != -EEXIST) {
        /* ENOMEM or other hard error: give up. */
        return NULL;
    }

    /* 3) Now it must exist (we just added it or someone else did), lookup again. */
    return ppr_ft_lookup(ft, key);
}

/* ------------------------------ Modification functions (add/modify) --------------------------------------------*/

/** 
* Build a new immutable action on the side (caller’s responsibility). 
* @param src
*   Pointer to source flow entry structure
* @param socket
*   NUMA socket ID for memory allocation
* @return
*   Pointer to created action structure 
**/
static inline ppr_flow_entry_t *ppr_ft_entry_dup_init(const ppr_flow_entry_t *src, int socket)
{
    ppr_flow_entry_t *e = rte_zmalloc_socket("entry", sizeof(*e), RTE_CACHE_LINE_SIZE, socket);
    if (e && src) 
        *e = *src;

    return e;
}

/** 
* Create a new indirect entry  handle
* @param socket
*   NUMA socket ID for memory allocation
* @param initial
*   Pointer to initial flow entry structure
* @return
*   Pointer to created indirect action handle structure
**/
static inline ppr_ft_indr_entry_handle_t *ppr_ft_entry_handle_create(int socket, ppr_flow_entry_t *initial)
{
    ppr_ft_indr_entry_handle_t *h = rte_zmalloc_socket("entry_handle", sizeof(*h), RTE_CACHE_LINE_SIZE, socket);
    if (!h) 
        return NULL;

    atomic_store_explicit(&h->ptr, initial, memory_order_release);   /* publish initial with relaxed is fine at init */
    return h;
}

/** 
* Check if an entry with the given key already exists
* @param ft
*   Pointer to flow table structure
* @param k
*   Pointer to flow key structure
* @param sig    
*   Signature hash value
* @return
*   0 if entry does not exist, -EEXIST if it does, negative errno on error
**/
static inline int ppr_ft_entry_valid(ppr_flow_table_t *ft, const void *k, uint32_t sig){

    // First check if the key exists
    ppr_ft_indr_entry_handle_t *h;
    int rc = rte_hash_lookup_with_hash_data(ft->s[ppr_ft_shard_id(ft,sig)].h, k, sig, (void**)&h);
    if (rc >= 0) {
        // Key already exists → fail
        return -EEXIST;
    }

    return rc;
}

/** 
* extenal flow table add - append function, adds a new entry or flow isn't present, else performs a modify
* @param ft
*   Pointer to flow table structure
* @param k
*   Pointer to flow key structure
* @param init_a
*   Pointer to flow entry structure
* @return
*   0 on success, negative errno on failure
**/
int ppr_ft_append(ppr_flow_table_t *ft, const void *k,
                  const ppr_flow_entry_t *init_e, uint64_t tsc_ns)
{
    const uint32_t sig = ppr_ft_key_sig(ft, k); // also fix the sig source
    int rc = ppr_ft_entry_valid(ft, k, sig);

    if (rc == -EEXIST)
        return ppr_ft_replace(ft, k, init_e, NULL);

    if (rc == -ENOENT)
        return ppr_ft_add(ft, k, init_e, tsc_ns, NULL);

    // Any other error: bubble it up
    return rc;
}

/** 
* Add a new entry to the flow table
* @param ft
*   Pointer to flow table structure
* @param k
*   Pointer to flow key structure
* @param init_a
*   Pointer to flow entry structure
* @return
*   0 on success, negative errno on failure
**/
int ppr_ft_add(ppr_flow_table_t *ft,const void *k,const ppr_flow_entry_t *init_e,uint64_t tsc_ns,const ppr_flow_entry_t **opt_existing_entry)
{
    const uint32_t sig   = ppr_ft_key_sig(ft, k);
    const uint32_t shard = ppr_ft_shard_id(ft, sig);
    struct rte_hash *hh  = ft->s[shard].h;
    ppr_ft_indr_entry_handle_t *h = NULL;

    /* 1) Check if key already exists in the hash */
    int lr = rte_hash_lookup_with_hash_data(hh, k, sig, (void **)&h);
    if (lr >= 0 && h) {
        const ppr_flow_entry_t *cur = atomic_load_explicit(&h->ptr, memory_order_acquire);

        if (cur && !(cur->state_flags & FLOWF_INVALID)) {
            /* Existing valid entry → treat as EEXIST */
            if (opt_existing_entry)
                *opt_existing_entry = cur;
            return -EEXIST;
        }

        /* Existing but invalid entry → reuse via replace */
        return ppr_ft_replace(ft, k, init_e, NULL);
    }

    /* 2) No entry found, allocate a brand new one */

    ppr_flow_entry_t *new_e = ppr_ft_entry_dup_init(init_e, ft->cfg.socket_id);
    if (!new_e)
        return -ENOMEM;

    size_t bytes = (size_t)ft->cfg.num_reader_threads * sizeof(ppr_flow_stats_hot_t);

    new_e->stats_hot = rte_zmalloc_socket("ft_stats_hot",
                                          bytes,
                                          RTE_CACHE_LINE_SIZE,
                                          ft->cfg.socket_id);
    if (!new_e->stats_hot) {
        rte_free(new_e);
        return -ENOMEM;
    }

    /* attach policy epoch and defaults */
    ppr_global_policy_epoch_t current_epoch;
    current_epoch.acl_policy_epoch = atomic_load_explicit(&ft->policy_epochs->acl_policy_epoch, memory_order_acquire);

    new_e->state_flags              = FLOWF_ESTABLISHED;
    new_e->install_ns               = tsc_ns;
    new_e->last_seen_ns             = tsc_ns;
    new_e->last_seen_cycles_low32   = (uint32_t)(rte_get_tsc_cycles() & 0xFFFFFFFF);
    new_e->refcnt                   = 1;
    new_e->shard_id                 = shard;
    new_e->policy_epoch             = current_epoch;

    //set key
    memcpy(&new_e->key, k, ft->key_size);

    /* 3) Create handle and add to hash */

    ppr_ft_indr_entry_handle_t *new_h = ppr_ft_entry_handle_create(ft->cfg.socket_id, new_e);
    if (!new_h) {
        rte_free(new_e->stats_hot);
        rte_free(new_e);
        return -ENOMEM;
    }

    PPR_DP_LOG(PPR_LOG_FLOW, RTE_LOG_DEBUG, "Adding flow key to flow table, shard %u hash=0x%x\n", shard, sig);

    int rc = rte_hash_add_key_with_hash_data(hh, k, sig, (void *)new_h);
    if (rc < 0) {
        /* roll back */
        rte_free(new_h);
        rte_free(new_e->stats_hot);
        rte_free(new_e);
        return rc;
    }

    if (opt_existing_entry)
        *opt_existing_entry = new_h->ptr;

    //increment per shard ACL rule counter based on rule type
    if (new_e->authored_stage == PPR_DEF_ACL_LKP_COMPLETED){

        if(unlikely(!ppr_ft_acl_ctx_valid(new_e))){
            PPR_LOG(PPR_LOG_FLOW, RTE_LOG_WARNING, "Invalid ACL runtime context detected during flow deletion, cannot update stats\n");
        }
        else {
            ppr_acl_stats_shard_t *acl_stats_shard = &new_e->acl_runtime_ctx->stats_shards[new_e->thread_index];
            if(new_e->acl_l3_type == PPR_L3_IPV4){
                atomic_fetch_add_explicit(&acl_stats_shard->ip4[new_e->acl_policy_index].new_flows, 1, memory_order_relaxed);
            }
            else if (new_e->acl_l3_type == PPR_L3_IPV6){
                atomic_fetch_add_explicit(&acl_stats_shard->ip6[new_e->acl_policy_index].new_flows, 1, memory_order_relaxed);
            }
            else{
                atomic_fetch_add_explicit(&acl_stats_shard->l2[new_e->acl_policy_index].new_flows, 1, memory_order_relaxed);
            }
        }
    }

    atomic_fetch_add_explicit(&ft->shard_new_flows[shard], 1, memory_order_relaxed);
    return 0;
}

/**
* when retiring an action pointer, put it into a qsbr defer queue to be processed later by the ft manager
* @param ft
*   Pointer to flow table structure
* @param old
*   Pointer to flow entry structure to retire   
**/
static inline void ppr_ft_retire_entry(ppr_flow_table_t *ft, const ppr_flow_entry_t *old)
{
    int rc = 0; 

    if (!old)
        return;

    // retire stats_hot first (if allocated)
    if (old->stats_hot) {
        const void *hot = old->stats_hot;
        rc = rte_rcu_qsbr_dq_enqueue(ft->dq, &hot);   // enqueue stats_hot pointer
        if (rc < 0) {
            ppr_ft_reclaim_actions(ft);
            rc = rte_rcu_qsbr_dq_enqueue(ft->dq, &hot);   // retry enqueue stats_hot pointer
            if (rc < 0) {
                PPR_LOG(PPR_LOG_FLOW, RTE_LOG_ERR, "Failed to enqueue stats_hot pointer for retirement\n");
            }
        }
    }

    // retire the entry itself
    rc = rte_rcu_qsbr_dq_enqueue(ft->dq, &old);       // enqueue entry pointer
    if (rc < 0) {
        ppr_ft_reclaim_actions(ft);
        rc = rte_rcu_qsbr_dq_enqueue(ft->dq, &old);   // retry enqueue entry pointer
        if (rc < 0) {
            PPR_LOG(PPR_LOG_FLOW, RTE_LOG_ERR, "Failed to enqueue entry pointer for retirement\n");
        }
    }
}


/**
* when retiring an indirect handle, put it into a qsbr defer queue to be processed later by the ft manager
* @param ft
*   Pointer to flow table structure
* @param h
*   Pointer to indirect entry handle structure to retire    
**/
static inline void ppr_ft_retire_indr_handle(ppr_flow_table_t *ft, ppr_ft_indr_entry_handle_t *h)
{
    if (!h) 
        return;

    // Start a grace-period token implicitly handled by the dq
    int rc = rte_rcu_qsbr_dq_enqueue(ft->dq, &h); // 1 element
    if (rc < 0) {
        ppr_ft_reclaim_actions(ft);
        rc = rte_rcu_qsbr_dq_enqueue(ft->dq, &h);   // retry enqueue indirect handle pointer
        if (rc < 0) {
            PPR_LOG(PPR_LOG_FLOW, RTE_LOG_ERR, "Failed to enqueue indirect handle pointer for retirement\n");
        }
    }
    // Do not free here; manager will reclaim later.
}


/** 
* Flow table replacement function - replaces an existing entry with a new one, retires the old one for later reclamation
* @param ft
*   Pointer to flow table structure
* @param k
*   Pointer to flow key structure
* @param new_a_src
*   Pointer to new flow entry structure
* @param old_a_opt
*   Pointer to pointer to old flow entry structure (optional, may be NULL)
* @return
*   0 on success, negative errno on failure
**/
int ppr_ft_replace(ppr_flow_table_t *ft,const void *k,const ppr_flow_entry_t *new_e_src,ppr_flow_entry_t **old_e_opt)
{
    //calculate the hash signature of the key
    const uint32_t sig = ppr_ft_key_sig(ft,k);

    ppr_ft_indr_entry_handle_t *h = NULL;

    //pick the right hashtable based on shard_id
    struct rte_hash *hh = ft->s[ppr_ft_shard_id(ft, sig)].h;

    //Find the handle for this key 
    int lr = rte_hash_lookup_with_hash_data(hh, k, sig, (void **)&h);
    if (lr < 0 || !h) 
        return -ENOENT;

    // Build the new immutable action
    ppr_flow_entry_t *new_e = ppr_ft_entry_dup_init(new_e_src, ft->cfg.socket_id);
    if (!new_e) 
        return -ENOMEM;

    /* Publish: single atomic pointer exchange.
       - release on writer makes prior stores to *new_e visible
       - acquire on readers ensures they see a fully built object */
    const ppr_flow_entry_t *cur = atomic_load_explicit(&h->ptr, memory_order_acquire);
    if (cur) {
        new_e->stats_hot = cur->stats_hot;
    }else {
        size_t bytes = (size_t)ft->cfg.num_reader_threads * sizeof(ppr_flow_stats_hot_t);

        new_e->stats_hot = rte_zmalloc_socket("ft_stats_hot",
                                            bytes,
                                            RTE_CACHE_LINE_SIZE,
                                            ft->cfg.socket_id);
        if (!new_e->stats_hot) {
            rte_free(new_e);
            return -ENOMEM;
        }
    }

    ppr_flow_entry_t *old = atomic_exchange_explicit(&h->ptr, new_e, memory_order_release);

    //reconcile policy stats is present 
    ppr_acl_reconcile_flow_stats(old, new_e);

    //return old action struct if requested
    if (old_e_opt) 
        *old_e_opt = (ppr_flow_entry_t *)old;

    //Readers may still hold 'old' in registers/L1 → retire safely
    if (old) {
        // IMPORTANT: prevent double-free of stats_hot; new_e now owns it
        ((ppr_flow_entry_t *)old)->stats_hot = NULL;

        // retire only the entry; stats_hot continues to be used by new_e
        rte_rcu_qsbr_dq_enqueue(ft->dq, &old);
    }

    return 0;
}

/** 
* Delete an entry from a flow table, deletes the entry and retires both action and handle for later reclamation
* @param ft
*   Pointer to flow table structure
* @param k
*   Pointer to flow key structure
* @return
*   0 on success, negative errno on failure
**/
int ppr_ft_del(ppr_flow_table_t *ft, const void *k)
{   
    //calculate the hash signature of the key
    const uint32_t sig = ppr_ft_key_sig(ft,k);

    ppr_ft_indr_entry_handle_t *h = NULL;

    //pick the right hashtable based on shard_id
    struct rte_hash *hh = ft->s[ppr_ft_shard_id(ft, sig)].h;

    //Lookup handle first so we can retire after removal
    if (rte_hash_lookup_with_hash_data(hh, k, sig, (void **)&h) < 0 || !h)
        return -ENOENT;

    //if present, delete the entry
    int rc = rte_hash_del_key_with_hash(hh, k, sig);
    if (rc < 0) 
        return rc;

    /* After removal from hash, L1 entries may still hold h.
       If you want to proactively invalidate L1, you can add an epoch/ttl.
       We retire the current action and the handle via RCU callback. */
    ppr_flow_entry_t *old = atomic_exchange_explicit(&h->ptr, NULL, memory_order_release);

    ppr_ft_retire_entry(ft, old);
    ppr_ft_retire_indr_handle(ft, h);

    return 0;
}

void ppr_ft_reclaim_actions(ppr_flow_table_t *ft){
    unsigned int freed = 0, pending= 0, avail = 0;
    rte_rcu_qsbr_dq_reclaim(ft->dq, ft->cfg.qsbr_max_reclaim_size, &freed, &pending, &avail);
    if (freed > 0) {
        PPR_DP_LOG(PPR_LOG_FLOW, RTE_LOG_DEBUG, "Reclaimed %u retired actions/handles, %u still pending, %u slots available\n", freed, pending, avail);
    }
}


/**
* Walk the flow table to perform maintenance tasks such as timeout checks and stats aggregation
* @param ft
*   Pointer to flow table structure
* @param now_ns
*   Current time in nanoseconds
**/
void ppr_flowtable_walker(ppr_flow_table_t *ft, uint64_t now_ns, uint32_t max_walks_per_call)
{

    if (max_walks_per_call == 0) {
        return;
    }

    uint32_t remaining_walks = max_walks_per_call;

    // Always do this for every shard, keeps aggregated stats up to date
    for (unsigned s = 0; s < ft->shards; s++) {
        uint64_t newf = atomic_exchange_explicit(&ft->shard_new_flows[s], 0, memory_order_acq_rel);
        ft->shard_total_flows[s]  += newf;
        ft->total_flows           += newf;
        ft->shard_active_flows[s] += newf;
        ft->total_active_flows    += newf;
    }

    /* Walk through all configured flowtables */
    for (unsigned int s = 0; s < ft->shards && remaining_walks > 0; s++) {
        struct rte_hash *h = ft->s[s].h;
        const void *key;
        void *data;

        //load cursor for this shard
        uint32_t iter = ft->shard_walk_iter[s];

        while (remaining_walks > 0) {
            int ret = rte_hash_iterate(h, &key, &data, &iter);
            if (ret < 0) {
                //end of table reached, reset cursor and break
                iter = 0;
                break;
            }

            remaining_walks--;

            bool acl_epoch_invalid = false;
            bool epoch_invalid = false;

            ppr_ft_indr_entry_handle_t *handle = (ppr_ft_indr_entry_handle_t *)data;
            ppr_flow_entry_t *fe = atomic_load_explicit(&handle->ptr, memory_order_acquire);

            //if null
            if (!fe) 
                continue;


            /* ----------------------------------- check for epoch changes ----------------------------- */
            
            //check if a policy epoch has changed that invalidates the flow entry
            epoch_invalid = false;
            int rc = ppr_ft_check_entry_epoch(ft,fe);
            if(rc < 0){
                PPR_DP_LOG(PPR_LOG_FLOW, RTE_LOG_INFO, "Flow entry policy epoch changed, marking invalid\n");
                ppr_flow_key_debug(ft,(ppr_flow_key_t *)key);

                //record which epoch was invalid for stats later 
                if (rc == -3)
                    acl_epoch_invalid = true;

                epoch_invalid = true;
                //print each epoch flag 
                PPR_DP_LOG(PPR_LOG_FLOW, RTE_LOG_INFO, "  \tACL policy epoch invalid: %s\n", acl_epoch_invalid ? "yes" : "no");

                }


            /* -------------------------------------- Check for timeouts --------------------------------*/
            uint64_t age_ns = 0;
            if (now_ns > fe->last_seen_ns) {
                age_ns = now_ns - fe->last_seen_ns;
            } else {
                age_ns = 0;
            }
            uint64_t idle_ns = (uint64_t)fe->idle_timeout_ms * 1000000ULL;
            uint64_t max_ns  = (uint64_t)fe->lifetime_ms *     1000000ULL;
            bool expired_idle = (fe->idle_timeout_ms && (age_ns > idle_ns));

            //compensate for clock drift between cores
            if(((int64_t)(now_ns - fe->install_ns) < 0)){
                fe->install_ns = now_ns;
            }   
            bool expired_lifetime = (fe->lifetime_ms && (now_ns - fe->install_ns > max_ns));

            bool expired = expired_idle || expired_lifetime;

            /* ---------------------------------- check for invalid flag ----------------------------- */
            bool invalid = (fe->state_flags & FLOWF_INVALID) != 0;


            /* ------------------------------------- process flow entry -------------------------------- */
            
            //if any invalidation conditions met, remove entry
            if (epoch_invalid || invalid || expired) {
                PPR_DP_LOG(PPR_LOG_FLOW, RTE_LOG_INFO, "Entry Marked as invalid / timeout, removing\n");
                PPR_DP_LOG(PPR_LOG_FLOW, RTE_LOG_INFO, "  \tIdle timeout expired: %s\n", expired_idle ? "yes" : "no");
                PPR_DP_LOG(PPR_LOG_FLOW, RTE_LOG_INFO, "  \tLifetime expired: %s\n", expired_lifetime ? "yes" : "no");
                PPR_DP_LOG(PPR_LOG_FLOW, RTE_LOG_INFO, "  \tEpoch invalid: %s\n", epoch_invalid ? "yes" : "no");
                PPR_DP_LOG(PPR_LOG_FLOW, RTE_LOG_INFO, "  \tPreviously marked invalid: %s\n", invalid ? "yes" : "no");

                ppr_flow_key_debug(ft,key);

                //mark entry as invalid
                ppr_ft_entry_mark_invalid(fe);


                //decrement per shard ACL rule counter based on rule type
                //we do this here so we only decrement if the flow is invalidated for NOT a acl epoch change
                //for ACL epoch changes we've scrapped the old rule set so doesn't matter.
                if (fe && fe->authored_stage == PPR_DEF_ACL_LKP_COMPLETED && !acl_epoch_invalid){

                    if(unlikely(!ppr_ft_acl_ctx_valid(fe))){
                        PPR_LOG(PPR_LOG_FLOW, RTE_LOG_WARNING, "Invalid ACL runtime context detected during flow deletion, cannot update stats\n");
                    }
                    else{
                        ppr_acl_stats_shard_t *acl_stats_shard = &fe->acl_runtime_ctx->stats_shards[fe->thread_index];
                        if(fe->acl_l3_type == PPR_L3_IPV4){
                            atomic_fetch_add_explicit(&acl_stats_shard->ip4[fe->acl_policy_index].closed_flows, 1, memory_order_relaxed);
                        }
                        else if (fe->acl_l3_type == PPR_L3_IPV6){
                            atomic_fetch_add_explicit(&acl_stats_shard->ip6[fe->acl_policy_index].closed_flows, 1, memory_order_relaxed);
                        }
                        else{
                            atomic_fetch_add_explicit(&acl_stats_shard->l2[fe->acl_policy_index].closed_flows, 1, memory_order_relaxed);
                        }
                    }
                }

                //Delete from hash table
                ppr_ft_del(ft, key);

                //update flowtable stats on eviction
                if(acl_epoch_invalid){
                    ft->shard_acl_policy_epoch_evicted_flows[s]++;
                    ft->total_acl_policy_epoch_evicted_flows++;
                }
                if(expired_idle){
                    ft->shard_timeout_evicted_flows[s]++;
                    ft->total_timeout_evicted_flows++;
                }
                if(expired_lifetime){
                    ft->shard_lifetime_evicted_flows[s]++;
                    ft->total_lifetime_evicted_flows++;
                }
                if(invalid){
                    ft->shard_invalidated_evicted_flows[s]++;
                    ft->total_invalidated_evicted_flows++;
                }
                
                ft->shard_evicted_flows[s]++;
                ft->total_flows_evicted++;
                ft->shard_active_flows[s]--;
                ft->total_active_flows--;
            }
            //else, perform normal housekeeping tasks
            else{
                
                //walk all lcore local hotstats    
                bool saw_activity = false; //activity calculated from packet stats   

                //accumulate hot stats into cold stats
                uint64_t pkts  = 0;
                uint64_t bytes = 0;
                uint64_t drops = 0;
                uint64_t sz_bins[FLOW_SIZE_BINS] = {0};
                ppr_flow_stats_cold_t   *cs = &fe->stats_cold;

                for (int l = 0; l < ft->cfg.num_reader_threads; l++) {
                    ppr_flow_stats_hot_t    *hs = &fe->stats_hot[l];

                    //accumulate all stats 
                    pkts  += __atomic_load_n(&hs->pkts, __ATOMIC_RELAXED);
                    bytes += __atomic_load_n(&hs->bytes, __ATOMIC_RELAXED);
                    drops += __atomic_load_n(&hs->drops, __ATOMIC_RELAXED);

                    for (int b = 0; b < FLOW_SIZE_BINS; b++) {
                        sz_bins[b] += __atomic_load_n(&hs->sz_bins[b], __ATOMIC_RELAXED);
                    }

                }

                //update cold stats 
                cs->pkts  = pkts;
                cs->bytes = bytes;
                cs->drops = drops;
                for (int b = 0; b < FLOW_SIZE_BINS; b++) {
                    cs->sz_bins[b] = sz_bins[b];
                }   

                //check for activity and update last pkts counter 
                if(cs->pkts > cs->last_pkts_cnt){
                    saw_activity = true;
                }
                cs->last_pkts_cnt = cs->pkts;

                //update last seen time
                if (saw_activity) {
                    //update last seen time 
                    fe->last_seen_ns = now_ns;
                }

            }

        }
    }
}

/** 
* Print flow table statistics
* @param ft 
*   Pointer to flow table structure
**/
void ppr_ft_print_stats(const ppr_flow_table_t *ft)
{
    uint64_t acl_epoch = atomic_load_explicit(&ft->policy_epochs->acl_policy_epoch, memory_order_acquire);
    
    PPR_LOG(PPR_LOG_FLOW, RTE_LOG_INFO, "Flow Table Stats:\n");
    PPR_LOG(PPR_LOG_FLOW, RTE_LOG_INFO, "  \tName: %s\n", ft->cfg.name);
    PPR_LOG(PPR_LOG_FLOW, RTE_LOG_INFO, "  \tPolicy Epochs: acl_policy=%lu\n", acl_epoch);
    PPR_LOG(PPR_LOG_FLOW, RTE_LOG_INFO, "  \tTotal Flows: %lu\n", ft->total_flows); 
    PPR_LOG(PPR_LOG_FLOW, RTE_LOG_INFO, "  \tActive Flows: %lu\n", ft->total_active_flows);
    PPR_LOG(PPR_LOG_FLOW, RTE_LOG_INFO, "  \tTotal Flows Evicted: %lu\n", ft->total_flows_evicted);
    PPR_LOG(PPR_LOG_FLOW, RTE_LOG_INFO, "  \t  - Invalidated Evicted: %lu\n", ft->total_invalidated_evicted_flows);
    PPR_LOG(PPR_LOG_FLOW, RTE_LOG_INFO, "  \t  - Timeout Evicted: %lu\n", ft->total_timeout_evicted_flows);
    PPR_LOG(PPR_LOG_FLOW, RTE_LOG_INFO, "  \t  - Lifetime Evicted: %lu\n", ft->total_lifetime_evicted_flows);
    PPR_LOG(PPR_LOG_FLOW,   RTE_LOG_INFO, "  \t  - ACL Policy Epoch Evicted: %lu\n", ft->total_acl_policy_epoch_evicted_flows);

    PPR_LOG(PPR_LOG_FLOW, RTE_LOG_INFO, "  \tShards: %d\n", ft->shards);
    PPR_LOG(PPR_LOG_FLOW, RTE_LOG_INFO, "  \tPer Shard Stats:\n");
    for (unsigned int s = 0; s < ft->shards; s++) {
        struct rte_hash *h = ft->s[s].h;
        uint32_t count = rte_hash_count(h);
        PPR_LOG(PPR_LOG_FLOW, RTE_LOG_INFO, "\t\tShard %d: %u entries\n", s, count);
        PPR_LOG(PPR_LOG_FLOW, RTE_LOG_INFO, "\t\tShard %d: %lu active flows\n", s, ft->shard_active_flows[s]);
        PPR_LOG(PPR_LOG_FLOW, RTE_LOG_INFO, "\t\tShard %d: %lu total flows\n", s, ft->shard_total_flows[s]);
        PPR_LOG(PPR_LOG_FLOW, RTE_LOG_INFO, "\t\tShard %d: %lu flows evicted\n", s, ft->shard_evicted_flows[s]);
        PPR_LOG(PPR_LOG_FLOW, RTE_LOG_INFO, "\t\tShard %d: %lu invalidated evicted flows\n", s, ft->shard_invalidated_evicted_flows[s]);
        PPR_LOG(PPR_LOG_FLOW, RTE_LOG_INFO, "\t\tShard %d: %lu timeout evicted flows\n", s, ft->shard_timeout_evicted_flows[s]);
        PPR_LOG(PPR_LOG_FLOW, RTE_LOG_INFO, "\t\tShard %d: %lu lifetime evicted flows\n", s, ft->shard_lifetime_evicted_flows[s]);
        PPR_LOG(PPR_LOG_FLOW, RTE_LOG_INFO, "\t\tShard %d: %lu acl policy epoch evicted flows\n", s, ft->shard_acl_policy_epoch_evicted_flows[s]); 
    }
}