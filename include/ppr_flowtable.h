/*
SPDX-License-Identifier: MIT
Copyright (c) 2025 jfdawson20

Filename: ppr_flowtable.h
Description: This file contains the API for creating and managing flow tables. Flow tables store flow entries that define how packets matching specific flow keys should be processed. 
The flow table supports sharding for scalability and uses DPDK hash tables for efficient lookups. The flowtable API is designed to support concurrent 
instances of flow tables being accessed by multiple worker threads safely. The API supports two types of flow keys: IPv4/IPv6 5-tuple and L2 (MAC address based) keys
allowing for creation of IP and Non IP flowtables. 
*/

#ifndef FLOW_TABLE_H
#define FLOW_TABLE_H

#include <sys/socket.h> //AF_INET, AF_INET6
#include <stdbool.h>

#include <rte_hash.h>
#include <rte_hash_crc.h>
#include <rte_thash.h>

#include <rte_rcu_qsbr.h>
#include <rte_ether.h>
#include <rte_per_lcore.h> 
#include <stddef.h>  

#include "ppr_app_defines.h"
#include "ppr_header_extract.h"
#include "ppr_actions.h"
#include "ppr_qsbr.h"


#define MAX_WALKS_PER_TICK 2048
#define PPR_L1_CACHE_SIZE 64 /* per-lcore tiny cache */


#define FLOW_SIZE_BINS 5    /* e.g., [0..63], [64..511], [512..1023], [1024..9K], [>9K] */
/* Intel default Toeplitz RSS key (40 bytes) */
static const uint8_t default_rss_key[40] = {
    0x6D, 0x5A, 0x56, 0xDA,
    0x25, 0x5B, 0x0E, 0xC2,
    0x41, 0x67, 0x25, 0x3D,
    0x43, 0xA3, 0x8F, 0xB0,
    0xD0, 0xCA, 0x2B, 0xCB,
    0xAE, 0x7B, 0x30, 0xB4,
    0x77, 0xCB, 0x2D, 0xA3,
    0x80, 0x30, 0xF2, 0x0C,
    0x6A, 0x42, 0xB7, 0x3B,
    0xBE, 0xAC, 0x01, 0xFA
};


typedef enum {
    MULTI_TENANT_PROTOCOL_NONE = 0,
    MULTI_TENANT_PROTOCOL_QINQ = 1,
    MULTI_TENANT_PROTOCOL_VXLAN = 2,
} ppr_multi_tenant_protocol_t;

/* -------------------------------------------- Flow Key Structs ------------------------------------------------- */

//L2 flow key for L2 (Non IP) Flow Tables
typedef struct ppr_l2_flow_key {
    uint32_t tenant_id;   // same concept as IP table

    uint16_t in_port;     // ingress port id
    uint16_t outer_vlan;  // 0 if absent
    uint16_t inner_vlan;  // 0 if absent (QinQ)
    uint16_t ether_type;  // outer or inner, depending on your design

    struct rte_ether_addr src;
    struct rte_ether_addr dst;

    uint32_t hash;        // precomputed signature if you want it here too
} ppr_l2_flow_key_t __rte_aligned(8);


//ipv4 flow key 
typedef struct ppr_flow_key_v4{
    uint32_t src_ip;   // be32
    uint32_t dst_ip;   // be32
    uint16_t src_port; // be16
    uint16_t dst_port; // be16
    uint8_t  proto;    // IPPROTO_*
    uint8_t  _pad[3];  // keep alignment (explicit)
} ppr_flow_key_v4_t __rte_aligned(8);


//ipv6 flow key
typedef struct ppr_flow_key_v6{
    uint8_t  src_ip[16]; // raw bytes (network order)
    uint8_t  dst_ip[16]; // raw bytes (network order)
    uint16_t src_port;   // be16
    uint16_t dst_port;   // be16 
    uint8_t  proto;      // IPPROTO_*
    uint8_t  _pad[1];    // keep alignment
} ppr_flow_key_v6_t __rte_aligned(8);


// Unify v4/v6: we store family + union
// Family is AF_INET / AF_INET6 
typedef struct ppr_flow_key{
    uint32_t tenant_id;  
    uint8_t  family;     
    uint8_t  _pad0[3];

    union {
        ppr_flow_key_v4_t v4;
        ppr_flow_key_v6_t v6;
    } ip;

    uint32_t hash; 
    uint32_t _pad1;
} ppr_flow_key_t __rte_aligned(8);

//calculate max key size 
#define PPR_FT_MAX_KEY_SIZE \
    (sizeof(ppr_flow_key_t) > sizeof(ppr_l2_flow_key_t) ? \
        sizeof(ppr_flow_key_t) : sizeof(ppr_l2_flow_key_t))


/* -------------------------------------------- Flow Action / Payload Structs ------------------------------------------------- */

//Flow action struct, kind + parameters + target ID's
typedef struct ppr_flow_action {
    uint8_t                 kind;            // action enum (above)
    uint8_t                 flags;           // e.g., “mirror aso follows primary”, “defer free”
    uint16_t                reserved;        //reserved for future use
    uint16_t                cookie;          // user/debug id or policy id
    uint8_t                 egress_target_count; // number of valid egress targets
    uint16_t                egress_port_ids[PPR_MAX_EGRESS_TARGETS]; // port id to forward packet for non inspection
} ppr_flow_action_t __rte_aligned(16);
_Static_assert(sizeof(ppr_flow_action_t) <= 16, "flow_action should stay compact");


//Per LCore hotpath Stats Struct
typedef struct ppr_flow_stats_hot {
    /* 16B: counters updated *every packet* by this lcore */
    uint64_t pkts;
    uint64_t bytes;
    uint32_t drops;                    // if action implies drop on congestion

    /* 20B: size histogram (per-lcore) */
    uint32_t sz_bins[FLOW_SIZE_BINS];  // e.g., [0..63], [64..511], [512..1023], [1024..9K], [>9K]
    uint32_t ns_bins[FLOW_SIZE_BINS];  // e.g., [< 1ms], [1ms - 10ms], [10ms - 100ms], [100ms-1s], [>1s]
    
    uint32_t last_update_cycles;       // optional (rdtsc masked down)
} ppr_flow_stats_hot_t __rte_aligned(RTE_CACHE_LINE_SIZE);
_Static_assert(sizeof(ppr_flow_stats_hot_t) == RTE_CACHE_LINE_SIZE, "hot stats must be one cache line");


//cold stats for stats accumulation, not touched by rx path 
typedef struct ppr_flow_stats_cold{
    uint64_t pkts;
    uint64_t bytes;
    uint64_t drops;
    uint64_t sz_bins[FLOW_SIZE_BINS];

    uint64_t last_pkts_cnt;
} ppr_flow_stats_cold_t;

typedef struct ppr_time_bins_cycles {
    uint32_t c_1ms;
    uint32_t c_10ms;
    uint32_t c_100ms;
    uint32_t c_1s;
} ppr_time_bins_cycles_t;


/* --------------------------- Top Level Flow Table Entry ------------------------------------------------- */

//flow table entry status enum
enum {
    FLOWF_ESTABLISHED  = 1u << 0,
    FLOWF_AGING_LOCKED = 1u << 1,
    FLOWF_SHADOW       = 1u << 2,
    FLOWF_HIT          = 1u << 3,
    FLOWF_INVALID      = 1u << 4
};


//Top level flow table entry
//keep hot and cold data separated for cache efficiency
//hot data first 
typedef struct ppr_flow_entry{
    /* ---- Hot region (first cache lines) ---- */
    union {
        ppr_flow_key_t    ip_key;     // helper view when key_kind == PPR_FT_KEY_IP
        ppr_l2_flow_key_t l2_key;     // helper view when key_kind == PPR_FT_KEY_L2
        uint8_t           raw[PPR_FT_MAX_KEY_SIZE];
    } key;
    ppr_flow_action_t           act;           // action is read on fast path
    ppr_global_policy_epoch_t   policy_epoch;  // policy epoch at install time
    uint8_t                     state_flags;
    uint8_t                     authored_stage;
    uint16_t                    shard_id;
    uint32_t                    user_tag;
    uint16_t                    owned_port_id;
    uint16_t                    _hot_pad;

    /* Per-lcore 64B stats array (L elements), cache-line aligned */
    ppr_flow_stats_hot_t *stats_hot;

    /* ---- Cold region (rarely touched in RX loop) ---- */
    //stats accumulated from hot stats periodically
    uint16_t                thread_index;   //worker thread that created this flow
    bool                    valid;            
    ppr_flow_stats_cold_t   stats_cold;  

    //acl policy index if applicable
    ppr_acl_runtime_t       *acl_runtime_ctx;
    uint32_t                acl_policy_index;
    ppr_l3_t                acl_l3_type;

    //lifetime and timeout values
    uint64_t                install_ns;
    uint64_t                last_seen_ns;
    uint32_t                last_seen_cycles_low32;
    uint32_t                idle_timeout_ms;
    uint32_t                lifetime_ms;
    uint32_t                refcnt;
    uint32_t                _cold_pad;
} ppr_flow_entry_t __rte_aligned(RTE_CACHE_LINE_SIZE);


/* -------------------------------------------- Per Worker / LCore helper Functions ------------------------------------------------- */

/** 
* Get flow size bin index for a given packet length
* @param len
*   Packet length in bytes
* @return
*   Flow size bin index
**/
static inline uint32_t ppr_flow_bin_index(uint32_t len)
{
    return (len <= 63)   ? 0 :
           (len <= 511)  ? 1 :
           (len <= 1023) ? 2 :
           (len <= 9216) ? 3 : 4;
}

/**
 * Update hot stats for a given packet length
 * @param s
 *   Pointer to the hot stats structure
 * @param len
 *   Packet length in bytes
 **/
static inline void ppr_flow_stats_hot_update(ppr_flow_stats_hot_t *s, uint32_t len, uint64_t now_tsc, const ppr_time_bins_cycles_t *tb)
{
    atomic_fetch_add_explicit(&s->pkts, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&s->bytes, len, memory_order_relaxed);
    atomic_fetch_add_explicit(&s->sz_bins[ppr_flow_bin_index(len)], 1, memory_order_relaxed);

    //<TODO> is 2^32 sufficent for time bins? should we use 64 bit last update?    
    if (likely(s->last_update_cycles != 0)) {
        /* 32-bit delta, wrap-safe as long as intervals < 2^32 cycles */
        uint32_t delta = (uint32_t)now_tsc - s->last_update_cycles; 
        uint32_t bin;
        if (delta < tb->c_1ms) {
            bin = 0;            /* < 1ms */
        } else if (delta < tb->c_10ms) {
            bin = 1;            /* 1ms - 10ms */
        } else if (delta < tb->c_100ms) {
            bin = 2;            /* 10ms - 100ms */
        } else if (delta < tb->c_1s) {
            bin = 3;            /* 100ms - 1s */
        } else {
            bin = 4;            /* > 1s */
        }   
        atomic_fetch_add_explicit(&s->ns_bins[bin], 1, memory_order_relaxed);
    }
    atomic_store_explicit(&s->last_update_cycles, (uint32_t)(now_tsc & 0xFFFFFFFFu), memory_order_relaxed);
}

static inline bool ppr_seq32_after(uint32_t a, uint32_t b)
{   
    PPR_DP_LOG(PPR_LOG_FLOW, RTE_LOG_DEBUG, "Comparing seq32: a=%u, b=%u, result=%d\n", a, b, (int32_t)(a - b) > 0);
    return (int32_t)(a - b) > 0;
}

/* -------------------------------------------- Flow Table Config Structs and Access ------------------------------------------------- */


/** indirect action pointer handle for atomic updates 
* @note: ptr must be atomic to allow safe concurrent updates
*        worker / readers hold long lived pointers to indirect handles, but load actual entries with atomic load 
         for micro updates (e.g. updating an existing flow entries rule), writers can atomically swap out the entry pointer.
         for macro changes, e.g., deleting a flow entry, the writer can mark the entry invalid and later retire the handle via QSBR 

         Writers (e.g. flow manager): 
            - always use atomic_exchange_explicit to modify 
            - always set entry to null before freeing handle (readers may still hold handle)
            - writers free handles via QSBR defer queue
        Readers (e.g. datapath workers):
            - must call QSBR registration / init functions as well as periodic idle calls
            - Inspect and honor null pointers (entry deleted) to remove local cached references
**/
typedef struct ppr_ft_indr_entry_handle{
    _Atomic(ppr_flow_entry_t *) ptr;
} ppr_ft_indr_entry_handle_t;



//flow table config struct, populated in main, passed into init function 
typedef struct ppr_ft_cfg{
    const char     *name;
    uint8_t        log_level;
    uint32_t       entries;                /* expected max flows (size hint) */
    int            socket_id;
    int            shards;                 /* 1, 2, 4, 8… (power of two); use >1 to reduce metadata contention */
    int            num_reader_threads;
    ft_hash_type_t hash_algo;

    //support L2 vs IPV4/6 Keys
    ppr_ft_key_kind_t        key_kind;    
    uint16_t                 key_size;    

    ppr_global_policy_epoch_t   *policy_epochs;
    bool                        enable_multi_tenancy;
    ppr_multi_tenant_protocol_t multi_tenant_protocol;
    uint32_t                    default_lifetime_ms;
    uint32_t                    default_idle_timeout_ms;

    int qsbr_reclaim_limit;
    int qsbr_max_reclaim_size;
} ppr_ft_cfg_t;


/* ---------- struct for holding small L1 cache per lcore of action information ---------- */
typedef struct ppr_ft_lcache_entry{
    uint8_t                   key_bytes[PPR_FT_MAX_KEY_SIZE];  // opaque key
    ppr_ft_indr_entry_handle_t   *h;
} ppr_ft_lcache_entry_t;

//per lcore key/action pair caches
RTE_DECLARE_PER_LCORE(ppr_ft_lcache_entry_t, l1)[PPR_L1_CACHE_SIZE];

/* ---------- Struct to support sharding of hash table if lcores are working on flow aware input queues ---------- */
typedef struct ppr_ft_shard{
    char   name[64];
    struct rte_hash *h;
} ppr_ft_shard_t __rte_aligned(RTE_CACHE_LINE_SIZE);

/* ---------- Struct for main flow table access and confguration ---------- */
typedef struct ppr_flow_table{
    ppr_ft_cfg_t                cfg;
    uint8_t                     log_level;
    unsigned int                shards;
    ppr_ft_shard_t              *s; /* [shards] */
    ppr_global_policy_epoch_t   *policy_epochs;
    bool                        enable_multi_tenancy;
    ppr_multi_tenant_protocol_t multi_tenant_protocol;
    ppr_time_bins_cycles_t      time_bins;
    uint32_t                    default_lifetime_ms;
    uint32_t                    default_idle_timeout_ms;

    ppr_ft_key_kind_t           key_kind; 
    uint16_t                    key_size;
   

    //per shard stats 
    _Atomic uint64_t            *shard_new_flows;                         //increment by workers
    uint64_t                    *shard_total_flows;                 
    uint64_t                    *shard_active_flows;          
    uint64_t                    *shard_evicted_flows; 
    uint64_t                    *shard_invalidated_evicted_flows;
    uint64_t                    *shard_timeout_evicted_flows;    
    uint64_t                    *shard_lifetime_evicted_flows;    
    uint64_t                    *shard_acl_policy_epoch_evicted_flows;          

    //global flow table stats
    uint64_t                    total_flows;    
    uint64_t                    total_active_flows;
    uint64_t                    total_flows_evicted;   
    uint64_t                    total_invalidated_evicted_flows;                 
    uint64_t                    total_timeout_evicted_flows;           
    uint64_t                    total_lifetime_evicted_flows;                
    uint64_t                    total_acl_policy_epoch_evicted_flows;    

    //qsbr manager struct
    ppr_rcu_ctx_t           *rcu_ctx;
    struct rte_rcu_qsbr_dq  *dq;
    
    // [shards], used with rte_hash_iterate
    uint32_t                *shard_walk_iter;   
} ppr_flow_table_t;

/* ---------- Lifecycle ---------- */
ppr_flow_table_t *ppr_ft_create(const ppr_ft_cfg_t *cfg,ppr_rcu_ctx_t *rcu_ctx);
void ppr_ft_destroy(ppr_flow_table_t *ft);
void ppr_ft_reclaim_actions(ppr_flow_table_t *ft);

/* ---------- lookup (readers) ------------------*/
const ppr_flow_entry_t *ppr_ft_lookup(const ppr_flow_table_t *ft, const void *key);
const ppr_flow_entry_t *ppr_ft_lookup_prehash(const ppr_flow_table_t *ft, const void *key, uint32_t sig);

/* ---------- Updates (control-plane) ---------- */
/* Insert: returns 0 on insert; -EEXIST if already present */
int ppr_ft_add(ppr_flow_table_t *ft, const void *key, const ppr_flow_entry_t *entry, uint64_t tsc_ns, const ppr_flow_entry_t **opt_existing_entry);
int ppr_ft_append(ppr_flow_table_t *ft, const void *k, const ppr_flow_entry_t *entry_a, uint64_t tsc_ns);

/* Upsert: replace or add; returns 0, sets *old_entry if replaced (may be NULL). */
int ppr_ft_replace(ppr_flow_table_t *ft, const void *key, const ppr_flow_entry_t *new_entry, ppr_flow_entry_t **old_entry);

/* Delete: returns 0 if removed; -ENOENT if missing. */
int ppr_ft_del(ppr_flow_table_t *ft, const void *key);

/* Walk: walk the hash table(s) and perform maintenance */
void ppr_flowtable_walker(ppr_flow_table_t *ft, uint64_t now_ns, uint32_t max_walks_per_call);

/* print debug stats */
void ppr_ft_print_stats(const ppr_flow_table_t *ft);

/** 
* Clear per-lcore flow table lookup cache
**/
static inline void ppr_ft_reader_clear_cache(){
    // Clear L1 cache for this lcore after each idle mark
    ppr_ft_lcache_entry_t *local_l1 = RTE_PER_LCORE(l1);
    for (uint32_t i = 0; i < PPR_L1_CACHE_SIZE; i++) {
        local_l1[i].h = NULL;
    }   
} 

/* ---------- Helpers functions ---------- */

/**
* Compute the flow key signature hash value
* @param ft
*   Pointer to flow table structure
* @param key
*   Pointer to flow key structure
* @return
*   Computed signature hash value
**/
static inline uint32_t ppr_ft_key_sig(const ppr_flow_table_t *ft, const void *key)
{
    if (ft->key_kind == PPR_FT_KEY_IP) {
        const ppr_flow_key_t *k = key;
        return k->hash;
    } else {
        const ppr_l2_flow_key_t *k = key;
        return k->hash;
    }
}

/** 
* Get pointer to flow key within flow entry
* @param ft
*   Pointer to flow table structure
* @param fe
*   Pointer to flow entry structure
* @return
*   Pointer to flow key structure
**/
static inline const void *ppr_ft_entry_key_ptr(const ppr_flow_table_t *ft, const ppr_flow_entry_t *fe)
{
    if (ft->key_kind == PPR_FT_KEY_L2)
        return &fe->key.l2_key;
    else
        return &fe->key.ip_key;
}


/**  
* init histogram bins for flow hotstats 
* @param tb
*   Pointer to time bins struct
* @param tsc_hz
*   TSC frequency in Hz
**/
static inline void ppr_time_bins_init(ppr_time_bins_cycles_t *tb, uint64_t tsc_hz)
{   
    //initialize in ns 
    tb->c_1ms   = (uint32_t)(tsc_hz / 1000ULL);  // 1ms
    tb->c_10ms  = (uint32_t)(tsc_hz / 100ULL);   // 10ms
    tb->c_100ms = (uint32_t)(tsc_hz / 10ULL);    // 100ms
    tb->c_1s    = (uint32_t)(tsc_hz);            // 1s
}

/** 
* Compare two flow keys for equality
* @param a
*   Pointer to first flow key structure
* @param b
*   Pointer to second flow key structure
* @return
*   1 if equal, 0 if not equal
**/
static inline int ppr_flow_key_equal(const ppr_flow_table_t *ft,
                                     const void *a_key,
                                     const void *b_key)
{
    if (ft->key_kind == PPR_FT_KEY_L2) {
        const ppr_l2_flow_key_t *a = (const ppr_l2_flow_key_t *)a_key;
        const ppr_l2_flow_key_t *b = (const ppr_l2_flow_key_t *)b_key;

        if (a->tenant_id  != b->tenant_id  ||
            a->in_port    != b->in_port    ||
            a->outer_vlan != b->outer_vlan ||
            a->inner_vlan != b->inner_vlan ||
            a->ether_type != b->ether_type)
            return 0;

        return rte_is_same_ether_addr(&a->src, &b->src) &&
               rte_is_same_ether_addr(&a->dst, &b->dst);
    } else { // IP table
        const ppr_flow_key_t *a = (const ppr_flow_key_t *)a_key;
        const ppr_flow_key_t *b = (const ppr_flow_key_t *)b_key;

        if (a->tenant_id != b->tenant_id || a->family != b->family)
            return 0;

        if (a->family == AF_INET) {
            const ppr_flow_key_v4_t *x = &a->ip.v4;
            const ppr_flow_key_v4_t *y = &b->ip.v4;
            return x->src_ip   == y->src_ip   &&
                   x->dst_ip   == y->dst_ip   &&
                   x->src_port == y->src_port &&
                   x->dst_port == y->dst_port &&
                   x->proto    == y->proto;
        } else { // AF_INET6
            const ppr_flow_key_v6_t *x = &a->ip.v6;
            const ppr_flow_key_v6_t *y = &b->ip.v6;
            const uint64_t *xs = (const uint64_t *)x->src_ip;
            const uint64_t *xd = (const uint64_t *)x->dst_ip;
            const uint64_t *ys = (const uint64_t *)y->src_ip;
            const uint64_t *yd = (const uint64_t *)y->dst_ip;

            return xs[0] == ys[0] && xs[1] == ys[1] &&
                   xd[0] == yd[0] && xd[1] == yd[1] &&
                   x->src_port == y->src_port &&
                   x->dst_port == y->dst_port &&
                   x->proto    == y->proto;
        }
    }
}

/* ---------- static inlined lookup functions -------------- */


/** 
* Compute the RSS hash for a given IPv4 flow key    
* @param k
*   Pointer to IPv4 flow key structure
* @param rss_key
*   Pointer to RSS key byte array
* @return
*   Computed RSS hash value
**/
static inline uint32_t ppr_ft_rss_hash_v4(const ppr_flow_key_v4_t *k, const uint8_t *rss_key)
{
    uint32_t w[4];

    w[0] = k->src_ip; /* be32 */
    w[1] = k->dst_ip; /* be32 */

    /* pack be16 ports into be32 */
    uint32_t ports = ((uint32_t)k->src_port << 16) | (uint32_t)k->dst_port;
    w[2] = ports; /* this is correct BE layout if src_port/dst_port are be16 */

    /* proto as be32 with proto in MSB */
    w[3] = rte_cpu_to_be_32((uint32_t)k->proto << 24);

    return rte_softrss_be(w, RTE_DIM(w), rss_key);
}

/**
* Compute the RSS hash for a given IPv6 flow key    
* @param k
*   Pointer to IPv6 flow key structure
* @param rss_key
*   Pointer to RSS key byte array
* @return
*   Computed RSS hash value
**/
static inline uint32_t ppr_ft_rss_hash_v6(const ppr_flow_key_v6_t *k, const uint8_t *rss_key)
{
    uint32_t w[11];

    /* src (16B) -> 4x32 */
    rte_memcpy(&w[0], k->src_ip, 16);
    /* dst (16B) -> 4x32 */
    rte_memcpy(&w[4], k->dst_ip, 16);

    /* ports -> one 32-bit word in network order */
    uint32_t ports = ((uint32_t)k->src_port << 16) | (uint32_t)k->dst_port;
    w[8] = ports; /* src_port/dst_port are already be16, so this is already BE layout */

    /* proto in top byte (BE) */
    w[9] = rte_cpu_to_be_32((uint32_t)k->proto << 24);

    w[10] = 0;

    return rte_softrss_be(w, RTE_DIM(w), rss_key);
}

/** 
* Compute the key hash for a given flow key
* @param ft
*   Pointer to flow table structure
* @param k
*   Pointer to flow key structure
* @return
*   Computed hash value 
**/

static inline uint32_t ppr_ft_tuple_hash(const ppr_flow_table_t *ft, const void *key)
{
    if (ft->cfg.hash_algo == FT_HASH_RSS && ft->cfg.key_kind == PPR_FT_KEY_IP) {
        const ppr_flow_key_t *k = (const ppr_flow_key_t *)key;
        return (k->family == AF_INET6)
             ? ppr_ft_rss_hash_v6(&k->ip.v6, default_rss_key)
             : ppr_ft_rss_hash_v4(&k->ip.v4, default_rss_key);
    }

    // All CRC paths: NEVER include the hash field itself
    if (ft->cfg.key_kind == PPR_FT_KEY_IP) {
        size_t len = offsetof(ppr_flow_key_t, hash);        // everything before hash
        return rte_hash_crc(key, len, 0);
    } else { // PPR_FT_KEY_L2
        size_t len = offsetof(ppr_l2_flow_key_t, hash);     // everything before hash
        return rte_hash_crc(key, len, 0);
    }
}

static inline uint32_t ppr_mix32(uint32_t x)
{
    x ^= x >> 16;
    x *= 0x7feb352d;
    x ^= x >> 15;
    x *= 0x846ca68b;
    x ^= x >> 16;
    return x;
}

static inline uint32_t ppr_sig_from_pkt_hash(uint32_t pkt_hash,
                                             uint32_t tenant_id,
                                             uint8_t family)
{
    uint32_t x = pkt_hash ^ (tenant_id * 0x9e3779b1u) ^ ((uint32_t)family << 24);
    return ppr_mix32(x);
}

static inline uint32_t ppr_ft_sig_from_hdrs(const ppr_flow_table_t *ft,
                                           const void *key,
                                           uint32_t tenant_id,
                                           uint32_t base_hash,   /* hdrs->pkt_hash */
                                           bool hash_valid,
                                           uint32_t discrim)     /* family for IP, ethertype for L2 */
{
    /* If we have a valid NIC hash and we’re in RSS mode, use it as the base */
    if (hash_valid && ft->cfg.hash_algo == FT_HASH_RSS) {
        uint32_t x = base_hash ^ (tenant_id * 0x9e3779b1u) ^ (discrim * 0x85ebca6bu);
        /* If NOT multi-tenant, tenant_id is 0, so this still behaves fine */
        return ppr_mix32(x);
    }

    /* Otherwise compute a real hash from the key bytes (CRC or softrss) */
    return ppr_ft_tuple_hash(ft, key);
}


/**
* Mark a flow entry as logically invalid 
* @param fe
*   Pointer to flow entry structure
* @return
*   true if the entry was transitioned from valid to invalid, false if it was already invalid
**/
static inline bool ppr_ft_entry_mark_invalid(ppr_flow_entry_t *fe)
{
    /* Return true if we transitioned from *not* invalid to invalid */
    uint8_t old = __atomic_fetch_or(&fe->state_flags, FLOWF_INVALID,__ATOMIC_RELAXED);
    return !(old & FLOWF_INVALID);
}


/** 
* Build a L2 flow table key from a packet headers structure
* @param ft
*   Pointer to flow table structure
* @param hdrs
*   Pointer to packet headers structure
* @param key
*   Pointer to L2 flow key structure to populate
* @return
*   0 on success, negative errno on failure
**/
static inline int ppr_l2_flowkey_from_hdr(const ppr_flow_table_t *ft,
                                          const ppr_hdrs_t *hdrs,
                                          ppr_l2_flow_key_t *key,
                                          bool use_precalc_sig,
                                          uint32_t sig)
{

    memset(key, 0, sizeof(*key));

    uint32_t tenant_id = 0;

    if (ft->enable_multi_tenancy) {
        if (ft->multi_tenant_protocol == MULTI_TENANT_PROTOCOL_QINQ) {
            if (hdrs->vlan_count == 2)
                tenant_id = hdrs->vlan[0].vid;
        } else if (ft->multi_tenant_protocol == MULTI_TENANT_PROTOCOL_VXLAN) {
            if (hdrs->vxlan_present)
                tenant_id = hdrs->vxlan_vni;
        }
    }

    key->tenant_id  = tenant_id;
    key->in_port    = hdrs->ingress_port_id;        // or hdrs->input_port_id
    key->outer_vlan = hdrs->vlan_count > 0 ? hdrs->vlan[0].vid : 0;
    key->inner_vlan = hdrs->vlan_count > 1 ? hdrs->vlan[1].vid : 0;
    key->ether_type = hdrs->ether_type;     // whatever you already parsed

    key->src = hdrs->src_mac;
    key->dst = hdrs->dst_mac;

    //decide were to get the hash signature 
    key->hash = use_precalc_sig ? sig : ppr_ft_sig_from_hdrs(ft, key, key->tenant_id, hdrs->pkt_hash, hdrs->hash_valid, (uint32_t)key->ether_type);



    return 0;
}


/** 
* Build a flow table key from a packet headers structure
* @param ft
*   Pointer to flow table structure
* @param hdrs
*   Pointer to packet headers structure
* @param key
*   Pointer to flow key structure to populate
* @return
*   0 on success, negative errno on failure 
**/
static inline int
ppr_flowkey_from_hdr(ppr_flow_table_t *ft,
                     const ppr_hdrs_t *hdrs,
                     ppr_flow_key_t *key,
                     bool use_precalc_sig,
                     uint32_t sig)
{
    if (hdrs->l3_type == PPR_L3_NONE)
        return -1;

    // Zero the key – we’ll fill every field we care about.
    // (You can drop this later if you guarantee no padding is hashed.)
    memset(key, 0, sizeof(*key));

    uint32_t tenant_id = 0;

    /* ---------- Multi-tenant selection (QinQ / VXLAN) ---------- */
    if (ft->enable_multi_tenancy) {
        if (ft->multi_tenant_protocol == MULTI_TENANT_PROTOCOL_QINQ &&
            hdrs->vlan_count == 2) {
            tenant_id = hdrs->vlan[0].vid;
        } else if (ft->multi_tenant_protocol == MULTI_TENANT_PROTOCOL_VXLAN &&
                   hdrs->vxlan_present) {
            tenant_id = hdrs->vxlan_vni;
        }
    }

    /* ---------- IPv4 path (no IPv6 memcpy at all) ---------- */
    if (hdrs->l3_type == PPR_L3_IPV4) {
        uint32_t src_ip = hdrs->outer_ipv4_src;
        uint32_t dst_ip = hdrs->outer_ipv4_dst;
        uint16_t src_port = hdrs->outer_l4_src_port;
        uint16_t dst_port = hdrs->outer_l4_dst_port;
        uint8_t  proto    = hdrs->outer_ipv4_protocol;

        if (ft->enable_multi_tenancy &&
            ft->multi_tenant_protocol == MULTI_TENANT_PROTOCOL_VXLAN &&
            hdrs->vxlan_present) {
            // For VXLAN, override with inner headers
            src_ip   = hdrs->inner_ipv4_src;
            dst_ip   = hdrs->inner_ipv4_dst;
            src_port = hdrs->inner_l4_src_port;
            dst_port = hdrs->inner_l4_dst_port;
            proto    = hdrs->inner_ipv4_protocol;
        }

        key->family             = AF_INET;
        key->tenant_id          = tenant_id;
        key->ip.v4.src_ip       = src_ip;
        key->ip.v4.dst_ip       = dst_ip;
        key->ip.v4.src_port     = src_port;
        key->ip.v4.dst_port     = dst_port;
        key->ip.v4.proto        = proto;

        goto compute_hash;
    }

    /* ---------- IPv6 path ---------- */
    if (hdrs->l3_type == PPR_L3_IPV6) {
        const uint8_t *src_ip = hdrs->outer_ipv6_src;
        const uint8_t *dst_ip = hdrs->outer_ipv6_dst;
        uint16_t src_port     = hdrs->outer_l4_src_port;
        uint16_t dst_port     = hdrs->outer_l4_dst_port;
        uint8_t  proto        = hdrs->outer_ipv6_protocol;

        if (ft->enable_multi_tenancy &&
            ft->multi_tenant_protocol == MULTI_TENANT_PROTOCOL_VXLAN &&
            hdrs->vxlan_present) {
            src_ip   = hdrs->inner_ipv6_src;
            dst_ip   = hdrs->inner_ipv6_dst;
            src_port = hdrs->inner_l4_src_port;
            dst_port = hdrs->inner_l4_dst_port;
            proto    = hdrs->inner_ipv6_protocol;
        }

        key->family         = AF_INET6;
        key->tenant_id      = tenant_id;
        memcpy(key->ip.v6.src_ip, src_ip, 16);
        memcpy(key->ip.v6.dst_ip, dst_ip, 16);
        key->ip.v6.src_port = src_port;
        key->ip.v6.dst_port = dst_port;
        key->ip.v6.proto    = proto;

        goto compute_hash;
    }

    // Unsupported l3 type
    return -1;

compute_hash:
    key->hash = use_precalc_sig ? sig : ppr_ft_sig_from_hdrs(ft, key, key->tenant_id, hdrs->pkt_hash, hdrs->hash_valid, (uint32_t)key->family);

    return 0;
}

/** 
* Compute the shard ID for a given signature
* @param ft
*   Pointer to flow table structure
* @param sig
*   Signature hash value
* @return
*   Shard ID (0 .. shards-1)
**/
static inline uint32_t ppr_ft_shard_id(const ppr_flow_table_t *ft, uint32_t sig) {
    //shard index comes from the lowest bits of the signature, depends on number of total shards
    return (sig & (ft->shards - 1));
}



/**
* Check if a flow entry's policy epoch is current, only flag invalid if relevant policy changed
* @param ft
*   Pointer to flow table structure
* @param fe
*   Pointer to flow entry structure
* @return
**/
static inline int ppr_ft_check_entry_epoch(ppr_flow_table_t *ft, const ppr_flow_entry_t *fe){
    ppr_global_policy_epoch_t current_epoch;
    current_epoch.acl_policy_epoch = atomic_load_explicit(&ft->policy_epochs->acl_policy_epoch, memory_order_relaxed);

    //if acl policy changed, invalidate flow
    if (fe->policy_epoch.acl_policy_epoch != current_epoch.acl_policy_epoch) {
        PPR_LOG(PPR_LOG_FLOW, RTE_LOG_DEBUG, "Flow entry acl policy epoch mismatch: flow epoch=%lu, current epoch=%lu\n",
                fe->policy_epoch.acl_policy_epoch, current_epoch.acl_policy_epoch);
        return -3; //epoch mismatch
    }


    return 0;
}


/* ----------------------------------------- Flowtable Display / Debug Functions --------------------------------*/

/** 
* Debug print a flow key
* @param ft
*   Pointer to flow table structure
* @param k
*   Pointer to flow key structure   
**/
static inline void ppr_flow_key_debug(const ppr_flow_table_t *ft, const void *keyp)
{
    if (ft->log_level < RTE_LOG_DEBUG)
        return;

    if (!keyp) {
        PPR_LOG(PPR_LOG_FLOW, RTE_LOG_DEBUG, "flowkey: (null)\n");
        return;
    }

    if (ft->key_kind == PPR_FT_KEY_L2) {
        const ppr_l2_flow_key_t *k = (const ppr_l2_flow_key_t *)keyp;

        char src[RTE_ETHER_ADDR_FMT_SIZE];
        char dst[RTE_ETHER_ADDR_FMT_SIZE];
        rte_ether_format_addr(src, sizeof(src), &k->src);
        rte_ether_format_addr(dst, sizeof(dst), &k->dst);

        PPR_LOG(PPR_LOG_FLOW, RTE_LOG_DEBUG,
                "L2 flowkey: tenant=%u in_port=%u outer_vlan=%u "
                "inner_vlan=%u ethertype=0x%04x %s -> %s hash=0x%08x\n",
                k->tenant_id,
                k->in_port,
                k->outer_vlan,
                k->inner_vlan,
                k->ether_type,
                src,
                dst,
                k->hash);
        return;
    }
    const ppr_flow_key_t *k = (const ppr_flow_key_t *)keyp;
    const char *fam_str = "UNK";

    if (k->family == AF_INET) {
        fam_str = "IPv4";

        char src_str[INET_ADDRSTRLEN];
        char dst_str[INET_ADDRSTRLEN];
        struct in_addr src4, dst4;

        src4.s_addr = k->ip.v4.src_ip; // already be32 (network)
        dst4.s_addr = k->ip.v4.dst_ip;

        if (!inet_ntop(AF_INET, &src4, src_str, sizeof(src_str)))
            snprintf(src_str, sizeof(src_str), "??");
        if (!inet_ntop(AF_INET, &dst4, dst_str, sizeof(dst_str)))
            snprintf(dst_str, sizeof(dst_str), "??");

        uint16_t sport = rte_be_to_cpu_16(k->ip.v4.src_port);
        uint16_t dport = rte_be_to_cpu_16(k->ip.v4.dst_port);
        uint8_t  proto = k->ip.v4.proto;

        PPR_LOG(PPR_LOG_FLOW, RTE_LOG_DEBUG,
                "flowkey: tenant=%u fam=%s proto=%s(%u) "
                "%s:%u -> %s:%u hash=0x%08x\n",
                k->tenant_id,
                fam_str,
                ppr_proto_to_str(proto), proto,
                src_str, sport,
                dst_str, dport,
                k->hash);

    } else if (k->family == AF_INET6) {
        fam_str = "IPv6";

        char src_str[INET6_ADDRSTRLEN];
        char dst_str[INET6_ADDRSTRLEN];

        if (!inet_ntop(AF_INET6, k->ip.v6.src_ip, src_str, sizeof(src_str)))
            snprintf(src_str, sizeof(src_str), "??");
        if (!inet_ntop(AF_INET6, k->ip.v6.dst_ip, dst_str, sizeof(dst_str)))
            snprintf(dst_str, sizeof(dst_str), "??");

        uint16_t sport = rte_be_to_cpu_16(k->ip.v6.src_port);
        uint16_t dport = rte_be_to_cpu_16(k->ip.v6.dst_port);
        uint8_t  proto = k->ip.v6.proto;

        PPR_LOG(PPR_LOG_FLOW, RTE_LOG_DEBUG,
                "flowkey: tenant=%u fam=%s proto=%s(%u) "
                "%s:%u -> %s:%u hash=0x%08x\n",
                k->tenant_id,
                fam_str,
                ppr_proto_to_str(proto), proto,
                src_str, sport,
                dst_str, dport,
                k->hash);

    } else {
        PPR_LOG(PPR_LOG_FLOW, RTE_LOG_DEBUG,
                "flowkey: tenant=%u fam=%u (unknown) hash=0x%08x\n",
                k->tenant_id,
                (unsigned)k->family,
                k->hash);
    }
}

static inline void atomic_dec_if_nonzero_u64(_Atomic uint64_t *p)
{
    uint64_t old = atomic_load_explicit(p, memory_order_relaxed);

    while (old != 0) {
        uint64_t desired = old - 1;
        if (atomic_compare_exchange_weak_explicit(
                p,
                &old,           // updated with current value if CAS fails
                desired,
                memory_order_relaxed,
                memory_order_relaxed)) {
            // Success: we decremented from non-zero to desired
            break;
        }
        // CAS failed: 'old' has been updated to the current value.
        // Loop again; if it’s now 0, we’ll exit without decrementing.
    }
}

#endif
