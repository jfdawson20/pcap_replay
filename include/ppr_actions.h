/*
SPDX-License-Identifier: MIT
Copyright (c) 2025 jfdawson20

Filename: ppr_actions.h
Description: header file containing app wide constants and structs around flow actions and global policies. 

*/
#include <netinet/in.h>
#include <rte_ether.h>

#include "ppr_log.h"

#ifndef PPR_ACTIONS_H
#define PPR_ACTIONS_H

/* max ports to forward to in one action */
//note this value has dependencies on flow table entry struct size and alignment
//4 was chosen to fit into a cache line while providing max flexability
#define PPR_MAX_EGRESS_TARGETS 4 

//forward delclarations
typedef struct ppr_lb_group        ppr_lb_group_t;

//enum for hash type
typedef enum {
    FT_HASH_CRC32 = 0,
    FT_HASH_RSS   = 1,
} ft_hash_type_t;

typedef enum {
    PPR_FT_KEY_IP  = 0,
    PPR_FT_KEY_L2  = 1,
} ppr_ft_key_kind_t;


//Enum for flow action kinds - keep < 8 bits
typedef enum ppr_flow_action_kind {
    FLOW_ACT_NOOP         = 0, //no action taken yet
    FLOW_ACT_DROP         = 1, //drop packet
    FLOW_ACT_FWD_PORT     = 2, //forward to port/ring
    FLOW_ACT_FWD_LB       = 3, //forward to load balanced port group
    FLOW_ACT_FWD_LB_PORT  = 4, //forward to load balanced port group and specified egress ports 
    FLOW_ACT_MAX_
} ppr_flow_action_kind_t;


typedef struct ppr_policy_action {
    bool                    hit;            //indicates if a rule was matched
    uint32_t                idx; 
    uint32_t                priority;
    ppr_flow_action_kind_t  default_policy;
    uint8_t                 egress_target_count;
    uint16_t                egress_port_ids[PPR_MAX_EGRESS_TARGETS]; //default egress ports for this policy entry
    uint8_t                 lb_groups_count; 
    uint16_t                lb_group_ids[PPR_MAX_EGRESS_TARGETS]; //load balancer groups associated with this policy entry
} ppr_policy_action_t;


// enum for action decisions 
typedef enum {
    PPR_DEF_EGRESS_LKP_COMPLETED = 0x1,
    PPR_DEF_FRAG_LKP_COMPLETED   = 0x2,
    PPR_DEF_ACL_LKP_COMPLETED    = 0x4,
    PPR_DEF_FLOW_LKP_COMPLETED   = 0x8,
    PPR_PROC_COMPLETED_ALL       = 0x10,
} ppr_lookup_stages_t;



/* Global Policy Epoch Variables */
typedef struct ppr_global_policy_epoch{
    _Atomic uint64_t acl_policy_epoch;
    _Atomic uint64_t lb_policy_epoch;
} ppr_global_policy_epoch_t;

/* ---------------------- Misc helper functions related to printing actions ------------------------- */

static inline void ppr_format_mac(const struct rte_ether_addr *mac, char *buf, size_t len)
{
    snprintf(buf, len, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac->addr_bytes[0], mac->addr_bytes[1],
             mac->addr_bytes[2], mac->addr_bytes[3],
             mac->addr_bytes[4], mac->addr_bytes[5]);
}

static inline const char * ppr_proto_to_str(uint8_t proto)
{
    switch (proto) {
    case 0:             return "any";
    case IPPROTO_TCP:   return "tcp";
    case IPPROTO_UDP:   return "udp";
    case IPPROTO_ICMP:  return "icmp";
    case IPPROTO_ICMPV6:return "icmpv6";
    default:            return "other";
    }
}

static inline const char *ppr_ethertype_to_str(uint16_t et)
{
    switch (et) {
    case 0x0000: return "any";
    case 0x0800: return "ipv4";
    case 0x86DD: return "ipv6";
    case 0x0806: return "arp";
    default:     return "other";
    }
}

static inline const char *ppr_flow_action_kind_to_str(ppr_flow_action_kind_t kind){
    switch(kind){
        case FLOW_ACT_DROP:
            return "FLOW_ACT_DROP";
        case FLOW_ACT_FWD_PORT:
            return "FLOW_ACT_FWD_PORT";
        case FLOW_ACT_FWD_LB:
            return "FLOW_ACT_FWD_LB";
        case FLOW_ACT_FWD_LB_PORT:
            return "FLOW_ACT_FWD_LB_PORT";
        default:
            return "UNKNOWN";
    }
}

/** 
* Print the action part of an ACL rule for debugging.
* @param a Pointer to the ACL policy action to print.
**/
static inline void ppr_acl_print_action(const ppr_policy_action_t *a)
{
    if (!a)
        return;

    PPR_LOG(PPR_LOG_ACL, RTE_LOG_INFO,
            "    action: policy=%s (%d), egress_targets=%u, lb_groups=%u\n",
            ppr_flow_action_kind_to_str(a->default_policy),
            (int)a->default_policy,
            a->egress_target_count,
            a->lb_groups_count);

    if (a->egress_target_count > 0) {
        PPR_LOG(PPR_LOG_ACL, RTE_LOG_INFO,
                "      egress_ports: ");
        for (uint8_t i = 0; i < a->egress_target_count; i++) {
            PPR_LOG(PPR_LOG_ACL, RTE_LOG_INFO,
                    "%u%s",
                    a->egress_port_ids[i],
                    (i + 1 < a->egress_target_count) ? ", " : "\n");
        }
    }

    if (a->lb_groups_count > 0) {
        PPR_LOG(PPR_LOG_ACL, RTE_LOG_INFO,
                "      lb_groups: ");
        for (uint8_t i = 0; i < a->lb_groups_count; i++) {
            PPR_LOG(PPR_LOG_ACL, RTE_LOG_INFO,
                    "%u%s",
                    a->lb_group_ids[i],
                    (i + 1 < a->lb_groups_count) ? ", " : "\n");
        }
    }
}

#endif