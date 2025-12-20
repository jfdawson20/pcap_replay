#include "ppr_stats_rpc.h"

/* --------------------------------- Stastics commands --------------------------------- */

/** 
* jsonize and return all configured memory pool stats 
* @param reply_root
*   json root object to populate
* @param args
*   json object containing the command arguments (if used)
* @param thread_args
*   Pointer to pthread args structure
* @return
*   - 0 on success
*   - -EINVAL if input parameters are invalid
**/
int ppr_cmd_mem_stats(json_t *reply_root, json_t *args, ppr_thread_args_t *thread_args){
    pthread_mutex_lock(&(thread_args->global_stats->mem_stats->lock));
    //silence unused param warnings
    (void)args;
    (void)thread_args;

    int rc = 0;
    json_t *arr = json_array();
    json_t *net_mem_info = json_object();
    json_t *clone_mem_info = json_object();
    json_t *copy_mem_info = json_object();
    char name[32];

    //network mempool
    rc = sprintf(name,"network_mempool");
    rc += json_object_set_new(net_mem_info, "pool_name", json_string(name));
    rc += json_object_set_new(net_mem_info, "mem_available", json_integer(thread_args->global_stats->mem_stats->mstats[0].available));
    rc += json_object_set_new(net_mem_info, "mem_used", json_integer(thread_args->global_stats->mem_stats->mstats[0].used));
    rc += json_object_set_new(net_mem_info, "mem_total", json_integer(thread_args->global_stats->mem_stats->mstats[0].total));
    rc += json_array_append_new(arr,net_mem_info);

    
    //clone mempool
    rc += sprintf(name,"clone_mempool");
    rc += json_object_set_new(clone_mem_info, "pool_name", json_string(name));
    rc += json_object_set_new(clone_mem_info, "mem_available", json_integer(thread_args->global_stats->mem_stats->mstats[1].available));
    rc += json_object_set_new(clone_mem_info, "mem_used", json_integer(thread_args->global_stats->mem_stats->mstats[1].used));
    rc += json_object_set_new(clone_mem_info, "mem_total", json_integer(thread_args->global_stats->mem_stats->mstats[1].total));
    rc += json_array_append_new(arr,clone_mem_info);

    //copy mempool
    rc += sprintf(name,"copy_mempool");
    rc += json_object_set_new(copy_mem_info, "pool_name", json_string(name));
    rc += json_object_set_new(copy_mem_info, "mem_available", json_integer(thread_args->global_stats->mem_stats->mstats[2].available));
    rc += json_object_set_new(copy_mem_info, "mem_used", json_integer(thread_args->global_stats->mem_stats->mstats[2].used));
    rc += json_object_set_new(copy_mem_info, "mem_total", json_integer(thread_args->global_stats->mem_stats->mstats[2].total));
    rc += json_array_append_new(arr,copy_mem_info);

    rc += json_object_set_new(reply_root,"mempool_info",arr);

    pthread_mutex_unlock(&(thread_args->global_stats->mem_stats->lock));
    
    //standardize return code
    if (rc < 0){
        return -EINVAL;
    }
    return 0;
}

/** 
* jsonize and return all configured port stats
* @param reply_root
*   json reply_root object to populate
* @param args
*   json object containing the command arguments (if used)
* @param thread_args
*   Pointer to pthread args structure
* @return
*   - 0 on success
*   - -EINVAL if input parameters are invalid
**/
int ppr_cmd_port_stats(json_t *reply_root, json_t *args, ppr_thread_args_t *thread_args){
    
    // guard against null
    if (args == NULL){
        return -EINVAL;
    }
   
    //extract requested port number
    const char *portno_str = json_string_value(json_object_get(args, "portno"));
    if (portno_str == NULL){
        return -EINVAL;
    }
    int portno = atoi(portno_str);
    PPR_LOG(PPR_LOG_RPC, RTE_LOG_DEBUG, "Requested port stats for port %d\n", portno);

    //calculate range if requested 
    unsigned int base_port_id = 0;
    unsigned int max_port_id = 0;
    if(portno == -1)
    {
        base_port_id = 0;
        max_port_id  = thread_args->global_port_list->num_ports;
        //if portno not specified, return stats for all ports
    }
    else if (portno < 0 || (unsigned int)portno >= thread_args->global_port_list->num_ports){
        return -EINVAL;
    }  
    else{
        base_port_id = (unsigned int)portno;
        max_port_id  = base_port_id + 1;
    }


    int rc = 0;
    char portname[30];
    //iterate across ports and grab latest stats, format into json struct
    for(unsigned int i=base_port_id; i<max_port_id; i++){
        //find entry
        ppr_port_entry_t *port_entry = ppr_find_port_by_global_index(thread_args->global_port_list, i);
        if (!port_entry) {
            PPR_LOG(PPR_LOG_RPC, RTE_LOG_ERR, "Error: Could not find port entry for port ID %u\n", i);
            continue;
        }

        //if drop port, skip 
        if(strcmp(port_entry->name, "drop_port") == 0){
            continue;
        }

        //get lock 
        pthread_mutex_lock(&(port_entry->stats.lock));

        //get stats struct pointer 
        ppr_single_port_stats_t *ps = &port_entry->stats;
        
        PPR_LOG(PPR_LOG_RPC, RTE_LOG_DEBUG, "Processing stats for port %d\n", i);
        rc += sprintf(portname, "port%d",i);
        json_t *portstats = json_object();
        

        if(ps->port_kind == PPR_PORT_TYPE_RING){
            rc += json_object_set_new(portstats,"type",json_string("ring"));
            rc += json_object_set_new(portstats,"name",json_string(port_entry->name));
            rc += json_object_set_new(portstats,"enq_pkts",json_integer(ps->ringstats.current_ring_stats->enq_pkts));
            rc += json_object_set_new(portstats,"deq_pkts",json_integer(ps->ringstats.current_ring_stats->deq_pkts));
            rc += json_object_set_new(portstats,"drop_pkts",json_integer(ps->ringstats.current_ring_stats->drop_pkts));
            rc += json_object_set_new(portstats,"enq_pkts_rate",json_integer(ps->ringstats.rates_ring_stats->enq_pkts));
            rc += json_object_set_new(portstats,"deq_pkts_rate",json_integer(ps->ringstats.rates_ring_stats->deq_pkts));
            rc += json_object_set_new(portstats,"drop_pkts_rate",json_integer(ps->ringstats.rates_ring_stats->drop_pkts));  
        } 
        else{
            //iterate over all xstats for the port
            rc += json_object_set_new(portstats,"type",json_string("NIC"));
            rc += json_object_set_new(portstats,"name",json_string(port_entry->name));
            for (int j = 0; j < ps->xstats.n_xstats;j++){
                rc += json_object_set_new(portstats,ps->xstats.port_stats_names[j].name,json_integer(ps->xstats.current_port_stats[j].value));
            }

            //add all rate metrics 
            for (int j = 0; j < ps->xstats.n_xstats;j++){
                char name[128]; 
                rc += sprintf(name, "%s_rate", ps->xstats.port_stats_names[j].name);

                rc += json_object_set_new(portstats,name,json_integer(ps->xstats.rates_port_stats[j].value));
            }
        }


        rc += json_object_set_new(reply_root,portname,portstats);
        
        //release portstats lock
        pthread_mutex_unlock(&(port_entry->stats.lock));   

    }
 

    //standardize return code
    if (rc < 0){
        return -EINVAL;
    }
    return 0;
}

/** 
* jsonize and return flowtable stats
* @param reply_root
*   json reply_root object to populate
* @param args
*   json object containing the command arguments (if used)
* @param thread_args
*   Pointer to pthread args structure
* @return
*   - 0 on success
*   - -EINVAL if input parameters are invalid
**/
int ppr_cmd_flowtable_stats(json_t *reply_root, json_t *args, ppr_thread_args_t *thread_args){
    //silence unused param warnings
    (void)args;

    int rc = 0;
    
    ppr_flow_table_t *ip_flow_tbl       = thread_args->ip_flowtable;
    ppr_flow_table_t *l2_flow_tbl       = thread_args->l2_flowtable;
    uint64_t lb_epoch                   = atomic_load_explicit(&ip_flow_tbl->policy_epochs->lb_policy_epoch, memory_order_acquire);
    uint64_t acl_epoch                  = atomic_load_explicit(&ip_flow_tbl->policy_epochs->acl_policy_epoch, memory_order_acquire);

    uint32_t num_shards = ip_flow_tbl->cfg.shards;

    //create json array to hold 2x flow table results
    json_t *flowtable_results = json_array();

    json_t *ip_ft_stats = json_object();
    rc += json_object_set_new(ip_ft_stats, "name", json_string(ip_flow_tbl->cfg.name));
    rc += json_object_set_new(ip_ft_stats, "current_lb_epoch", json_integer(lb_epoch));
    rc += json_object_set_new(ip_ft_stats, "current_acl_policy_epoch", json_integer(acl_epoch));
    rc += json_object_set_new(ip_ft_stats, "total_flows", json_integer(ip_flow_tbl->total_flows));
    rc += json_object_set_new(ip_ft_stats, "active_flows", json_integer(ip_flow_tbl->total_active_flows));
    rc += json_object_set_new(ip_ft_stats, "total_flows_evicted", json_integer(ip_flow_tbl->total_flows_evicted));
    rc += json_object_set_new(ip_ft_stats, "total_invalidated_evicted_flows", json_integer(ip_flow_tbl->total_invalidated_evicted_flows));
    rc += json_object_set_new(ip_ft_stats, "total_timeout_evicted_flows", json_integer(ip_flow_tbl->total_timeout_evicted_flows)); 
    rc += json_object_set_new(ip_ft_stats, "total_lifetime_evicted_flows", json_integer(ip_flow_tbl->total_lifetime_evicted_flows));
    rc += json_object_set_new(ip_ft_stats, "total_acl_policy_epoch_evicted_flows", json_integer(ip_flow_tbl->total_acl_policy_epoch_evicted_flows));

    rc += json_object_set_new(ip_ft_stats, "num_shards", json_integer(num_shards));
    for(unsigned int i=0; i<num_shards; i++){
        char shardname[30];
        snprintf(shardname, sizeof(shardname), "shard%u", i);
        struct rte_hash *h = ip_flow_tbl->s[i].h;
        json_t *ip_shardstats = json_object();
        uint32_t count = rte_hash_count(h);
        
        rc += json_object_set_new(ip_shardstats, "entries", json_integer(count));
        rc += json_object_set_new(ip_shardstats, "active_flows", json_integer(ip_flow_tbl->shard_active_flows[i]));
        rc += json_object_set_new(ip_shardstats, "total_flows", json_integer(ip_flow_tbl->shard_total_flows[i]));
        rc += json_object_set_new(ip_shardstats, "flows_evicted", json_integer(ip_flow_tbl->shard_evicted_flows[i]));
        rc += json_object_set_new(ip_shardstats, "invalidated_evicted_flows", json_integer(ip_flow_tbl->shard_invalidated_evicted_flows[i]));
        rc += json_object_set_new(ip_shardstats, "timeout_evicted_flows", json_integer(ip_flow_tbl->shard_timeout_evicted_flows[i]));
        rc += json_object_set_new(ip_shardstats, "lifetime_evicted_flows", json_integer(ip_flow_tbl->shard_lifetime_evicted_flows[i]));
        rc += json_object_set_new(ip_shardstats, "acl_policy_epoch_evicted_flows", json_integer(ip_flow_tbl->shard_acl_policy_epoch_evicted_flows[i]));
        rc += json_object_set_new(ip_ft_stats, shardname, ip_shardstats);
    }

    //add ip table stats to flowtable results array
    rc += json_array_append_new(flowtable_results, ip_ft_stats);

    //now do L2 flowtable stats
    json_t *l2_ft_stats = json_object();
    num_shards              = l2_flow_tbl->cfg.shards;
    lb_epoch              = atomic_load_explicit(&l2_flow_tbl->policy_epochs->lb_policy_epoch, memory_order_acquire);
    acl_epoch               = atomic_load_explicit(&l2_flow_tbl->policy_epochs->acl_policy_epoch, memory_order_acquire);

    rc += json_object_set_new(l2_ft_stats, "name", json_string(l2_flow_tbl->cfg.name));
    rc += json_object_set_new(l2_ft_stats, "current_lb_epoch", json_integer(lb_epoch));
    rc += json_object_set_new(l2_ft_stats, "current_acl_policy_epoch", json_integer(acl_epoch));
    rc += json_object_set_new(l2_ft_stats, "total_flows", json_integer(l2_flow_tbl->total_flows));
    rc += json_object_set_new(l2_ft_stats, "active_flows", json_integer(l2_flow_tbl->total_active_flows));
    rc += json_object_set_new(l2_ft_stats, "total_flows_evicted", json_integer(l2_flow_tbl->total_flows_evicted));
    rc += json_object_set_new(l2_ft_stats, "total_invalidated_evicted_flows", json_integer(l2_flow_tbl->total_invalidated_evicted_flows));
    rc += json_object_set_new(l2_ft_stats, "total_timeout_evicted_flows", json_integer(l2_flow_tbl->total_timeout_evicted_flows)); 
    rc += json_object_set_new(l2_ft_stats, "total_lifetime_evicted_flows", json_integer(l2_flow_tbl->total_lifetime_evicted_flows));
    rc += json_object_set_new(l2_ft_stats, "total_acl_policy_epoch_evicted_flows", json_integer(l2_flow_tbl->total_acl_policy_epoch_evicted_flows));

    rc += json_object_set_new(l2_ft_stats, "num_shards", json_integer(num_shards));
    for(unsigned int i=0; i<num_shards; i++){
        char shardname[30];
        snprintf(shardname, sizeof(shardname), "shard%u", i);
        struct rte_hash *h = l2_flow_tbl->s[i].h;
        json_t *l2_shardstats = json_object();
        uint32_t count = rte_hash_count(h);
        
        rc += json_object_set_new(l2_shardstats, "entries", json_integer(count));
        rc += json_object_set_new(l2_shardstats, "active_flows", json_integer(l2_flow_tbl->shard_active_flows[i]));
        rc += json_object_set_new(l2_shardstats, "total_flows", json_integer(l2_flow_tbl->shard_total_flows[i]));
        rc += json_object_set_new(l2_shardstats, "flows_evicted", json_integer(l2_flow_tbl->shard_evicted_flows[i]));
        rc += json_object_set_new(l2_shardstats, "invalidated_evicted_flows", json_integer(l2_flow_tbl->shard_invalidated_evicted_flows[i]));
        rc += json_object_set_new(l2_shardstats, "timeout_evicted_flows", json_integer(l2_flow_tbl->shard_timeout_evicted_flows[i]));
        rc += json_object_set_new(l2_shardstats, "lifetime_evicted_flows", json_integer(l2_flow_tbl->shard_lifetime_evicted_flows[i]));
        rc += json_object_set_new(l2_shardstats, "acl_policy_epoch_evicted_flows", json_integer(l2_flow_tbl->shard_acl_policy_epoch_evicted_flows[i]));
        rc += json_object_set_new(l2_ft_stats, shardname, l2_shardstats);
    }

    //add l2 table stats to flowtable results array
    rc += json_array_append_new(flowtable_results, l2_ft_stats);

    rc += json_object_set_new(reply_root, "flowtable_stats", flowtable_results);
    //standardize return code
    if (rc < 0){
        return -EINVAL;
    }
    return 0;
}

/** 
* jsonize and return worker stats
* @param reply_root
*   json reply_root object to populate
* @param args
*   json object containing the command arguments (if used)
* @param thread_args
*   Pointer to pthread args structure
* @return
*   - 0 on success
*   - -EINVAL if input parameters are invalid
**/
int ppr_cmd_worker_stats(json_t *reply_root, json_t *args, ppr_thread_args_t *thread_args){

    //claim worker stats lock
    pthread_mutex_lock(&(thread_args->global_stats->worker_stats->lock));
    int rc = 0;
    const char *workerid_str = json_string_value(json_object_get(args, "worker_id"));
    if(workerid_str == NULL){
        pthread_mutex_unlock(&(thread_args->global_stats->worker_stats->lock));
        return -EINVAL;
    }
    int worker_id = atoi(workerid_str);

    PPR_LOG(PPR_LOG_RPC, RTE_LOG_DEBUG, "Requested worker stats for worker %d\n", worker_id);

    unsigned int base_worker_id = 0;
    unsigned int max_worker_id = 0;
    if(worker_id == -1)
    {
        base_worker_id = 0;
        max_worker_id  = thread_args->global_stats->worker_stats->num_workers;
        //if worker_id not specified, return stats for all workers
    }
    else if (worker_id < 0 || (unsigned int)worker_id >= thread_args->global_stats->worker_stats->num_workers){
        return -EINVAL;
    }  
    else{
        base_worker_id = (unsigned int)worker_id;
        max_worker_id = base_worker_id + 1;
    }

    for (unsigned int i =base_worker_id; i<max_worker_id; i++){
        PPR_LOG(PPR_LOG_RPC, RTE_LOG_DEBUG, "Processing stats for worker %d\n", i);
        char workername[30];
        int rc = sprintf(workername, "worker%d",i);
        json_t *workerstats = json_object();
        
        rc += json_object_set_new(workerstats, "rx_packets", json_integer(thread_args->global_stats->worker_stats->current_worker_stats[i].rx_packets));
        rc += json_object_set_new(workerstats, "rx_bytes", json_integer(thread_args->global_stats->worker_stats->current_worker_stats[i].rx_bytes));
        rc += json_object_set_new(workerstats, "rx_packet_rate", json_integer(thread_args->global_stats->worker_stats->rates_worker_stats[i].rx_packets));
        rc += json_object_set_new(workerstats, "rx_byte_rate", json_integer(thread_args->global_stats->worker_stats->rates_worker_stats[i].rx_bytes));
        
        rc += json_object_set_new(workerstats, "rx_bad_packets", json_integer(thread_args->global_stats->worker_stats->current_worker_stats[i].rx_bad_packets));
        rc += json_object_set_new(workerstats, "rx_bad_packet_rate", json_integer(thread_args->global_stats->worker_stats->rates_worker_stats[i].rx_bad_packets));

        rc += json_object_set_new(workerstats, "frag_packets_rx", json_integer(thread_args->global_stats->worker_stats->current_worker_stats[i].frag_packets_rx));
        rc += json_object_set_new(workerstats, "frag_reassembled_packets", json_integer(thread_args->global_stats->worker_stats->current_worker_stats[i].frag_reassembled_packets));

        rc += json_object_set_new(workerstats, "tx_packets", json_integer(thread_args->global_stats->worker_stats->current_worker_stats[i].tx_packets));
        rc += json_object_set_new(workerstats, "tx_bytes", json_integer(thread_args->global_stats->worker_stats->current_worker_stats[i].tx_bytes));
        rc += json_object_set_new(workerstats, "tx_packet_rate", json_integer(thread_args->global_stats->worker_stats->rates_worker_stats[i].tx_packets));
        rc += json_object_set_new(workerstats, "tx_byte_rate", json_integer(thread_args->global_stats->worker_stats->rates_worker_stats[i].tx_bytes));
        rc += json_object_set_new(workerstats, "tx_dropped_packets", json_integer(thread_args->global_stats->worker_stats->current_worker_stats[i].tx_dropped_packets));

        rc += json_object_set_new(reply_root,workername,workerstats);

    }
    //release worker stats lock
    pthread_mutex_unlock(&(thread_args->global_stats->worker_stats->lock));
    //standardize return code
    if (rc < 0){
        return -EINVAL;
    }
    return 0;

}
