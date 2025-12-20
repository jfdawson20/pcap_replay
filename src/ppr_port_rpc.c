
#include "ppr_port_rpc.h"

int ppr_cmd_get_port_list(json_t *reply_root, json_t *args, ppr_thread_args_t *thread_args){
    //silence unused param warnings
    (void)args;
    ppr_ports_t *port_list = thread_args->global_port_list;
    json_t *portlist = json_object();

    PPR_LOG(PPR_LOG_PORTS, RTE_LOG_DEBUG, "\n Dumping Global Port List: num_ports=%u\n", port_list->num_ports);
    for (unsigned int i = 0; i < port_list->num_ports; i++) {
        json_t *portentry = json_object();
        json_t *rx_queue_arr = json_array();
        json_t *tx_queue_arr = json_array();
        int rc = 0;

        char direction[32];
        if (port_list->ports[i].dir == PPR_PORT_RX){
            snprintf(direction, sizeof(direction), "RX");
        }
        else if (port_list->ports[i].dir == PPR_PORT_TX){
            snprintf(direction, sizeof(direction), "TX");
        }
        else {
            snprintf(direction, sizeof(direction), "RXTX");
        }

        const char *name = port_list->ports[i].name;
        uint16_t port_id = port_list->ports[i].port_id;
        const char *is_external = port_list->ports[i].is_external ? "true" : "false";
        uint16_t total_rx_queues = port_list->ports[i].total_rx_queues;
        uint16_t total_tx_queues = port_list->ports[i].total_tx_queues;
        
        rc += json_object_set_new(portentry, "name", json_string(name));
        rc += json_object_set_new(portentry, "port_id", json_integer(port_id));
        rc += json_object_set_new(portentry, "is_external", json_string(is_external));
        rc += json_object_set_new(portentry, "total_rx_queues", json_integer(total_rx_queues));
        rc += json_object_set_new(portentry, "total_tx_queues", json_integer(total_tx_queues));
        rc += json_object_set_new(portentry, "dir", json_string(direction));

        PPR_LOG(PPR_LOG_PORTS, RTE_LOG_DEBUG, "\t\tRX Queue Assignments: ");
        for (unsigned int q=0; q < port_list->ports[i].total_rx_queues; q++){
            json_t *rx_queue_entry = json_object();
            rc += json_object_set_new(rx_queue_entry, "queue_index", json_integer(q));
            rc += json_object_set_new(rx_queue_entry, "assigned_worker_core", json_integer(port_list->ports[i].rx_queue_assignments[q]));
            rc += json_array_append_new(rx_queue_arr,rx_queue_entry);
            PPR_LOG(PPR_LOG_PORTS, RTE_LOG_DEBUG, "%u ", port_list->ports[i].rx_queue_assignments[q]);
        }
        
        PPR_LOG(PPR_LOG_PORTS, RTE_LOG_DEBUG, "\n");
        
        PPR_LOG(PPR_LOG_PORTS, RTE_LOG_DEBUG, "\t\tTX Queue Assignments: ");
        for (unsigned int q=0; q < port_list->ports[i].total_tx_queues; q++){
            json_t *tx_queue_entry = json_object();
            rc += json_object_set_new(tx_queue_entry, "queue_index", json_integer(q));
            rc += json_object_set_new(tx_queue_entry, "assigned_worker_core", json_integer(port_list->ports[i].tx_queue_assignments[q]));
            rc += json_array_append_new(tx_queue_arr,tx_queue_entry);
            PPR_LOG(PPR_LOG_PORTS, RTE_LOG_DEBUG, "%u ", port_list->ports[i].tx_queue_assignments[q]);
        }
        PPR_LOG(PPR_LOG_PORTS, RTE_LOG_DEBUG, "\n");
        rc += json_object_set_new(portentry, "rx_queues", rx_queue_arr);
        rc += json_object_set_new(portentry, "tx_queues", tx_queue_arr);
        rc += json_object_set_new(portlist,name, portentry);
    }

    int rc = 0;
    rc = json_object_set_new(reply_root, "port_list", portlist);
    if (rc < 0){
        return -EINVAL;
    }
    
    return 0;
}