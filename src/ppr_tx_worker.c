/*
SPDX-License-Identifier: MIT
Copyright (c) 2025 jfdawson20

Filename: tx_worker.c 
Description: Primary entry point and supporting code for DPDK transmit core threads. Transmit cores are responsible for 
taking pcap data provided by buffer fill threads and transmitting them out the approperate network port. Multiple Tx cores can 
drive traffic out the same network port (each tx core has a separate tx queue to each configured network port), however order 
across different tx cores is not maintained. To maintain per flow order, tx workers read data provided by their linked buffer threads using a 
per tx core + port global sequence ID. 

Tx cores are not signaled to start / stop, data flow is controlled by the buffer threads. Tx cores simply monitor their assigned shared memory 
double buffer arrays for valid data to transmit. 

*/
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h> 
#include <pthread.h> 
#include <sched.h>
#include <time.h>
#include <jansson.h>
#include <unistd.h>

#include <rte_eal.h>
#include <rte_debug.h>
#include <rte_log.h> 
#include <rte_common.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_byteorder.h>
#include <limits.h>
#include <rte_ring.h>

#include "ppr_control.h"
#include "ppr_app_defines.h"
#include "ppr_ports.h"
#include "ppr_stats.h"
#include "ppr_tx_worker.h"
#include "ppr_buff_worker.h"

/* Main entry point for tx worker thread */
int tx_worker(__rte_unused void *arg) {

    //parse tx args struct for future use 

    //figure out which core i'm running on 
    unsigned lcore_id = rte_lcore_id();

    /* Main tx thread loop */
    for(;;){

    }
    return 0;
}

