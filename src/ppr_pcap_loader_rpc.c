#include <unistd.h> 

#include "ppr_pcap_loader_rpc.h"
#include "ppr_app_defines.h"


/* Return a json list of all pcaps loaded into memory currently. Returns the following information for each active pcap storage slot
- slot id 
- pcap name 
- number of mbuffs in the slot array
- which tx core it's assigned to 
*/
int ppr_get_loaded_pcaps_list(json_t *reply_root, json_t *args, ppr_thread_args_t *thread_args){
    
    (void) args; //unused parameter

    int num_pcaps = thread_args->pcap_storage_t->count;

    json_object_set_new(reply_root,"num_pcaps",json_integer(num_pcaps));
    json_t *arr = json_array();
    for(int i=0; i<num_pcaps;i++){
        json_t *pcap_info = json_object();
        char *pcapname  = thread_args->pcap_storage_t->slots[i].pcap_name;
        int numpackets  = thread_args->pcap_storage_t->slots[i].numpackets;
        uint64_t start_ns = thread_args->pcap_storage_t->slots[i].start_ns;
        uint64_t end_ns = thread_args->pcap_storage_t->slots[i].end_ns;
        uint64_t delta_ns = thread_args->pcap_storage_t->slots[i].delta_ns;
        uint64_t size_bytes = thread_args->pcap_storage_t->slots[i].size_in_bytes;

        json_object_set_new(pcap_info,"slotid",json_integer(i));
        json_object_set_new(pcap_info,"pcap_name",json_string(pcapname));
        json_object_set_new(pcap_info,"pcap_packets",json_integer(numpackets));
        json_object_set_new(pcap_info,"first_ns",json_integer(start_ns));
        json_object_set_new(pcap_info,"last_ns",json_integer(end_ns));
        json_object_set_new(pcap_info,"delta_ns",json_integer(delta_ns));
        json_object_set_new(pcap_info,"size_in_bytes",json_integer(size_bytes));

        json_array_append_new(arr,pcap_info);

    }

    json_object_set_new(reply_root,"loaded_pcaps",arr);
    return 0;
}

/* 
The next two functions (check_pcap_status) and (return_pcap_loader) are responsible for taking a pcapfile path and loading it into the
Pcap Replay pcap storage memory.  
*/

/* check for pcap loading complete - polls pcap thread control structure 
   returns 0 if busy and 1 if done. slot ID loaded and result (error) returned in pointers 
*/
static int check_pcap_status(ppr_thread_args_t *thread_args, int *result, unsigned int *slot){
    int done = 0;
    
    pthread_mutex_lock(&thread_args->pcap_controller->lock);
    if (!thread_args->pcap_controller->busy && thread_args->pcap_controller->command == CMD_NONE) {
        // worker finished last command
        *result = thread_args->pcap_controller->result;
        *slot   = thread_args->pcap_controller->latest_slotid;
        done = 1;
    }
    pthread_mutex_unlock(&thread_args->pcap_controller->lock);
    return done;
}

/* Primary pcap load command handler. This function takes a filename and a assigned tx core ID 
   from the command args json struct and uses the information to kick the pcap_loader pthread. 
   
   The pcap_loader pthread is started at lanch time (launched from the main DPDk thread) and
   sits in a poll loop waiting for commands to be issued. Pcap loader command and status are 
   relayed using a shared memory pcap control struct that is accessed via the thread args struct. 

   access to the pcap loader control struct is guarded with standard pthread muxtex locks. 

   after completing the load operation, the function formats a response json string into the root json 
   pointer provided by the dispatch function (this is the return string). 

   note, this function both kicks and then waits for the pcap_loader thread to complete the load operation, 
   polling on loader complete (above function). This negates the use of a separate loader thread. I designed it this way
   so in the future if I want the loader thread to do more work per pcap (like TSO aggregation), the logic can be changed to not 
   block the control_server thread while loading / processing pcaps.

*/

int ppr_load_pcap_file(json_t *reply_root, json_t *args, ppr_thread_args_t *thread_args){
    
    //extract filename from command
    const char *filename             = json_string_value(json_object_get(args, "filename"));

    //get pcap thread lock
    pthread_mutex_lock(&thread_args->pcap_controller->lock);

    //copy filename into shared struct 
    snprintf(thread_args->pcap_controller->filename, sizeof(thread_args->pcap_controller->filename), "%s", filename);

    //signal loader thread
    thread_args->pcap_controller->command = CMD_LOAD_PCAP;
    pthread_cond_signal(&thread_args->pcap_controller->cond);
    pthread_mutex_unlock(&thread_args->pcap_controller->lock);

    //wait for load to complete , will change this later 
    int pcap_error = 0;
    unsigned int slot = 0;
    while(check_pcap_status(thread_args,&pcap_error,&slot) == 0){
        usleep(10*1000);
    }

    int numpackets  = thread_args->pcap_storage_t->slots[slot].numpackets;

    //format result
    json_object_set_new(reply_root,"status",json_integer(pcap_error));
    json_object_set_new(reply_root,"slot",json_integer(slot));
    json_object_set_new(reply_root,"num_packets",json_integer(numpackets));

    //print pcap storage stats 
    int count = thread_args->pcap_storage_t->count;
    printf("pcap stored in slot: %d\n", count);

    //read all slots 
    for (int i = 0; i < count; i++){
        char *pcapname  = thread_args->pcap_storage_t->slots[i].pcap_name;
        int pcap_mbufs  = thread_args->pcap_storage_t->slots[i].numpackets;

        printf("Slot %d - File Loaded: %s, NumPackets: %d\n",i,pcapname,pcap_mbufs);
    }

    return 0; 
}