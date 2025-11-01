# Pcap Replay
Pcap Replay is a packet generator application designed to support performance testing of flow and content aware network security applications such as an IDS/IPS. Traditionally the challenge of performance testing these types of systems revolves around the makeup of the network traffic patterns used and how accurately they align with "real world" conditions. When traffic patterns used in lab environments fail to align with real world traffic mixes, there is high risk of over or under reporting device throughput. 

To address this challenge, multiple aspects of test traffic generation must be considered: 

1) Protocol Mix - any network security applicaiton will have some (small or large) degree of protocol awareness. Depending o the application under test, consideration of L2 through L5+ protocols must be included in any input traffic sequence. The ideal traffic generator would allow the user to easily craft test sequences with specified mixtures of protocols, specific protocol addresses, etc. 

2) Content Mix - content aware applications under test (such as an IDS/IPS) can alter their behavior depending on the content / payload of input traffic, not just the header information. The ideal traffic generator for testing these types of applications would allow the user to inject valid content to excersize these alternate paths.

3) Packet / Session Sizes - network application performance can vary significantly depending on the size of data received. The ideal traffic generator would allow the user to control the size distribution of both L2 frames as well as L4+ segments in the input traffic sequence.

4) Flow Count & Diversity - Many network applications use flow identification to categorize and process input traffic. This approach typically requires the application to leverage lookup table structures that are excersized when processing a new packet to determine what actions to perform on it. Given this behavior, the flow counts, connections per second, and flow diversity included in the input traffic sequence will greatly affect how the application under test performs. The ideal traffic generator would allow the user to control the flow configuration of a traffic sequence. 

5) Flow Timing & Sequencing - Real world users generate flows with different timing and sequencing properties. Some flows are short lived, high throughput, some are long lived, low throughput, and anything inbetween. The ideal traffic generator would allow the user to control timing and longevity of each individual flow used in the input traffic sequence. 

6) Traffic Bandwidth - Ultimatly one of the priamry goals of testing an network application is to determine maximum throughput under various configurations. The ideal traffic generator would allow the user to control the input traffic streams pps and bps rates to facitate performance measurements. 

Considering the traffic generation aspects above, the approach used by Pcap Replay is to divide and concour. This involves splitting the responsibilties between pre-processing applications and the Pcap Replay datapath. 

In this model, protocol / content / size knobs are used to drive the creation of "template" pcap files used by the traffic generator datapath. These files can be created or captured many ways. They can be synthetically created (see PacketSmith) or derived from live pcap captures. The goal of these "template" pcaps are to capture the content, mix, and timing properties desired while keeping the overall size (file size in bytes) small-ish (up to a few gig, not 10G+, this is all arbitrary but consider how much RAM your traffic generator system will have..). an ideal template pcap would capture traffic generation from a few clients in a way that looks realistic (e.g. packet and segment sizes, flow timing parameters, etc.). 

Once a template file has been created, the Pcap Replay datapath handles control of flow diversity, timing & sequencing, and overall bandwidth at runtime. 

1) Flow Diversity - The Pcap Replay dataplane uses a global flowtable alongside the concept of "virtual clients" to control the flow diversity while replaying traffic from the pcap template. When uploading the template pcap to the datapath, the user also has the option to upload a json file of flow table actions. This allows the user to specify on a per flow basis, a variety of L2/L3/L4 header modifications to peform. 

The worker threads in the datapath peform a per packet lookup into the flow table and perform the requested modification actions. The lookup action itself only encodes a base modifer action (e.g. I want you to change the src_ip of every packet in this flow) but it doesn't say which exact value to use (action includes a base value, e.g. a subnet). To allow for high levels of flow expansion, each worker thread maintains an array of "virtual clients / flows" with the total count enabled controlled by the user. for each packet, each worker thread performs one lookup, and N copies / modifications. This allows one template packet to spawn N new packets with variable flow information. 

2) Timing & Sequencing - The Pcap Replay datapath preserves the packet timing and sequencing included in the pcap template, for all virtual flows enabled. When transmission starts a global "start time" is captured, packet timestamps are checked and copy / modification / transmission only occurs if the template packet time is >= the global time. In order to add more realism to the dynamically expanded traffic, each virtual client / flow gets assigned a random starttime offset (between 0 - time length of pcap template) this ensures that as virtual clients / flows are added to the traffic mix, they don't all repeat at the same time. start/end times are uniformally distributed throughout the replay window. 

3) Bandwidth Control - The Pcap Replay datapath is designed to be used with NIC's that support VF rate limiting. "Ports" used in the datapath for transmission are actually VF interfaces, and VF rate limiting provides a easy knob to control the bps transmission rate with mbps resolution. The entire datapath is designed to be droppless (e.g. if tx_workers can't transmit they will loop infinitely until they can, if the rx/tx rings are full, buffer workers will continuously poll until they can enueue). The approach here is to configure the system for the maximum desired transmit rate (e.g number of tx & buffer cores, number of virtual flows / clients configured) then utilize VF rate limiting to set the target rate thats <= the maximum supported throughput. 

## Repo Structure

/configs - contains sample json formatted configuration files for describing the runtime configuration of Pcap Replay. Both python services and the dpdk dataplane open and consume the same configuration file to configure different aspects of the system. 

/include - C header files for the DPDK dataplane application

/python - contains all python tools and services. PcapReplay_Server is the primary entry point Pcap Replay

/src - c source files for the DPDK dataplane application. 

## Architecture Description

The architecture is split into two subsystems: a DPDK based datapath and a Python based control server. The design approach was to keep the DPDK application as lean as possible, focusing only on functionality that must reside within the datapath to ensure high transmit performance while pushing a majority of the out of band configuration logic into Python where it's easier to maintain and adjust. 

### High Level Init 
As stated above, the design is partitioned into a DPDK based dataplane application (Pcap_Replay_dataplane) and a python control plane. At a high level, Pcap Replay works as follows: 

1) Pcap Replay_Server.py creates an RPC or local CLI interface (based on CLI config options) to configure and control the dataplane

2) Once running, the user loads and configures the dataplane via RPC or CLI commands. The python subsystem contains the required logic to create the DPDK application environment (e.g. create hugepages and hugepagefs), configure the target NIC device (create VF's), and launch the DPDK Pcap Replay_dataplane application. 

3) Once launched, the Pcap Replay_Server communicates directly to the dataplane application via a local TCP socket, using json formatted commands and responses.  

4) Once the dataplane is running, the python front end allows the user to interact with the dataplane. Primarly this involves loading pcap's into datapath memory, assigning pcap files to ports, enabling/disabling transmission, loading / modifying runtime flowtable actions, and collecting stats. 

### Dataplane Components 
a key design point here was to keep the actual dataplane design simple and performant. The DPDK dataplane is responsible for
initializing the DPDK EAL, memory pools, ports, globoal flow table, and launching all worker theads. The DPDK dataplane utilizes a number of different worker threads: 

    a) tx_workers (dpdk lcore) - these are the main transmit threads for traffic generation. Each worker can service all configured ports in the system. Each worker pulls packets from a N input rte_rings (one ring per port configured at runtime). tx_workers simply pull packets of each ring and call the rte_tx_burst call for the target port / queue. Tx workers run in a infinite loop and are not gated on/off, if no work is in the queue they wait in a idle loop. 

    b) buff_workers (dpdk lcore)- these are the main worker threads responsible for reading packets out of global pcap mbuff memory, performing any required packet modifications, and assigning packets to the respective output ring. 

    c) control_server pthread - this is a pthread based thread that runs on the service core (lcore=1) thats responsible for processing commands submitted to the dataplane from the connected python interface via a TCP socket. Commands are simple json formatted command / response structures. 
    
    d) stats pthread - this is a pthread based thread that runs on the service core (lcore=1) and is responsible for periodic collection of all statistics and updating global stats structures. Currently the stats thread monitors all dpdk port xstats, memory usage stats, and tx / buff lcore worker stats. 

    e) pcap_loader pthread - this is a pthread based thread that runs on the service core (lcore=1) that handles requests to open pcap files and load them into the global pcap storage structure used by the datapath. Its designed to use a simple lock based command / response interface using posix conditional wait flags. When no operations are pending, this thread spends most of its time a sleep. The primary interaction with this thread comes from the control_server thread when users want to load / modify pcap storage. 

    f) ft_manager pthread - this is a pthread based thread that runs on the service core (lcore=1) responsible for managing the global flowtable used by the datapath. The buff_worker threads perform per packet flow lookups into the global flow table to determine what (if any) modification actions they should perform on each packet. The ft_manager pthread is responsible for taking add/modify/delete requests from the user (via the control_server <-> python cli interface). It also performs the necessary periodic QSBR reclaimation functions to retire old action pointers safely. 


## Hardware Prerequisits 
All testing was done with a Mellanox/Nvidia Connect-X5 NIC. In theory any NIC supporting multiple VF's with VF tx rate shaping would work, but I've not tested it. Specifically I suspect initial runtime issues if running with non Mellanox/Nvidia NIC's based on how they handle linux vs DPDK ownership. 

## Build Prerequisits 
To build Pcap Replay, you need to ensure the following libraries are installed on your system: 

libdpdk 
jansson 
threads 
libpcap 

for DPDK, version 24.11.3 (LTS) was used for development, it was built from source which you can get here (https://fast.dpdk.org/rel/dpdk-24.11.3.tar.xz)

The other packages are the base versions available with Ubuntu 24.04.3 apt-get. 

In addition to the packages above, Pcap Replay uses meson/ninja to build (uses a DPDK style build env). If you can build DPDK from source successfully you should be able to build the Pcap Replay datapath.

## Build 
to build the application, cd into pcap_replay and run: 

mkdir build 
meson setup build --wipe;ninja -C build

If successful you will see output similar to below: 
The Meson build system
Version: 1.3.2
Source dir: /home/jack/Projects/pcap_replay
Build dir: /home/jack/Projects/pcap_replay/build
Build type: native build
Project name: pcap_replay_dataplane
Project version: 0.1
C compiler for the host machine: cc (gcc 13.3.0 "cc (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0")
C linker for the host machine: cc ld.bfd 2.42
Host machine cpu family: x86_64
Host machine cpu: x86_64
Found pkg-config: YES (/usr/bin/pkg-config) 1.8.1
Run-time dependency libdpdk found: YES 24.11.3
Run-time dependency jansson found: YES 2.14
Run-time dependency threads found: YES
Run-time dependency libpcap found: YES 1.10.4
Build targets in project: 1

Found ninja-1.11.1 at /usr/bin/ninja
ninja: Entering directory `build'
[11/11] Linking target src/pcap_replay_dataplane


## Runtime Config 
To run the application, modify the configs/default.json to work with your system: 
{
    "core_config" : 
    {
        "total_lcores"    : 4,   <- Change this to total number of cores you want DPDK to use on your system
        "tx_cores"        : 1,   <- Number of tx cores to use, at a minimum you need a 1:1 ratio of buffer to tx cores 
        "base_lcore_id"   : 0,   <- base lcore id, dont change this 
        "limit_buf_cores" : 1    <- limits the number of buffer cores to assign per tx core. e.g. keep this at 1 for now
    },
    "memory_configs":
    {
        "default_hugepage_size" : "1G", <- hugepage size to use, don't change
        "num_pages" : 24                <- number of hugepages, this by default will reserve ~24 GB for datapath
    },
    "port_configs": [                   
        {
            "portid"    : 0,
            "portnetd"  : "enp1s0f0np0",   <- update to your NIC's netdev name
            "pf_devid"  : "0000:01:00.0",  <- update to your NIC's PF PCIe Address
            "numvfs"    : 2,               <- how many VFs you want 
            "vf_devids" : [
                "0000:01:00.2",            <- expected PCIe VF addresses
                "0000:01:00.3"
            ]
        }
    ],
    "dpdk_config" :                        <- dont change this
    {
        "appname" : "pcap_replay_dataplane",
        "path"    : "build/src"
    }
}

## Run 
the easiest way to run the tool is to utilize the PcapReplay_Server.py in CLI Mode: 

1) Launch the CLI
    sudo python3 python/PcapReplay_Server.py -m cli

2) Load the DPDK datapath
    PcapReplay> load_app
    load_app
    already configured hugepages
    already created
    ['./build/src/pcap_replay_dataplane', '-l', '0-3', '-a', '0000:01:00.2', '-a', '0000:01:00.3', '--', '--config', 'configs/default.json']
    Socket is open on 127.0.0.1:9000
    Connected
    True
    PcapReplay> 

3) Load a pcap template
    PcapReplay> load_pcap filepath:test64.pcap
    load_pcap
    ['filepath', 'test64.pcap']
    {'cmd': 'load_pcap', 'args': {'filename': 'test64.pcap'}}
    (0, {'status': 0, 'slot': 0, 'num_packets': 1000})
    PcapReplay> 

4) Assign pcap template to a tx port (mode:2 = dynamic expansion, default mode)
    PcapReplay> pcap_assign_port_all pcap:test64.pcap portno:0 mode:2
    pcap_assign_port_all
    {'cmd': 'slot_assign', 'args': {'pcap_slotid': 0, 'portno': 0, 'coreid': 0, 'mode': 2}}
    None
    PcapReplay> 

5) Enable Traffic 
    PcapReplay> tx_enable portno:0
    tx_enable
    (0, {'status': 0})
    PcapReplay> 

6) check stats 
    PcapReplay> port_stats port0 true good_packets
    port_stats
    {'tx_good_packets': 48256, 'tx_good_packets_rate': 2219}
    PcapReplay> port_stats port0 true good_packets
    port_stats
    {'tx_good_packets': 53834, 'tx_good_packets_rate': 2219}
    PcapReplay> port_stats port0 true good_packets
    port_stats
    {'tx_good_packets': 54938, 'tx_good_packets_rate': 2197}
    PcapReplay>

the about above shows a pps rate of ~2200 which matches the test64.pcap structure. It's 1000 64 byte packets with a replay time of ~.44 seconds. 

