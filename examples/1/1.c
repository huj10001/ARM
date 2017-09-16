#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"

#include <string.h>
#include <math.h>       /* floor */

#define DEBUG DEBUG_PRINT
#include "net/uip-debug.h"

#include "net/rpl/rpl.h"
#include "net/rpl/rpl-private.h"

#include "debug.h"

#include "rpl-icmp6.c"

#include "/media/abc/ids-origin/apps/powertrace/powertrace.h" // change 09/16

#define UIP_IP_BUF   ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])
#define UIP_UDP_BUF  ((struct uip_udp_hdr *)&uip_buf[uip_l2_l3_hdr_len])

/**
 * Copy the contents from source (needs to be a normal type) to dest, which
 * needs to be a pointer and increment dest by the size of source.
 *
 * Usefull for writing data to a buffer, the inverse of MAPPER_GET_PACKETDATA
 */
#define MAPPER_ADD_PACKETDATA(dest, source) \
  memcpy(dest, &source, sizeof(source)); dest += sizeof(source)
/**
 * Copy the contents from source (needs to be a pointer) to dest, which
 * needs to be normal data type. Increase source with the size of dest.
 *
 * Usefull for reading data from a buffer, the inverse of MAPPER_ADD_PACKETDATA
 */
#define MAPPER_GET_PACKETDATA(dest, source) \
  memcpy(&dest, source, sizeof(dest)); source += sizeof(dest)

static struct uip_udp_conn *server_conn, *server_conn1;
static uip_ipaddr_t ipaddr;
static rpl_dag_t *dag;
struct uip_ds6_addr *root_if;

// struct node_info_t {
//   uint8_t parent_info;
//   uint16_t rank_info;
//   int malicious_info;
//   int etx_info;
// }
node_info_t monitor_table[12]={};

static int flag_stable = 0;

#define UNDEFINED_PARENT 99

extern int attacker;

// static uint8_t monitor_table [11][3] = {};

/*---------------------------------------------------------------------------*/
PROCESS(udp_server_process, "UDP server process");
AUTOSTART_PROCESSES(&udp_server_process);
/*---------------------------------------------------------------------------*/
static void
tcpip_handler(void)
{
    int numof_nbr;
    uint8_t nodeid, version,instance_id, parent_node;
    uint16_t node_rank, node_parent_rank;
    uint8_t *appdata;
    // int malicious_activity;
    // int number_of_nodes = 0;
    if(uip_newdata()) {

        appdata = (uint8_t *) uip_appdata;
        MAPPER_GET_PACKETDATA(nodeid,appdata);
        //MAPPER_GET_PACKETDATA(version,appdata);
        //MAPPER_GET_PACKETDATA(instance_id,appdata);
        MAPPER_GET_PACKETDATA(node_rank,appdata);
        MAPPER_GET_PACKETDATA(parent_node,appdata);
        MAPPER_GET_PACKETDATA(node_parent_rank,appdata);
        MAPPER_GET_PACKETDATA(numof_nbr,appdata);

        uint8_t nbr_id[numof_nbr];
        uint16_t nbr_rank[numof_nbr];
        uint16_t nbr_rank_fake[numof_nbr];
        uint16_t nbr_etx_fake[numof_nbr];
        

        printf("\n Node %u, rank %u,parent %u PRank %u, Numof_nbr %d, ",nodeid,node_rank,parent_node,node_parent_rank,numof_nbr);
        int i;
        for(i=0; i<numof_nbr; i++) {
            MAPPER_GET_PACKETDATA(nbr_id[i],appdata);
            MAPPER_GET_PACKETDATA(nbr_rank[i],appdata);
            MAPPER_GET_PACKETDATA(nbr_rank_fake[i],appdata);
            MAPPER_GET_PACKETDATA(nbr_etx_fake[i],appdata);

        //MAPPER_GET_PACKETDATA(a,appdata);
            //MAPPER_GET_PACKETDATA(b,appdata);
                        
        printf("Nbr %d: %u nbr_rank %u, ",i,nbr_id[i],nbr_rank[i]);
        }
    printf("\n");
    if(monitor_table[nodeid].parent_info==NULL){
            monitor_table[nodeid].parent_info = parent_node;
            monitor_table[nodeid].rank_info = node_rank;
            monitor_table[nodeid].etx_info = (int)(node_rank/128);
            monitor_table[nodeid].malicious_info = 0;
            // monitor_table[nodeid][0] = parent_node;
            // monitor_table[nodeid][1] = node_rank;
            // malicious_activity = 0;
            // monitor_table[nodeid][2] = malicious_activity;
            // number_of_nodes++;
            // printf("Node %u is added to monitor table at index %u.\n", nodeid, parent_node);
            printf("Node %u is added to monitor table.\n", nodeid);
            // int j;
            // for(j=0; j<numof_nbr; j++){
            //     if(monitor_table[nbr_id[j]].parent_info ==NULL){
            //         monitor_table[nbr_id[j]].parent_info = UNDEFINED_PARENT;
            //         monitor_table[nbr_id[j]].rank_info = nbr_rank[j];
            //         monitor_table[nbr_id[j]].etx_info = (int)(nbr_rank[j]/128);
            //         // malicious_activity = 0;
            //         monitor_table[nbr_id[j]].malicious_info = 0;
            //         // printf("Node %u is added to monitor table at index %u.\n", nbr_id[i], parent_node);
            //         printf("Node %u is added to monitor table with undefined parent.\n", nbr_id[j]);
            //     }
            //     /*not applicable for attack*/
            //     else{
            //         uint16_t node_rank_prevv = monitor_table[nbr_id[j]].rank_info;
            //         monitor_table[nbr_id[j]].rank_info = nbr_rank[j];
            //         monitor_table[nbr_id[j]].etx_info = (int)(nbr_rank[j]/128);
            //         printf("Node %u is safe, updates rank from %u to %u.\n", nodeid, node_rank_prevv, nbr_rank[j]);
            //     }
            // }
        }else{
            if(monitor_table[nodeid].parent_info==parent_node){
                if(monitor_table[nodeid].rank_info != node_rank){
                    uint16_t node_rank_prev = monitor_table[nodeid].rank_info;
                    monitor_table[nodeid].rank_info = node_rank;
                    monitor_table[nodeid].etx_info = (int)(node_rank/128);
                    printf("Node %u is safe, updates rank from %u to %u.\n", nodeid, node_rank_prev, node_rank);
                }else{
                    if(flag_stable){}else{
                    printf("Node %u is safe, with stable rank %u.\n", nodeid, node_rank);
                    flag_stable=1;}
                }
                // monitor_table[nodeid].parent_info = parent_node;
                // malicious_activity = 0;
                // monitor_table[nodeid].malicious_info = 0;
            }else if(monitor_table[nodeid].parent_info==UNDEFINED_PARENT){
                monitor_table[nodeid].parent_info = parent_node;
                printf("Node %u is safe, updates parent from undefined parent to %u.\n", nodeid, parent_node);

            }else if(monitor_table[nodeid].parent_info!=parent_node){
                // uint8_t parent_node_prev = monitor_table[nodeid].parent_info;
                // monitor_table[nodeid].parent_info = parent_node;
                // monitor_table[nodeid].malicious_info = 1;
                // printf("Node %u is under attack, changes parent from %u to %u.\n", nodeid, parent_node_prev, parent_node);
            }else{

            }

        }
        int j;
        for(j=0; j<numof_nbr; j++){
                if(monitor_table[nbr_id[j]].parent_info ==NULL){
                    monitor_table[nbr_id[j]].parent_info = UNDEFINED_PARENT;
                    monitor_table[nbr_id[j]].rank_info = nbr_rank[j];
                    monitor_table[nbr_id[j]].etx_info = (int)(nbr_rank[j]/128);
                    // malicious_activity = 0;
                    monitor_table[nbr_id[j]].malicious_info = 0;
                    // printf("Node %u is added to monitor table at index %u.\n", nbr_id[i], parent_node);
                    printf("Node %u is added to monitor table with undefined parent.\n", nbr_id[j]);
                }
                /*not applicable for attack*/
                else{
                    if(monitor_table[nbr_id[j]].rank_info != nbr_rank[j]){
                    uint16_t node_rank_prevv = monitor_table[nbr_id[j]].rank_info;
                    monitor_table[nbr_id[j]].rank_info = nbr_rank[j];
                    monitor_table[nbr_id[j]].etx_info = (int)(nbr_rank[j]/128);
                    printf("Node %u fake rank is %u.\n", nbr_id[j], nbr_rank_fake[j]);
                    printf("Node %u fake etx is %u.\n", nbr_id[j], nbr_etx_fake[j]);
                    if(nbr_rank_fake[j] != 0){
                        monitor_table[nbr_id[j]].malicious_info = 1;
                        // monitor_table[nbr_id[j]].rank_info = nbr_rank_fake[j];
                        printf("Node %u is malicious with fake rank %u.\n", nbr_id[j], nbr_rank_fake[j]);
                    }else{
                    	if(nbr_etx_fake[j] != 0){
                    		monitor_table[nbr_id[j]].malicious_info = 1;
                    		printf("Node %u is malicious with fake etx %u.\n", nbr_id[j], nbr_etx_fake[j]);
                    	}
                    // if(nbr)
                    printf("Node %u is safe, updates rank from %u to %u.\n", nbr_id[j], node_rank_prevv, nbr_rank[j]);
                    }
                    }else{
                        // if(flag_stable){}else{
                        if(nbr_rank_fake[j] != 0){
                        monitor_table[nbr_id[j]].malicious_info = 1;
                        // monitor_table[nbr_id[j]].rank_info = nbr_rank_fake[j];
                        printf("Node %u is malicious with fake rank %u.\n", nbr_id[j], nbr_rank_fake[j]);
                    }else{
                    	if(nbr_etx_fake[j] != 0){
                    		monitor_table[nbr_id[j]].malicious_info = 1;
                    		printf("Node %u is malicious with fake etx %u.\n", nbr_id[j], nbr_etx_fake[j]);
                    	}
                        printf("Node %u is safe, with stable rank %u.\n", nbr_id[j], nbr_rank[j]);
                    }
                        // flag_stable=1;
                    }
                // }
                }
            }
    }
    printf("---------------------------- Monitor Table ----------------------------------\n");
    printf("Node    |Parent     |Rank   |ETX    |Malicious Activity\n");
    int k;
    // int row = (sizeof(monitor_table)/sizeof(monitor_table[0]));
    // int col = (sizeof(monitor_table)/sizeof(monitor_table[0][0]))/row;
    int row = (sizeof(monitor_table)/sizeof(monitor_table[0]));
    // printf("row is %u\n", row);
    // for(k=2; k<=row;k++){
    //     if(monitor_table[k][0] == NULL){
    //         printf("n/a     |n/a        |n/a    |n/a\n");
    //     }else{
    //         printf("%u       |%u          |%u     |%u\n", k, monitor_table[k][0], monitor_table[k][1], monitor_table[k][2]);
    //     }
    // }
    for (k=1; k<=row-1; k++)
    {
        if(monitor_table[k].parent_info == NULL){
            printf("n/a     |n/a        |n/a    |n/a   |n/a\n");
        }else{
            printf("%u       |%u          |%u     |%u       |%u\n", k, monitor_table[k].parent_info, monitor_table[k].rank_info, monitor_table[k].etx_info, monitor_table[k].malicious_info);
        }
    }
    printf("-------------------------------* 99=undefined----------------------------------------------\n");
}
void
create_dag()
{
    uip_ip6addr(&ipaddr, 0xaaaa, 0, 0, 0, 0, 0, 0, 1);
    /* uip_ds6_set_addr_iid(&ipaddr, &uip_lladdr); */
    uip_ds6_addr_add(&ipaddr, 0, ADDR_MANUAL);
    root_if = uip_ds6_addr_lookup(&ipaddr);
    if(root_if != NULL) {
        rpl_dag_t *dag;
        dag = rpl_set_root(RPL_DEFAULT_INSTANCE,(uip_ip6addr_t *)&ipaddr);
        uip_ip6addr(&ipaddr, 0xaaaa, 0, 0, 0, 0, 0, 0, 0);
        rpl_set_prefix(dag, &ipaddr, 64);
        PRINTF("created a new RPL dag with ID:");
        PRINT6ADDR(&dag->dag_id);printf("\n");
    } else {
        PRINTF("failed to create a new RPL DAG\n");
    }
    /*
      uip_ip6addr(&ipaddr, 0xaaaa, 0, 0, 0, 0, 0, 0, 0);
      uip_ds6_set_addr_iid(&ipaddr, &uip_lladdr);
      uip_ds6_addr_add(&ipaddr, 0, ADDR_AUTOCONF);

      dag = rpl_set_root(RPL_DEFAULT_INSTANCE,
                         &uip_ds6_get_global(ADDR_PREFERRED)->ipaddr);
      if(dag != NULL) {
        uip_ip6addr(&ipaddr, 0xaaaa, 0, 0, 0, 0, 0, 0, 0);
        rpl_set_prefix(dag, &ipaddr, 64);
        PRINTF("Created a new RPL dag with ID: ");
        PRINT6ADDR(&dag->dag_id);
        PRINTF("\n");
      }*/
}



PROCESS_THREAD(udp_server_process, ev, data)
{

    PROCESS_BEGIN();

    // printf("Ticks per second: %u\n", RTIMER_SECOND);
    powertrace_start(CLOCK_SECOND * 10);


    create_dag();

    server_conn = udp_new(NULL, UIP_HTONS(12345), NULL);
    udp_bind(server_conn, UIP_HTONS(2345));

    server_conn1 = udp_new(NULL, UIP_HTONS(12345), NULL);
    udp_bind(server_conn1, UIP_HTONS(2346));

    PRINTF("Listen port: 2345, TTL=%u\n", server_conn->ttl);

    while(1) {
        PROCESS_YIELD();
        if(ev == tcpip_event)
            tcpip_handler();
    }

    PROCESS_END();
}
/*---------------------------------------------------------------------------*/
