/*
 * Copyright (C) 2015 Martine Lenders <mlenders@inf.fu-berlin.de>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @{
 *
 * @file
 * @brief       Example application for demonstrating the RIOT's POSIX sockets
 *
 * @author      Martine Lenders <mlenders@inf.fu-berlin.de>
 *
 * @}
 * 
 * @modified-by Stefano Milani <stefano.milani96@gmail.com>
 *
 */

// Useful to UDP server and send msg
#include "msg.h"
#include "udp.h"

// Useful to retrieve IP address
#include "net/ipv6/addr.h"
#include "net/gnrc.h"
#include "net/gnrc/netif.h"

// Shell library
#include "shell.h"

// define for msg queue
#define MAIN_MSG_QUEUE_SIZE (4)
static msg_t main_msg_queue[MAIN_MSG_QUEUE_SIZE];


// Add custon shell command
static const shell_command_t commands[] = {
    { "start-exchange", "Start public key exchange with given IP address", start_exchange },
    { "send-encrypted", "Send encrypted message to specified IP address", send_encrypted  },
    { NULL, NULL, NULL}
}; 

int main(void) {
    /*
     *  Get the interfaces and print the addresses
     */

    // Get the IPv6 addredd
    gnrc_netif_t *netif = NULL;
    while ((netif = gnrc_netif_iter(netif))) { 
        ipv6_addr_t ipv6_addrs[GNRC_NETIF_IPV6_ADDRS_NUMOF];
        int res = gnrc_netapi_get(netif->pid, NETOPT_IPV6_ADDR, 0, ipv6_addrs, sizeof(ipv6_addrs));
        
        if (res < 0) {
           continue;
        }

        for (unsigned i = 0; i < (unsigned)(res / sizeof(ipv6_addr_t)); i++) {
            char ipv6_addr[IPV6_ADDR_MAX_STR_LEN];
            ipv6_addr_to_str(ipv6_addr, &ipv6_addrs[i], IPV6_ADDR_MAX_STR_LEN);
            printf("My address is %s\n", ipv6_addr);
        }

    }

    /* a sendto() call performs an implicit bind(), hence, a message queue is
     * required for the thread executing the shell */
    msg_init_queue(main_msg_queue, MAIN_MSG_QUEUE_SIZE);

    // Start UDP server on port 8888
    udp_start_server(DEFAULT_PORT);
    
    // Start shell
    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(commands, line_buf, SHELL_DEFAULT_BUFSIZE);

    /* should be never reached */
    return 0;
}
