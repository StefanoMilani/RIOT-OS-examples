/*
*   @ingroup my_examples
*   @{
*       @file       udp.h
*       @brief      udp header file 
*       @author     Stefano Milani <stefano.milani96@gmail.com>
*   }@
*/

#ifndef UDP_H
#define UDP_H

/* needed for posix usleep */
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 600
#endif

#ifndef DEFAULT_NUM
#define DEFAULT_NUM 1
#endif
#ifndef DEFAULT_DELAY
#define DEFAULT_DELAY 1000000
#endif
// Server utils define
#define SERVER_MSG_QUEUE_SIZE   (8)
#define SERVER_BUFFER_SIZE      (128)
#define DEFAULT_PORT            "8043"
// Message utils define 
#define MSG_TYPE_SIZE   1
#define KEY_REQUEST     1
#define KEY_ACK         2
#define ACK             3
#define MSG             4


#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// Network libraries 
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
// Thread library
#include "thread.h"
// Support functions
#include "utils.h"
// AES library
#include "tinycrypt/aes.h"


// Start server thread function
void *_server_thread(void *args);

// Handle received messages
int handle_message(char* src_addr);

// Store device info
int store_dev_info(char* addr, uint8_t* compr);

// Sent UDP packet
int udp_send(char *addr_str, char *port_str, char *data, size_t data_len, 
                unsigned int num, unsigned int delay);

// Start UDP server 
int udp_start_server(char *port_str);

// Shell command to start key exchange
int start_exchange(int argc, char **argv);

// Shell command to send encrypted message
int send_encrypted(int argc, char **argv);

#endif // UDP_H
