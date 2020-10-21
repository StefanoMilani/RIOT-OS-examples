/*
*  
*	@file       udp.h
*	@brief      udp header file 
*	@author     Stefano Milani <stefano.milani96@gmail.com>
*   
*/

#ifndef UDP_H
#define UDP_H

#include <stdio.h>
#include <stdlib.h>

#define DEFAULT_PORT            "8043"

// Start UDP server 
int udp_start_server(char *port_str);

// Shell command to start key exchange
int start_exchange(int argc, char **argv);

// Shell command to send encrypted message
int send_encrypted(int argc, char **argv);

#endif // UDP_H
