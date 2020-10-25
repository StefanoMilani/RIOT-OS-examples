/*
 * Copyright (C) 2015 Martine Lenders <mlenders@inf.fu-berlin.de>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     examples
 * @{
 *
 * @file
 * @brief       Demonstrating the sending and receiving of UDP data over POSIX sockets.
 *
 * @author      Martine Lenders <mlenders@inf.fu-berlin.de>
 *
 * @}
 * @{
 * 
 * @modified_by Stefano Milani <stefano.milani96@gmail.com>
 *
 */

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


#include <unistd.h>
#include <string.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "thread.h"
#include "key-management.h"
#include "crypto/aes.h"
#include "crypto/modes/cbc.h"

#include "udp.h"

// Server utils define
#define SERVER_MSG_QUEUE_SIZE   8
#define SERVER_BUFFER_SIZE      128

//
#define IV_SIZE					16

// Message utils define 
#define MSG_TYPE_SIZE   		1
#define KEY_REQUEST     		0x01
#define KEY_ACK         		0x02
#define ACK             		0x03
#define MSG             		0x04

// Server global variables
static int server_socket=-1;
static char server_buffer[SERVER_BUFFER_SIZE];
static char server_stack[THREAD_STACKSIZE_DEFAULT];
static msg_t server_msg_queue[SERVER_MSG_QUEUE_SIZE];

// Keys management global variables
const struct uECC_Curve_t *curve;
size_t curve_size;
size_t public_key_size;
Key *key;
Device* dev=NULL;

// Function declarations
int udp_send(char *addr_str, char *port_str, char *data, size_t data_len, unsigned int num, unsigned int delay);
int handle_message(char* src_addr, int data_count);
int manage_key_request(char* src_addr);
int decrypt_received_message(char* src_addr, int data_count);
int store_dev_info(char* addr, uint8_t* compr);
void *_server_thread(void *args);
int send_ack(char* src_addr);

// Send UDP packet
int udp_send(char *addr_str, char *port_str, char *data, size_t data_len,  unsigned int num,
                    unsigned int delay) {
    struct sockaddr_in6 src, dst;
    uint16_t port;
    int s;
    src.sin6_family = AF_INET6;
    dst.sin6_family = AF_INET6;
    memset(&src.sin6_addr, 0, sizeof(src.sin6_addr));
    /* parse destination address */
    if (inet_pton(AF_INET6, addr_str, &dst.sin6_addr) != 1) {
        puts("Error: unable to parse destination address");
        return 1;
    }
    /* parse port */
    port = atoi(port_str);
    dst.sin6_port = htons(port);
    src.sin6_port = htons(port);
    s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (s < 0) {
        puts("error initializing socket");
        return 1;
    }
    for (unsigned int i = 0; i < num; i++) {
        if (sendto(s, data, data_len, 0, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
            puts("could not send");
        }
        else {
            printf("Success: send %u byte to %s:%u\n", (unsigned)data_len, addr_str, port);
        }

        usleep(delay);
    }
    close(s);
    return 0;
}

// Handle received message
int handle_message(char* src_addr, int data_count) {
    uint8_t msg_type;
    // Get message type from message (First char)
    memcpy(&msg_type, server_buffer, MSG_TYPE_SIZE);
	// Behave differently according to the message type
    switch (msg_type) {
        case KEY_REQUEST:
			// Public key exchange request received
			if(manage_key_request(src_addr) == -1) {
				perror("Failed to send back public key");
				return -1;
			}
            break;
        case KEY_ACK:
			// Public key received, Send back ACK
			if(send_ack(src_addr) == -1) {
				perror("Failed to send back ACK message");
				return -1;
			}
            break;
        case ACK:
			// ACK received, Handshake completed
            printf("\n-ACK RECEIVED... your public key has been correctly received.\n");
            break;
        case MSG:
			// Ecrypted message received
			if(decrypt_received_message(src_addr, data_count) == -1) {
				perror("Failed to  received message");
				return -1;
			}
            break;
        default:
            printf("\n-MESSAGE TYPE NOT RECOGNIZED!\n");
    }
    return 0;
}

// Manage the request of your public key 
int manage_key_request(char* src_addr) {
	uint8_t* src_pub_key = (uint8_t*) malloc(public_key_size);
    
	// Get public key from message
	memcpy(src_pub_key, server_buffer+MSG_TYPE_SIZE, public_key_size);
    printf("\n-PUBLIC KEY REQUEST FROM %s\n", src_addr);
    
	// Print received public key
	printf("Public key received:");
    print_key(src_pub_key, public_key_size);
    
	// Store info of struct
    if(store_dev_info(src_addr, src_pub_key) == -1) {
		perror("Failed to store device public key");
		return -1;
	}
    
	// Clean server buffer for response
    memset(server_buffer, 0, SERVER_BUFFER_SIZE);
    
	// Fill server_buffer with your key
	memset(server_buffer, KEY_ACK, MSG_TYPE_SIZE);
    memcpy(server_buffer+MSG_TYPE_SIZE, key->pub, public_key_size);
    
	// Send your public key
    printf("\n-REPLAYING TO %s WITH MY COMPRESSED KEY...\n", src_addr);
    udp_send(src_addr, DEFAULT_PORT, server_buffer, public_key_size+MSG_TYPE_SIZE,  DEFAULT_NUM, DEFAULT_DELAY);
    printf("KEY SENT\n");

	return 0;
}

// Send back ACK message to conclude handshake
int send_ack(char* src_addr) {
	uint8_t* src_pub_key = (uint8_t*) malloc(public_key_size);
    
	// Get public key from message
	memcpy(src_pub_key, server_buffer+MSG_TYPE_SIZE, public_key_size);
    printf("\n-RECEIVED PUBLIC KEY FROM %s PREVIOUSLY REQUESTED\n", src_addr);
    printf("Public key received:");
    print_key(src_pub_key, public_key_size);
    
	// Store info on struct
    if(store_dev_info(src_addr, src_pub_key) == -1) {
		perror("Failed to store device public key");
		return -1;
	}
    
	// Clean the server_buffer for response
    memset(server_buffer, 0, SERVER_BUFFER_SIZE);
    
	// Fill the buffer with ACK
	memset(server_buffer, ACK, MSG_TYPE_SIZE);
    
	// Send ACK
    printf("\n-SENDING ACK TO %s.\n", src_addr);
    udp_send(src_addr, DEFAULT_PORT, server_buffer, MSG_TYPE_SIZE, DEFAULT_NUM, DEFAULT_DELAY);
    printf("ACK SENT\n");

	return 0;
}

// Encrypted message received
int decrypt_received_message(char* src_addr, int data_count) {
    printf("\n-Decrypting message! Data size: %d\n", data_count);
    // Initializing aes struct
    cipher_t aes_context;
    int ret;
	// Initialize AES context 
    if(cipher_init(&aes_context, CIPHER_AES_128, (const uint8_t*)dev->secret, AES_KEY_SIZE) != CIPHER_INIT_SUCCESS ) {
		perror("Failed to initialize aes context");
		return -1;
	}
    
	// Retrieve IV
	uint8_t initialization_vector[IV_SIZE];
	memcpy(initialization_vector, server_buffer + MSG_TYPE_SIZE, IV_SIZE);

	// Decrypt content
	size_t plaintext_len = data_count - MSG_TYPE_SIZE - IV_SIZE;
	uint8_t plaintext[plaintext_len];
	uint8_t ciphertext[plaintext_len];
	memset(plaintext, 0x00, plaintext_len);
	memcpy(ciphertext, server_buffer + MSG_TYPE_SIZE + IV_SIZE, plaintext_len);

	ret = cipher_decrypt_cbc(	&aes_context, initialization_vector, 
  		  						(const uint8_t*) ciphertext, plaintext_len, plaintext);
	if(ret < 0) {
		perror("Failed to decrypt data");
		return -1;
	}
	
	// Get actual message size
	uint8_t msg_len_b = plaintext[0];
	// memcpy(&msg_len_b, plaintext, 0);
	size_t msg_len = (size_t) msg_len_b;
 	printf("MSG_LEN: %d\t, 0x%x\n", msg_len, msg_len_b); 
	// Get message (plus one to add NULL terminator)
	char msg[msg_len+1];
	memcpy(msg, plaintext + 1, msg_len);
	/* 
 	 * 	Add NULL terminator for testing purpose
 	 *	
 	 */
	msg[msg_len] = 0x00;

	printf("Message received: \"%s\" of %d bytes\tfrom: %s\n", msg, msg_len , src_addr);

	memset(server_buffer, 0x00, SERVER_BUFFER_SIZE);

	return 0;
}

// Store IP address and Public key of a device 
int store_dev_info(char* addr, uint8_t* pub_key){
    dev = (Device*) malloc(sizeof(struct device_t));
    // Get IPv6 address
    dev->ip_addr = (char*) malloc(sizeof(char)*INET6_ADDRSTRLEN);
    memcpy(dev->ip_addr, addr, INET6_ADDRSTRLEN);
    // Get pub key
    dev->pub_key = (uint8_t*) malloc(sizeof(uint8_t)*public_key_size);
    memcpy(dev->pub_key, pub_key, public_key_size);
    if(!uECC_valid_public_key(dev->pub_key, curve)){
        printf("INVALID PUB KEY!!\n");
        return -1;
    }
    // Generate and store secret
    dev->secret = (uint8_t*) malloc(sizeof(uint8_t)*curve_size);
    if(!(uECC_shared_secret(dev->pub_key, key->priv, dev->secret, curve)))
        return -1;
    // Print info stored in the struct
    printf("\n\n TESTING THE STORING FUNCTION\n");
    printf("IP Address: %s\n", dev->ip_addr);
    printf("Public key:\n");
    print_key(dev->pub_key, public_key_size);
    printf("Shared secret: \n");
    print_key(dev->secret, curve_size);
    printf("\n\n END \n");
    return 0;
}

/*
 *	Shell commands
 */

// Shell command to start key exchange
int start_exchange(int argc, char **argv){
 
    if(argc < 2){
        printf("usage: start_exchange <IPv6 address>\n");
        return -1;
    }    
    // Get dest IP address
    printf("\nSENDING PUBLIC KEY EXCHANGE REQUEST TO %s\n", argv[1]);
    // Prapare message to send
    char buf[public_key_size+MSG_TYPE_SIZE];
    memset(buf, 0, public_key_size+MSG_TYPE_SIZE);
	memset(buf, KEY_REQUEST, MSG_TYPE_SIZE);
    memcpy(buf+MSG_TYPE_SIZE, key->pub, public_key_size);
    udp_send(argv[1], DEFAULT_PORT, buf, public_key_size+MSG_TYPE_SIZE, DEFAULT_NUM, DEFAULT_DELAY);
    return 0;
}

// Shell command to send encrypted message
int send_encrypted(int argc, char **argv){
    
    if(argc < 3) {
        printf("usage: send_encrypted <IPv6 address> <msg>\n");
        return -1;
    }
    if(dev == NULL) {
        printf("Exchange pub key with a device first!\n");
        return -1;
    }
    printf("IP addr in argument: %s\n",argv[1]);
    printf("IP addr stored: %s\n", dev->ip_addr);
    if(memcmp(dev->ip_addr, argv[1], 25) != 0) {
        printf("Key exchange not yet performed with %s\n", argv[1]);
        return -1;
    }
    // Initialize aes struct
    cipher_t aes_context;

    // Initialize context
    int ret = cipher_init(&aes_context, CIPHER_AES_128,  (const uint8_t*) dev->secret, AES_KEY_SIZE);
	if(ret != CIPHER_INIT_SUCCESS) {
		printf("ERROR: %d\n", ret);
		perror("Failed to initialize aes context");
		return -1;
	}

    // Clean up server buffer
	memset(server_buffer, 0x00, SERVER_BUFFER_SIZE);

    // Set message type in server buffer
	memset(server_buffer, MSG, MSG_TYPE_SIZE);
	
	// Get new IV and populate server buffer
	uint8_t initialization_vector[IV_SIZE];
	random_bytes(initialization_vector, IV_SIZE);
	memcpy(server_buffer + MSG_TYPE_SIZE, initialization_vector, IV_SIZE);

	// Get message length
	size_t msg_len = strlen(argv[2]);
	printf("MSG_LEN: %d\t, 0x%x\n", msg_len, (uint8_t) msg_len);
	// Initialize and populate plaintext
	size_t plaintext_len = (msg_len + 1) + (AES_BLOCK_SIZE - ((msg_len +1)  % AES_BLOCK_SIZE));
	if( plaintext_len > SERVER_BUFFER_SIZE - MSG_TYPE_SIZE - IV_SIZE) {
		perror("Message to long");
		return -1;
	}
	uint8_t plaintext[plaintext_len];
	memset(plaintext, 0x00, plaintext_len);
	memset(plaintext, (uint8_t) msg_len, 1);
	memcpy(plaintext + 1, argv[2], msg_len);


    // Encrypt len+message and put it in server buffer
    uint8_t ciphertext[plaintext_len];
	memset(ciphertext, 0x00, plaintext_len);
    ret = cipher_encrypt_cbc(	&aes_context, initialization_vector,
								(const uint8_t*) plaintext, plaintext_len, ciphertext);
	if(ret < 0) {
		perror("Failed to encrypt data");
		return -1;
	}
    // cipher_encrypt((const cipher_t*)&aes_context, (const uint8_t *) argv[2], (uint8_t*) server_buffer+MSG_TYPE_SIZE);
	memcpy(server_buffer + MSG_TYPE_SIZE + IV_SIZE, ciphertext, plaintext_len);
    
    // Send encrypted message
    udp_send(argv[1], DEFAULT_PORT, server_buffer, MSG_TYPE_SIZE + IV_SIZE + plaintext_len, DEFAULT_NUM, DEFAULT_DELAY);

	memset(server_buffer, 0x00, SERVER_BUFFER_SIZE);

    return 0;
}

/*
 *	Start server functions
 */

// Start server
void *_server_thread(void *args) {
    // Start server
    struct sockaddr_in6 server_addr;
    uint16_t port;
    msg_init_queue(server_msg_queue, SERVER_MSG_QUEUE_SIZE);
    server_socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    // Variables to retrieve src address
    char src_addr[INET6_ADDRSTRLEN];
    /* parse port */
    port = atoi(((char*) args));
    if (port == 0) {
        puts("Error: invalid port specified");
        return NULL;
    }
    server_addr.sin6_family = AF_INET6;
    memset(&server_addr.sin6_addr, 0, sizeof(server_addr.sin6_addr));
    server_addr.sin6_port = htons(port);
    if (server_socket < 0) {
        puts("error initializing socket");
        server_socket = 0;
        return NULL;
    }
    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        server_socket = -1;
        puts("error binding socket");
        return NULL;
    }
    printf("Success: started UDP server on port %" PRIu16 "\n", port);
    while (1) {
        int ret;
        struct sockaddr_in6 src;
        socklen_t src_len = sizeof(struct sockaddr_in6);
        memset(server_buffer, 0, SERVER_BUFFER_SIZE);
        if ((ret = recvfrom(server_socket, server_buffer, sizeof(server_buffer), 0,
                            (struct sockaddr *)&src, &src_len)) < 0) {
            puts("Error on receive");
        }
        else if (ret == 0) {
            puts("Peer did shut down");
        }
        else {
            inet_ntop(AF_INET6, (void*)&src.sin6_addr, src_addr, INET6_ADDRSTRLEN );
            if(src_addr == NULL) {
                printf("Failed to parse IP address");
                continue;
            }
            handle_message(src_addr, ret);
        }
    }
    return NULL;
}

// Start UDP server
int udp_start_server(char *port_str) {
	int ret = 0;

    // Check if server is already running
    if (server_socket >= 0) {
        puts("Error: server already running");
        return 1;
    }
    
    /*  
     *  Public/private key generation
     */
    
    // Curve initialization
    curve = uECC_secp256r1();
    curve_size = uECC_curve_private_key_size(curve);
    public_key_size = uECC_curve_public_key_size(curve);
    // Initialize the key struct
    key = (Key*)malloc(sizeof(Key));
    key->priv = (uint8_t*) malloc(sizeof(uint8_t)*curve_size); 
    key->pub = (uint8_t*) malloc(sizeof(uint8_t)*public_key_size);
    
    // Generate the keys (private, public, public compressed)
    ret = generate_keys(key, curve);
    if(ret == -1) {
		perror("Failed to generate keys");
		return 1;
	}
    /* start server (which means registering pktdump for the chosen port) */
    if (thread_create(server_stack, sizeof(server_stack), THREAD_PRIORITY_MAIN - 1,
                      THREAD_CREATE_STACKTEST,
                      _server_thread, port_str, "UDP server") <= KERNEL_PID_UNDEF) {
        server_socket = -1;
        puts("error initializing thread");
        return 1;
    }
    return 0;
}
