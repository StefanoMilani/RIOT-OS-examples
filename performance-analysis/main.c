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

#include "ECC-key-utils.h"

// Shell library
#include "shell.h"

// Add custon shell command
static const shell_command_t commands[] = {
	{ "compute-ecc-keys", "Compute a pir of privat/public ECC key and compress the public key", compute_keys},
	{ "generate-secret", "Uncompress public key and compute ECC-DH secret", compute_secret}
    { NULL, NULL, NULL}
}; 

int main(void) {

	if(generate_fake_server_keys() < 0) {
		perror("Failed to generate fake server key");
		return -1;
	}

    // Start shell
    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(commands, line_buf, SHELL_DEFAULT_BUFSIZE);

    /* should be never reached */
    return 0;
}
