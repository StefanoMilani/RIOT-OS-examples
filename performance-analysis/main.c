
#include <unistd.h>
#include <stdio.h>

#include "ECC-key-utils.h"

// Shell library
#include "shell.h"

// Add custom shell command
static const shell_command_t commands[] = {
	{ "compute-ecc-keys", "Compute a pair of private/public ECC key", compute_keys},
	{ "compress-ecc-public-key", "Compress a public ECC key", compress_key },
	{ "decompress=ecc=public-key", "De-compress a compressed public ECC key", decompress_key},
	{ "generate-secret", "Compute ECC-DH secret", compute_secret},
	{ "encrypt-message", "Encrypt a message using AES-128 bits", encrypt_text},
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
