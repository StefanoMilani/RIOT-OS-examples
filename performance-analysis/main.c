#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#define TESTROUNDS 60
#define DEFAULT_SLEEP 20

#include "ECC-key-utils.h"

// Shell library
#include "shell.h"
#include "xtimer.h"

// Add custom shell command
static const shell_command_t commands[] = {
	{ "compute-ecc-keys", "Compute a pair of private/public ECC key", compute_keys},
	{ "compress-ecc-public-key", "Compress a public ECC key", compress_key },
	{ "decompress-ecc-public-key", "De-compress a compressed public ECC key", decompress_key},
	{ "generate-secret", "Compute ECC-DH secret", compute_secret},
	{ "encrypt-message", "Encrypt a message using AES-128 bits", encrypt_text},
	{ NULL, NULL, NULL}
}; 

int main(void) {

	if(generate_fake_server_keys() < 0) {
		perror("Failed to generate starting key");
		return -1;
	}

	printf("SLEEPING  SECONDS\n");
	xtimer_sleep(DEFAULT_SLEEP);

	int i = 0;

	for(i = 0; i < TESTROUNDS ; i++) {
		compute_keys(0, NULL);
	}
	printf("KEYS COMPUTED... SLEEPING 20 SECONDS\n");
	xtimer_sleep(DEFAULT_SLEEP);

	for(i = 0; i < TESTROUNDS ; i++) {
		compress_key(0, NULL);
	}
	printf("KEY COMPRESSED... SLEEPING 20 SECONDS\n");
	xtimer_sleep(DEFAULT_SLEEP);

	for(i = 0; i < TESTROUNDS ; i++) {
		decompress_key(0, NULL);
	}
	printf("KEY DECOMPRESSED... SLEEPING 20 SECONDS\n");
	xtimer_sleep(DEFAULT_SLEEP);

	for(i = 0; i < TESTROUNDS ; i++) {
		compute_secret(0, NULL);
	}
	printf("SECRET COMPUTED... SLEEPING 20 SECONDS\n");
	xtimer_sleep(DEFAULT_SLEEP);

	for(i = 0; i < TESTROUNDS ; i++) {
		encrypt_text(0, NULL);
	}
	printf("MESSAGE ENCRYPTED... Finished\n");

    return 0;
	// Start shell
	char line_buf[SHELL_DEFAULT_BUFSIZE];
 	shell_run(commands, line_buf, SHELL_DEFAULT_BUFSIZE);

    /* should be never reached */
    return 0;
}
