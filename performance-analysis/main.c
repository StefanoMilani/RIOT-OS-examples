#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#define DEFAULT_SLEEP 20

#include "ECC-key-utils.h"

// Shell library
#include "xtimer.h"

int main(void) {

	if(generate_fake_server_keys() < 0) {
		perror("Failed to generate starting key");
		return -1;
	}

	printf("SLEEPING %d SECONDS\n",DEFAULT_SLEEP);
	xtimer_sleep(DEFAULT_SLEEP);


	printf("START COMPUTE ECC KEYS TEST\n");
	compute_keys(0, NULL);
	printf("KEYS COMPUTED... SLEEPING %d SECONDS\n", DEFAULT_SLEEP);
	xtimer_sleep(DEFAULT_SLEEP);

	printf("START COMPRESS ECC PUBLIC KEY TEST\n");
	compress_key(0, NULL);
	printf("KEY COMPRESSED... SLEEPING %d SECONDS\n", DEFAULT_SLEEP);
	xtimer_sleep(DEFAULT_SLEEP);

	printf("START DECOMPRESS ECC PUBLIC KEY TEST\n");
	decompress_key(0, NULL);
	printf("KEY DECOMPRESSED... SLEEPING %d SECONDS\n", DEFAULT_SLEEP);
	xtimer_sleep(DEFAULT_SLEEP);

	printf("START GENERATE ECC SECRET TEST\n");
	compute_secret(0, NULL);
	printf("SECRET COMPUTED... SLEEPING %d SECONDS\n", DEFAULT_SLEEP);
	xtimer_sleep(DEFAULT_SLEEP);

	printf("START AES128-BITS ENCRYPT TEST\n");
	encrypt_text(0, NULL);
	printf("MESSAGE ENCRYPTED... Finished\n");

    return 0;
}
