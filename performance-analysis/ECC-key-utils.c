/**
 * @file        ECC-key-utils.c
 * @brief       Contains implementations of key management functions
 *
 * @author      Stefano Milani <stefano.milani96@gmail.com>
 *
 */

#include <stdio.h>

#include "uECC.h"
#include "random.h"
#include "xtimer.h"
#include "crypto/aes.h"

#include "ECC-key-utils.h"

#define TESTROUNDS 100

// Struct for storing key pair
struct key_t {
    uint8_t		priv[32];
    uint8_t		pub[64];
	uint8_t		compressed_pub[33];
};
typedef struct key_t Key;

void print_key(uint8_t* key, size_t size);
void generate_private_key(uint8_t *key, size_t size);
int generate_keys(Key *key, const struct uECC_Curve_t *curve);

// Global variables
Key device_keys;
Key server_keys;
uint8_t secret[32];
uint8_t server_compressed[33];
const struct uECC_Curve_t *curve;
uint8_t plaintext[AES_BLOCK_SIZE];
uint8_t ciphertext[AES_BLOCK_SIZE];


// Generate fake server keys
int generate_fake_server_keys(void) {
	curve = uECC_secp256r1();

	if(generate_keys(&server_keys, curve)) {
		printf("Failed to generate fake server keys\n");
		return -1;
	}

	if(generate_keys(&device_keys, curve)){ 
		printf("Failed to generate device keys\n");
		return -1;
	}

	if(!uECC_shared_secret(server_keys.pub, device_keys.priv, secret, curve)) {
		perror("Failed to compute secret");
		return -1;
	} 
	random_bytes(plaintext, AES_BLOCK_SIZE);	
	return 0; 
}

/*
 *	Shell functions
 */

// Compute priv/pub key pair
int compute_keys(int argc, char* argv[]) {
	argv++;
	argc++;	
	
	uint32_t avg_time = 0;

	for(uint8_t i = 0; i < TESTROUNDS; i++) {
		// Start Timer
		uint32_t start = xtimer_now_usec();

		// Private key
		generate_private_key(device_keys.priv, uECC_curve_private_key_size(curve));
		
		// Compute public key
		if(!uECC_compute_public_key(device_keys.priv, device_keys.pub, curve)) {
			perror("Failed to compute public key");
			return -1;
		}
		
		// End Timer
		uint32_t end = xtimer_now_usec();
		
		avg_time += (end-start);
	}

	printf("Generated pair of private/public ECC key\nAverage elapsed time: %ld microsenconds\n", avg_time/TESTROUNDS);

	return 0;
}

// Compress public key
int compress_key(int argc, char* argv[]) {
	argv++;
	argc++;

	uint32_t avg_time = 0;

	for(uint8_t i = 0; i < TESTROUNDS; i++) {
		// Start time
		uint32_t start = xtimer_now_usec();
		
		// Compress public key
		uECC_compress(server_keys.pub, server_keys.compressed_pub, curve);
		
		// End time
		uint32_t end = xtimer_now_usec();
		
		avg_time += (end-start);
	}
	printf("Compressed public ECC key.\naverage elapsed time: %ld microseconds\n", avg_time/TESTROUNDS);

	return 0;
}

// Decompress public key
int decompress_key(int argc, char* argv[]) {
	uint32_t avg_time = 0;

	for(uint8_t i = 0; i < TESTROUNDS; i++) {
		// Start time
		uint32_t start = xtimer_now_usec();

		// Decompress keys
		uint8_t server_pub[64];
		uECC_decompress(server_keys.compressed_pub, server_keys.pub, curve);

		// End time
		uint32_t end = xtimer_now_usec();
		
		avg_time += (end-start);
	}

	printf("Decompressed public key\naverage elapsed time: %ld microseconds\n", avg_time/TESTROUNDS);

	return 0;
	
}

// Uncompress key and compute secret
int compute_secret(int argc, char* argv[]) {
	argv++;
	argc++;	
	
	uint32_t avg_time = 0;

	for(uint8_t i = 0; i < TESTROUNDS; i++) {
		// Start time
		uint32_t start = xtimer_now_usec();
		// Compute secret
		if(!uECC_shared_secret(server_keys.pub, device_keys.priv, secret, curve)) {
			perror("Failed to compute secret");
			return -1;
		} 
		
		// End time
		uint32_t end = xtimer_now_usec();
		
		avg_time += (end-start);
	}

	printf("Secret computed\nAverage elapsed time: %ld microseconds\n", avg_time/TESTROUNDS);
	
	return 0;
}

// Encrypt with AES
int encrypt_text(int argc, char* argv[]) {    

	// Initialize aes struct
	cipher_context_t aes_context;

	uint32_t avg_time = 0;

	for(uint8_t i = 0; i < TESTROUNDS; i++) {
		// Start time
		uint32_t start = xtimer_now_usec();

		// Initialize context
		int ret = aes_init(&aes_context, (const uint8_t*) secret, AES_KEY_SIZE);
		if(ret != CIPHER_INIT_SUCCESS) {
			printf("ERROR: %d\n", ret);
			perror("Failed to initialize aes context");
			return -1;
		}

		// Encrypt len+message and put it in server buffer
		ret = aes_encrypt(&aes_context, (const uint8_t*) plaintext, ciphertext);
		if(ret < 0) {
			perror("Failed to encrypt data");
			return -1;
		}

		// End time
		uint32_t end = xtimer_now_usec();

		avg_time += (end-start);
	}
	
	printf("Text encrypted.\nAverage elapsed time: %ld microseconds\n", avg_time/TESTROUNDS);	    

	return 0;
}

// Print key
void print_key(uint8_t* key, size_t size) {
    for(size_t i = 0; i < size; i++){
        if(i%5 == 0)
            printf("\n");
        printf("0x%x\t", key[i]);
    }
    printf("\n");
}

// Generate private random key (without hwrng)
void generate_private_key(uint8_t *key, size_t size) {
	random_bytes(key, size);
}

// Generate private, public and compressed keys
int generate_keys(Key *key, const struct uECC_Curve_t *curve) {
	
	// Private key
	generate_private_key(key->priv, uECC_curve_private_key_size(curve));
	// printf("Private key:\n");
	// print_key(key->priv, uECC_curve_private_key_size(curve));
	
	// Compute public key
	if(!uECC_compute_public_key(key->priv, key->pub, curve)) {
		perror("Failed to compute public key");
		return -1;
	}
	// printf("Public key:\n");
	// print_key(key->pub, uECC_curve_public_key_size(curve));
	
	// Compress public key
	uECC_compress(key->pub, key->compressed_pub, curve);
	
	// printf("Compressed key:\n");
	// print_key(key->compressed_pub, uECC_curve_private_key_size(curve) + 1);

	printf("--- Keys generated successfully ---\n");
	return 0;
}
