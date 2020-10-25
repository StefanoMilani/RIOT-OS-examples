/**
 * @file        key-management.c
 * @brief       Contains implementations of key management functions
 *
 * @author      Stefano Milani <stefano.milani96@gmail.com>
 *
 */

#include "key-management.h"

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
	/*
 	 *	TODO: Try to set a more secure seed even if hwrng not available on m3 board
 	 *	random_init(uint32_t seed);
 	 */
	random_bytes(key, size);
}


// Generate private, public and compressed keys
int generate_keys(Key *key, const struct uECC_Curve_t *curve) {
	
	// Private key
	generate_private_key(key->priv, uECC_curve_private_key_size(curve));
	printf("Private key:\n");
	print_key(key->priv, uECC_curve_private_key_size(curve));
	// Compute public key
	if(!uECC_compute_public_key(key->priv, key->pub, curve)) {
		perror("Failed to compute public key");
		return -1;
	}
	printf("Public key:\n");
	print_key(key->pub, uECC_curve_public_key_size(curve));
	return 0;
}
