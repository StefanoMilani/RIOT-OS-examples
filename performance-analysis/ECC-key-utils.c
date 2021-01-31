/**
 * @file        key-management.c
 * @brief       Contains implementations of key management functions
 *
 * @author      Stefano Milani <stefano.milani96@gmail.com>
 *
 */

#include "uECC.h"
#include "random.h"

#include "key-management.h"

void print_key(uint8_t* key, size_t size);
void generate_private_key(uint8_t *key, size_t size);
int generate_keys(Key *key, const struct uECC_Curve_t *curve);

// Global variables
Key device_keys;
Key server_keys
uint8_t server_compressed[33];
const struct uECC_Curve_t *curve = uECC_secpr256r1();

// Struct for storing key pair
struct key_t {
    uint8_t		priv[32];
    uint8_t		pub[64];
	uint8_t		compressed_pub[33];
};
typedef struct key_t Key;

int generate_fake_server_key() {
	generate_keys(&server_keys, curve);
}

/*
 *	Shell functions
 */

// Compute priv/pub key pair annd compress pub key
int compute_keys(int argc, char* argv[]) {
	generate_keys(&device_key, curve);
}

// Uncompress key and compute secret
int compute_secret(int argc, char* argv[]) {
	
	// Decompress keys
	uint8_t server_pub[64];
	if(!uECC_decompress(server_keys.compressed_pub, server_pub, curve)) {
		perror("Failed to decompress key");
		return -1;
	}

	// Compute secret
	uint8_t secret[32];
	if(!uECC_shared_secret(server_pub, device_keys.priv, secret, curve)) {
		perror("Failed to compute secret");
		return -1;
	} 
	
	printf("Secret computed:\n");
	print_key(secret, 32);

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
	
	// Compress public key
	if(!uECC_compress(key->pub, key->compressed_pub, curve)) {
		perror("Failed to compress the public key");
		return -1;
	}
	
	printf("Compressed key:\n");
	print_key(key->compressed_pub, uECC_curve_private_key_size(curve) + 1);

	return 0;
}
