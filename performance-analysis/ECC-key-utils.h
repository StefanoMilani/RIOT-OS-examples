/**
 * @file        ECC-key-utils.h
 * @brief       Contains declaration of structs and functions
 * 				to manage keys
 *
 * @author      Stefano Milani <stefano.milani96@gmail.com>
 *
 */
#ifndef ECC_UTILS_H
#define ECC_UTILS_H

#include <unistd.h>

// Compute fake server keys
int generate_fake_server_keys(void);

// Compute priv/pub key pair
int compute_keys(int argc, char* argv[]);

// Compress public key
int compress_key(int argc, char* argv[]);

// Decompress public key
int decompress_key(int argc, char* argv[]);

// Uncompress key and compute secret
int compute_secret(int argc, char* argv[]);

// Encrypt message using AES-128 bits
int encrypt_text(int argc, char* argv[]);

#endif // ECC_UTILS_H
