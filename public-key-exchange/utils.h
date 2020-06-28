/**
 * @file        utils.h
 * @brief       Contains declaration of useful structs and functions
 *
 * @author      Stefano Milani <stefano.milani96@gmail.com>
 *
 */
#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
// include random library
#include "random.h"
// include xtimer library
#include "xtimer.h"
// micro-ecc library
#include "tinycrypt/ecc_dh.h"

// Struct for curve 
typedef struct uECC_Curve_t* ECC_Curve;

// Struct for storing key pair
struct key_t {
    uint8_t*    priv;
    uint8_t*    pub;
};
typedef struct key_t Key;

// Struct for remote host pub key
struct device_t {
  char*         ip_addr;
  uint8_t*      pub_key;
  uint8_t*      secret;
};
typedef struct device_t Device;

// Print key
void print_key(uint8_t* key, size_t size);

// Generate private random key (without kwrng)
void generate_private_key(uint8_t *key, size_t size);

// Generate private, public and compressed keys
void generate_keys(Key *key, const struct uECC_Curve_t *curve);

#endif // UTILS_H
