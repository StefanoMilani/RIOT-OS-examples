/**
 * @file        utils.h
 * @brief       Contains declaration of useful structs and functions
 *
 * @author      Stefano Milani <stefano.milani96@gmail.com>
 *
 */

#include "utils.h"

// Print key
void print_key(uint8_t* key, size_t size){
    for(size_t i = 0; i < size; i++){
        if(i%5 == 0)
            printf("\n");
        printf("0x%x\t", key[i]);
    }
    printf("\n");
}

// Generate private random key (without kwrng)
void generate_private_key(uint8_t *key, size_t size){
   // random_init(xtimer_now_usec());
   random_bytes(key, size);
}


// Generate private, public and compressed keys
void generate_keys(Key *key, const struct uECC_Curve_t *curve) {
    // Private key
    generate_private_key(key->priv, uECC_curve_private_key_size(curve));
    printf("Private key:\n");
    print_key(key->priv, uECC_curve_private_key_size(curve));
    // Public key
    uECC_compute_public_key(key->priv, key->pub, curve);
    if(uECC_valid_public_key(key->pub, curve)){
       printf("Public key creation failed!!\n");
       return;
    }
    printf("Public key:\n");
    print_key(key->pub, uECC_curve_public_key_size(curve));
}
