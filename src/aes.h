/*
 * aes.h
 *
 *  Created on: 27/12/2012
 *      
 */

#ifndef AES_H_
#define AES_H_

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

/**
 * Create an 256 bit key and IV using the supplied key_data. salt can be added for taste.
 * Fills in the encryption and decryption ctx objects and returns 0 on success
 **/
int aes_init_cdc(unsigned char *key_data,
			int key_data_len,
			unsigned char *salt,
			EVP_CIPHER_CTX *e_ctx,
            EVP_CIPHER_CTX *d_ctx);

/**
 * Create an 256 bit key and IV using the supplied key_data. salt can be added for taste.
 * Fills in the encryption and decryption ctx objects and returns 0 on success
 **/
int aes_init_ecb(unsigned char *key_data,
			int key_data_len,
			unsigned char *salt,
			EVP_CIPHER_CTX *e_ctx,
            EVP_CIPHER_CTX *d_ctx);

/*
 * Encrypt *len bytes of data
 * All data going in & out is considered binary (unsigned char[])
 */
unsigned char *aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len);

/*
 * Decrypt *len bytes of ciphertext
 */
unsigned char *aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext, int *len);

#endif /* AES_H_ */
