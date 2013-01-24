/*
 * strutil.h
 *
 *  Created on: 24/12/2012
 *      
 */

#ifndef STRUIL_H_
#define STRUIL_H_

#include <openssl/sha.h>
#include <openssl/md5.h>

/*****************************************************************************/
/* Begin Functions                                                           */
/*****************************************************************************/
#ifdef __cplusplus
extern "C" {
#endif

/*
 * Returns a Hexadecimal Representation of a String
 */
char* strhex(const char* s);

/*
 * Replaces all special scaped string for its ascii value
 */
char* unliteral(const char* s);

/*
 * Returns the String representation of a Hexadecimal Representation of a String
 */
char* hex2str(const char* s);

char** regex_match(const char* pattern, const char* data);

/*
 * Frees regex result
 */
void free_regex_result(char** result);

/**
 * SHA-256 Hash utility
 */
int sha256hex(const char *data, size_t data_length, char outputHex[SHA256_DIGEST_LENGTH*2+1]);

/**
 * MD5 Hash utility in Hex Format
 */
int md5hex(const char *data, size_t data_length, char outputHex[MD5_DIGEST_LENGTH*2+1]);

/**
 * MD5 Hash utility in Binary Format
 */
void md5bin(const char *data, long data_length, unsigned char* outputBuffer);

/*
 * Decrypt using Rijndael AES-256 CDC
 */
int decrypt_aes256_cdc(
		const unsigned char* ct, size_t ct_size,
		unsigned char *key_data, size_t key_data_len,
		char* pt);

/*
 * Decrypt using Rijndael AES-256 ECB
 */
int decrypt_aes256_ecb(
		const unsigned char* ct, size_t ct_size,
		unsigned char *key_data, size_t key_data_len,
		char* pt);

void md5bin2hex(unsigned char md[MD5_DIGEST_LENGTH], char hex[MD5_DIGEST_LENGTH*2+1]);

int hex2bin(const char* hexString, unsigned char* binResult);

/*
 * trim (char) c from right-side of string *p
 */
char *strtrim_right(register char *p, register char c);

char *trimwhitespace(char *str);

/*
 * Right Pad a String
 */
char* str_right_pad(char *dest, const char *src, const char* pad,
		const size_t sz);

/*
 * Left Pad a String
 */
char* str_left_pad(char *dest, const char *src, const char* pad,
		const size_t sz);

char* lowOrder(const char* src);

/**
 * Replace string with another
 */
char *str_replace(char *orig, char *rep, char *with);


void log_debug(char* d);

char* pdfhex(char* hex);

#ifdef __cplusplus
}
#endif
/*****************************************************************************/
/* End Functions                                                             */
/*****************************************************************************/
#endif/* STRUIL_H_*/
