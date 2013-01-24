/*
 * struitl.c
 *
 *  Created on: 29/12/2012
 *      
 */

#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <regex.h>
#include <string.h>

#include "strutil.h"
#include "regpx.h"
#include "aes.h"

/*****************************************************************************/
/* Constants Declaration                                                     */
/*****************************************************************************/

#define MAX_REGEX_GROUPS		20

/*****************************************************************************/
/* Data Structres Declaration                                                */
/*****************************************************************************/

/*****************************************************************************/
/* Local Functions Declaration                                               */
/*****************************************************************************/

/*****************************************************************************/
/* Global Variables                                                          */
/*****************************************************************************/

/*****************************************************************************/
/* Functions Implementation                                                  */
/*****************************************************************************/

char* strhex(const char* s){
	//TODO
	return NULL;
}

char* unliteral(const char* s){
	//TODO
	return NULL;
}

char* hex2str(const char* s){
	//TODO
	return NULL;
}

char* lowOrder(const char* src) {
	size_t src_size = strlen(src);
	char* lorder = malloc(src_size*sizeof(char*));
	memset(lorder, 0, src_size);
	int i;
	for (i = src_size - 2; i >= 0; i-=2) {
		sprintf(lorder, "%s%c%c", lorder, src[i], src[i+1]);
	}
	return lorder;
}

/*
 * trim (char) c from right-side of string *p
 */
char *strtrim_right(register char *p, register char c){
	register char *end;
	register int len;

	len = strlen(p);
	while (*p && len) {
		end = p + len - 1;

		if(c == *end)
			*end = 0;
		else
			break;
		len = strlen(p);
	}
	return (p);
}

char *trimwhitespace(char *str){
  char *end;

  // Trim leading space
  while(isspace(*str)) str++;

  if(*str == 0)  // All spaces?
    return str;

  // Trim trailing space
  end = str + strlen(str) - 1;
  while(end > str && isspace(*end)) end--;

  // Write new null terminator
  *(end+1) = 0;

  return str;
}


char* str_right_pad(char *dest, const char *src, const char* pad,
		const size_t sz) {

	memcpy(dest, pad, sz);
	dest[sz] = 0x0;
	memcpy(dest, src, strlen(src));
	return dest;
}

char* str_left_pad(char *dest, const char *src, const char* pad,
		const size_t sz) {

	memcpy(dest, pad, sz);
	dest[sz] = 0x0;
	memcpy(dest + sz - strlen(src), src, strlen(src));
	return dest;
}

char** regex_match(const char* pattern, const char* data){
	char** result = NULL;
	regex_t    regex_info;
	int        rc;
	size_t     nmatch = MAX_REGEX_GROUPS;
	regmatch_t pmatch[MAX_REGEX_GROUPS];

	if (REG_NOERROR == (rc = regcomp(&regex_info, pattern, REG_EXTENDED))) {
		if (REG_NOERROR == (rc = regexec(&regex_info, data, nmatch, pmatch, 0))) {
			result = malloc(MAX_REGEX_GROUPS * sizeof(char*));
			memset(result, 0, MAX_REGEX_GROUPS * sizeof(char*));

			int i;
			for(i=0; i < MAX_REGEX_GROUPS && pmatch[i].rm_so!=-1; i++){
				size_t match_size = pmatch[i].rm_eo - pmatch[i].rm_so;
				result[i] = malloc((match_size + 1)*sizeof(char*));
				memcpy(result[i], &data[pmatch[i].rm_so], match_size);
				result[i][match_size] = '\0';
			}
		}
	}
	return result;
}

void inline free_regex_result(char** results){
	if(results == NULL)
		return;
	int i;
    for(i=0; results[i] != NULL; i++){
    	free(results[i]);
    }
	free(results);
}


int sha256hex(const char *data, size_t data_length, char outputHex[SHA256_DIGEST_LENGTH*2+1]) {
	if(data == NULL)
		return EXIT_FAILURE;
	if(outputHex == NULL)
		return EXIT_FAILURE;

	unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data, strlen(data));
    SHA256_Final(hash, &sha256);
    int i = 0;
    for(i = 0; i < SHA256_DIGEST_LENGTH; i++){
        sprintf(outputHex + (i * 2), "%02x", hash[i]);
    }
    outputHex[64] = '\0';

    return EXIT_SUCCESS;
}

int md5hex(const char *data, size_t data_length, char outputHex[MD5_DIGEST_LENGTH*2+1]){
	if(data == NULL)
		return EXIT_FAILURE;
	if(outputHex == NULL)
		return EXIT_FAILURE;

	unsigned char hash[MD5_DIGEST_LENGTH];
	MD5_CTX md5;
	MD5_Init(&md5);
	MD5_Update(&md5, data, data_length);
	MD5_Final(hash, &md5);
	int i = 0;

	for(i = 0; i < MD5_DIGEST_LENGTH; i++){
		sprintf(outputHex + (i * 2), "%02x", hash[i]);
	}
	outputHex[33] = '\0';

	return EXIT_SUCCESS;
}


/**
 * MD5 Hash utility
 */
void md5bin(const char *data, long data_length, unsigned char* result){
	MD5((unsigned char*) data, data_length, result);
}

/*
 * Decrypt using Rijndael AES-256
 */
int decrypt_aes256_cdc(const unsigned char* ct, size_t ct_size,
				unsigned char *key_data, size_t key_data_len, char* pt){
	EVP_CIPHER_CTX en, de;
	unsigned int salt[] = {12345, 54321};
	if (aes_init_cdc(key_data, key_data_len, (unsigned char *)&salt, &en, &de)) {
		printf("Couldn't initialize AES cipher\n");
	    return -1;
	}
	int len = ct_size + 1;
	pt = (char *)aes_decrypt(&de, (unsigned char*)ct, &len);

	EVP_CIPHER_CTX_cleanup(&en);
	EVP_CIPHER_CTX_cleanup(&de);

	if(len == 0)
		return EXIT_FAILURE;
	return EXIT_SUCCESS;
}

/*
 * Decrypt using Rijndael AES-256 EDC
 */
int decrypt_aes256_ecb(
		const unsigned char* ct, size_t ct_size,
		unsigned char *key_data, size_t key_data_len,
		char* pt){
	EVP_CIPHER_CTX en, de;
	unsigned int salt[] = {12345, 54321};
	if (aes_init_ecb(key_data, key_data_len, (unsigned char *)&salt, &en, &de)) {
		printf("Couldn't initialize AES cipher\n");
	    return -1;
	}
	int len = ct_size + 1;
	pt = (char *)aes_decrypt(&de, (unsigned char*)ct, &len);

	EVP_CIPHER_CTX_cleanup(&en);
	EVP_CIPHER_CTX_cleanup(&de);

	if(len == 0)
		return EXIT_FAILURE;
	return EXIT_SUCCESS;
}


void md5bin2hex(unsigned char hash[MD5_DIGEST_LENGTH], char hex[MD5_DIGEST_LENGTH*2+1]) {
    int i;
    for(i = 0; i < MD5_DIGEST_LENGTH; i++) {
    	sprintf(hex + (i * 2), "%02x", hash[i]);
    }
    hex[MD5_DIGEST_LENGTH*2] = '\0';
}

// You must free the result if result is non-NULL.
char *str_replace(char *orig, char *rep, char *with) {
    char *result; // the return string
    char *ins;    // the next insert point
    char *tmp;    // varies
    int len_rep;  // length of rep
    int len_with; // length of with
    int len_front; // distance between rep and end of last rep
    int count;    // number of replacements

    if (!orig)
        return NULL;
    if (!rep || !(len_rep = strlen(rep)))
        return NULL;
    if (!(ins = strstr(orig, rep)))
        return NULL;
    if (!with)
        with = "";
    len_with = strlen(with);

    for (count = 0; (tmp = strstr(ins, rep)); ++count) {
        ins = tmp + len_rep;
    }

    // first time through the loop, all the variable are set correctly
    // from here on,
    //    tmp points to the end of the result string
    //    ins points to the next occurrence of rep in orig
    //    orig points to the remainder of orig after "end of rep"
    tmp = result = malloc(strlen(orig) + (len_with - len_rep) * count + 1);

    if (!result)
        return NULL;

    while (count--) {
        ins = strstr(orig, rep);
        len_front = ins - orig;
        tmp = strncpy(tmp, orig, len_front) + len_front;
        tmp = strcpy(tmp, with) + len_with;
        orig += len_front + len_rep; // move to next "end of rep"
    }
    strcpy(tmp, orig);
    return result;
}


void log_debug(char* d){
#ifdef _PMA_DEBUG_
	puts(d);
#endif
}


char* pdfhex(char* hex){
	int i;
	size_t hex_size = strlen(hex);
	char* ret = malloc(2*hex_size+1);

	memset(ret, 0, 2*hex_size);

	for (i = 0; i < hex_size; i++) {
		if (i+2 <= hex_size &&
				hex[i] == '#' &&
				isalnum(hex[i+1]) &&
				isalnum(hex[i+2])) {
			char n[3];
			sprintf(n,"%c%c", hex[i+1], hex[i+2]);
			char c = strtoul(n, 0, 16);
			sprintf(ret, "%s%c", ret, c);
			i+=2;
 		} else {
			sprintf(ret, "%s%c", ret, hex[i]);
		}
	}

  return ret;
}



