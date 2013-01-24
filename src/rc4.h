/*
 * rc4.h
 *
 *  Created on: 04/01/2013
 *      
 */

#ifndef RC4_H_
#define RC4_H_

/*****************************************************************************/
/* Constants Declaration                                                     */
/*****************************************************************************/

/*****************************************************************************/
/* Data Structres Declaration                                                */
/*****************************************************************************/
typedef struct rc4_key {
	unsigned char state[256];
	unsigned char x;
	unsigned char y;
} RC4_KEY;


/*****************************************************************************/
/* Begin Functions                                                           */
/*****************************************************************************/
#ifdef __cplusplus
extern "C" {
#endif

void prepare_key(unsigned char *key_data_ptr, int key_data_len, RC4_KEY *key);

void rc4(unsigned char *buffer_ptr, int buffer_len, RC4_KEY *key);

#ifdef __cplusplus
}
#endif
/*****************************************************************************/
/* End Functions                                                             */
/*****************************************************************************/
#endif /* RC4_H_ */
