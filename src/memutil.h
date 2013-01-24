/*
 * memutil.h
 *
 *  Created on: 02/01/2013
 *      
 */

#ifndef MEMUTIL_H_
#define MEMUTIL_H_

/*****************************************************************************/
/* Begin Functions                                                           */
/*****************************************************************************/
#ifdef __cplusplus
extern "C" {
#endif

/*
 * Checks if a string is not NULL and free its memory
 */
void free_is_not_null(char* c);

#ifdef __cplusplus
}
#endif
/*****************************************************************************/
/* End Functions                                                             */
/*****************************************************************************/

#endif /* MEMUTIL_H_ */
