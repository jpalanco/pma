/*
 * pma.h
 *
 *  Created on: 24/12/2012
 *      
 */

#ifndef PMA_H_
#define PMA_H_

#include "pma_def.h"

/*****************************************************************************/
/* Begin Functions                                                           */
/*****************************************************************************/
#ifdef __cplusplus
extern "C" {
#endif


/*
 * Initialize PMA Library
 */
int pma_initialize();

/*
 * Initialize PMA Results Structure
 */
void init_pma_results(PMA_RESULTS* result);

/*
 * Free PMA Results Structure
 */
void free_pma_results(PMA_RESULTS* result);

/*
 * Analyze the Target File for Malware
 */
int pma_analyze_file(const char* targetFileName, PMA_RESULTS* result);


#ifdef __cplusplus
}
#endif
/*****************************************************************************/
/* End Functions                                                             */
/*****************************************************************************/
#endif /* PMA_H_ */
