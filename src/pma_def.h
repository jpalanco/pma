/*
 * pma_def.h
 *
 *  Created on: 27/12/2012
 *      
 */

#ifndef PMA_DEF_H_
#define PMA_DEF_H_

typedef int BOOL;
#define FALSE		0
#define TRUE		1

/*****************************************************************************/
/* Begin Data Structures                                                     */
/*****************************************************************************/

typedef struct {
	BOOL	not_pdf;				/* TRUE is file is not a PDF			*/
	int		exploit;				/* Number of Exploits Found				*/
	int		hits;					/* Number of Hits						*/
	BOOL	completed;				/* Is Completed?						*/
	BOOL	is_malware;				/* Is Malware?							*/
	char*	summary;				/* Summary string						*/
	int		severity;				/* Severity of the malware				*/

	BOOL	encrypted;				/* 										*/
	char*	key;					/* 										*/
	int		encrypt_alg;			/* 										*/
	int		key_length;				/* 										*/

}PMA_RESULTS;

/*****************************************************************************/
/* End Data Structures                                                       */
/*****************************************************************************/

#endif /* PMA_DEF_H_ */
