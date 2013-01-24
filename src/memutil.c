/*
 * memutil.c
 *
 *  Created on: 02/01/2013
 *      
 */

#include <stdlib.h>

#include "memutil.h"

void inline free_is_not_null(char* c){
	if(c != NULL){
		free(c);
	}
}
