//#include <pcre.h>
//#include <stdio.h>
//#include <string.h>
#include "regpx.h"

#define PCRE_COMP_DEF_OPT	PCRE_CASELESS|PCRE_DOTALL
#define PCRE_EXEC_DEF_OPT	PCRE_NO_UTF8_CHECK

pcre *regex_info_compile(char* regxp) {
	pcre *re; 					/* Pcre pointer  					*/
	const char *error; 			/* Const char error pointer			*/
	int errorOffset;

	re = pcre_compile(regxp, 				/* regexp 							*/
			PCRE_COMP_DEF_OPT,	 			/* default options 					*/
			&error, 						/* for error message 				*/
			&errorOffset, 					/* for error offset 				*/
			NULL 							/* use default character tab		*/
	);

	if (!re) {
		printf("PCRE compilation failed at expression offset %d: %s\n",
				errorOffset, error);
		return NULL;
	}

	return re;
}

char *regex_info_error(int rc) {
	char *errorMsg = (char*) malloc(128);

	switch (rc) {
	case PCRE_ERROR_NOMATCH:
		errorMsg = "No match found in string \n";
		break;

	case PCRE_ERROR_MATCHLIMIT:
		errorMsg = "Match is out of possible matches \n";
		break;

	case PCRE_ERROR_NOMEMORY:
		errorMsg = "Out of memory \n";
		break;

	default:
		sprintf(errorMsg, "Match error %d \n", rc);
		break;
	}

	return errorMsg;
}

char **regex_match(char *regxp, char *data, size_t data_len) {

	pcre *re = regex_info_compile(regxp); 	/* Pcre pointer						*/

	int rc;
	int	ovector[OVECCOUNT];
	int	groupsCount; 					/* state integers					*/

	pcre_fullinfo(re,
			NULL,
			PCRE_INFO_CAPTURECOUNT,
			&groupsCount);

	rc = pcre_exec(
			re, 						/* The compiled pattern 			*/
			NULL, 						/* No extra data 					*/
			data, 						/* the subject string 				*/
			data_len,	 				/* Length of subject 				*/
			0, 							/* Start at offset 0				*/
			0, 							/* Default options 					*/
			ovector, 					/* Output vector for substring info	*/
			OVECCOUNT); 				/* Number of elements in the output	*/

	if (rc < 0) {
		regex_info_error(rc);
		return NULL;
	}

	char **results = (char**) malloc(OVECCOUNT * sizeof(char));

	char *tmp;
	int i = 3, it = 0, tmpInt = 0;

	for (it = 0; it < groupsCount; it++) {
		tmp = data + ovector[i - 1];
		tmpInt = ovector[i] - ovector[i - 1];
		results[it] = (char*) malloc(tmpInt + 1);
//            sprintf(results[it], "%.*s\0", tmpInt, tmp);
		sprintf(results[it], "%.*s", tmpInt, tmp);
		i += 2;
	}
	return results;
}

LPPREG_SPLIT_RESULTS regex_info_split(char *regxp, char *subject, size_t subject_len){
	int				rc;
	int				limit_val = -1;
	int				*offsets;			/* Array of subpattern offsets */
	int				 size_offsets;		/* Size of the offsets array */
	int				 count = 0;			/* Count of matched subpatterns */
	int				 start_offset;		/* Where the new search starts */
//	int				 next_offset;		/* End of the last delimiter match + 1 */
	char			*last_match;		/* Location of last match */
	int				 g_notempty = 0;	/* If the match should not be empty */

	pcre *re = regex_info_compile(regxp); // Pcre pointer

	rc = pcre_fullinfo(re, NULL, PCRE_INFO_CAPTURECOUNT, &size_offsets);

	if (rc < 0) {
		return NULL;
	}

	size_offsets = (size_offsets + 1) * 3;
	offsets = (int *)malloc(size_offsets * sizeof(int));

	/* Start at the beginning of the string */
	start_offset = 0;
//	next_offset = 0;
	last_match = subject;

	/* Get next piece if no limit or limit not yet reached and something matched*/
	while ((limit_val == -1 || limit_val > 1)) {
		count = pcre_exec(re,
					NULL,
					subject,
					subject_len,
					start_offset,
					PCRE_EXEC_DEF_OPT|g_notempty,
					offsets, size_offsets);

		/* Check for too many substrings condition. */
		if (count == 0) {
			count = size_offsets/3;
		}

		/* If something matched */
		if (count > 0) {
			if (&subject[offsets[0]] != last_match) {
				//TODO
				puts(last_match);
//				add_next_index_stringl(return_value, last_match,
//								   &subject[offsets[0]]-last_match, 1);

				/* One less left to do */
				if (limit_val != -1)
					limit_val--;
			}

			last_match = &subject[offsets[1]];
//			next_offset = offsets[1];
		} else {
			break;
		}

		/* If we have matched an empty string, mimic what Perl's /g options does.
		   This turns out to be rather cunning. First we set PCRE_NOTEMPTY and try
		   the match again at the same point. If this fails (picked up above) we
		   advance to the next character. */
		g_notempty = (offsets[1] == offsets[0])? PCRE_NOTEMPTY | PCRE_ANCHORED : 0;

		/* Advance to the position right after the last full match */
		start_offset = offsets[1];
	}


	start_offset = last_match - subject; /* the offset might have been incremented, but without further successful matches */

	if (start_offset < subject_len) {
		/* Add the last piece to the return value */
//		add_next_index_stringl(return_value, last_match, subject + subject_len - last_match, 1);
	}

	/* Clean up */
	free(offsets);

	return NULL;
}


LPPREG_MATCH_ALL_RESULT regex_match_all(char *regxp, char *subject, size_t data_len) {

	int				start_offset = 0;		/* Where the new search starts		*/
	int				matched;				/* Number of Matched Results		*/
	int				num_subpats;			/* Number of captured subpatterns	*/
	int				count = 0;				/* Count of matched subpatterns		*/
	const char**	stringlist;				/* Holds list of subpatterns		*/
	int				i, rc;

	pcre *re = regex_info_compile(regxp); // Pcre pointer

	rc = pcre_fullinfo(re, NULL, PCRE_INFO_CAPTURECOUNT, &num_subpats);

	if (rc < 0) {
		return NULL;
	}

	num_subpats++;

	int size_offsets = num_subpats * 3;
	int* offsets = (int *)malloc(size_offsets * sizeof(int));


	LPPREG_MATCH_ALL_RESULT results = create_regex_match_all_results(num_subpats);

	results->subPartsCount = num_subpats;

	matched = 0;

	do{
		count = pcre_exec(re, 				/* The compiled pattern 			*/
				NULL, 						/* No extra data 					*/
				subject, 					/* the subject string 				*/
				data_len, 					/* Length of subject 				*/
				start_offset, 				/* Start at offset 0				*/
				PCRE_EXEC_DEF_OPT,			/* Default options 					*/
				offsets, 					/* Output vector for substring info */
				size_offsets);				/* Size of Offset					*/

		/* Check for too many substrings condition. */
		if (count == 0) {
			puts("Matched, but too many substrings");
			count = size_offsets/3;
		}

		/* If something has matched */
		if (count > 0) {
			matched++;

			if (!pcre_get_substring_list(subject, offsets, count, &stringlist)) {
				for (i = 0; i < count; i++) {
					LPPCRE_INFO info = regex_match_insert_info(results, i);
					if(info != NULL){
						info->length = offsets[(i<<1)+1] - offsets[i<<1];
						info->match = malloc(info->length+1);
						memcpy(info->match, (char *)stringlist[i], info->length);
						info->match[info->length] = '\0';
						info->offset = offsets[i<<1];
					}
				}
				if (count < num_subpats) {
					for (; i < num_subpats; i++) {
						regex_match_insert_info(results, i);
					}
				}
				pcre_free_substring_list(stringlist);
			}
		}

		/* Advance to the position right after the last full match */
		start_offset = offsets[1];
	}while(count > 0);

	results->countOfMatches = matched;

	return results;
}


LPPREG_MATCH_ALL_RESULT create_regex_match_all_results(int subPartsCount){
	if(subPartsCount <= 0)
		return NULL;

	LPPREG_MATCH_ALL_RESULT ret = malloc(sizeof(PREG_MATCH_ALL_RESULT));

	ret->countOfMatches = 0;
	ret->subPartsCount = subPartsCount;
	ret->subPartsList = malloc(subPartsCount*sizeof(PCRE_INFO));
	int i;
	for(i = 0; i < subPartsCount; i++)
		ret->subPartsList[i] = NULL;


	return ret;
}


void free_regex_match_all_results(LPPREG_MATCH_ALL_RESULT resultsets){
	if(resultsets == NULL)
		return;

	int i;
	for(i = 0; i < resultsets->subPartsCount; i++)
		free_regex_match_all_info(resultsets->subPartsList[i]);

	free(resultsets);
}


LPPCRE_INFO create_regex_match_all_info(){
	LPPCRE_INFO ret = malloc(sizeof(PCRE_INFO));
	ret->length = 0;
	ret->match = NULL;
	ret->next = NULL;
	ret->offset = 0;

	return ret;
}

void free_regex_match_all_info(LPPCRE_INFO info){
	if(info == NULL)
		return;

	free(info->match);
	free_regex_match_all_info(info->next);

	free(info);
}


LPPCRE_INFO regex_match_insert_info(LPPREG_MATCH_ALL_RESULT resultsets, int index){
	if(resultsets == NULL)
		return NULL;
	if(resultsets->subPartsCount <= index)
		return NULL;

	LPPCRE_INFO ret = create_regex_match_all_info();

	if(resultsets->subPartsList[index] == NULL){
		/* Add to the head of the list */
		resultsets->subPartsList[index] = ret;
	}else{
		/* Add to the tail of the list */
		LPPCRE_INFO tmp = resultsets->subPartsList[index];
		while(tmp->next != NULL){
			tmp = tmp->next;
		}
		tmp->next = ret;
	}
	return ret;
}

LPPCRE_INFO regex_match_get_info(LPPREG_MATCH_ALL_RESULT resultsets, int i, int j){
	if(resultsets == NULL)
		return NULL;
	if(resultsets->subPartsCount <= i)
		return NULL;
	if(j < 0)
		return NULL;

	LPPCRE_INFO tmp = resultsets->subPartsList[i];
	while(j > 0 && tmp != NULL){
		tmp = tmp->next;
		j--;
	}
	return tmp;
}

PREG_INFO_TRANS** regex_info_info_transpose(LPPREG_MATCH_ALL_RESULT resultsets){
	int i;
	int j;
	int count = resultsets->countOfMatches;
	int sub_count = resultsets->subPartsCount;

	PREG_INFO_TRANS** ret = malloc(sizeof(LPPREG_INFO_TRANS)*count);

	for(j = 0; j < count; j++){
		PCRE_INFO* info = regex_match_get_info(resultsets, 2, j);
		if(info != NULL){
			LPPREG_INFO_TRANS pTrans = malloc(sizeof(PREG_INFO_TRANS));
			ret[j] = pTrans;
			pTrans->offset = info->offset;
			if(sub_count > 0){
				pTrans->matches = malloc(sizeof(char*)* sub_count - 1);
				for(i = 1; i < sub_count; i++){
					PCRE_INFO* m = regex_match_get_info(resultsets, i, j);
					pTrans->matches[i - 1] = m->match;
				}
			}
		}else{
			puts("Error");
		}
	}

	return ret;
}

void free_regex_info_info_transpose(PREG_INFO_TRANS** transposed, int count){
	if(transposed == NULL)
		return;

	if(count > 0){
		int i;
		for(i = 0; i < count; i++){
			LPPREG_INFO_TRANS pTrans = transposed[i];
			free(pTrans->matches);
			free(pTrans);
		}
	}
	free(transposed);
}

void free_regex_info_split_results(LPPREG_SPLIT_RESULTS pResults){
	free(pResults);
}
