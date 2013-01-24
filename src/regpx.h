/*
 * File:   Regxp.h
 * Author: solution
 *
 * Created on 11. listopad 2011, 16:00
 */

#ifndef REGXP_H
#define	REGXP_H
#define OVECCOUNT 30

#include <stdio.h>
#include <string.h>
#include <pcre.h>

#define COUNT(a, b) (sizeof(a)/sizeof(b))

typedef struct pcreInfo{
	char*	match;
	int 	offset;
	int		length;
	struct pcreInfo* next;
}PCRE_INFO, *LPPCRE_INFO;

typedef struct _regex_match_all_result{
	int 			countOfMatches;
	int 			subPartsCount;
	PCRE_INFO**		subPartsList;
}PREG_MATCH_ALL_RESULT,*LPPREG_MATCH_ALL_RESULT;

typedef struct _regex_info_info_trans_ {
	int		offset;
	char**	matches;
}PREG_INFO_TRANS,*LPPREG_INFO_TRANS;

typedef struct _regex_info_split_result_ {
	int		result_size;
	char**	results;

}PREG_SPLIT_RESULTS, *LPPREG_SPLIT_RESULTS;

/*****************************************************************************/
/* Begin Functions                                                           */
/*****************************************************************************/
#ifdef __cplusplus
extern "C" {
#endif

char *regex_info_error(int rc);

pcre *regex_info_compile(char* regxp);

char **regex_match(char *regxp, char *data, size_t data_len);

LPPREG_MATCH_ALL_RESULT regex_match_all(char *regxp, char *data, size_t data_len);

LPPREG_MATCH_ALL_RESULT create_regex_match_all_results(int subPartsCount);

void free_regex_match_all_results(LPPREG_MATCH_ALL_RESULT resultsets);

LPPCRE_INFO create_regex_match_all_info();

void free_regex_match_all_info(LPPCRE_INFO info);

LPPCRE_INFO regex_match_insert_info(LPPREG_MATCH_ALL_RESULT resultsets, int position);

LPPCRE_INFO regex_match_get_info(LPPREG_MATCH_ALL_RESULT resultsets, int i, int j);

PREG_INFO_TRANS** regex_info_info_transpose(LPPREG_MATCH_ALL_RESULT resultsets);

void free_regex_info_info_transpose(PREG_INFO_TRANS** transposed, int count);

LPPREG_SPLIT_RESULTS regex_info_split(char *regxp, char *subject, size_t subject_len);

void free_regex_info_split_results(LPPREG_SPLIT_RESULTS pResults);

#ifdef __cplusplus
}
#endif
/*****************************************************************************/
/* End Functions                                                             */
/*****************************************************************************/
#endif	/* REGXP_H */
