/*
 * pma.c
 *
 *  Created on: 24/12/2012
 *      
 */

#include <stdlib.h>
#include <stdio.h>
#include <regex.h>
#include <errno.h>
#include <string.h>
#include <math.h>
#include <zlib.h>

#include "pma.h"
#include "regpx.h"
#include "strutil.h"

/*****************************************************************************/
/* Constants Declaration                                                     */
/*****************************************************************************/

#define PDF_DEFAULT_PADDIN		"28BF4E5E4E758A4164004E56FFFA01082E2E00B6D0683E802F0CA9FE6453697A"
#define PDF_DEFAULT_U			"00000000000000000000000000000000"

#define PDF_DEFAULT_PADDIN_SIZE sizeof(PDF_DEFAULT_PADDIN)
#define PDF_DEFAULT_U_SIZE 		sizeof(PDF_DEFAULT_U)

#define MAX_REGEX_GROUPS		20

#define REGEX_CRIPT_HEADER_1    "\\/AuthEvent\\/DocOpen\\/CFM\\/AESV2"
#define REGEX_CRIPT_HEADER_2    "\\/Encrypt\\s+/s"

#define REGEX_ENCRIPT			"\\/Encrypt (\\d+)\\D+(\\d+)\\D+R"

#define REGEX_ENCRIPT_1			"(\\x0a|\\x0d|\\x20)"
#define REGEX_ENCRIPT_2         "[^\\d]{1,3}"
#define REGEX_ENCRIPT_3			"[^\\d]{1,3}obj(.+?)endobj"
#define REGEX_ENCRIPT_4			"\\/Encrypt(.*?)(endobj|$)"

#define REGEX_ID_1				"\\/ID[^\\[]{0,5}\\[\\s*<(.*?)>"
#define REGEX_ID_2				"\\/ID[^\\[]{0,5}\\[\\s*\\((.*?)\\)"

#define REGEX_O_1				"\\/O[^\\(]{0,5}\\((.{32,64}?)\\)"
#define REGEX_O_2				"\\/O[^\\<]{0,5}\\<(.{64}?)\\>"
#define REGEX_O_3				"trailer.{1,400}\\/O[^\\<]{0,5}\\<(.{32,64}?)\\>"
#define REGEX_O_4				"\\/O[^\\(]{0,5}\\((.{48,132}?)\\)"
#define REGEX_O_5				"\\/O[^\\<]{0,5}\\<(.{96,164}?)\\>"

#define REGEX_KEY_LENGTH		"\\/Length\\s+(\\d{1,4})\\D"

#define REGEX_R					"\\/R (\\d{1})\\D"
#define REGEX_VERSION			"\\/V (\\d{1})\\D"
#define REGEX_P					"\\/P ([0-9-]*)"

#define REGEX_OE_1				"\\/OE[^\\(]{0,5}\\((.{32,64}?)\\)"
#define REGEX_OE_2				"\\/OE[^\\<]{0,5}\\<(.{64}?)\\>"

#define REGEX_UE_1				"\\/UE[^\\(]{0,5}\\((.{32,64}?)\\)"
#define REGEX_UE_2				"\\/UE[^\\<]{0,5}\\<(.{64}?)\\>"

#define REGEX_PERMS_1			"\\/Perms[^\\(]{0,5}\\((.{16,32}?)\\)"
#define REGEX_PERMS_2			"\\/Perms[^\\<]{0,5}\\<(.{32}?)\\>"

#define REGEX_ALL_OBJ_1			"((\\x0a|\\x0d|\\x20)(\\d{1,4})[^\\d]{1,3}(\\d{1,2})\\sobj|(\\x0a|\\x0d)(xref|trailer)(\\x0a|\\x0d))"

#define REGEX_NSO_1				"(\\x0a|\\x0d|\\x20)(\\d{1,4})[^\\d]{1,3}(\\d{1,2})\\sobj(.*?)endobj"

#define REGEX_SAS_1				"(\\x0a|\\x0d|\\x20)(\\d{1,4})[^\\d]{1,3}(\\d{1,2})\\s+obj((?:(?! obj).){1,350}?)(s|#73)(t|#74)(r|#72)(e|#65)(a|#61)(m|#6d)(.*?)(e|#65)(n|#6e)(d|#64)(s|#73|o|#6f)"

#define REGEX_JS_1				"(\\x0a|\\x0d|\\x20)(\\d{1,4})[^\\d]{1,3}(\\d{1,2})\\sobj((?:(?!\\s+\\d{1,2}\\s+obj).){1,350}?)(#4a|J)(#53|S)[\\s]{0,5}\\((.+?)\\)endobj"

#define REGEX_JHS_1				"(\\x0a|\\x0d|\\x20)(\\d{1,4})[^\\d]{1,3}(\\d{1,2})\\sobj((?:(?!\\s+\\d{1,2}\\s+obj).){1,350}?)(#4a|J)(#53|S)[\\s]{0,5}\\<(.*?)\\>(\\x20|\\x0a|\\x0d|>>|\\)\\/)"

#define	REGEX_SF_1				"(\\d{1,4})[^\\d]{1,3}(\\d{1,2})\\s+obj((?:(?!\\s+\\d{1,2}\\s+obj).){1,350}?)\\/(F|#46)(i|#69)(l|#6c)(t|#74)(e|#65)(r|#72).{0,8}?\\/(.{1,200}?)>>(.{0,100}?)(s|#73)(t|#74)(r|#72)(e|#65)(a|#61)(m|#6d)(.*?)(e|#65)(n|#6e)(d|#64)(s|#73|o|#6f)"

#define REGEX_PDF_HEADER		"%PDF"


/*****************************************************************************/
/* Data Structres Declaration                                                */
/*****************************************************************************/

typedef struct pdf_object_data_tag {
	char*	object_id; 							/* Object Id				*/
	char*	object;
	int		generation;
	char*	obj_hex;
	char*	gen_hex;
	int		dup_id;
	char*	parameters;
	char*	decoded;

	char*	otype;
	char*	atype;

	char*	decrypt_part;

	char*	md5_raw;
	char*	stream;

	struct pdf_object_data_tag* 	next;
}OBJECT_DATA, *LPOBJECT_DATA;



typedef struct pdf_split_result_tag {
	int 	version;							/* Document Version         */
	int		r;									/* Document Version ?       */
	int		p;									/* Document Permission		*/
	int		aesv3;								/* AESv3					*/

	BOOL 	encrypted;							/* Encrypted Document		*/
	char*	password;							/* Password					*/
	int		key_length;							/* Encryption Key Length	*/
	char*	key;								/* Key						*/
	char*	test2;								/* Test 2					*/

	char*	encrypt_obj;
	char*	encrypt_gen;

	char*	padding;							/* Document Padding			*/
	char*	u;									/* U						*/
	char*	o;									/* O						*/
	char*	o_orig;								/* O Orig					*/
	char*	oe;									/* OE 						*/
	char*	ue;									/* UE 						*/
	char	ue_key[SHA256_DIGEST_LENGTH*2+1];	/* UE Key					*/
	char*	perms;								/* Perms					*/

	char*	id;									/* Id						*/

	char*	p_hexh;								/*							*/
	char*	p_hex;								/*							*/
	int		p_raw;								/*							*/
	double	p_max;								/*							*/
	long	p_check;							/*							*/

	char	hashbuilder[256];					/*							*/

	OBJECT_DATA*	object_head;				/*							*/
	OBJECT_DATA*	object_tail;				/*							*/
} PDF_SLICE_RESULT, *LPPDF_SLICE_RESULT;


typedef struct pdf_object_str_tag {
	char*	otype;								/*							*/
	int		obj_id;								/*							*/
	int		gen_id;								/*							*/
	int		start;								/*							*/
	int		end;								/*							*/
	int		len;								/*							*/
	int		dup_id;								/*							*/
	char**	parameters;							/*							*/
}OBJECT_STRUCTURE;

typedef struct pdf_obj_stm_tag{
	char* 	ident;								/*							*/
	char*	object;								/*							*/
	int		generation;							/*							*/
	char*	obj_id;								/*							*/
	int		gen_id;								/*							*/
	char*	dup_id;								/*							*/
	char*	parameters;							/*							*/
	char*	objstm;								/*							*/
	char*	datal;								/*							*/
	struct pdf_obj_stm_tag* 	next;			/*							*/
}OBJECT_STM_RESULT,*LPOBJECT_STM_RESULT;

typedef struct _order_tag{
	char*	otype;
	int		obj_id;
	int		gen_id;
	int		start;
	int		end;
	int		len;
	int		dup_id;
	char*	parameters;
}ORDER, *LPORDER;


typedef struct malware_result_tag{
	int		found;								/*							*/
	char*	javascript;							/*							*/
	char*	javascriptencoding;					/*							*/
}MALWARE, *LPMALWARE;

/*****************************************************************************/
/* Local Functions Declaration                                               */
/*****************************************************************************/

LPMALWARE javascriptScan(LPMALWARE pMalware, char* dec, char* stringSearch, char* hexSearch);

char* findHiddenJS(char* string);

/**
 * Explode a Stream
 */
char* flashExplode (char* stream);

/**
 * Inflate a deflated string
 */
char* gzinflate (char* content, size_t data_len);

/*
 * Extract PDF Information
 */
int pdf_wedge(char* data, size_t data_len, PDF_SLICE_RESULT* lpResult);
/*
 * Initialize PDF Result Structure
 */
void init_pdf_wedge_result(PDF_SLICE_RESULT* lpResult);
/*
 * Free PDF Result Structure
 */
void free_pdf_wedge_result(PDF_SLICE_RESULT* lpResult);

/**
 * Creates a OBJECT_DATA Node and add it to tail of the list
 */
LPOBJECT_DATA create_object_data_node(PDF_SLICE_RESULT* lpResult);

/**
 * Free a Object Data Result
 */
void free_object_data_node(LPOBJECT_DATA lpObjectData);

/**
 * Creates a OBJECT_DATA Node Structure
 */
LPOBJECT_STM_RESULT create_object_stm_node();

/**
 * Free a OBJECT_DATA Node Structure
 */
void free_object_stm_node(LPOBJECT_STM_RESULT node);


LPOBJECT_STM_RESULT parseObjStm(char* params, char* stream);

LPORDER create_order();

void free_order(LPORDER pOrder);

LPOBJECT_DATA pdf_object_data_find_with_id(LPPDF_SLICE_RESULT pResults, char* object_id);

/*****************************************************************************/
/* Global Variables                                                          */
/*****************************************************************************/
/*
static const char * const encodingMethods[][] = {
		{"PA", "PDF ASCIIHexDecode"},
		{"PL", "PDF LZWDecode"},
		{"P8", "PDF ASCII85Decode"},
		{"PR", "PDF RunLengthDecode"},
		{"PF", "PDF FlateDecode"},
		{"pf", "PDF FlateDecode2"},
		{"OC", ""},
		{"ES", "JavaScript Escaped"},
		{"JA", "JavaScript Ascii codes"},
		{"UC", "Unicode"},
		{"RH", "JavaScript Hex codes"},
		{"CF", "JavaScript fromCharCode"},
		{"OC", "PDF Octal codes"},
		{"oc", "PDF Octal codes2"},
		{"pa", "PDF ASCIIHexDecode2"},
		{"JB", "JavaScript in Annotation Block"},
		{"JR", "JavaScript in Block"},
		{"CR", "PDF Standard Encryption"},
		{NULL, NULL}
};
*/

static char* global_block_encoding = NULL;

static char* PDFstringSearch = NULL;

static char* PDFhexSearch  = NULL;

/*****************************************************************************/
/* Functions Implementation                                                  */
/*****************************************************************************/

int pma_initialize(){

	return EXIT_SUCCESS;
}

void init_pma_results(PMA_RESULTS* result){
	result->not_pdf = FALSE;
	result->completed = FALSE;
	result->exploit = 0;
	result->hits = 0;
	result->is_malware = FALSE;
	result->severity = 0;
	result->summary = NULL;
}

void free_pma_results(PMA_RESULTS* result){
	free(result->summary);
}


int pma_analyze_file(const char* targetFileName, PMA_RESULTS* pma_result){

	FILE *f_target;
	long lSize;
	char * buffer;

	f_target = fopen(targetFileName, "rb");

	if(f_target == NULL){
		fprintf(stderr, "Error reading target file: %s.\nError: %s",
				targetFileName,
				strerror(errno));
		return EXIT_FAILURE;
	}

	// obtain file size:
	fseek (f_target , 0 , SEEK_END);
	lSize = ftell (f_target);
	rewind (f_target);

	// allocate memory to contain the whole file:
	buffer = (char*) malloc (sizeof(char)*lSize);
	if (buffer == NULL) {
		fputs ("Memory error", stderr);
		return EXIT_FAILURE;
	}

	// copy the file into the buffer:
	size_t result;
	result = fread (buffer, 1, lSize, f_target);
	if (result != lSize) {
		fputs ("Reading error", stderr);
		return EXIT_FAILURE;
	}
	fclose (f_target);

	/* the whole file is now loaded in the memory buffer. */


	char md5[MD5_DIGEST_LENGTH*2+1];
	memset(md5, 0, MD5_DIGEST_LENGTH*2+1);

	md5hex(buffer, lSize, md5);

	printf("%s start processing\n", md5);

	PDF_SLICE_RESULT wedge_result;

	init_pdf_wedge_result(&wedge_result);
	int slide_result = pdf_wedge(buffer, (size_t)lSize, &wedge_result);


	if(slide_result == EXIT_SUCCESS){
		printf("%s end processing\n", md5);
		pma_result->completed = TRUE;
	}else{
		fputs ("Slide PDF error", stderr);
		return EXIT_FAILURE;
	}

	// Get PDF Header
	char* header = malloc(sizeof(char*)*(1024+1));
	memcpy(header, buffer, sizeof(char*)*1024);
	header[1024] = '\0';


	char** match_pdf = NULL;   // O Matches
	// PDF% por /PDF%/si
	if((match_pdf = regex_match(REGEX_PDF_HEADER, header)) == NULL){
		puts("File missing PDF signature - not processed.\n");
		pma_result->not_pdf = TRUE;
	}else{
		free_regex_result(match_pdf);
	}
	free(header);

	if(!pma_result->not_pdf){
		//store encryption metadata
		if(wedge_result.encrypted) {
			pma_result->encrypted = TRUE;

			pma_result->key = malloc(sizeof(wedge_result.key));
			strcpy(pma_result->key, wedge_result.key);
			pma_result->encrypt_alg = wedge_result.version;
			pma_result->key_length = wedge_result.key_length;

		}
	}

	LPOBJECT_DATA lpObjData = wedge_result.object_head;

	while(lpObjData != NULL){
		if(lpObjData->parameters != NULL){
			char** param_result = regex_match("(#4F|O)(#62|b)(#6a|j)(#53|S)(#74|t)(#6d|m)", lpObjData->parameters);
			if(param_result != NULL){
				//check for ObjStm
				lpObjData->otype = "ObjStm";

				LPOBJECT_STM_RESULT lpObjStm = parseObjStm(lpObjData->parameters, lpObjData->decoded);
				if(lpObjStm != NULL){
					LPOBJECT_STM_RESULT datal = lpObjStm;
					while(datal != NULL){
						datal->objstm = lpObjData->object;
						datal->dup_id += lpObjData->dup_id;
						datal->datal = "objstm";
						//FIXME ¿Buscar por object_id y reemplazar?
//					$result[$uniquel] = $datal;

						datal = datal->next;
					}
					free_object_stm_node(lpObjStm);
				}
				free_regex_result(param_result);
			}
		}
		lpObjData = lpObjData->next;
	}

	//objstm  endsection

	lpObjData = wedge_result.object_head;

	while(lpObjData != NULL){
		/**
		 * Scan for Malware
		 */

		MALWARE malware;
		malware.found = 0;


		char *d = "";
		if (lpObjData->decoded != NULL)
			d = lpObjData->decoded;

		/**
		 * Uncompress flash
		 **/

		if (regex_match("^CWS(.{1}?)", d)) {
			log_debug("Uncompress");
			char* uncompressed = flashExplode(d);

			char unmd5[MD5_DIGEST_LENGTH*2+1];
			memset(unmd5, 0, MD5_DIGEST_LENGTH*2+1);
			md5hex(uncompressed, strlen(uncompressed), unmd5);

			if (uncompressed != NULL) {

			}

		}


			//original
		LPMALWARE m = javascriptScan(&malware, d, PDFstringSearch, PDFhexSearch);

		if(m != NULL && m->found >= 1 && (m->javascript == NULL || strcmp(m->javascript, "") == 0)) {
			// Copy javascript
			m->javascript = d;
		}

		//correct for unicoce
		d = str_replace("\x00", "", d); //turf unicode here

		m = javascriptScan(m, d, PDFstringSearch, PDFhexSearch);
		if(m != NULL && m->found >= 1 && (m->javascript == NULL || strcmp(m->javascript, "") == 0)) {
			// Copy javascript
			m->javascript = d;
		}

		//correct for hexcodes
		char* df = findHiddenJS(d);

//		logDebug($file['md5']."obj ".$data['object']." hex");

		m = javascriptScan(m, df, PDFstringSearch, PDFhexSearch);
		if(m != NULL && m->found >= 1 && (m->javascript == NULL || strcmp(m->javascript, "") == 0)) {
			// Copy javascript
			m->javascriptencoding = global_block_encoding;
		}

		if(malware.found){
			log_debug("Malware Found:");
		}
		lpObjData = lpObjData->next;
	}


	free_pdf_wedge_result(&wedge_result);


	// terminate
	free (buffer);

	return EXIT_SUCCESS;
}




/*****************************************************************************/
/* Local Functions Implementation                                            */
/*****************************************************************************/

int pdf_wedge(char* data, size_t data_len, PDF_SLICE_RESULT* lpResult) {
//	global $global_test, $literalEncodings;
	char* key = NULL;

	char* master_block_encoding = NULL;
	char* block_encoding = NULL;

	int i;
	char* encrypt_block = NULL;

	lpResult->version = 0;
	lpResult->encrypted = FALSE;

	log_debug("crypto check");

	char** criptoResult1 = regex_match(REGEX_CRIPT_HEADER_1, data);
	char** criptoResult2 = regex_match(REGEX_CRIPT_HEADER_2, data);

	if(criptoResult1 != NULL || criptoResult2 != NULL){
		//find Encryption defns
		log_debug("find Encryption defns");

		free_regex_result(criptoResult1);
		free_regex_result(criptoResult2);

		char **results;


		if ((results = regex_match(REGEX_ENCRIPT, data)) != NULL) {
			strcpy(lpResult->encrypt_obj, results[1]);
			strcpy(lpResult->encrypt_gen, results[2]);

		    // Free Results
			free_regex_result(results);

			//echo "Looking for encryption obj ".$result['document']['encrypt_obj']." ".$result['document']['encrypt_gen']."\n";
		    char * pattern = malloc(snprintf(NULL, 0, "%s%s%s%s%s",
		    		REGEX_ENCRIPT_1,
		    		lpResult->encrypt_obj,
		    		REGEX_ENCRIPT_2,
		    		lpResult->encrypt_gen,
		    		REGEX_ENCRIPT_3) + 1);
		    sprintf(pattern, "%s%s%s%s%s",
		    		REGEX_ENCRIPT_1,
		    		lpResult->encrypt_obj,
		    		REGEX_ENCRIPT_2,
		    		lpResult->encrypt_gen,
		    		REGEX_ENCRIPT_3);

		    LPPREG_MATCH_ALL_RESULT resultset = regex_match_all(pattern, data, data_len);

		    if(resultset != NULL){
		    	int count = resultset->countOfMatches;

		    	/* Transpose array */
		    	PREG_INFO_TRANS** ordered = regex_info_info_transpose(resultset);

	    		encrypt_block = ordered[count-1]->matches[2];
				//print_r(encrypt_block);

	    		free_regex_info_info_transpose(ordered, count);
	    		free_regex_match_all_results(resultset);
		    }
		}


		if(encrypt_block == NULL){
			if((results = regex_match(REGEX_ENCRIPT_4, data)) != NULL){
				strcpy(encrypt_block, results[1]);
			    // Free Results
				free_regex_result(results);
			}
		}

		if(encrypt_block == NULL){
			encrypt_block = data;
		}

		lpResult->encrypted = TRUE;
		lpResult->padding = malloc(PDF_DEFAULT_PADDIN_SIZE);
		lpResult->u = malloc(PDF_DEFAULT_U_SIZE);

		strcpy(lpResult->padding, PDF_DEFAULT_PADDIN);
		strcpy(lpResult->u, PDF_DEFAULT_U);
		lpResult->o = NULL;
		lpResult->id = NULL;

		// Look for the Document ID

		LPPREG_MATCH_ALL_RESULT resultset = regex_match_all(REGEX_ID_1, data, data_len);
		if(resultset != NULL){
			LPPCRE_INFO tmp = resultset->subPartsList[resultset->subPartsCount-1];
			if(tmp != NULL){
				lpResult->id = malloc(tmp->length+1);
				strcpy(lpResult->id, tmp->match);
			}
			free_regex_match_all_results(resultset);
		}else {
			resultset = regex_match_all(REGEX_ID_2, data, data_len);
			if(resultset != NULL){
				LPPCRE_INFO tmp = resultset->subPartsList[resultset->subPartsCount-1];
				lpResult->id = strhex(unliteral(tmp->match));
				free_regex_match_all_results(resultset);
			}
		}

		char** matcho = NULL;   // O Matches
		if((matcho = regex_match(REGEX_O_1, encrypt_block)) != NULL){
			lpResult->o = strhex(matcho[1]);
			free_regex_result(matcho);
		}else if((matcho = regex_match(REGEX_O_2, encrypt_block)) != NULL){
			lpResult->o = matcho[1];
			free_regex_result(matcho);
		}

		if(lpResult->o == NULL && ((matcho = regex_match(REGEX_O_3, encrypt_block)) != NULL)){
			lpResult->o = matcho[1];
			free_regex_result(matcho);
		}

		strcpy(lpResult->o_orig, lpResult->o);

		if (strlen(lpResult->o) > 64) { //fix escaped things
			lpResult->o = strhex(unliteral(hex2str(lpResult->o)));
		}

		// Set the key length
		lpResult->key_length  = 128;

		char** matchl = NULL;		// L Matches
		if((matchl = regex_match(REGEX_KEY_LENGTH, encrypt_block)) != NULL){
			lpResult->key_length = atoi(matchl[1]);
			free_regex_result(matchl);
		}
		if (lpResult->key_length <= 16)
			lpResult->key_length *= 8;

		// R
		lpResult->r = 1; //version
		char** matchr = NULL;		// R Matches
		if ((matchr = regex_match(REGEX_R, encrypt_block)) != NULL){
			lpResult->r = atoi(matchr[1]); //version 1-4
			free_regex_result(matchr);
		}

		//Version
		lpResult->version = 4;		//version

		char** matchv = NULL;		// V Matches
		if((matchv = regex_match(REGEX_VERSION, encrypt_block)) != NULL){
			lpResult->version = atoi(matchv[1]); //version 1-4
			free_regex_result(matchv);
		}

		char** matchp = NULL;		// P Matches
		if((matchp = regex_match(REGEX_P, encrypt_block)) != NULL){
			lpResult->version = atoi(matchp[1]); //permission - 32 bit
			free_regex_result(matchp);
		}

		if (lpResult->r <= 2)
			lpResult->key_length = 40;

		//r=5 AESV3 (AES-256) 2011 12 15
		if (lpResult->r == 5) {
			lpResult->key_length = 256;

			//StrF-EFF

			//O is 48 bytes
			char** matcho = NULL;
			if((matcho = regex_match(REGEX_O_4, encrypt_block)) != NULL){
				lpResult->o = strhex(matcho[1]);
				free_regex_result(matcho);
			} else if((matcho = regex_match(REGEX_O_5, encrypt_block)) != NULL){
				lpResult->o = matcho[1];
				free_regex_result(matcho);
			}

			if (strlen(lpResult->o) > 96) { //fix escaped things
				lpResult->o = strhex(unliteral(hex2str(lpResult->o)));
			}
			if (strlen(lpResult->o) > 96){
				strncpy(lpResult->o, lpResult->o, 96 * sizeof(char*));
			}

			char** matchu = NULL;
			if((matchu = regex_match("/\\/U[\\s]{0,5}\\((.{48,132}?)\\)/si", encrypt_block)) != NULL){
				lpResult->u = strhex(matchu[1]);
				free_regex_result(matchu);
			}else if((matchu = regex_match("/\\/U[\\s]{0,5}\\<(.{96,164}?)\\>/si", encrypt_block)) != NULL){
				lpResult->u = matchu[1];
				free_regex_result(matchu);
			}

			if(strlen(lpResult->u) > 96) { //fix escaped things
				lpResult->u = strhex(unliteral(hex2str(lpResult->u)));
			}
			if(strlen(lpResult->u) > 96){
				strncpy(lpResult->u, lpResult->u, 96);
			}

			lpResult->oe = NULL;
			lpResult->ue = NULL;
			lpResult->perms = NULL;

			char** matchoe = NULL;
			if((matchoe = regex_match(REGEX_OE_1, encrypt_block)) != NULL){
				lpResult->oe = strhex(matchoe[1]);
				free_regex_result(matchoe);
			}else if((matchoe = regex_match(REGEX_OE_2, encrypt_block)) != NULL){
				lpResult->oe = matcho[1];
				free_regex_result(matchoe);
			}

			if (strlen(lpResult->oe) > 64) { //fix escaped things
				lpResult->oe = strhex(unliteral(hex2str(lpResult->oe)));
			}

			char** matchue = NULL;
			if((matchue = regex_match(REGEX_UE_1, encrypt_block)) != NULL){
				lpResult->ue = strhex(matchue[1]);
				free_regex_result(matchue);
			}else if((matchue = regex_match(REGEX_UE_2, encrypt_block)) != NULL){
				lpResult->ue = matchue[1];
				free_regex_result(matchue);
			}
			if (strlen(lpResult->ue) > 64) { //fix escaped things
				lpResult->ue = strhex(unliteral(hex2str(lpResult->ue)));
			}

			char** matchperms = NULL;
			if((matchperms = regex_match(REGEX_PERMS_1, encrypt_block)) != NULL){
				lpResult->perms = strhex(matchperms[1]);
				free_regex_result(matchperms);
			}else if((matchperms = regex_match(REGEX_PERMS_2, encrypt_block)) != NULL){
				lpResult->perms = matchperms[1];
				free_regex_result(matchperms);
			}
			if (strlen(lpResult->perms) > 32) { //fix escaped things
				lpResult->perms = strhex(unliteral(hex2str(lpResult->perms)));
			}


			lpResult->password = NULL;


			char hexPasswordU[256];
			unsigned char binPasswordU[129];
			memset(hexPasswordU,0, 256);
			memset(binPasswordU,0, 129);

			strcat(hexPasswordU, lpResult->password);
			strncat(hexPasswordU, lpResult->u + 80, 16);
			hex2bin(hexPasswordU, binPasswordU);

			sha256hex((const char*)binPasswordU, 128, (char*) lpResult->ue_key);

			//AES256 CDC
			unsigned char binUEKey[SHA256_DIGEST_LENGTH];
			unsigned char binUE[sizeof(lpResult->ue)];

			hex2bin(lpResult->ue_key, binUEKey);
			hex2bin(lpResult->ue, binUE);

			char* plaintext = NULL;
			decrypt_aes256_cdc(binUE, sizeof(binUE), binUEKey, sizeof(binUEKey), plaintext);

			lpResult->key = strhex(plaintext);
			free(plaintext);


			unsigned char binKey[strlen(lpResult->key)/2];
			char subPerms[32];
			unsigned char binPerms[16];
			memcpy(subPerms, lpResult->perms, 32);

			hex2bin(lpResult->key, binKey);
			hex2bin(subPerms, binPerms);

			decrypt_aes256_ecb(binPerms, sizeof(binPerms), binKey, sizeof(binKey), plaintext);
			lpResult->test2 = strhex(plaintext);
			free(plaintext);

			unsigned char binTest2[16];
			hex2bin(lpResult->test2, binTest2);
			char* subTest2[4];

			memcpy(subTest2, &binTest2[9], 3);
			subTest2[3] = '\0';

			if(strcmp("abd", (const char*)&subTest2) == 0){
				lpResult->aesv3 = 1;
			}else{
				lpResult->aesv3 = 0;
			}

			key = lpResult->key;
		} else {

			char* trimmed = strtrim_right(lpResult->u, '0');


			if (strlen(trimmed) % 2 == 1){
				strcat(trimmed, "0");
			}

			lpResult->password = str_right_pad(
					lpResult->password,
					trimmed,
					lpResult->padding,
					64);


			char hashbuilder[256];
			strcpy(hashbuilder, lpResult->password);

			strcat(hashbuilder, lpResult->o);

			double permissions = 0.0;
			if (lpResult->p < 0){
				permissions = pow(2, 32) + (lpResult->p);
			}else{
				permissions = lpResult->p;
			}

			char hexh[8+1];
			memset(hexh, '0', 8);
			hexh[8]='\0';

			double h = pow(2, 32)- pow(2, 32) + permissions;
			sprintf(hexh, "%02x", (int)h);

			str_left_pad(lpResult->p_hexh, hexh, "00000000", 8);
			lpResult->p_hex = lowOrder(lpResult->p_hexh);
			lpResult->p_raw = permissions;
			lpResult->p_max = pow(2, 32);
			lpResult->p_check = strtoul(lpResult->p_hexh, 0, 16);

			strcat(hashbuilder, lpResult->p_hex);

			strcat(hashbuilder, lpResult->id);

			strcpy(lpResult->hashbuilder, hashbuilder);
			char hash[MD5_DIGEST_LENGTH*2+1];
			unsigned char binHashbuilder[256];

			memset(hash, 0, MD5_DIGEST_LENGTH*2+1);
			hex2bin(hashbuilder, binHashbuilder);
			md5hex((const char*)binHashbuilder,
					strlen((const char*)binHashbuilder),
					hash);

			if (lpResult->r > 2) {
				for (i = 0; i < 50; i++) {
					char partial[128];
					unsigned char binPartial[128];

					memcpy(partial, hash, lpResult->key_length/4);
					partial[lpResult->key_length/4] = '\0';

					hex2bin(partial, binPartial);

					md5hex((const char*)binPartial,
							strlen((const char*)binPartial),
							hash);
					//echo "step h $i md5($partial) = $hash\n";
				}
			}

			if (lpResult->r > 2){
				memcpy(key, hash, lpResult->key_length/4);
			}else{
				memcpy(key, hash, 10);
			}

			strcpy(lpResult->key, key);
		}
	}


	log_debug("all obj slicing");

	LPPREG_MATCH_ALL_RESULT aos_result = regex_match_all(REGEX_ALL_OBJ_1, data, data_len);

	ORDER** ppOrders;
	int orders_count = 0;
	if(aos_result != NULL){
		orders_count = aos_result->countOfMatches;
		ppOrders = malloc(sizeof(LPORDER) * orders_count);
		int j;
		for(j = 0; j < orders_count; j++) {
			LPORDER pOrder = create_order();

			int end = 0;
			int start = 0;
			int len = 0;
			int dup_id = 0;

			LPPCRE_INFO info_0j1 = NULL;
			LPPCRE_INFO info_0j0 = NULL;
			LPPCRE_INFO info_3j0 = NULL;
			LPPCRE_INFO info_4j0 = NULL;
			LPPCRE_INFO info_6j0 = NULL;

			info_0j0 = regex_match_get_info(aos_result, 0, j+0);
			info_0j1 = regex_match_get_info(aos_result, 0, j+1);
			info_3j0 = regex_match_get_info(aos_result, 3, j+0);
			info_4j0 = regex_match_get_info(aos_result, 4, j+0);
			info_6j0 = regex_match_get_info(aos_result, 6, j+0);

			if (info_0j1 != NULL){
				end = info_0j1->offset+1;
			}else{
				end = data_len;
			}

			dup_id = info_0j0->offset+1;

			if ((info_6j0 != NULL && info_6j0->match != NULL) && (strcmp(info_6j0->match, "xref") == 0 || strcmp(info_6j0->match, "trailer") == 0)) {
				start = info_0j0->offset+1;
				len = (end-start);
				pOrder->dup_id = dup_id;
				pOrder->otype = malloc(info_6j0->length);
				strcpy(pOrder->otype, info_6j0->match);
				pOrder->obj_id = 0;
				pOrder->gen_id = 0;
				pOrder->start = start;
				pOrder->end = end;
				pOrder->len = len;
				pOrder->dup_id = dup_id;
				pOrder->parameters = malloc(sizeof(char*)*len+1);
				memcpy(pOrder->parameters, data+start, len);
				pOrder->parameters[len] = '\0';


			} else {
				start = info_4j0->offset + strlen(info_4j0->match) + 4;
				len = (end - start);

				pOrder->dup_id = dup_id;
				pOrder->obj_id = atoi(info_3j0->match);
				pOrder->gen_id = atoi(info_4j0->match);
				pOrder->start = start;
				pOrder->end = end;
				pOrder->len = len;
				pOrder->dup_id = dup_id;
				pOrder->parameters = malloc(sizeof(char*)*len+1);
				memcpy(pOrder->parameters, data+start, len);
				pOrder->parameters[len] = '\0';
			}
			ppOrders[j] = pOrder;
		}

		free_regex_match_all_results(aos_result);
		aos_result = NULL;
	}

	for(i = 0; i < orders_count; i++) {
		LPORDER pOrder = ppOrders[i];
		LPOBJECT_DATA lpObjectData = create_object_data_node(lpResult);

		if(pOrder != NULL){
			lpObjectData->object_id = malloc(sizeof(char*)*32);
			memset(lpObjectData->object_id, 0, 32);

			sprintf(lpObjectData->object_id,
					"%d.%d.%d",
					pOrder->obj_id,
					pOrder->gen_id,
					pOrder->dup_id);

			lpObjectData->generation = pOrder->gen_id;

			lpObjectData->obj_hex = malloc(sizeof(char*)*7);
			sprintf(lpObjectData->obj_hex, "%06x", pOrder->obj_id);

			lpObjectData->gen_hex = malloc(sizeof(char*)*5);
			sprintf(lpObjectData->gen_hex, "%04x", pOrder->gen_id);

			lpObjectData->dup_id = pOrder->dup_id;
			int par_size = strlen(pOrder->parameters);
			lpObjectData->parameters = malloc(par_size+1);
			memcpy(lpObjectData->parameters, pOrder->parameters, par_size);
			lpObjectData->parameters[par_size] = '\0';

			lpObjectData->atype = malloc(4);
			strcpy(lpObjectData->atype, "sas");
			lpObjectData->atype[4] = '\0';

			if (pOrder->otype != NULL){
				lpObjectData->otype = malloc(strlen(pOrder->otype)+1);
				strcpy(lpObjectData->otype, pOrder->otype);
			}

			char* loObjHex = lowOrder(lpObjectData->obj_hex);
			char* loGenHex = lowOrder(lpObjectData->gen_hex);
			int dp_size = strlen(loObjHex) + strlen(loGenHex);
			lpObjectData->decrypt_part = malloc(dp_size + 10);
			sprintf(lpObjectData->decrypt_part, "%s%s", loObjHex, loGenHex);

			free(loObjHex);
			free(loGenHex);

			if (lpResult->version >= 3) {
				strcat(lpObjectData->decrypt_part, "73416C54");
			}

			if (lpResult->key != NULL && (strcmp(lpResult->key, "") != 0) && lpObjectData->otype == NULL) {
				LPPREG_MATCH_ALL_RESULT resultset = regex_match_all("\\((.*?)\\)(\\x0a|\\x0d)",
						lpObjectData->parameters,
						strlen(lpObjectData->parameters));

				if(resultset != NULL){
					int count = resultset->countOfMatches;
					int j;
					for(j = 0; j< count; j++) {
						LPPCRE_INFO info_1j = regex_match_get_info(resultset, 1, j);
						char* p = unliteral(info_1j->match);
						log_debug(p);
					}
					free_regex_match_all_results(resultset);
				}
			}
		}

	}


	log_debug("no stream objects");

	LPPREG_MATCH_ALL_RESULT nso_results = regex_match_all(REGEX_NSO_1, data, data_len);

	if(nso_results != NULL){
		int count = nso_results->countOfMatches;

		/* Transpose array */
		PREG_INFO_TRANS** ordered = regex_info_info_transpose(nso_results);

    	for(i = 0; i < count; i++){
    		PREG_INFO_TRANS* pTrans = ordered[i];
    		char object_id[32];
			sprintf(object_id,
					"%d.%d.%d",
					atoi(pTrans->matches[1]),
					atoi(pTrans->matches[2]),
					pTrans->offset);

    		LPOBJECT_DATA lpObjectData = pdf_object_data_find_with_id(lpResult, object_id);

    		if(lpObjectData == NULL){
    			lpObjectData = create_object_data_node(lpResult);

    			size_t obj_size = strlen(object_id);
    			lpObjectData->object_id = malloc(obj_size+1);
    			memcpy(lpObjectData->object_id, object_id, obj_size);
    			lpObjectData->object_id[obj_size] = '\0';


    			lpObjectData->generation = atoi(pTrans->matches[2]);

    			lpObjectData->obj_hex = malloc(sizeof(char*)*7);
    			sprintf(lpObjectData->obj_hex, "%06x", atoi(pTrans->matches[1]));

    			lpObjectData->gen_hex = malloc(sizeof(char*)*5);
    			sprintf(lpObjectData->gen_hex, "%04x", atoi(pTrans->matches[2]));

    			lpObjectData->dup_id = pTrans->offset;

    			size_t param_size = strlen(pTrans->matches[3]);
    			lpObjectData->parameters = malloc(param_size+1);
    			memcpy(lpObjectData->parameters, pTrans->matches[3], param_size);
    			lpObjectData->parameters[param_size] = '\0';

    			lpObjectData->atype = malloc(4);
    			strcpy(lpObjectData->atype, "nos");

    			char* loObjHex = lowOrder(lpObjectData->obj_hex);
    			char* loGenHex = lowOrder(lpObjectData->gen_hex);
    			int dp_size = strlen(loObjHex) + strlen(loGenHex);
    			lpObjectData->decrypt_part = malloc(dp_size + 10);
    			sprintf(lpObjectData->decrypt_part, "%s%s", loObjHex, loGenHex);

    			free(loObjHex);
    			free(loGenHex);

    			if (lpResult->version >= 3) {
    				strcat(lpObjectData->decrypt_part, "73416C54");
    			}
    		}
    	}

    	free_regex_info_info_transpose(ordered, count);
		free_regex_match_all_results(nso_results);
		nso_results = NULL;
	}


	log_debug("scan all streams");
	log_debug(REGEX_SAS_1);
	LPPREG_MATCH_ALL_RESULT all_streams_results = regex_match_all(REGEX_SAS_1, data, data_len);

	if(all_streams_results != NULL){
		int count = all_streams_results->countOfMatches;

		/* Transpose array */
		PREG_INFO_TRANS** ordered = regex_info_info_transpose(all_streams_results);

    	for(i = 0; i < count; i++){
    		PREG_INFO_TRANS* pTrans = ordered[i];
    		char object_id[32];
			sprintf(object_id,
					"%d.%d.%d",
					atoi(pTrans->matches[1]),
					atoi(pTrans->matches[2]),
					pTrans->offset);

			LPOBJECT_DATA lpObjectData = create_object_data_node(lpResult);

			size_t obj_size = strlen(object_id);
			lpObjectData->object_id = malloc(obj_size+1);
			memcpy(lpObjectData->object_id, object_id, obj_size);
			lpObjectData->object_id[obj_size] = '\0';

			lpObjectData->generation = atoi(pTrans->matches[2]);

			lpObjectData->obj_hex = malloc(sizeof(char*)*7);
			sprintf(lpObjectData->obj_hex, "%06x", atoi(pTrans->matches[1]));

			lpObjectData->gen_hex = malloc(sizeof(char*)*5);
			sprintf(lpObjectData->gen_hex, "%04x", atoi(pTrans->matches[2]));

			lpObjectData->dup_id = pTrans->offset;

			size_t param_size = strlen(pTrans->matches[3]);
			lpObjectData->parameters = malloc(param_size+1);
			memcpy(lpObjectData->parameters, pTrans->matches[3], param_size);
			lpObjectData->parameters[param_size] = '\0';

			lpObjectData->atype = malloc(5);
			strcpy(lpObjectData->atype, "alls");

			char* loObjHex = lowOrder(lpObjectData->obj_hex);
			char* loGenHex = lowOrder(lpObjectData->gen_hex);
			int dp_size = strlen(loObjHex) + strlen(loGenHex);
			lpObjectData->decrypt_part = malloc(dp_size + 10);
			sprintf(lpObjectData->decrypt_part, "%s%s", loObjHex, loGenHex);

			free(loObjHex);
			free(loGenHex);

			if (lpResult->version >= 3) {
				strcat(lpObjectData->decrypt_part, "73416C54");
			}

			char* d = trimwhitespace(pTrans->matches[10]);

			lpObjectData->md5_raw = malloc(MD5_DIGEST_LENGTH*2+1);
			md5hex(d, strlen(d), lpObjectData->md5_raw);

			size_t d_size = strlen(d);
			lpObjectData->stream = malloc(d_size+1);
			memcpy(lpObjectData->stream, d, d_size);
			lpObjectData->stream[d_size] = '\0';


    	}

		free_regex_info_info_transpose(ordered, count);
		free_regex_match_all_results(all_streams_results);
		all_streams_results = NULL;
	}


	log_debug("js streams");

	log_debug(REGEX_JS_1);
	LPPREG_MATCH_ALL_RESULT js_results = regex_match_all(REGEX_JS_1, data, data_len);

	if(js_results != NULL){
		int count = js_results->countOfMatches;

		/* Transpose array */
		PREG_INFO_TRANS** ordered = regex_info_info_transpose(js_results);

    	for(i = 0; i < count; i++){
    		PREG_INFO_TRANS* pTrans = ordered[i];
    		char object_id[32];
			sprintf(object_id,
					"%d.%d.%d",
					atoi(pTrans->matches[1]),
					atoi(pTrans->matches[2]),
					pTrans->offset);

			LPOBJECT_DATA lpObjectData = create_object_data_node(lpResult);

			size_t obj_size = strlen(object_id);
			lpObjectData->object_id = malloc(obj_size+1);
			memcpy(lpObjectData->object_id, object_id, obj_size);
			lpObjectData->object_id[obj_size] = '\0';

			lpObjectData->generation = atoi(pTrans->matches[2]);

			lpObjectData->obj_hex = malloc(sizeof(char*)*7);
			sprintf(lpObjectData->obj_hex, "%06x", atoi(pTrans->matches[1]));

			lpObjectData->gen_hex = malloc(sizeof(char*)*5);
			sprintf(lpObjectData->gen_hex, "%04x", atoi(pTrans->matches[2]));

			lpObjectData->dup_id = pTrans->offset;

			size_t param_size = strlen(pTrans->matches[3]);
			lpObjectData->parameters = malloc(param_size+1);
			memcpy(lpObjectData->parameters, pTrans->matches[3], param_size);
			lpObjectData->parameters[param_size] = '\0';

			lpObjectData->atype = malloc(3);
			strcpy(lpObjectData->atype, "js");

			char* loObjHex = lowOrder(lpObjectData->obj_hex);
			char* loGenHex = lowOrder(lpObjectData->gen_hex);
			int dp_size = strlen(loObjHex) + strlen(loGenHex);
			lpObjectData->decrypt_part = malloc(dp_size + 10);
			sprintf(lpObjectData->decrypt_part, "%s%s", loObjHex, loGenHex);

			free(loObjHex);
			free(loGenHex);

			if (lpResult->version >= 3) {
				strcat(lpObjectData->decrypt_part, "73416C54");
			}

			LPPREG_MATCH_ALL_RESULT d_results = regex_match_all("(.*)\\)$",
					pTrans->matches[6], strlen(pTrans->matches[6]));
			char* d = NULL;
			if(d_results != NULL){
				PCRE_INFO* info = regex_match_get_info(d_results, 1, 0);
				d = info->match;
			}else{
				d = pTrans->matches[6];
			}
			puts(d);
    	}
		free_regex_info_info_transpose(ordered, count);
		free_regex_match_all_results(js_results);
		js_results = NULL;
	}

	log_debug("js hex streams");
	log_debug(REGEX_JHS_1);
	LPPREG_MATCH_ALL_RESULT jhs_results = regex_match_all(REGEX_JHS_1, data, data_len);

	if(jhs_results != NULL){
		int count = jhs_results->countOfMatches;


		PREG_INFO_TRANS** ordered = regex_info_info_transpose(jhs_results);

    	for(i = 0; i < count; i++){
    		PREG_INFO_TRANS* pTrans = ordered[i];
    		char object_id[32];
			sprintf(object_id,
					"%d.%d.%d",
					atoi(pTrans->matches[1]),
					atoi(pTrans->matches[2]),
					pTrans->offset);

			LPOBJECT_DATA lpObjectData = create_object_data_node(lpResult);

			size_t obj_size = strlen(object_id);
			lpObjectData->object_id = malloc(obj_size+1);
			memcpy(lpObjectData->object_id, object_id, obj_size);
			lpObjectData->object_id[obj_size] = '\0';

			lpObjectData->generation = atoi(pTrans->matches[2]);

			lpObjectData->obj_hex = malloc(sizeof(char*)*7);
			sprintf(lpObjectData->obj_hex, "%06x", atoi(pTrans->matches[1]));

			lpObjectData->gen_hex = malloc(sizeof(char*)*5);
			sprintf(lpObjectData->gen_hex, "%04x", atoi(pTrans->matches[2]));

			lpObjectData->dup_id = pTrans->offset;

			size_t param_size = strlen(pTrans->matches[3]);
			lpObjectData->parameters = malloc(param_size+1);
			memcpy(lpObjectData->parameters, pTrans->matches[3], param_size);
			lpObjectData->parameters[param_size] = '\0';

			lpObjectData->atype = malloc(3);
			strcpy(lpObjectData->atype, "js");

			char* loObjHex = lowOrder(lpObjectData->obj_hex);
			char* loGenHex = lowOrder(lpObjectData->gen_hex);
			int dp_size = strlen(loObjHex) + strlen(loGenHex);
			lpObjectData->decrypt_part = malloc(dp_size + 10);
			sprintf(lpObjectData->decrypt_part, "%s%s", loObjHex, loGenHex);

			free(loObjHex);
			free(loGenHex);

			if (lpResult->version >= 3) {
				strcat(lpObjectData->decrypt_part, "73416C54");
			}


    	}
		free_regex_info_info_transpose(ordered, count);
		free_regex_match_all_results(jhs_results);
		jhs_results = NULL;
	}

	log_debug("single filters");

	//single objects s
	log_debug(REGEX_SF_1);
	LPPREG_MATCH_ALL_RESULT sf_results = regex_match_all(REGEX_SF_1, data, data_len);

	if(sf_results != NULL){
		int count = sf_results->countOfMatches;

		/* Transpose array */
		PREG_INFO_TRANS** ordered = regex_info_info_transpose(sf_results);
		int block_no = 0;

    	for(i = 0; i < count; i++){
    		PREG_INFO_TRANS* pTrans = ordered[i];
			block_no++;
			master_block_encoding = block_encoding;
			if(master_block_encoding != NULL)
				puts(master_block_encoding);

			char* filter_raw = pdfhex(pTrans->matches[9]);
			if(filter_raw != NULL){
				filter_raw = trimwhitespace(filter_raw);
				LPPREG_SPLIT_RESULTS pResults = regex_info_split("( |\\/)", filter_raw, strlen(filter_raw));

				if(pResults != NULL){
					free_regex_info_split_results(pResults);
				}

				free(filter_raw);
			}
    	}
		free_regex_info_info_transpose(ordered, count);
		free_regex_match_all_results(sf_results);
		sf_results = NULL;
	}


	log_debug("multi filters");


	return EXIT_SUCCESS;
}


void init_pdf_wedge_result(PDF_SLICE_RESULT* lpResult){
	lpResult->version = 0;							/* Document Version         */
	lpResult->r = 0;								/* Document Version ?       */
	lpResult->encrypted = FALSE;					/* Encrypted Document		*/
	lpResult->password = NULL;						/* Password					*/
	lpResult->key_length = 0;						/* Encryption Key Length	*/
	lpResult->encrypt_obj = NULL;
	lpResult->encrypt_gen = NULL;
	lpResult->padding = NULL;						/* Document Padding			*/
	lpResult->u = NULL;								/* U						*/
	lpResult->o = NULL;								/* O						*/
	lpResult->o_orig = NULL;						/* O orig					*/
	lpResult->id = NULL;							/* Id						*/

	lpResult->object_head = NULL;
	lpResult->object_tail = NULL;
}

void free_pdf_wedge_result(PDF_SLICE_RESULT* lpResult){
	free(lpResult->password);
	free(lpResult->encrypt_obj);
	free(lpResult->encrypt_gen);
	free(lpResult->padding);
	free(lpResult->u);
	free(lpResult->o);
	free(lpResult->o_orig);
	free(lpResult->id);
	free_object_data_node(lpResult->object_head);
}

int hex2bin(const char* hexString, unsigned char* binResutl){
	if (hexString == NULL)
		return EXIT_FAILURE;
	if (binResutl == NULL)
		return EXIT_FAILURE;

	size_t hexLenth = strlen(hexString);
	int i;
	for(i = 0; i < (hexLenth/2); i++){
		char h  = hexString[(i*2)];
		char h2 = hexString[(i*2)+1];

		unsigned char b = 0;

	    if ( h - '0' < 10 ) b = h - '0';
	    else if ( h - 'a' < 'g' - 'a' ) b = ( h - 'a' ) + 10;
	    else if ( h - 'A' < 'G' - 'A' ) b = ( h - 'A' ) + 10;

	    b = b << 4;

	    if(h2 - '0' < 10 ) b += h2 - '0';
	    else if (h2 - 'a' < 'g' - 'a') b += (h2 - 'a' ) + 10;
	    else if (h2 - 'A' < 'G' - 'A') b += (h2 - 'A' ) + 10;

	    binResutl[i] = b;
	}

	binResutl[hexLenth/2] = 0;
	return EXIT_SUCCESS;
}



LPOBJECT_DATA create_object_data_node(PDF_SLICE_RESULT* lpResult){
	LPOBJECT_DATA node = malloc(sizeof(OBJECT_DATA));

	node->object_id = NULL;
	node->object = NULL;
	node->generation = 0;
	node->obj_hex = NULL;
	node->gen_hex = NULL;
	node->dup_id = 0;
	node->parameters = NULL;
	node->decoded = NULL;
	node->next = NULL;

	node->otype = NULL;
	node->atype = NULL;
	node->decrypt_part = NULL;

	node->md5_raw = NULL;
	node->stream = NULL;

	if(lpResult->object_head == NULL){
		lpResult->object_head = node;
	}
	if(lpResult->object_tail != NULL){
		lpResult->object_tail->next = node;
	}
	lpResult->object_tail = node;

	return node;
}

void free_object_data_node(LPOBJECT_DATA node){
	if(node == NULL)
		return;

	free(node->object_id);
	free(node->object);
	free(node->obj_hex);
	free(node->gen_hex);
	free(node->parameters);
	free(node->decoded);
	free(node->otype);
	free(node->atype);
	free(node->decrypt_part);
	free(node->md5_raw);
	free(node->stream);

	free_object_data_node(node->next);
	free(node);
}

LPOBJECT_STM_RESULT create_object_stm_node(){
	LPOBJECT_STM_RESULT node = malloc(sizeof(LPOBJECT_STM_RESULT));

	node->ident = NULL;
	node->object = NULL;
	node->generation = 0;
	node->obj_id = NULL;
	node->gen_id = 0;
	node->dup_id = NULL;
	node->parameters = NULL;
	node->next = NULL;

	node->objstm = NULL;
	node->datal = NULL;

	return node;
}

void free_object_stm_node(LPOBJECT_STM_RESULT node){
	if(node == NULL)
		return;

	free(node->ident);
	free(node->object);
	free(node->obj_id);
	free(node->dup_id);
	free(node->parameters);
	free(node->objstm);
	free(node->datal);

	free_object_stm_node(node->next);

	free(node);
}


LPOBJECT_STM_RESULT parseObjStm(char* params, char* stream){
//	int n = 0;

	LPOBJECT_STM_RESULT head = NULL;
	LPOBJECT_STM_RESULT tail = NULL;

//	char** match_1 = NULL;
//	if((match_1 = regex_match("(#4E|N)\\s+(\\d+)", params)) != NULL){
//		n = atoi(match_1[2]);
//		free_regex_result(match_1);
//	}

	int first = 0;
	char** match_2 = NULL;
	if((match_2 = regex_match("(#46|F)(#69|i)(#72|r)(#73|s)(#74|t)\\s+(\\d+)", params)) != NULL){
		first = atoi(match_2[6]);
		free_regex_result(match_2);
	}

	if(first > 0){
		char* header = malloc(first * sizeof(char*));
		memcpy(header, stream, first-1);
		header[first] = '\0';

		LPPREG_MATCH_ALL_RESULT resh = regex_match_all("(\\d+)\\s+(\\d+)", header, first);

		if(resh != NULL) {
			int count = strlen(resh->subPartsList[0]->match);
			int i;
			int end;
			for (i = 0; i < count; i++) {
				if (i + 1 >= count) {
					end = strlen(stream);
				} else {
					char* s = resh->subPartsList[2]->match+i+1;
					end = atoi(s) + first - 1;
				}

				LPOBJECT_STM_RESULT node = create_object_stm_node();
				if(head == NULL){
					head = node;
					tail = node;
				}else{
					tail->next = node;
					tail = node;
				}

				node->ident = malloc(32*sizeof(char*));
				memset(node->ident, 0, 32);
				//FIXME
//				strcat(node->ident, &resh[1]->match[i]);
//				strcat(node->ident, ".0.");
//				strcat(node->ident, &resh[2]->match[i + first]);
//
//				node->object = malloc(strlen(resh[1]->match)*sizeof(char*));
//				strcpy(node->object, resh[1]->match);
//
//				node->generation = 0;
//
//				node->obj_id = malloc(strlen(resh[1]->match)*sizeof(char*));
//				strcpy(node->obj_id, resh[1]->match);

				node->gen_id = 0;

//				node->dup_id = malloc(strlen(resh[2]->match)*sizeof(char*));
//				strcpy(node->obj_id, &resh[2]->match[i+first]);

				//split params and stream
				node->parameters = malloc((end - first + 1)*sizeof(char*));
				memcpy(node->parameters, stream+first, end - first);
				node->parameters[end - first] = '\0';
			}
		}
	}
	return head;
}

LPORDER create_order(){
	LPORDER ret = malloc(sizeof(ORDER));

	ret->dup_id = 0;
	ret->end = 0;
	ret->gen_id = 0;
	ret->len = 0;
	ret->obj_id = 0;
	ret->otype = NULL;
	ret->parameters = NULL;
	ret->start = 0;

	return ret;
}

void free_order(LPORDER pOrder){
	free(pOrder->otype);
	free(pOrder->parameters);
}


char* flashExplode (char* stream) {
	char magic[4];
	memcpy(magic, stream, 3);
	magic[3] = '\0';

	if(strcmp(magic,"CWS") == 0) {
		char header[6];
		memcpy(header, stream+4, 5);
		header[5] = '\0';

		char* content = stream+10;

		char* uncompressed = gzinflate(content, strlen(content));

		char* exploded;
		int exploded_size = strlen(header) + strlen(uncompressed)+4;

		exploded = malloc(exploded_size*sizeof(char*));
		sprintf(exploded, "FWS%s%s", header, uncompressed);
		return exploded;
	} else
		return stream;

}

char* gzinflate (char* content, size_t data_len){
	int status;
	unsigned int factor=1, maxfactor=16;
	unsigned long plength=0, length;
	char *s1=NULL, *s2=NULL;
	z_stream stream;

	stream.zalloc = Z_NULL;
	stream.zfree = Z_NULL;
	stream.opaque = Z_NULL;
	stream.avail_in = data_len + 1; /* there is room for \0 */
	stream.next_in = (Bytef *) content;
	stream.total_out = 0;

	/* init with -MAX_WBITS disables the zlib internal headers */
	status = inflateInit2(&stream, -MAX_WBITS);
	if (status != Z_OK) {
		return NULL;;
	}

	/*
	  stream.avail_out wants to know the output data length
	  if none was given as a parameter
	  we try from input length * 2 up to input length * 2^15
	  doubling it whenever it wasn't big enough
	  that should be enaugh for all real life cases
	*/
	do {
		length = (unsigned long)data_len * (1 << factor++);
		s2 = (char *) realloc (s1, length);

		if (s2 == NULL && length != 0){
	    	fputs("Error reallocating memory", stderr);
	    	return NULL;
	    }

		if (!s2) {
			if (s1) {
				free(s1);
			}
			inflateEnd(&stream);
			return NULL;
		}
		s1 = s2;

		stream.next_out = (Bytef *) &s2[stream.total_out];
		stream.avail_out = length - stream.total_out;
		status = inflate(&stream, Z_NO_FLUSH);

	} while ((Z_BUF_ERROR == status || (Z_OK == status && stream.avail_in)) && !plength && factor < maxfactor);

	inflateEnd(&stream);

	if ((plength && Z_OK == status) || factor >= maxfactor) {
		status = Z_MEM_ERROR;
	}

	if (Z_STREAM_END == status || Z_OK == status) {
		s2 = realloc(s2, stream.total_out + 1); /* room for \0 */
		s2[stream.total_out] = '\0';
		return s2;
	} else {
		free(s2);
	}
	return NULL;
}


LPMALWARE javascriptScan(LPMALWARE pMalware, char* dec, char* stringSearch, char* hexSearch){
	return NULL;
}


char* findHiddenJS(char* string){
	return NULL;
}

LPOBJECT_DATA pdf_object_data_find_with_id(LPPDF_SLICE_RESULT pResults, char* object_id){
	LPOBJECT_DATA head = pResults->object_head;
	while(head != NULL){
		if(strcmp(object_id, head->object_id) == 0)
			return head;
		head = head->next;
	}
	return NULL;
}
