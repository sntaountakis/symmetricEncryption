#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/cmac.h>
#include <openssl/sha.h>

#define BLOCK_SIZE 16
#define CMAC_SIZE 16
#define MAXBUFLEN 1000000

/* function prototypes */
void print_hex(unsigned char *, size_t);
void print_string(unsigned char *, size_t); 
void usage(void);
void check_args(char *, char *, unsigned char *, int, int);
void keygen(unsigned char *, unsigned char **, unsigned char **, int);
int encrypt(unsigned char *, int, unsigned char **, unsigned char **, 
    unsigned char **, int );
int decrypt(unsigned char *, int, unsigned char **, unsigned char **, 
    unsigned char **, int);
void gen_cmac(unsigned char *, size_t, unsigned char *, unsigned char **, int);
int verify_cmac(unsigned char *, unsigned char *);


/* TODO Declare your function prototypes here... */
void encode_file(char* input_path, char* output_path, unsigned char* password, int bit_mode);
void decode_file(char* input_path, char* output_path, unsigned char* password, int bit_mode);
void verify_file(char* input_path, char* output_path, unsigned char* password, int bit_mode);
unsigned char* read_file(char* file_name, int *file_size);
void write_file(unsigned char* text, char* path, int textsize);
unsigned char* concatenate(unsigned char *text1, int text1_len, unsigned char *text2, int text2_len);
/*
 * Prints the hex value of the input
 * 16 values per line
 */
void
print_hex(unsigned char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++) {
			if (!(i % 16) && (i != 0))
				printf("\n");
			printf("%02X ", data[i]);
		}
		printf("\n");
	}
}


/*
 * Prints the input as string
 */
void
print_string(unsigned char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++)
			printf("%c", data[i]);
		printf("\n");
	}
}


/*
 * Prints the usage message
 * Describe the usage of the new arguments you introduce
 */
void
usage(void)
{
	printf(
	    "\n"
	    "Usage:\n"
	    "    assign_1 -i in_file -o out_file -p passwd -b bits" 
	        " [-d | -e | -s | -v]\n"
	    "    assign_1 -h\n"
	);
	printf(
	    "\n"
	    "Options:\n"
	    " -i    path    Path to input file\n"
	    " -o    path    Path to output file\n"
	    " -p    psswd   Password for key generation\n"
	    " -b    bits    Bit mode (128 or 256 only)\n"
	    " -d            Decrypt input and store results to output\n"
	    " -e            Encrypt input and store results to output\n"
	    " -s            Encrypt+sign input and store results to output\n"
	    " -v            Decrypt+verify input and store results to output\n"
	    " -h            This help message\n"
	);
	exit(EXIT_FAILURE);
}


/*
 * Checks the validity of the arguments
 * Check the new arguments you introduce
 */
void
check_args(char *input_file, char *output_file, unsigned char *password, 
    int bit_mode, int op_mode)
{
	if (!input_file) {
		printf("Error: No input file!\n");
		usage();
	}

	if (!output_file) {
		printf("Error: No output file!\n");
		usage();
	}

	if (!password) {
		printf("Error: No user key!\n");
		usage();
	}

	if ((bit_mode != 128) && (bit_mode != 256)) {
		printf("Error: Bit Mode <%d> is invalid!\n", bit_mode);
		usage();
	}

	if (op_mode == -1) {
		printf("Error: No mode\n");
		usage();
	}
}


/*
 * Generates a key using a password
 */
void
keygen(unsigned char *password, unsigned char **key, unsigned char **iv,
    int bit_mode)
{	
	if (bit_mode == 128){
		EVP_BytesToKey(EVP_aes_128_ecb(), EVP_sha1(), NULL, password, strlen((char*)password),
						1, *key, *iv);
	}
	else{
		EVP_BytesToKey(EVP_aes_256_ecb(), EVP_sha1(), NULL, password, strlen((char*)password),
						1, *key, *iv);
	}
}


/*
 * Encrypts the data
 */
int
encrypt(unsigned char *plaintext, int plaintext_len, unsigned char **key,
    unsigned char **iv, unsigned char **ciphertext, int bit_mode)
{
	EVP_CIPHER_CTX *ctx; 

	int len; 
	int ciphertext_len;

	if(!(ctx = EVP_CIPHER_CTX_new())){
		ERR_print_errors_fp(stderr);
		abort();
	}

	if (bit_mode == 128){
		if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, *key, *iv)){
			ERR_print_errors_fp(stderr);
			abort();
		}

	}else{
		if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, *key, *iv)){
			ERR_print_errors_fp(stderr);
			abort();
		}
	}
	
	if(1 != EVP_EncryptUpdate(ctx, *ciphertext, &len, plaintext, plaintext_len)){
		ERR_print_errors_fp(stderr);
		abort();
	}

    ciphertext_len = len;

	/*Handling any data that remains after the final block*/
	if(1 != EVP_EncryptFinal_ex(ctx, *ciphertext + len, &len)){
		ERR_print_errors_fp(stderr);
		abort();
	}
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
	return ciphertext_len;
}


/*
 * Decrypts the data and returns the plaintext size
 */
int
decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char **key,
    unsigned char **iv, unsigned char **plaintext, int bit_mode)
{
	EVP_CIPHER_CTX *ctx;

	int len;
	int plaintext_len;
	
	if(!(ctx = EVP_CIPHER_CTX_new())){
		ERR_print_errors_fp(stderr);
		abort();
	}

	if (bit_mode == 128){
		if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, *key, *iv)){
			ERR_print_errors_fp(stderr);
			abort();
		}

	}else{
		if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, *key, *iv)){
			ERR_print_errors_fp(stderr);
			abort();
		}
	}

	if(1 != EVP_DecryptUpdate(ctx, *plaintext, &len, ciphertext, ciphertext_len)){
		ERR_print_errors_fp(stderr);
		abort();
	}
	plaintext_len = len; 

	if(1 != EVP_DecryptFinal_ex(ctx, *plaintext + len, &len)){
        ERR_print_errors_fp(stderr);
		abort();
	}
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

	return plaintext_len;
}


/*
 * Generates a CMAC
 */
void
gen_cmac(unsigned char *data, size_t data_len, unsigned char *key, 
    unsigned char **cmac, int bit_mode)
{
	size_t cmac_len; 
	CMAC_CTX *ctx;

	if(!(ctx = CMAC_CTX_new())){
		ERR_print_errors_fp(stderr);
		abort();
	}

	if (bit_mode == 128){
		if(1 != CMAC_Init(ctx, key, bit_mode/8, EVP_aes_128_ecb(), NULL)){
			ERR_print_errors_fp(stderr);
			abort();
		}

	}else{
		if(1 != CMAC_Init(ctx, key, bit_mode/8, EVP_aes_256_ecb(), NULL)){
			ERR_print_errors_fp(stderr);
			abort();
		}
	}

	if(1 != CMAC_Update(ctx, data, data_len)){
		ERR_print_errors_fp(stderr);
		abort();
	}

	if(1 != CMAC_Final(ctx, *cmac, &cmac_len)){
		ERR_print_errors_fp(stderr);
		abort();
	}

	CMAC_CTX_free(ctx);
}


/*
 * Verifies a CMAC
 */
int
verify_cmac(unsigned char *cmac1, unsigned char *cmac2)
{
	int verify;

	verify = 0;

	/* TODO Task E */

	return verify;
}


void encode_file(char* input_path, char* output_path, unsigned char* password, int bit_mode){

	unsigned char* key, *iv, *plaintext, *ciphertext;	
	int ciphertext_len;
	int file_size; 
	
	/* Generate key */
	key = (unsigned char*)malloc((bit_mode/8+1)*sizeof(unsigned char*));
	iv = (unsigned char*)malloc((bit_mode/8+1)*sizeof(unsigned char*));
	keygen(password, &key, &iv, bit_mode);
		 
	/* read file */ 
	plaintext = read_file(input_path, &file_size);
	if (plaintext == 0){
		printf("Could not read file.\n");
		exit(0);
	}
	
	/* encrypt */
	ciphertext = (unsigned char*)malloc((file_size*2)*sizeof(unsigned char*));
	ciphertext_len = encrypt(plaintext, file_size, &key, &iv, &ciphertext, bit_mode);
	  
	/* write output file */
	write_file(ciphertext, output_path, ciphertext_len);

}

void decode_file(char* input_path, char* output_path, unsigned char* password, int bit_mode){
	
	unsigned char* key, *iv, *plaintext, *ciphertext;	
	int plaintext_len;
	int file_size; 
	
	/* Generate key */
	key = (unsigned char*)malloc((bit_mode/8+1)*sizeof(unsigned char*));
	iv = (unsigned char*)malloc((bit_mode/8+1)*sizeof(unsigned char*));
	keygen(password, &key, &iv, bit_mode);

	/* read file */
	ciphertext = read_file(input_path, &file_size);
	if (ciphertext == 0){
		printf("Could not read file.\n");
		exit(0);
	}

	/* decrypt */
	plaintext = (unsigned char*)malloc((file_size*2)*sizeof(unsigned char*));
	plaintext_len = decrypt(ciphertext, file_size, &key, &iv, &plaintext, bit_mode);
	plaintext[plaintext_len] = '\0';
	
	/* write file */
	write_file(plaintext, output_path, plaintext_len);

}

void sign_file(char* input_path, char* output_path, unsigned char* password, int bit_mode){
	
	unsigned char *key, *iv, *plaintext, *ciphertext, *cmac, *conctext;
	int ciphertext_len; 
	int file_size; 
	
	/* Generate key */
	key = (unsigned char*)malloc((bit_mode/8+1)*sizeof(unsigned char*));
	iv = (unsigned char*)malloc((bit_mode/8+1)*sizeof(unsigned char*));
	keygen(password, &key, &iv, bit_mode);
	
	/* read file */
	plaintext = read_file(input_path, &file_size);
	if (plaintext == 0){
		printf("Could not read file.\n");
		exit(0);
	}

	/* Encrypt Data */
	ciphertext = (unsigned char*)malloc((file_size*2)*sizeof(unsigned char*));
	ciphertext_len = encrypt(plaintext, file_size, &key, &iv, &ciphertext, bit_mode);

	/* generate CMAC */
	cmac = (unsigned char*)malloc((CMAC_SIZE+1)*sizeof(unsigned char*));
	gen_cmac(plaintext, file_size, key, &cmac, bit_mode);

	/* concatenate ciphertext with cmac */
	conctext = (unsigned char*)malloc((ciphertext_len+CMAC_SIZE+2)*sizeof(unsigned char*));
	conctext = concatenate(ciphertext, ciphertext_len, cmac, CMAC_SIZE);
	
	/* write to file */
	write_file(conctext, output_path, ciphertext_len+CMAC_SIZE);
}

void verify_file(char* input_path, char* output_path, unsigned char* password, int bit_mode){

	unsigned char* key, *iv, *plaintext, *conctext, *ciphertext, *cmac, *plain_cmac;	
	int plaintext_len;
	int file_size; 
	
	/* Generate key */
	key = (unsigned char*)malloc((bit_mode/8+1)*sizeof(unsigned char*));
	iv = (unsigned char*)malloc((bit_mode/8+1)*sizeof(unsigned char*));
	keygen(password, &key, &iv, bit_mode);

	/* read file */
	conctext = read_file(input_path, &file_size);
	if (conctext == 0){
		printf("Could not read file.\n");
		exit(0);
	}
	
	/* split ciphertext from CMAC */
	ciphertext = (unsigned char*)malloc((file_size)*sizeof(unsigned char*));
	cmac = (unsigned char*)malloc((CMAC_SIZE)*sizeof(unsigned char*));
	memcpy(ciphertext, conctext, file_size-CMAC_SIZE);
	memcpy(cmac, &conctext[file_size-CMAC_SIZE], CMAC_SIZE);
	
	/* Decrypt file */
	plaintext = (unsigned char*)malloc((file_size*2)*sizeof(unsigned char*));
	plaintext_len = decrypt(ciphertext, file_size-CMAC_SIZE, &key, &iv, &plaintext, bit_mode);
	plaintext[plaintext_len] = '\0';

	//write_file(plaintext, output_path, plaintext_len);

	/* Generate CMAC from plaintext */
	plain_cmac = (unsigned char*)malloc((CMAC_SIZE+1)*sizeof(unsigned char*));
	gen_cmac(plaintext, plaintext_len, key, &plain_cmac, bit_mode);

	/* Compare the two CMAC */
	if (memcmp(cmac, plain_cmac, CMAC_SIZE)!=0){
		printf("Not the same\n");
		return;
	}

	printf("Same\n");
}

unsigned char* concatenate(unsigned char *text1, int text1_len, unsigned char *text2, int text2_len){
	unsigned char *conctext = (unsigned char*)malloc((text1_len+text2_len+2)*sizeof(unsigned char*));
	memcpy(conctext, text1, text1_len);
	memcpy(conctext+text1_len, text2, text2_len);

	return conctext; 
}

unsigned char* read_file(char* file_name, int *file_size){
	FILE* fp = fopen(file_name, "r");
	if (fp == NULL)
		return 0; 
	
	char* source = (char*)malloc((MAXBUFLEN+1)*sizeof(char));
	size_t newLen = fread(source, sizeof(char), MAXBUFLEN, fp);
	fclose(fp);
	
	char* buffer = (char*)malloc((newLen)*sizeof(char));
	memcpy(buffer, source, newLen);
	
	free(source);
	*file_size = (int)newLen;
	return (unsigned char*)buffer;
}

void write_file(unsigned char* text, char* path, int textsize){
	FILE* fp = fopen(path, "w"); 
	if (fp == NULL){
		printf("Unable to create file.\n");
		return; 
	}
	
	for (int i=0; i<textsize; i++){
		fwrite(&text[i], 1, sizeof(text[i]), fp);
	}

	fclose(fp);
}


/*
 * Encrypts the input file and stores the ciphertext to the output file
 *
 * Decrypts the input file and stores the plaintext to the output file
 *
 * Encrypts and signs the input file and stores the ciphertext concatenated with 
 * the CMAC to the output file
 *
 * Decrypts and verifies the input file and stores the plaintext to the output
 * file
 */
int
main(int argc, char **argv)
{
	int opt;			/* used for command line arguments */
	int bit_mode;			/* defines the key-size 128 or 256 */
	int op_mode;			/* operation mode */
	char *input_file;		/* path to the input file */
	char *output_file;		/* path to the output file */
	unsigned char *password;	/* the user defined password */

	/* Init arguments */
	input_file = NULL;
	output_file = NULL;
	password = NULL;
	bit_mode = -1;
	op_mode = -1;

	
	/*
	 * Get arguments
	 */
	
	while ((opt = getopt(argc, argv, "b:i:m:o:p:desvh:")) != -1) {
		switch (opt) {
		case 'b':
			bit_mode = atoi(optarg);
			break;
		case 'i':
			input_file = strdup(optarg);
			break;
		case 'o':
			output_file = strdup(optarg);
			break;
		case 'p':
			password = (unsigned char *)strdup(optarg);
			break;
		case 'd':
			/* if op_mode == 1 the tool decrypts */
			op_mode = 1;
			break;
		case 'e':
			/* if op_mode == 0 the tool encrypts */
			op_mode = 0;
			break;
		case 's':
			/* if op_mode == 2 the tool signs */
			op_mode = 2;
			break;
		case 'v':
			/* if op_mode == 3 the tool verifies */
			op_mode = 3;
			break;
		case 'h':
		default:
			usage();
		}
	}
	

	
	/* check arguments */
	check_args(input_file, output_file, password, bit_mode, op_mode);

	
	if (op_mode == 0){
		encode_file(input_file, output_file, password, bit_mode);
	}
	else if (op_mode == 1){
		decode_file(input_file, output_file, password, bit_mode);
	}
	else if (op_mode == 2){
		sign_file(input_file, output_file, password, bit_mode);
	}
	else if (op_mode == 3){
		verify_file(input_file, output_file, password, bit_mode);
	}

	/* END */
	EVP_cleanup();
 	exit(0);
	return 0;
}
