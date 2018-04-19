#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <stdint.h>
#include <string.h>
#include <regex.h>

const uint8_t  num_of_hashes     = 20;
const uint32_t min_hash_bytes    = 8;
const uint32_t e_b85_divisors[5] = {52200625, 614125, 7225, 85, 1};
const char     *e_b85_chars   = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-_?+=^!/*&<>()[]{}@%$~";
const uint32_t adler32_mod_val   = 65521;
const char     *reg_split_val = "(\n{4,}|(\r\n){2,})";
regex_t  reg;

struct Adler32
{
    uint32_t high;
    uint32_t low;
    uint32_t size;
};

struct Hash
{
    unsigned char buff;
    uint32_t      buff_size;
    char          *hashes[21];
    uint8_t       hash_size;
    uint8_t       hash_concat_loc;
};

//initializes the Adler32 struct.
void adler32_init(struct Adler32 *adler)
{
    adler->high = 0;
    adler->low = 1;
    adler->size = 0;
}

//adds data to the Adler32 struct.
void adler32_update(struct Adler32 *adler, unsigned char *data, uint32_t data_len)
{
    adler->size += data_len;
    uint32_t i;
    for(i = 0; i < data_len; i++)
    {
        adler->low += data[i];
        adler->low %= adler32_mod_val;
        adler->high += adler->low;
        adler->high %= adler32_mod_val;
    }
}

//returns the Adler32 value. Need to re-initialize the struct before using again.
uint32_t adler32_finalize(struct Adler32 *adler)
{
    return adler->high << 16 | adler->low;
}

//base85 encoding of a 32bit unsigned int
void b85_encode(uint32_t hash, char *enc_hash)
{
    uint32_t i;
    for(i = 0; i < 5; i++)
    {
        enc_hash[i] = e_b85_chars[(hash / e_b85_divisors[i]) % 85];
    }
}

//test function to verify everything is working correctly
void test_func(void)
{
    unsigned char wiki[] = "Wikipedia";
    struct Adler32 hash;
    printf("String: %s\n", wiki);
    adler32_init(&hash);
    adler32_update(&hash, wiki, 9);
    uint32_t hash_val = adler32_finalize(&hash);
    printf("Adler32 values: %d\n", hash_val);
    char enc_val[6];
    enc_val[5] = 0;
    b85_encode(hash_val, enc_val);
    printf("Base85 Encoding: %s\n", enc_val);

}

//Clean up function before exiting.
void cleanup(void)
{
    regfree(&reg);
}

void init(void)
{
    int res = regcomp(&reg, reg_split_val, REG_EXTENDED);
    if (res)
    {
        char error_message[0x1000];
        regerror(res, &reg, error_message, 0x1000);
        printf("Error compiling '%s': %s\n", reg_split_val, error_message);
        exit(1);
    }
}

void init_hasher(struct Hash *hash)
{
    hash->hash_size = 0;
    hash->hash_concat_loc = 1;
    hash->buff_size = 0;
}

//split data from the buffer return the size and set the value of data.
uint32_t split_data(struct Hash *hash, unsigned char data)
{
    
}

int main(void)
{
    init();
    //test_func();
    //REG_EXTENDED REG_NOMATCH
    int max_match = 1;
    regmatch_t matches[max_match];
    int resd = regexec(&reg, "hasmatch\r\n\r\nnextval", max_match, matches, 0);
    if (!resd)
    {
        printf("Reg offset 1: %d\n", matches[0].rm_so);
        printf("Reg offset 2: %d\n", matches[0].rm_eo);
    } else {
        char error_message[0x1000];
        regerror(resd, &reg, error_message, 0x1000);
        printf("Error Exec: %s\n", error_message);
    }
    cleanup();
}
