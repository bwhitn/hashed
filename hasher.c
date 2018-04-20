#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>

const uint8_t  num_of_hashes     = 20;
const uint32_t min_hash_bytes    = 8;
const uint32_t e_b85_divisors[5] = {52200625, 614125, 7225, 85, 1};
const char     *e_b85_chars      = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-_?+=^!/*&<>()[]{}@%$~";
const uint32_t adler32_mod_val   = 65521;
// 4 nulls, 4 LF, 2 CRLF
enum           char_match        { NUL=0, LF=10, CR=13 };

struct Adler32 {
    uint32_t high;
    uint32_t low;
    uint32_t size;
};

struct Hash {
    uint8_t        buff[512];
    uint32_t       buff_size;
    char           hashes[21][6];
    uint8_t        hash_size;
    uint8_t        hash_concat_loc;
    uint8_t        finalize_data;
    struct Adler32 current_hash;
};

//initializes the Adler32 struct.
void adler32_init(struct Adler32 *adler) {
    adler->high = 0;
    adler->low = 1;
    adler->size = 0;
}

//adds data to the Adler32 struct.
void adler32_update(struct Adler32 *adler, unsigned char *data, uint32_t data_len) {
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
uint32_t adler32_finalize(struct Adler32 *adler) {
    return adler->high << 16 | adler->low;
}

//base85 encoding of a 32bit unsigned int
void b85_encode(uint32_t hash, char *enc_hash) {
    uint32_t i;
    for(i = 0; i < 5; i++)
    {
        enc_hash[i] = e_b85_chars[(hash / e_b85_divisors[i]) % 85];
    }
}

//test function to verify everything is working correctly
void test_func(void) {
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

//initializes the Hash struct.
void init_hasher(struct Hash *hash) {
    hash->hash_size = 0;
    hash->hash_concat_loc = 1;
    hash->buff_size = 0;
    hash->finalize_data = 0;
}

//updates the hash with data in the size of data_size
void update_hasher(struct Hash *hash, uint8_t *data, uint32_t data_size) {

}

//finalize the hash. data should be large enough to store the hash. return value is the hash size in bytes
uint16_t finalize_hasher(struct Hash *hash, char *data) {

}

//remove the n number of bytes from the head of the buffer and reposition the data.
void remove_nbuff_bytes(struct Hash *hash, uint32_t size) {
    memmove(hash->buff, hash->buff + size, hash->buff_size - size);
    hash->buff_size -= size;
}

//move bytes to data and adjust the buffer. May not move the exact size. Will return the number of bytes moved.
uint32_t set_data_move_buff(struct Hash *hash, uint8_t *data, uint32_t size) {
    if (size + 4 >= hash->buff_size) {
        if (!hash->finalize_data) {
            size = hash->buff_size - 4;
        }
    }
    memmove(data, hash->buff, size);
    remove_nbuff_bytes(hash, size);
}

//TODO: Need to check if within 4 of hash->buff_size.
//split data from the buffer return the size and set the value of data.
uint32_t split_data(struct Hash *hash, uint8_t *data) {
    if (hash->buff_size > 3) {
        uint32_t i = 1;
        switch(hash->buff[0]) {
            case NUL:
                while (i < hash->buff_size) {
                    if (hash->buff[i] != NUL) {
                        break;
                    }
                    i++;
                }
                if (i > 3) {
                    break;
                }
                return set_data_move_buff(hash, data, i);
            case LF:
                while (i < hash->buff_size) {
                    if (hash->buff[i] != LF) {
                        break;
                    }
                    i++;
                }
                if (i > 3) {
                    break;
                }
                return set_data_move_buff(hash, data, i);
            case CR:
                while (i < hash->buff_size) {
                    if (i % 2) {
                    	if (hash->buff[i] != LF) {
                            i--;
                            break;
                        }
                    } else {
                        if (hash->buff[i] != CR) {
                            break;
                        }
                    }
                    i++;
                }
                if (i > 3) {
                    break;
                }
                return set_data_move_buff(hash, data, i);
            default:
                while (i < hash->buff_size) {
                    if (hash->buff[i] == NUL && hash->buff[i] == LF && hash->buff[i] == CR) {
                        break;
                    }
                    i++;
                }
                return set_data_move_buff(hash, data, i);
            remove_nbuff_bytes(hash, i);
        }
    }
    return 0;
}

int main(void) {
    test_func();
    struct Hash hash;
    printf("test1");
    init_hasher(&hash);
    uint32_t data_size;
    char data[512];
    printf("test");
    char *mystr = "test\n\n\n\n\n\n\n\ntest2";
    memmove(hash.buff, mystr, 17);
    hash.buff_size = 18;
    data_size = split_data(&hash, data);
    data[data_size] = 0;
    printf("%s\n", data);
}
