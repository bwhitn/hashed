#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

const uint8_t  num_of_hashes     = 20;
const uint32_t min_hash_bytes    = 8;
const uint32_t e_b85_divisors[5] = {52200625, 614125, 7225, 85, 1};
const char     *e_b85_chars      = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-_?+=^!/*&<>()[]{}@%$~";
const uint32_t adler32_mod_val   = 65521;
const uint32_t buff_size_s       = 128;
// 4 nulls, 4 LF, 2 CRLF
enum           char_match        { NUL=0, LF=10, CR=13 };


//This should probably be replaced with the zlib version at some point
struct Adler32 {
    uint16_t high;
    uint16_t low;
    uint32_t size;
};

// buff is the hash buffer, buff size is the current size of data on the buffer, hashes is the array that contains
// the hashes, hash_size is the number of hashes in hashes, hash_concat_loc is the current location used for concating
// hashes, finalize_data says wether it should expect more data, current_hash is the current hash.
struct Hash {
    uint8_t        buff[buff_size_s];
    uint32_t       buff_size;
    uint32_t       hashes[21];
    uint8_t        hash_size;
    uint8_t        hash_concat_loc;
    uint8_t        finalize_data;
    uint8_t        first_hash;
    struct Adler32 current_hash;
};

//initializes the Adler32 struct.
void adler32_init(struct Adler32 *adler) {
    adler->high = 0;
    adler->low = 1;
    adler->size = 0;
}

//adds data to the Adler32 struct.
void adler32_update(struct Adler32 *adler, uint8_t *data, uint32_t data_len) {
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

//initializes the Hash struct.
void init_hasher(struct Hash *hash) {
    hash->hash_size = 0;
    hash->hash_concat_loc = 1;
    hash->buff_size = 0;
    hash->finalize_data = 0;
    hash->first_hash = 1;
    adler32_init(&hash->current_hash);
}

//move data starting at location to the end of hash buff and return the next location for reading data.
//if the next location is greater than or equal to the data size then all of the data has been read.
uint32_t move_to_buff(struct Hash *hash, uint8_t *data, uint32_t data_size, uint32_t location) {
    if ((buff_size_s > hash->buff_size) || (data_size > location)) {
        uint32_t buff_left = buff_size_s - hash->buff_size;
        uint32_t data_left = data_size - location;
        if (!buff_left) {
            if (buff_left > data_left) {
                memcpy(hash->buff + hash->buff_size, data + location, data_left);
                hash->buff_size += data_left;
            } else {
                memcpy(hash->buff + hash->buff_size, data + location, buff_left);
                hash->buff_size += buff_left;
                return data_size - data_left;
            }
        }
    }
    return 0;
}

// are we adding a duplicate hash?
uint8_t has_hash(struct Hash *hash, uint32_t hash_val) {
    uint8_t i = 0;
    for (; i < hash->hash_size; i++) {
        if (hash_val == hash->hashes[i]) {
            return 1;
        }
    }
    return 0;
}

void shuffle_value(struct Hash *hash) {
    hash->hashes[hash->hash_concat_loc] = hash->hashes[hash->hash_concat_loc] ^ hash->hashes[hash->hash_concat_loc + 1];
    if (hash->hash_concat_loc == 20) {
        hash->hash_concat_loc = 1;
    } else {
        hash->hash_concat_loc++;
    }
}

// add a hash to the hash values or don't
void add_hash(struct Hash *hash, uint32_t hash_val) {
    if (hash->current_hash.size < 8) {
        return;
    }
    uint8_t dup_val = has_hash(hash, hash_val);
    if (!dup_val) {
        hash->hashes[hash->hash_size] = hash_val;
        hash->hash_size++;
        if (hash->hash_size == 21) {
            shuffle_value(hash);
            hash->current_hash.size--;
        }
    }
}

//finalize the hash. data should be large enough to store the hash. return value is the hash size in bytes
uint16_t finalize_hasher(struct Hash *hash, char *data) {
    return 0;
}

//remove the n number of bytes from the head of the buffer and reposition the data.
void remove_nbuff_bytes(struct Hash *hash, uint32_t size) {
    memmove(hash->buff, hash->buff + size, hash->buff_size - size);
    hash->buff_size -= size;
}

//move bytes to data and adjust the buffer. May not move the exact size. Will return the number of bytes moved.
uint32_t set_data_move_buff(struct Hash *hash, uint8_t *data, uint32_t size) {
    if (size >= hash->buff_size) {
        if (!hash->finalize_data) {
            size = hash->buff_size - 4;
        }
    }
    memmove(data, hash->buff, size);
    remove_nbuff_bytes(hash, size);
    return size;
}

//split data from the buffer return the size and set the value of data.
uint32_t split_data(struct Hash *hash, uint8_t *data) {
    if (hash->buff_size > 3 || (hash->finalize_data && hash->buff_size)) {
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
                    if (hash->buff[i] == NUL || hash->buff[i] == LF || hash->buff[i] == CR) {
                        break;
                    }
                    i++;
                }
                return set_data_move_buff(hash, data, i);
        }
        remove_nbuff_bytes(hash, i);
    }
    return 0;
}

//TODO: need to add condition for first hash being the first 8 bytes
//updates the hash with data in the size of data_size
void update_hasher(struct Hash *hash, uint8_t *data, uint32_t data_size) {
    uint32_t location = move_to_buff(hash, data, data_size, location);
    uint8_t hash_data[buff_size_s];
    if (hash->first_hash && hash->buff_size > 7) {
        memcpy(hash_data, hash->buff, 8);
        adler32_update(&hash->current_hash, hash_data, 8);
        hash->hashes[0] = adler32_finalize(&hash->current_hash);
    }
    uint8_t data_for_hashing[128];
    while (location < data_size) {
        location = move_to_buff(hash, data, data_size, location);
        while (hash->buff_size > 4) {
            uint32_t hash_data_size = split_data(hash, hash_data);
            if (hash_data_size) {
                adler32_update(&hash->current_hash, hash_data, hash_data_size);
            } else {
                uint32_t hash_val = adler32_finalize(&hash->current_hash);
                adler32_init(&hash->current_hash);
            }
        }
    }
}

//test function to verify everything is working correctly
void test_func(void) {
    unsigned char wiki[] = "Wikipedia";
    struct Adler32 adler;
    printf("String: %s\n", wiki);
    adler32_init(&adler);
    adler32_update(&adler, wiki, 9);
    uint32_t hash_val = adler32_finalize(&adler);
    printf("Adler32 values: %d\n", hash_val);
    char enc_val[6];
    enc_val[5] = 0;
    b85_encode(hash_val, enc_val);
    printf("Base85 Encoding: %s\n", enc_val);
    struct Hash hash;
    init_hasher(&hash);
    uint32_t data_size;
    uint8_t data[128];
    uint8_t *mystr = (uint8_t *) "test\n\n\n\n\n\n2\0\0";
    memmove(&hash.buff, mystr, 14);
    hash.buff_size = 14;
    while (data_size || hash.buff_size > 4) {
        data_size = split_data(&hash, data);
        printf("data size: %d\n", data_size);
        printf("data: %.*s\n", data_size, data);
        printf("buff size: %d\n", hash.buff_size);
        printf("buff:%.*s\n", hash.buff_size, hash.buff);
    }
    printf("--- finalize data ---\n");
    hash.finalize_data = 1;
    while (hash.buff_size) {
        data_size = split_data(&hash, data);
        printf("data size: %d\n", data_size);
        printf("data: %.*s\n", data_size, data);
        printf("buff size: %d\n", hash.buff_size);
        printf("buff:%.*s\n", hash.buff_size, hash.buff);
    }
}

int main(void) {
    test_func();
}
