#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

const uint8_t  num_of_hashes     = 20;
const uint32_t min_hash_bytes    = 8;
const uint32_t e_b85_divisors[5] = {52200625, 614125, 7225, 85, 1};
const char     *e_b85_chars      = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.:_?+=^!/*&<>()[]{}@%$~";
const uint32_t adler32_mod_val   = 65521;
const uint32_t buff_size_s       = 128;
// 4 nulls, 4 LF, 2 CRLF
enum           char_match        { NUL=0, LF=10, CR=13 };


//This Adler32 implementation should probably be replaced with the zlib version at some point
struct Adler32 {
    uint32_t high;
    uint32_t low;
    uint32_t size;
};

// TODO: change buff to pointer and buff_size to the size of the buff,tail of last buff 4 bytes and last size, and buff_loc
// TODO: remove as many memmove and memcpy as possible
// buff is the hash buffer, buff size is the current size of data on the buffer, hashes is the array that contains
// the hashes, hash_size is the number of hashes in hashes, hash_concat_loc is the current location used for concating
// hashes, finalize_data says wether it should expect more data, current_hash is the current hash.
struct Hash {
    uint8_t        *buff; //Should be the same size as value of buff_size_s
    uint32_t       buff_size;
    uint8_t        prev_buff[4];
    uint32_t       prev_buff_size;
    uint32_t       curr_buff_pos; // 0 to buff_size - 1 + 4
    uint32_t       hashes[21];
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
    adler32_init(&hash->current_hash);
}

//move data starting at location to the end of hash buff and return the next location for reading data.
//if the next location is greater than or equal to the data size then all of the data has been read.
uint32_t move_to_buff(struct Hash *hash, uint8_t *data, uint32_t data_size, uint32_t location) {
    if ((buff_size_s > hash->buff_size) || (data_size > location)) {
        uint32_t buff_left = buff_size_s - hash->buff_size;
        uint32_t data_left = data_size - location;
        if (buff_left) {
            if (buff_left > data_left) {
                memcpy(hash->buff + hash->buff_size, data + location, data_left);
                hash->buff_size += data_left;
                return data_size;
            } else {
                memcpy(hash->buff + hash->buff_size, data + location, buff_left);
                hash->buff_size += buff_left;
                return location + buff_left;
            }
        }
    }
    return location;
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
    hash->hashes[hash->hash_concat_loc] ^= hash->hashes[hash->hash_concat_loc + 1];
    uint32_t i = ++hash->hash_concat_loc;
    //TODO: replace with memmove
    for (;i < 20; i++) {
        hash->hashes[i] = hash->hashes[i + 1];
    }
    if (hash->hash_concat_loc == 20) {
        hash->hash_concat_loc = 1;
    }
}

// add a hash to the hash values or don't if it is currently one of the values
void add_hash(struct Hash *hash, uint32_t hash_val) {
    uint8_t dup_val = has_hash(hash, hash_val);
    if (!dup_val) {
        hash->hashes[hash->hash_size] = hash_val;
        hash->hash_size++;
        if (hash->hash_size == 21) {
            shuffle_value(hash);
            hash->hash_size--;
        }
    }
}

void hash_data_move_buff(struct Hash *hash, uint32_t size) {
    if (hash->prev_buff_size == 0) {
        adler32_update(&hash->current_hash, hash->buff + hash->curr_buff_pos, size);
    } else {
        // TODO: need to fix these
        if (size >= hash->prev_buff_size) {
            adler32_update(&hash->current_hash, hash->prev_buff + hash->curr_buff_pos, size);
        } else {
            adler32_update(&hash->current_hash, , );
            memcpy(data, hash->prev_buff + hash->curr_buff_pos, hash->prev_buff_size - hash->curr_buff_pos);
            memcpy(data, hash->buff , size);
        }
    }
}

// move bytes to data starting at curr_buff_pos to curr_buff + size.
// if prev_buff_size == 0 location is offset of buff otherwise it is offset of buff + prev_buff offset
// TODO: We don't need the data buff. We could move directly to the hashing.
// old comment: May not move the exact size. Will return the number of bytes moved.
void set_data_move_buff(struct Hash *hash, uint32_t size) {
    if (hash->curr_buff_pos == hash->buff_size + hash->prev_buff_size) {
        if (!hash->finalize_data) {
            size = hash->prev_buff_size + hash->buff_size - 4;
        }
    }
    hash_data_move_buff(hash, size);
    hash->curr_buff_pos += size;
}

// TODO: need to change i to
uint32_t nul_lf_check(struct Hash *hash, uint8_t char_val) {
    uint32_t i = 1;
    while (i < hash->prev_buff_size) {
        if (hash->prev_buff[i]) {
            return i;
        }
        i++;
    }
    i = 0;
    while (i < hash->buff_size) {
        if (hash->buff[i] != char_val) {
            return i + hash->prev_buff_size;
        }
        i++;
    }
    return i;
}

uint32_t crlf_check(struct Hash *hash) {
    uint32_t i = 1;
    while (i < hash->prev_buff_size) {
        if (i % 2) {
            if (hash->prev_buff[i] != LF) {
                return i;
            }
        } else {
            if (hash->prev_buff[i] != CR) {
                i--;
                return i;
            }
        }
        i++;
    }
    i = 0;
    while (i < hash->buff_size) {
        if (i % 2) {
            if (hash->buff[i] != LF) {
                return i + hash->prev_buff_size;
            }
        } else {
            if (hash->buff[i] != CR) {
                i--;
                return i + hash->prev_buff_size;
            }
        }
        i++;
    }
    return i;
}

uint32_t non_nul_lf_cr_check(struct Hash *hash) {
    uint32_t i = 1;
    while (i < hash->prev_buff_size) {
        if (hash->buff[i] == NUL || hash->buff[i] == LF || hash->buff[i] == CR) {
            return i;
        }
        i++;
    }
    i = 0;
    while (i < hash->buff_size) {
        if (hash->buff[i] == NUL || hash->buff[i] == LF || hash->buff[i] == CR) {
            return i + hash->prev_buff_size;
        }
        i++;
    }
    return i;
}

//split data from the buffer return the size and set the value of data.
uint32_t split_data(struct Hash *hash, uint8_t *data) {
    if (hash->buff_size > 3 || (hash->finalize_data && hash->buff_size)) {
        uint32_t i = 1;
        switch(hash->buff[0]) {
            case NUL:
                i = nul_lf_check(hash, NUL);
                if (i > 3) {
                    break;
                }
                return set_data_move_buff(hash, i);
            case LF:
                i = nul_lf_check(hash, LF);
                if (i > 3) {
                    break;
                }
                return set_data_move_buff(hash, i);
            case CR:
                i = crlf_check(hash);
                if (i > 3) {
                    break;
                }
                return set_data_move_buff(hash, i);
            default:
                i = non_nul_lf_cr_check(hash);
                return hash_data_move_buff(hash, i);
        }
        hash->curr_buff_pos + i;
    }
    return 0;
}

void hash_data(struct Hash *hash, uint32_t to_size) {
    uint8_t data[buff_size_s];
    while (hash->buff_size > to_size || (!to_size && hash->current_hash.size)) {
        uint32_t data_size = split_data(hash, data);
        if (data_size) {
            adler32_update(&hash->current_hash, data, data_size);
        } else {
            if (hash->current_hash.size > 7) {
                add_hash(hash, adler32_finalize(&hash->current_hash));
            }
            if (!hash->buff_size) {
                hash->buff_size = to_size;
            }
            adler32_init(&hash->current_hash);
        }
    }
}

void check_first_hash(struct Hash *hash) {
    if (hash->buff_size > 7 || hash->finalize_data) {
        uint8_t head_data[8];
        uint8_t size;
        if (hash->buff_size > 8) {
            size = 8;
        } else {
            size = hash->buff_size;
        }
        memcpy(head_data, hash->buff, size);
        adler32_update(&hash->current_hash, head_data, size);
        add_hash(hash, adler32_finalize(&hash->current_hash));
        adler32_init(&hash->current_hash);
    }
}

//updates the hash with data in the size of data_size
void update_hasher(struct Hash *hash, uint8_t *data, uint32_t data_size) {
    uint32_t location = move_to_buff(hash, data, data_size, 0);
    if (!hash->hash_size) {
        check_first_hash(hash);
    }
    while (location < data_size) {
        location = move_to_buff(hash, data, data_size, location);
        hash_data(hash, 4);
    }
}

//finalize the hash. data should be large enough to store the hash. return value is the hash size in bytes
uint32_t finalize_hasher(struct Hash *hash, char *hash_val, uint32_t size) {
    hash->finalize_data = 1;
    if (!hash->hash_size) {
        check_first_hash(hash);
    }
    hash_data(hash, 0);
    uint32_t ret_size = hash->hash_size * 6;
    if (size >= ret_size) {
        uint32_t i = 0;
        for (; i < hash->hash_size; i++) {
            b85_encode(hash->hashes[i], hash_val+(i*6));
            if (i+1 < hash->hash_size) {
                hash_val[(i * 6) + 5] = 45;
            }
        }
    }
    hash_val[size - 1] = 0;
    return ret_size;
}

int main(int argc, char *argv[]) {
    if (argc <= 1) {
        return -1;
    }
    struct Hash hashy_mc_hasherton;
    init_hasher(&hashy_mc_hasherton);
    uint32_t ssize = 2048;
    uint8_t file_buff[ssize];
    FILE *filehashing = fopen(argv[1], "r");
    uint16_t ret_val = 0;
    while ((ret_val = fread(&file_buff, 1, ssize, filehashing))) {
        update_hasher(&hashy_mc_hasherton, file_buff, ret_val);
    }
    fclose(filehashing);
    char ret_hash_str[121];
    uint32_t hash_val_size = finalize_hasher(&hashy_mc_hasherton, ret_hash_str, 120);
    printf("%.*s\n", hash_val_size, ret_hash_str);
    return 0;
}
