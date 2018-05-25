#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

const uint8_t  num_of_hashes     = 20;
const uint32_t min_hash_bytes    = 8;
const uint32_t e_b85_divisors[5] = {52200625, 614125, 7225, 85, 1};
const uint32_t adler32_mod_val   = 65521;
const uint32_t buff_size_s       = 128;
const char     *e_b85_chars      = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.:_?+=^!/*&<>()[]{}@%$~";
// 4 nulls, 4 LF, 2 CRLF
enum           char_match        { NUL=0, LF=10, CR=13 };

// TODO: change buff to pointer and buff_size to the size of the buff,tail of last buff 4 bytes and last size, and buff_loc
// TODO: remove as many memmove and memcpy as possible
// buff is the hash buffer, buff size is the current size of data on the buffer, hashes is the array that contains
// the hashes, hash_size is the number of hashes in hashes, hash_merge_pos is the current location used for concating
// hashes, finalize_data says wether it should expect more data, current_hash is the current hash.
struct Hash {
    uint_fast8_t        hash_size; // The number of hashes
    uint_fast8_t        hash_merge_pos; // The current position of the merge rotate operation
    uint_fast8_t        finalize_data; // TODO: remove this to use the buff_size as the buff_size should be zero if finalizing is going on.
    uint_fast32_t       prev_buff_size; // The current size of the buff. It will change as prev_buff grows and shrinks
    uint_fast32_t       buff_size; // should be the size of the buff and should not change during the life of the buff ref.
    uint_fast32_t       high; //high adler word
    uint_fast32_t       low; //low adler word
    uint_fast32_t       size; //bytes used in calc
    uint_fast32_t       hashes[21]; // The array of hash values. The size is max hashes + 1. The +1 is to hold a temporary hash while merges and rotates the hashes.
    uint_fast8_t        prev_buff[8]; // what is left of the previous buff. Needs to be 8 incase only one byte is given to the update at a time for first hash.
    uint_fast8_t        *buff; //Should be the same size as value of buff_size_s
};

//This Adler32 implementation should probably be replaced with the zlib version at some point
//initializes the Adler32 struct.
inline void adler32_init(struct Hash *hash) {
    hash->high = 0;
    hash->low = 1;
    hash->size = 0;
}

//adds data to the Adler32 struct.

inline void adler32_update(struct Hash *hash, uint8_t data) {
    ++size;
    hash->low = (hash->low + data[i]) % adler32_mod_val;
    hash->high = (hash->high + hash->low) % adler32_mod_val;
}

//returns the Adler32 value. Need to re-initialize the struct before using again.
inline uint32_t adler32_finalize(struct Hash *hash) {
    return hash->high << 16 | hash->low;
}

//base85 encoding of a 32bit unsigned int
void b85_encode(uint32_t hash, char *enc_hash) {
    uint32_t i;
    for(i = 0; i < 5;)
    {
        enc_hash[i] = e_b85_chars[(hash / e_b85_divisors[i]) % 85];
        ++i;
    }
}

//initializes the Hash struct.
void init_hasher(struct Hash *hash) {
    hash->hash_size = 0;
    hash->hash_merge_pos = 1;
    hash->prev_buff_size = 0;
    hash->buff_size = 0;
    hash->finalize_data = 0;
    adler32_init(&hash);
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
    hash->hashes[hash->hash_merge_pos] ^= hash->hashes[hash->hash_merge_pos + 1];
    uint32_t i = ++hash->hash_merge_pos;
    //TODO: replace with memmove
    for (;i < 20; i++) {
        hash->hashes[i] = hash->hashes[i + 1];
    }
    if (hash->hash_merge_pos == 20) {
        hash->hash_merge_pos = 1;
    }
}

// add a hash to the hash values or don't if it is currently one of the values
void add_hash(struct Hash *hash) {
    uint32_t hash_val = adler32_finalize(&hash);
    adler32_init(&hash);
    uint8_t dup_val = has_hash(hash, hash_val);
    //char b85_hash[5];
    //b85_encode(hash_val, b85_hash);
    //printf("%.*s\t", 5, b85_hash);
    if (!dup_val) {
        hash->hashes[hash->hash_size] = hash_val;
        hash->hash_size++;
        if (hash->hash_size == 21) {
            shuffle_value(hash);
            hash->hash_size--;
        }
    }
}


inline void hash_data_move_buff(struct Hash *hash) {
    if (!hash->prev_buff_size) {
        adler32_update(&hash, hash->buff, size);
        hash->buff += size;
        hash->buff_size -= size;
        // we determined that we have some prev hash to move. Do we have current_hash to move?
        // if size <= prev_buff_size then hash the prev buff and remove the size from buff_pos and prev_buff_size
    } else  if (size <= hash->prev_buff_size) {
        adler32_update(&hash, hash->prev_buff, size);
        hash->prev_buff_size -= size;
        if (hash->prev_buff_size) {
            memmove(hash->prev_buff, hash->prev_buff + size, hash->prev_buff_size);
        }
    } else {
        //else hash prev_buff and current buff and set prev_buff_size = 0
        adler32_update(&hash->current_hash, hash->prev_buff, hash->prev_buff_size);
        size -= hash->prev_buff_size;
        hash->prev_buff_size = 0;
        adler32_update(&hash, hash->buff, size);
        hash->buff += size;
        hash->buff_size -= size;
    }
}

// move bytes to data starting at buff_pos to curr_buff + size.
// if prev_buff_size == 0 location is offset of buff otherwise it is offset of buff + prev_buff offset
// old comment: May not move the exact size. Will return the number of bytes moved.
void check_data_size_before_hashing(struct Hash *hash, uint32_t size) {
    if (size == hash->buff_size + hash->prev_buff_size) {
        if (!hash->finalize_data) {
            size = hash->prev_buff_size + hash->buff_size - 4;
        }
    }
    hash_data_move_buff(hash, size);
}

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
            break;
        }
        i++;
    }
    return i + hash->prev_buff_size;
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
                break;
            }
        } else {
            if (hash->buff[i] != CR) {
                i--;
                break;
            }
        }
        i++;
    }
    return i + hash->prev_buff_size;
}

inline uint32_t non_nul_lf_cr_check(struct Hash *hash) {
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
    return i + hash->prev_buff_size;
}

//split data from the buffer return the size and set the value of data.
uint8_t split_data(struct Hash *hash) {
    if ((hash->hash_size && hash->buff_size > 4) || (hash->prev_buff_size && !hash->buff_size)) {
        uint8_t test_val;
        if (hash->prev_buff_size) {
            test_val = hash->prev_buff[0];
        } else {
            test_val = hash->buff[0];
        }
        uint32_t i;
        switch(test_val) {
            case NUL:
                i = nul_lf_check(hash, NUL);
                if (i > 3) {
                    break;
                }
                check_data_size_before_hashing(hash, i);
                return 1;
            /*case LF:
                i = nul_lf_check(hash, LF);
                if (i > 3) {
                    break;
                }
                check_data_size_before_hashing(hash, i);
                return 1;
            case CR:
                i = crlf_check(hash);
                if (i > 3) {
                    break;
                }
                if (i) {
                    check_data_size_before_hashing(hash, i);
                } else {
                    check_data_size_before_hashing(hash, 1);
                }
                return 1;*/
            default:
                i = non_nul_lf_cr_check(hash);
                hash_data_move_buff(hash, i);
                return 1;
        }
        if(hash->prev_buff_size) {
            i -= hash->prev_buff_size;
            hash->prev_buff_size = 0;
        } else {
            hash->buff += i;
        }
    }
    return 0;
}


void hash_data(struct Hash *hash, uint32_t to_size) {
    while (hash->buff_size + hash->prev_buff_size > to_size || (!to_size && hash->current_hash.size)) {
        uint8_t data_was_hashed = split_data(hash);
        if (!data_was_hashed) {
            if (hash->current_hash.size > 7) {
                add_hash(hash);
            }
            if (!(hash->buff_size + hash->prev_buff_size)) {
                return;
            }
        }
    }
}

void check_first_hash(struct Hash *hash) {
    uint32_t size;
    if (hash->finalize_data) {
        adler32_update(&hash, hash->prev_buff, hash->prev_buff_size);
    } else if (hash->buff_size + hash->prev_buff_size >= 8) {
        if (hash->prev_buff_size) {
            adler32_update(&hash, hash->prev_buff, hash->prev_buff_size);
        }
        adler32_update(&hash, hash->buff, 8 - hash->prev_buff_size);
    } else {
        memcpy(&hash->prev_buff + hash->prev_buff_size, hash->buff, hash->buff_size);
        hash->prev_buff_size += hash->buff_size;
        hash->buff_size = 0;
        return;
    }
    add_hash(hash);
    return;
}

//updates the hash with data in the size of data_size
void update_hasher(struct Hash *hash, uint8_t *data, uint32_t data_size) {
    if (!data_size) {
        return;
    }
    hash->buff = data;
    hash->buff_size = data_size;
    if (!hash->hash_size) {
        check_first_hash(hash);
    }
    while (hash->buff_size > 4) {
        hash_data(hash, 4);
    }
    if (hash->buff_size) {
        memcpy(hash->prev_buff, hash->buff, hash->buff_size);
        hash->prev_buff_size = hash->buff_size;
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
    uint16_t ssize = 65535;
    uint8_t file_buff[ssize];
    FILE *filehashing = fopen(argv[1], "r");
    uint16_t ret_val = 0;
    while ((ret_val = fread(&file_buff, 1, ssize, filehashing))) {
        update_hasher(&hashy_mc_hasherton, file_buff, ret_val);
    }
    fclose(filehashing);
    char ret_hash_str[121];
    uint32_t hash_val_size = finalize_hasher(&hashy_mc_hasherton, ret_hash_str, 120);
    printf("Hash\t%.*s\n", hash_val_size, ret_hash_str);
    return 0;
}
