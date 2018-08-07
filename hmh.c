#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "hmh.h"

// set the temp buffer data
static inline void buff_set(struct Hash *hash, uint8_t *data, size_t size) {
    hash->temp_buff = data;
    hash->temp_buff_size = size;
}

// total size of the buff
static inline size_t buff_get_size(struct Hash *hash) {
    return hash->head_buff_size + hash->temp_buff_size;
}

// TODO: needs work in here
// Return a byte at set position
static inline uint8_t buff_read(struct Hash *hash, uint32_t loc) {
    if (hash->head_buff_size) {
        if (hash->head_buff_size > loc) {
            printf("Getting %i\n", hash->head_buff[hash->head_buff_size - (loc + 1)]);
            return hash->head_buff[hash->head_buff_size - (loc + 1)];
        } else {
            return hash->temp_buff[loc - hash->head_buff_size];
        }
    } else if (hash->temp_buff_size > loc) {
        return hash->temp_buff[loc];
    }
    return 0;
}

// TODO: needs work in here
// advance the buffer by pos positions
static inline void buff_adv_pos(struct Hash *hash, size_t pos) {
    if (hash->head_buff_size) {
        if (pos >= hash->head_buff_size) {
            pos -= hash->head_buff_size;
            hash->head_buff_size = 0;
            hash->temp_buff += pos;
            hash->temp_buff_size -= pos;
        } else {
            hash->head_buff_size -= pos;
        }
    } else {
        hash->temp_buff_size -= pos;
        hash->temp_buff += pos;
    }
}

// TODO: memmove should probably be used.
// Move left over data from temp_buff to head_buff. It will fail and not move
// it if temp_buff is greater than head_buff max size.
static inline void buff_mv_temp_to_head(struct Hash *hash) {
    if (buff_get_size(hash) <= MIN_HASH_BYTES) {
        for (uint8_t i = hash->head_buff_size; i < MIN_HASH_BYTES; i++) {
            printf("Setting %i\n", hash->temp_buff[i]);
            hash->head_buff[(MIN_HASH_BYTES - 1) - i] = hash->temp_buff[i];
        }
        hash->head_buff_size += hash->temp_buff_size;
        hash->temp_buff_size = 0;
    }
}

//This Adler32 implementation should probably be replaced with the zlib version at some point?
//initializes the Adler32 struct.
static inline void adler32_init(struct Hash *hash) {
    hash->high = 0;
    hash->low  = 1;
    hash->size = 0;
}

//adds data to the Adler32 struct.
static inline void adler32_update_one(struct Hash *hash, uint8_t data) {
    printf("%i\n", data);
    if (!(hash->size & MIN_HASH_BYTES)) {
        ++hash->size;
    }
    hash->low = (hash->low + data) % ADLER32_MOD_VAL;
    hash->high = (hash->high + hash->low) % ADLER32_MOD_VAL;
}

//returns the Adler32 value. Need to re-initialize the struct before using again.
static inline uint32_t adler32_finalize(struct Hash *hash) {
    return hash->high << 16 | hash->low;
}

//initializes the Hash struct.
void init_hasher(struct Hash *hash) {
    hash->hash_size = 0;
    hash->hash_merge_pos = 1;
    hash->head_buff_size = 0;
    hash->temp_buff_size = 0;
    adler32_init(hash);
}

// are we adding a duplicate hash?
static inline bool has_hash(struct Hash *hash, uint32_t hash_val) {
    for (uint8_t i = 0; i < hash->hash_size; i++) {
        if (hash_val == hash->hashes[i]) {
            return true;
        }
    }
    return false;
}

// hash merges should happen with 1-18, 0 should be the first hash and 19 should be the last
static inline void shuffle_value(struct Hash *hash) {
    hash->hashes[hash->hash_merge_pos] ^= hash->hashes[hash->hash_merge_pos + 1];
    ++hash->hash_merge_pos;
    memmove(&hash->hashes[hash->hash_merge_pos], &hash->hashes[hash->hash_merge_pos + 1], \
      sizeof(uint_fast32_t) * (MAX_NUM_OF_HASHES - hash->hash_merge_pos));
    if (hash->hash_merge_pos == MAX_NUM_OF_HASHES - 1) {
        hash->hash_merge_pos = 1;
    }
}

// add a hash to the hash values or don't if it is currently one of the values
static inline void add_hash(struct Hash *hash) {
    uint32_t hash_val = adler32_finalize(hash);
    adler32_init(hash);
    bool dup_val = has_hash(hash, hash_val);
    if (!dup_val) {
        if (hash->hash_size < MAX_NUM_OF_HASHES) {
            hash->hash_size++;
        } else {
            shuffle_value(hash);
        }
        printf("Hash %u\n", hash_val);
        hash->hashes[hash->hash_size - 1] = hash_val;
    }
}

// multi character matching check
static inline uint32_t multi_char_check(struct Hash *hash, unsigned char * chars, uint32_t size, uint32_t start_num) {
    uint32_t i;
    for (i = start_num; i < buff_get_size(hash); i++) {
        uint32_t mod = i % size;
        if (buff_read(hash, i) != chars[mod]) {
            i -= mod;
            break;
        }
    }
    return i;
}

// Checks to make sure there is a non break character and hashes it.
static inline void non_nul_lf_cr_check(struct Hash *hash) {
    uint32_t i = 0;
    uint_fast8_t temp_char;
    while (++i < buff_get_size(hash)) {
        temp_char = buff_read(hash, i);
        if (temp_char == NUL || temp_char == LF || temp_char == CR) {
            printf("Moving buffer after hitting possible break at %u with %zu left\n", i, buff_get_size(hash));
            buff_adv_pos(hash, i);
            return;
        }
        adler32_update_one(hash, temp_char);
    }
    printf("Moving buffer %u after running out of buffer", i);
    buff_adv_pos(hash, i);
    return;
}

// checks for repeat charactersr
static inline uint32_t char_check(struct Hash *hash, uint8_t char_val) {
    uint32_t i = 1;
    while (i < buff_get_size(hash)) {
        if (buff_read(hash, i) != char_val) {
            break;
        }
        ++i;
    }
    return i;
}

static inline void hash_data_move_buff(struct Hash *hash, uint32_t size) {
    uint32_t i;
    for (i = 0; i < size; i++) {
        adler32_update_one(hash, buff_read(hash, i));
    }
    buff_adv_pos(hash, i);
}

// check and modify buff as needed. To be used for each case statement other than default.
static inline uint32_t min_buff_depth_check(struct Hash *hash, uint32_t size, uint32_t check_size, uint32_t to_size){
    if (buff_get_size(hash) - size == 0 && to_size) {
        size -= size % check_size;
    }
    return size;
}

// split data from the buffer return the size and set the value of data.
static inline bool split_data(struct Hash *hash, uint32_t to_size) {
    uint8_t test_val = buff_read(hash, 0);
    uint32_t i;
    switch(test_val) {
        case NUL:
            i = char_check(hash, NUL);
            if (i >= 4) {
                printf("Have buffer of %u\n", i);
                i = min_buff_depth_check(hash, i, 4, to_size);
                printf("And now it is %u\n", i);
                break;
            }
            hash_data_move_buff(hash, i);
            return false;
        case LF:
            i = char_check(hash, LF);
            if (i >= 4) {
                i = min_buff_depth_check(hash, i, 4, to_size);
                break;
            }
            hash_data_move_buff(hash, i);
            return false;
        case CR:
            i = multi_char_check(hash, (unsigned char *) "\r\n", 2, 1);
            if (i >= 4) {
                i = min_buff_depth_check(hash, i, 4, to_size);
                break;
            }
            hash_data_move_buff(hash, ++i);
            return false;
        default:
            adler32_update_one(hash, test_val);
            non_nul_lf_cr_check(hash);
            return false;
    }
    buff_adv_pos(hash, i);
    return true;
}


static inline void hash_data(struct Hash *hash, uint32_t to_size) {
    while (buff_get_size(hash) > to_size) {
        bool data_was_split = split_data(hash, to_size);
        if (data_was_split) {
            if (hash->size >= MIN_HASH_BYTES) {
                add_hash(hash);
            }
        }
    }
}

//Checks if the first hash has been created and creates it if possible otherwise it continues the hash process
static inline void check_first_hash(struct Hash *hash, uint32_t to_size) {
    if (!hash->hash_size) {
        if (!to_size || buff_get_size(hash) >= MIN_HASH_BYTES) {
            uint_fast8_t i;
            for (i = 0; i < buff_get_size(hash) && i < MIN_HASH_BYTES; i++) {
                adler32_update_one(hash, buff_read(hash, i));
            }
            add_hash(hash);
        }
    }
}

//updates the hash with data in the size of data_size
void update_hasher(struct Hash *hash, unsigned char *data, size_t data_size) {
    if (!data_size) {
        return;
    }
    buff_set(hash, data, data_size);
    check_first_hash(hash, MIN_HASH_BYTES);
    if (hash->hash_size) {
        hash_data(hash, MIN_HASH_BYTES);
    }
    buff_mv_temp_to_head(hash);
}

//finalize the hash. data should be large enough to store the hash. return value is the hash size in bytes
size_t finalize_hasher(struct Hash *hash, unsigned char *hash_val) {
    if (!hash->hash_size) {
        check_first_hash(hash, 0);
    }
    hash_data(hash, 0);
    size_t ret_size = 0;
    for (uint_fast8_t i = 0; i < hash->hash_size; i++) {
        hash_val[ret_size + 0] = (0x000000ff & hash->hashes[i]) >> 0;
        hash_val[ret_size + 1] = (0x0000ff00 & hash->hashes[i]) >> 8;
        hash_val[ret_size + 2] = (0x00ff0000 & hash->hashes[i]) >> 16;
        hash_val[ret_size + 3] = (0xff000000 & hash->hashes[i]) >> 24;
        ret_size += 4;
    }
    return ret_size;
}

int main(int argc, char *argv[]) {
    if (argc == 1) {
        return -1;
    }
    struct Hash hashy_mc_hasherton;
    //size_t ssize = 1024000;
    //size_t ssize = 65535;
    size_t ssize = 256;
    uint8_t *file_buff;
    file_buff = (uint8_t *) malloc(ssize);
    for (uint32_t cnt = 1; cnt < argc; cnt++) {
        init_hasher(&hashy_mc_hasherton);
        FILE *filehashing = fopen(argv[cnt], "r");
        if (!filehashing) {
            printf("No file %s\n", argv[cnt]);
            return -1;
        }
        uint16_t ret_val = 0;
        while ((ret_val = fread(file_buff, 1, ssize, filehashing))) {
            update_hasher(&hashy_mc_hasherton, file_buff, ret_val);
        }
        fclose(filehashing);
        free(file_buff);
        unsigned char ret_hash[HMH_MAX_LEN];
        uint32_t hash_val_size = finalize_hasher(&hashy_mc_hasherton, ret_hash);
        char hex_hash[HMH_MAX_LEN * 2 + 1];
        for ( size_t i = 0; i < hash_val_size; i++ ) {
            snprintf(hex_hash + i * 2, 3, "%02x", ret_hash[i]);
        }
        printf("Hash\t%s\t%.*s\n", argv[cnt], hash_val_size * 2, hex_hash);
    }
    return 0;
}
