#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

static const uint8_t  max_num_of_hashes = 20;
static const uint32_t min_hash_bytes    = 8;
static const uint32_t e_b85_divisors[5] = {52200625, 614125, 7225, 85, 1};
static const uint32_t adler32_mod_val   = 65521;
static const char     *e_b85_chars      = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.:_?+=^!/*&<>()[]{}@%$~";

// 4 nulls, 4 LF, 2 CRLF
enum                  char_match        { NUL=0, LF=10, CR=13 };


// TODO: change buff to pointer and buff_size to the size of the buff,tail of last buff 4 bytes and last size, and buff_loc
// TODO: remove as many memmove and memcpy as possible
// buff is the hash buffer, buff size is the current size of data on the buffer, hashes is the array that contains
// the hashes, hash_size is the number of hashes in hashes, hash_merge_pos is the current location used for concating
// hashes, finalize_data says wether it should expect more data, current_hash is the current hash.
struct Hash {
    bool          finalize_data; // TODO: remove this to use the buff_size as the buff_size should be zero if finalizing is going on.
    uint_fast8_t  hash_size; // The number of hashes
    uint_fast8_t  hash_merge_pos; // The current position of the merge rotate operation
    uint_fast32_t high; //high adler word
    uint_fast32_t low; //low adler word
    uint_fast32_t size; //bytes in hash
    uint_fast32_t head_buff_size; // Size of the head buff
    uint_fast32_t temp_buff_size; // Size of the temp buff
    uint8_t       *temp_buff; //Should be the same size as value of temp_buff_size. This buff should be valid only during the life of the update_hasher function.
    uint8_t       head_buff[8]; // what is left of the previous buff. Needs to be 8 incase only one byte is given to the update at a time for first hash.
    uint_fast32_t hashes[21]; // The array of hash values. The size is max hashes + 1. The +1 is to hold a temporary hash while merges and rotates the hashes.
};

// set the temp buffer data
static inline void buff_set(struct Hash *hash, uint8_t *data, uint32_t size) {
    hash->temp_buff = data;
    hash->temp_buff_size = size;
}

// total size of the buff
static inline uint32_t buff_get_size(struct Hash *hash) {
    return hash->head_buff_size + hash->temp_buff_size;
}

// Return a byte at set position
static inline uint8_t buff_read(struct Hash *hash, uint32_t loc) {
    if (hash->head_buff_size) {
        if (hash->head_buff_size > loc) {
            return hash->head_buff[hash->head_buff_size - (loc + 1)];
        } else {
            return hash->temp_buff[loc - hash->head_buff_size];
        }
    } else if (hash->temp_buff_size) {
        if (hash->temp_buff_size > loc) {
            return hash->temp_buff[loc];
        }
    }
    return 0;
}

// advance the buffer by pos positions
static inline void buff_adv_pos(struct Hash *hash, uint32_t pos) {
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

// Move left over data from temp_buff to head_buff. It will fail and not move it if temp_buff is greater than head_buff max size.
static inline void buff_mv_temp_to_head(struct Hash *hash) {
    if (buff_get_size(hash) <= min_hash_bytes) {
        for (uint8_t i = hash->head_buff_size; i < min_hash_bytes; i++) {
            hash->head_buff[7 - i] = hash->temp_buff[i];
        }
        hash->head_buff_size += hash->temp_buff_size;
        hash->temp_buff_size = 0;
    }
}

//This Adler32 implementation should probably be replaced with the zlib version at some point
//initializes the Adler32 struct.
static inline void adler32_init(struct Hash *hash) {
    hash->high = 0;
    hash->low  = 1;
    hash->size = 0;
}

//adds data to the Adler32 struct.
static inline void adler32_update_one(struct Hash *hash, uint8_t data) {
    ++hash->size;
    hash->low = (hash->low + data) % adler32_mod_val;
    hash->high = (hash->high + hash->low) % adler32_mod_val;
}

//returns the Adler32 value. Need to re-initialize the struct before using again.
static inline uint32_t adler32_finalize(struct Hash *hash) {
    return hash->high << 16 | hash->low;
}

//base85 encoding of a 32bit unsigned int
static inline void b85_encode(uint32_t hash, char *enc_hash) {
    for(uint32_t i = 0; i < 5; i++) {
        enc_hash[i] = e_b85_chars[(hash / e_b85_divisors[i]) % 85];
    }
}

//initializes the Hash struct.
static inline void init_hasher(struct Hash *hash) {
    hash->hash_size = 0;
    hash->hash_merge_pos = 1;
    hash->finalize_data = 0;
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

static inline void shuffle_value(struct Hash *hash) {
    hash->hashes[hash->hash_merge_pos] ^= hash->hashes[hash->hash_merge_pos + 1];
    //TODO: replace with memmove
    for (uint32_t i = ++hash->hash_merge_pos; i < max_num_of_hashes; i++) {
        hash->hashes[i] = hash->hashes[i + 1];
    }
    if (hash->hash_merge_pos == max_num_of_hashes) {
        hash->hash_merge_pos = 1;
    }
}

// add a hash to the hash values or don't if it is currently one of the values
static inline void add_hash(struct Hash *hash) {
    uint32_t hash_val = adler32_finalize(hash);
    adler32_init(hash);
    bool dup_val = has_hash(hash, hash_val);
    if (!dup_val) {
        hash->hashes[hash->hash_size] = hash_val;
        hash->hash_size++;
        if (hash->hash_size == 21) {
            shuffle_value(hash);
            hash->hash_size--;
        }
    }
}
yepu
static inline uint32_t alt_two_char_check(struct Hash *hash, uint8_t first_char, uint8_t second_char) {
    uint32_t i;
    for (i = 1; i < buff_get_size(hash); i++) {
        if(i % 2) {
            if (buff_read(hash, i) != second_char) {
                break;
            }
        } else {
            if (buff_read(hash, i) != first_char) {
                i--;
                break;
            }
        }
    }
    return i;
}

// Checks to make sure there is a non break character and hashes it.
static inline void non_nul_lf_cr_check(struct Hash *hash) {
    uint32_t i = 0;
    uint_fast8_t temp_char;
    while (i < buff_get_size(hash)) {
        ++i;
        temp_char = buff_read(hash, i);
        // TODO: this will come back one we have this figured out
        if (temp_char == NUL /*|| temp_char == LF || temp_char == CR*/) {
            buff_adv_pos(hash, i);
            return;
        }
        adler32_update_one(hash, temp_char);
    }
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
    uint32_t i = 0;
    while (i < size) {
        adler32_update_one(hash, buff_read(hash, i));
        i++;
    }
    buff_adv_pos(hash, i);
}

// check and modify buff as needed. To be used for each case statement other than default.
static inline uint32_t min_buff_depth_check(struct Hash *hash, uint32_t size, uint32_t check_size){
    if (buff_get_size(hash) == size && !hash->finalize_data) {
        size -= check_size;
    }
    return size;
}

// split data from the buffer return the size and set the value of data.
static inline bool split_data(struct Hash *hash) {
    uint8_t test_val = buff_read(hash, 0);
    uint32_t i;
    switch(test_val) {
        case NUL:
            i = char_check(hash, NUL);
            if (i >= 4) {
                i = min_buff_depth_check(hash, i, 4);
                break;
            }
            hash_data_move_buff(hash, i);
            return false;
        case LF:
            i = char_check(hash, LF);
            if (i >= 4) {
                i = min_buff_depth_check(hash, i, 4);
                break;
            }
            hash_data_move_buff(hash, i);
            return false;
        case CR:
            i = alt_two_char_check(hash, CR, LF);
            if (i >= 4) {
                i = min_buff_depth_check(hash, i, 4);
                break;
            }
            hash_data_move_buff(hash, i);
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
        uint8_t data_was_split = split_data(hash);
        if (data_was_split) {
            if (hash->size >= to_size) {
                add_hash(hash);
            }
        }
    }
}

//Checks if the first hash has been created and creates it if possible otherwise it continues the hash process
static inline void check_first_hash(struct Hash *hash) {
    if (!hash->hash_size) {
        if (hash->finalize_data || buff_get_size(hash) >= min_hash_bytes) {
            uint_fast8_t i;
            for (i = 0; i < buff_get_size(hash) && i < min_hash_bytes; i++) {
                adler32_update_one(hash, buff_read(hash, i));
            }
            add_hash(hash);
        }
    }
    return;
}

//updates the hash with data in the size of data_size
void update_hasher(struct Hash *hash, uint8_t *data, uint32_t data_size) {
    if (!data_size) {
        return;
    }
    buff_set(hash, data, data_size);
    check_first_hash(hash);
    if (hash->hash_size) {
        hash_data(hash, min_hash_bytes);
    }
    buff_mv_temp_to_head(hash);
}

//finalize the hash. data should be large enough to store the hash. return value is the hash size in bytes
uint32_t finalize_hasher(struct Hash *hash, char *hash_val, uint32_t size) {
    hash->finalize_data = 1;
    if (!hash->hash_size) {
        check_first_hash(hash);
    }
    hash_data(hash, 0);
    // TODO: This will need to be fixed. It is pretty messy
    uint32_t ret_size = hash->hash_size * 6 - 1;
    if (size >= ret_size) {
        uint32_t i = 0;
        for (; i < hash->hash_size; i++) {
            b85_encode(hash->hashes[i], hash_val+(i*6));
            if (i < hash->hash_size) {
                //places a dash at correct positions
                hash_val[(i * 6) + 5] = 45;
            }
        }
    }
    // Verifies string ends in a null byte.
    hash_val[size - 1] = 0;
    return ret_size;
}

int main(int argc, char *argv[]) {
    if (argc == 1) {
        return -1;
    }
    struct Hash hashy_mc_hasherton;
    uint32_t ssize = 65535;
    uint8_t file_buff[ssize];
    for (uint32_t cnt = 1; cnt < argc; cnt++) {
        init_hasher(&hashy_mc_hasherton);
        FILE *filehashing = fopen(argv[cnt], "r");
        uint16_t ret_val = 0;
        while ((ret_val = fread(&file_buff, 1, ssize, filehashing))) {
            update_hasher(&hashy_mc_hasherton, file_buff, ret_val);
        }
        fclose(filehashing);
        char ret_hash_str[121];
        uint32_t hash_val_size = finalize_hasher(&hashy_mc_hasherton, ret_hash_str, 120);
        printf("Hash\t%s\t%.*s\n", argv[cnt], hash_val_size, ret_hash_str);
    }
    return 0;
}
