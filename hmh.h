#include <stdint.h>


// 4 nulls, 4 LF, 2 CRLF
enum                  CHAR_MATCH        { NUL=0, LF=10, CR=13 };

static const uint8_t  MAX_NUM_OF_HASHES = 20;

static const uint8_t  MIN_HASH_BYTES    = 8;

static const uint32_t ADLER32_MOD_VAL   = 65521;

static const size_t   HMH_MAX_LEN       = 80;

// buff is the hash buffer, buff size is the current size of data on the buffer, hashes is the array that contains
// the hashes, hash_size is the number of hashes in hashes, hash_merge_pos is the current location used for concating
// hashes, current_hash is the current hash.
struct Hash {
    uint_fast8_t  hash_size; // The number of hashes
    uint_fast8_t  hash_merge_pos; // The current position of the merge rotate operation
    uint_fast8_t  size; //bytes in hash. used to track that the min bytes were used.
    uint_fast32_t high; //high adler word
    uint_fast32_t low; //low adler word
    size_t        head_buff_size; // Size of the head buff
    size_t        temp_buff_size; // Size of the temp buff
    uint8_t       *temp_buff; //Should be the same size as value of temp_buff_size. This buff should be valid only during the life of the update_hasher function.
    uint8_t       head_buff[8]; // what is left of the previous buff. Needs to be 8 incase only one byte is given to the update at a time for first hash.
    uint_fast32_t hashes[20]; // The array of hash values. The size is max hashes + 1. The +1 is to hold a temporary hash while merges and rotates the hashes.
};

void init_hasher(struct Hash *hash);

void update_hasher(struct Hash *hash, unsigned char *data, size_t data_size);

size_t finalize_hasher(struct Hash *hash, unsigned char *hash_val);
