#include "hmh.c"

static const uint32_t e_b85_divisors[5] = { 52200625, 614125, 7225, 85, 1 };
static const char     *e_b85_chars      = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.:_?+=^!/*&<>()[]{}@%$~";

//base85 encoding of a 32bit unsigned int
static inline void b85_encode(uint32_t hash, char *enc_hash) {
    for(uint32_t i = 0; i < 5; i++) {
        enc_hash[i] = e_b85_chars[(hash / e_b85_divisors[i]) % 85];
    }
}

// TODO: This will need to be fixed. It is pretty messy
uint32_t ret_size = hash->hash_size * 6 - 1;
if (size >= ret_size) {
    for (uint32_t i = 0; i < hash->hash_size; i++) {
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
        if (!filehashing) {
            printf("No file %s\n", argv[cnt]);
            return -1;
        }
        uint16_t ret_val = 0;
        while ((ret_val = fread(&file_buff, 1, ssize, filehashing))) {
            update_hasher(&hashy_mc_hasherton, file_buff, ret_val);
        }
        fclose(filehashing);
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
