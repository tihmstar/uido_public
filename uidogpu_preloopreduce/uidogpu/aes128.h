//
//  aes128.h
//  uido
//
//  Created by tihmstar on 08.07.20.
//  Copyright © 2020 tihmstar. All rights reserved.
//

#ifndef aes128_h
#define aes128_h

#ifdef __cplusplus
extern "C"{
#endif

#include <stdint.h>

void aes128_precompute_tables(void);
void aes128_encrypt(const uint8_t plaintext[16], uint8_t roundkeys[11*16], uint8_t ciphertext[16]);
void aes128_decrypt(const uint8_t ciphertext[16], uint8_t aeskey[11*16], uint8_t plaintext[16]);
void aes128_KeyExpansion(uint8_t* RoundKey, const uint8_t* Key);



#ifdef __cplusplus
};
#endif

#endif /* aes128_h */
