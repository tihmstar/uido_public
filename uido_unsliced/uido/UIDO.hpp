//
//  UIDO.hpp
//  uido
//
//  Created by tihmstar on 08.07.20.
//  Copyright © 2020 tihmstar. All rights reserved.
//

#ifndef UIDO_hpp
#define UIDO_hpp

#include <stdint.h>
#include <unistd.h>

typedef uint64_t word_t;

#define MAX_CLASS_KEYS                      20
class UIDO{
public:
    struct ClassKey{
        unsigned char uuid[16];
        unsigned int clas;
        unsigned int wrap;
        unsigned char wpky[40];
    };
    struct KeyBag{
        unsigned int version;
        unsigned int type;
        unsigned char uuid[16];
        unsigned char hmck[40];
        unsigned char salt[20];
        unsigned int iter;
        unsigned int numKeys;
        struct ClassKey keys[MAX_CLASS_KEYS];
    };
private:
    uint8_t _uidRoundKeys[11*16];
    uint8_t _key835[11*16];
    KeyBag _kb;

    uint64_t _sliceRK[11][128];
    
    
public:
    UIDO(const uint8_t uidkey[0x10], const char *kbdumppath);
    
    void uid_encrypt128_cbc(uint8_t *iv, uint8_t *in, uint8_t *out, size_t len);
    
    const KeyBag &get_KeyBag(void);
    
    void IOAES_key835(uint8_t outBuf[0x10]);
    bool AppleKeyStore_unlockKeybagFromUserland(const char* passcode, size_t passcodeLen);
    
    int AppleKeyStore_getPasscodeKey(const char* passcode, size_t passcodeLen, uint8_t* passcodeKey);
    int AppleKeyStore_derivation(void* data, uint32_t dataLength, uint32_t iter, uint32_t vers);
    
};

#endif /* UIDO_hpp */
