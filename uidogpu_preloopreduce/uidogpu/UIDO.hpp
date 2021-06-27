//
//  UIDO.hpp
//  uidogpu
//
//  Created by tihmstar on 17.07.20.
//  Copyright © 2020 tihmstar. All rights reserved.
//

#ifndef UIDO_hpp
#define UIDO_hpp

#include <stdint.h>
#include <unistd.h>
#include <iostream>

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
    UIDO(const uint8_t uidkey[0x10], std::string kbdumppath);
        
    const KeyBag &get_KeyBag(void);
    const uint8_t *IOAES_key835();
    
    bool AppleKeyStore_unlockKeybag(uint8_t passcodeKey[32]);

};
#endif /* UIDO_hpp */
