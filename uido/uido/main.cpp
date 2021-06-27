//
//  main.cpp
//  uido
//
//  Created by tihmstar on 08.07.20.
//  Copyright © 2020 tihmstar. All rights reserved.
//

#include <iostream>
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>

#include <libgeneral/macros.h>
#include <libgeneral/exception.hpp>
#include "UIDO.hpp"

#include "aes128.h"

int main_r(int argc, const char * argv[]) {
    const char *pin = NULL;
    const char *uid_key_str = NULL;
    const char *kbdumpPath = NULL;
    uint8_t uid[0x10]; //128bit AES
    char c = 0;
    
    printf("uido\n");
    
    while ((c = getopt(argc, (char* const *)argv, "p:")) != -1){
        switch (c){
            case 'p':
                assure(pin = optarg);
                break;
            default:
                reterror("unkown option %c\n",c);
        }
    }
    
    retassure(argc-optind >= 1,"next arg needs to be uidkey");
    argc -= optind;
    argv += optind;
    uid_key_str = argv[0];
    argc--;
    argv++;
    
    for (int i=0; i<strlen(uid_key_str); i+=2) {
        unsigned int b;
        retassure(i/2<sizeof(uid), "UID key too long");
        retassure(sscanf(&uid_key_str[i], "%02x",&b) == 1, "failed to parse UID key");
        uid[i/2] = (uint8_t)b;
    }
    
    retassure(argc >= 1,"next arg needs to be uidkey");
    kbdumpPath = argv[0];

    
    UIDO u{uid,kbdumpPath};
    {
        uint8_t key835[0x10];
        u.IOAES_key835(key835);
        printf("IOAES_key835: ");
        for (size_t i = 0; i < 16; i++) {
          printf("%02x",key835[i]);
        }
        printf("\n");
    }
    
    printf("KeyBag Iterations=%d\n",u.get_KeyBag().iter);
    
    bool success = false;
    if (pin) {
        printf("Testing pin=\"%s\"\n",pin);
        success = u.AppleKeyStore_unlockKeybagFromUserland(pin, strlen(pin));
        printf("Pin=\"%s\" is %s\n",pin, (success) ? "CORRECT" : "WRONG");
    }else{
        uint64_t pinStart = 0;
        uint64_t pinEnd   = 10000;
        printf("Bruteforcing pin start=%llu end=%llu\n",pinStart,pinEnd);
        char pinStr[0x100] = {};
        for (uint64_t curPin = pinStart; curPin<pinEnd; curPin++) {
            snprintf(pinStr, sizeof(pinStr), "%llu",curPin);
            if ((curPin % 100) == 0) {
                printf("testing pin=%s\n",pinStr);
            }
            if ((success = u.AppleKeyStore_unlockKeybagFromUserland(pinStr, strlen(pinStr)))){
                printf("FOUND CORRECT PIN: %s\n",pinStr);
                break;
            }
        }
        
    }
    
    printf("success=%d\n",success);
    
    printf("done\n");
    return 0;
}


int main(int argc, const char * argv[]) {
#ifdef DEBUG
    return main_r(argc, argv);
#else
    try {
        return main_r(argc, argv);
    } catch (tihmstar::exception &e) {
        printf("Usage: uido (-p PIN) <uid key> <kbdump>\n");
        printf("%s: failed with exception:\n",PACKAGE_NAME);
        e.dump();
        return e.code();
    }
#endif
}
