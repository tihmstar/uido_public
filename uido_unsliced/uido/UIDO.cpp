//
//  UIDO.cpp
//  uido
//
//  Created by tihmstar on 08.07.20.
//  Copyright © 2020 tihmstar. All rights reserved.
//

#include "UIDO.hpp"
#include "aes128.h"

#include <string.h>
#include <plist/plist.h>
#include <libgeneral/macros.h>
#include <arpa/inet.h>

extern "C"{
#include "pbkdf2.h"
#include "key_wrap.h"
#include "aes128_bitsliced.h"
#include "bs.h"
};

struct KeyBagBlobItem{
    unsigned int tag;
    unsigned int len;
    union{
        unsigned int intvalue;
        unsigned char bytes[1];
    } data;
};

static plist_t readPlistFromFile(const char *filePath){
    FILE *f = fopen(filePath,"rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    
    size_t fSize = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = (char*)malloc(fSize);
    fread(buf, fSize, 1, f);
    fclose(f);
    
    plist_t plist = NULL;
    
    if (memcmp(buf, "bplist00", 8) == 0)
        plist_from_bin(buf, (uint32_t)fSize, &plist);
    else
        plist_from_xml(buf, (uint32_t)fSize, &plist);
    
    return plist;
}

static size_t parseHex(const char *hexStr, uint8_t *outBuf, size_t outBufSize){
    size_t i = 0;
    for (i=0; i<strlen(hexStr); i+=2) {
        unsigned int b;
        retassure(i/2<outBufSize, "hexStr key too long");
        retassure(sscanf(&hexStr[i], "%02x",&b) == 1, "failed to parse hexStr");
        outBuf[i/2] = (uint8_t)b;
    }
    return i;
}

UIDO::UIDO(const uint8_t uidkey[0x10], const char *kbdumppath)
: _kb{}, _key835{}
{
    plist_t keybag = NULL;
    char *keybagdata = NULL;
    char *uuid = NULL;
    char *salt = NULL;
    
    cleanup([&]{
        safeFreeCustom(keybag,plist_free);
        safeFree(keybagdata);
        safeFree(uuid);
        safeFree(salt);
    });
    uint64_t keybagdataLen = 0;
    plist_t p_keybagKeys = NULL;
    plist_t p_uuid = NULL;
    plist_t p_salt = NULL;
    
    struct KeyBagBlobItem* p = NULL;
    const uint8_t* end = NULL;
    int kbuuid=0;
    int i = -1;
    
    aes128_precompute_tables(); //calling this multiple times is fine
    aes128_KeyExpansion((uint8_t*)_uidRoundKeys, uidkey);
    
    retassure(keybag = readPlistFromFile(kbdumppath),"failed to read keybagdump");
    
    
    // uuid
    retassure(p_uuid = plist_dict_get_item(keybag, "uuid"),"failed to read uuid");
    retassure(plist_get_node_type(p_uuid) == PLIST_STRING, "uuid is not string");
    plist_get_string_val(p_uuid, &uuid);
    parseHex(uuid, _kb.uuid, sizeof(_kb.uuid));
    
    // salt
    retassure(p_salt = plist_dict_get_item(keybag, "salt"),"failed to read salt");
    retassure(plist_get_node_type(p_salt) == PLIST_STRING, "salt is not string");
    plist_get_string_val(p_salt, &salt);
    parseHex(salt, _kb.salt, sizeof(_kb.salt));
    
    
    // KeyBagKeys
    retassure(p_keybagKeys = plist_dict_get_item(keybag, "KeyBagKeys"),"failed to read KeyBagKeys");
    retassure(plist_get_node_type(p_keybagKeys) == PLIST_DATA, "KeyBagKeys is not data");
    plist_get_data_val(p_keybagKeys, &keybagdata, &keybagdataLen);
    
    
    // AppleKeyStore_parseBinaryKeyBag //https://github.com/dinosec/iphone-dataprotection/blob/master/ramdisk_tools/AppleKeyStore.c#L270
    p = (struct KeyBagBlobItem*) keybagdata;
    retassure(p->tag == 'ATAD',"Keybag does not start with DATA");
    retassure((8 + htonl(p->len) <= keybagdataLen),"Bad length");
    end = (uint8_t*)keybagdata + 8 + htonl(p->len);
    p = (struct KeyBagBlobItem*) p->data.bytes;
    while ((uint8_t*)p < end) {
        uint64_t len = htonl(p->len);
        
        if (p->tag == 'SREV') _kb.version = htonl(p->data.intvalue);
            else if (p->tag == 'EPYT') _kb.type = htonl(p->data.intvalue);
                else if (p->tag == 'TLAS') memcpy(_kb.salt, p->data.bytes, 20);
                    else if (p->tag == 'RETI') _kb.iter = htonl(p->data.intvalue);
                        else if (p->tag == 'DIUU') {
                            if (!kbuuid){
                                memcpy(_kb.uuid, p->data.bytes, 16);
                                kbuuid = 1;
                            }
                            else{
                                i++;
                                if (i >= MAX_CLASS_KEYS)
                                    break;
                                memcpy(_kb.keys[i].uuid, p->data.bytes, 16);
                            }
                        }
                        else if (p->tag == 'SALC') _kb.keys[i].clas = htonl(p->data.intvalue);
                            else if (p->tag == 'PARW' && kbuuid) _kb.keys[i].wrap = htonl(p->data.intvalue);
                                else if (p->tag == 'YKPW') memcpy(_kb.keys[i].wpky, p->data.bytes, (len > 40)  ? 40 : len);
                                    p = (struct KeyBagBlobItem*) &p->data.bytes[len];
                                    }
    _kb.numKeys = i + 1;
    
    //init key835
    {
        const uint8_t input[0x10] = { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 };
        aes128_encrypt(input, _uidRoundKeys, (uint8_t*)_key835);
        aes128_KeyExpansion((uint8_t*)_key835, (uint8_t*)_key835);
    }
    
    
    //init bitslice
    bs_expand_key(_sliceRK, _uidRoundKeys);

    
}

void UIDO::uid_encrypt128_cbc(uint8_t *iv, uint8_t *in, uint8_t *out, size_t len){
    for (size_t i=0; i+0x10<=len; i+=0x10){
        uint8_t input[0x10];
        memcpy(input, &in[i], 0x10);
        if (i == 0){
            if (iv){
                for (int z=0; z<0x10; z++){
                    input[z] ^= iv[z];
                }
            }
        }else{
            for (int z=0; z<0x10; z++){
                input[z] ^= out[i - 0x10 + z];
            }
        }
        aes128_encrypt(input, _uidRoundKeys, &out[i]);
    }
}

const UIDO::KeyBag &UIDO::get_KeyBag(void){
    return _kb;
}


void UIDO::IOAES_key835(uint8_t outBuf[0x10]){
    memcpy(outBuf, _key835, 0x10);
}

#pragma mark dataprotection

uint32_t AppleKeyStore_xorExpand(uint32_t* dst, uint32_t dstLen, uint32_t* input, uint32_t inLen, uint32_t xorKey){
    uint32_t* dstEnd = &dst[dstLen/4];
        
    while (dst < dstEnd){
        for (uint32_t i = 0; i<inLen/4; i++){
            *dst = input[i] ^ xorKey;
            dst++;
        }
        xorKey++;
    }
    return xorKey;
}

void AppleKeyStore_xorCompress(uint32_t* input, uint32_t inputLen, uint32_t* output, uint32_t outputLen){
    for (uint32_t i=0; i < (inputLen/4); i++){
        output[i%(outputLen/4)] ^= input[i];
    }
}

int UIDO::AppleKeyStore_derivation(void* data, uint32_t dataLength, uint32_t iter, uint32_t vers){
#define DERIVATION_BUFFER_SIZE  4096
    uint32_t r4;
    uint32_t nBlocks = DERIVATION_BUFFER_SIZE / dataLength;    //4096/32=128
    uint32_t xorkey = 1;
    uint8_t buf1[DERIVATION_BUFFER_SIZE] = {};
    uint8_t buf2[DERIVATION_BUFFER_SIZE] = {};
    
    
    uint32_t* buffer2 = (uint32_t*)malloc(dataLength);
    memcpy(buffer2, data, dataLength);
    
    uint8_t iv[0x10] = {};
    
    while (iter > 0){
        xorkey = AppleKeyStore_xorExpand((uint32_t*)buf1, DERIVATION_BUFFER_SIZE, buffer2, dataLength, xorkey);
        uid_encrypt128_cbc(iv, buf1, buf2, DERIVATION_BUFFER_SIZE);
        memcpy(iv, &buf2[DERIVATION_BUFFER_SIZE-0x10], 0x10);
        
        r4 = nBlocks;
        if (r4 >= iter){
            r4 = iter;
        }
        iter -= r4;
        AppleKeyStore_xorCompress((uint32_t*) buf2,  r4 * dataLength, (uint32_t*)data, dataLength);
    }

    free(buffer2);
    return 0;
}


int UIDO::AppleKeyStore_getPasscodeKey( const char* passcode, size_t passcodeLen, uint8_t* passcodeKey){
    //One PBKDF2 iter, hardcoded salt length
    pkcs5_pbkdf2(passcode, passcodeLen, (const char*)_kb.salt, 20, passcodeKey, 32, 1);
    
    return AppleKeyStore_derivation(passcodeKey, 32, _kb.iter, _kb.version);
}


bool UIDO::AppleKeyStore_unlockKeybagFromUserland(const char* passcode, size_t passcodeLen){
    uint8_t passcodeKey[32 + 20]={0};
    uint8_t unwrappedKey[40]={0};
    aes_key_wrap_ctx ctx;
    
    AppleKeyStore_getPasscodeKey(passcode, passcodeLen, passcodeKey);
    aes_key_wrap_set_key(&ctx, passcodeKey, 32);
    
    for (int i=0; i < _kb.numKeys; i++){
        if (_kb.keys[i].wrap & 2){
            if(aes_key_unwrap(&ctx, _kb.keys[i].wpky, unwrappedKey, 4))
                return false;
            memcpy(_kb.keys[i].wpky, unwrappedKey, 32);
            _kb.keys[i].wrap &= ~2;
        }
        if (_kb.keys[i].wrap & 1){
            aes128_decrypt(_kb.keys[i].wpky, _key835, _kb.keys[i].wpky);
            _kb.keys[i].wrap &= ~1;
        }
    }
    return true;
}
