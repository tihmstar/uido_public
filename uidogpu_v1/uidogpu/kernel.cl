//
//  kernel.c
//  uidogpu
//
//  Created by tihmstar on 10.07.20.
//  Copyright © 2020 tihmstar. All rights reserved.
//


#define PASSWORD_MAX_LENGTH 20


/* -----GITHUB STUFF---- */

// All macros left defined for usage in the program
#define ceilDiv(n,d) (((n) + (d) - 1) / (d))

// All important now, defining whether we're working with unsigned ints or longs
#define wordSize 4

// Practical sizes of buffers, in words.
#define inBufferSize ceilDiv(4, wordSize)
#define outBufferSize ceilDiv(20, wordSize)
#define saltBufferSize ceilDiv(24, wordSize)

//
#define hashBlockSize_bytes ceilDiv(512, 8) /* Needs to be a multiple of 4, or 8 when we work with unsigned longs */
#define hashDigestSize_bytes ceilDiv(160, 8)

// just Size always implies _word
#define hashBlockSize ceilDiv(hashBlockSize_bytes, wordSize)
#define hashDigestSize ceilDiv(hashDigestSize_bytes, wordSize)

unsigned int SWAP (unsigned int val);



// Ultimately hoping to faze out the Size_int32/long64,
//   in favour of just size (_word implied)
#if wordSize == 4
    #define hashBlockSize_int32 hashBlockSize
    #define hashDigestSize_int32 hashDigestSize
    #define word unsigned int
        
    unsigned int SWAP (unsigned int val)
    {
        return
        ((val & 0xff000000) >> 24) |
        ((val & 0x00ff0000) >> 8) |
        ((val & 0x0000ff00) << 8) |
        ((val & 0x000000ff) << 24);
    }
#endif



// ====  Define the structs with the right word size  =====
//  Helpful & more cohesive to have the lengths of structures as words too,
//   (rather than unsigned int for both)
typedef struct {
    word length; // in bytes
    word buffer[inBufferSize];
} inbuf;

typedef struct {
    word buffer[outBufferSize];
} outbuf;

// Salt buffer, used by pbkdf2 & pbe
typedef struct {
    word length; // in bytes
    word buffer[saltBufferSize];
} saltbuf;


/*
    SHA1 OpenCL Optimized kernel
    (c) B. Kerler 2018
    MIT License
*/

/*
    (small) Changes:
    outbuf and inbuf structs defined using the buffer_structs_template
    func_sha1 renamed to hash_main
    hash array trimmed to size 5
*/

#define rotl32(a,n) rotate ((a), (n))

#define mod(x,y) ((x)-((x)/(y)*(y)))

#define F2(x,y,z)  ((x) ^ (y) ^ (z))
#define F1(x,y,z)   (bitselect(z,y,x))
#define F0(x,y,z)   (bitselect (x, y, ((x) ^ (z))))

#define SHA1M_A 0x67452301u
#define SHA1M_B 0xefcdab89u
#define SHA1M_C 0x98badcfeu
#define SHA1M_D 0x10325476u
#define SHA1M_E 0xc3d2e1f0u

#define SHA1C00 0x5a827999u
#define SHA1C01 0x6ed9eba1u
#define SHA1C02 0x8f1bbcdcu
#define SHA1C03 0xca62c1d6u

#define SHA1_STEP(f,a,b,c,d,e,x)    \
{                                   \
  e += K;                           \
  e += x;                           \
  e += f (b, c, d);                 \
  e += rotl32 (a,  5u);             \
  b  = rotl32 (b, 30u);             \
}



void sha1_process2 (const unsigned int *W, unsigned int *digest){
  unsigned int A = digest[0];
  unsigned int B = digest[1];
  unsigned int C = digest[2];
  unsigned int D = digest[3];
  unsigned int E = digest[4];

  unsigned int w0_t = W[0];
  unsigned int w1_t = W[1];
  unsigned int w2_t = W[2];
  unsigned int w3_t = W[3];
  unsigned int w4_t = W[4];
  unsigned int w5_t = W[5];
  unsigned int w6_t = W[6];
  unsigned int w7_t = W[7];
  unsigned int w8_t = W[8];
  unsigned int w9_t = W[9];
  unsigned int wa_t = W[10];
  unsigned int wb_t = W[11];
  unsigned int wc_t = W[12];
  unsigned int wd_t = W[13];
  unsigned int we_t = W[14];
  unsigned int wf_t = W[15];

  #undef K
  #define K SHA1C00

  SHA1_STEP (F1, A, B, C, D, E, w0_t);
  SHA1_STEP (F1, E, A, B, C, D, w1_t);
  SHA1_STEP (F1, D, E, A, B, C, w2_t);
  SHA1_STEP (F1, C, D, E, A, B, w3_t);
  SHA1_STEP (F1, B, C, D, E, A, w4_t);
  SHA1_STEP (F1, A, B, C, D, E, w5_t);
  SHA1_STEP (F1, E, A, B, C, D, w6_t);
  SHA1_STEP (F1, D, E, A, B, C, w7_t);
  SHA1_STEP (F1, C, D, E, A, B, w8_t);
  SHA1_STEP (F1, B, C, D, E, A, w9_t);
  SHA1_STEP (F1, A, B, C, D, E, wa_t);
  SHA1_STEP (F1, E, A, B, C, D, wb_t);
  SHA1_STEP (F1, D, E, A, B, C, wc_t);
  SHA1_STEP (F1, C, D, E, A, B, wd_t);
  SHA1_STEP (F1, B, C, D, E, A, we_t);
  SHA1_STEP (F1, A, B, C, D, E, wf_t);
  w0_t = rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (F1, E, A, B, C, D, w0_t);
  w1_t = rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (F1, D, E, A, B, C, w1_t);
  w2_t = rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (F1, C, D, E, A, B, w2_t);
  w3_t = rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (F1, B, C, D, E, A, w3_t);

  #undef K
  #define K SHA1C01

  w4_t = rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (F2, A, B, C, D, E, w4_t);
  w5_t = rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (F2, E, A, B, C, D, w5_t);
  w6_t = rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (F2, D, E, A, B, C, w6_t);
  w7_t = rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (F2, C, D, E, A, B, w7_t);
  w8_t = rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (F2, B, C, D, E, A, w8_t);
  w9_t = rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (F2, A, B, C, D, E, w9_t);
  wa_t = rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (F2, E, A, B, C, D, wa_t);
  wb_t = rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (F2, D, E, A, B, C, wb_t);
  wc_t = rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (F2, C, D, E, A, B, wc_t);
  wd_t = rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (F2, B, C, D, E, A, wd_t);
  we_t = rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (F2, A, B, C, D, E, we_t);
  wf_t = rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (F2, E, A, B, C, D, wf_t);
  w0_t = rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (F2, D, E, A, B, C, w0_t);
  w1_t = rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (F2, C, D, E, A, B, w1_t);
  w2_t = rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (F2, B, C, D, E, A, w2_t);
  w3_t = rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (F2, A, B, C, D, E, w3_t);
  w4_t = rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (F2, E, A, B, C, D, w4_t);
  w5_t = rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (F2, D, E, A, B, C, w5_t);
  w6_t = rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (F2, C, D, E, A, B, w6_t);
  w7_t = rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (F2, B, C, D, E, A, w7_t);

  #undef K
  #define K SHA1C02

  w8_t = rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (F0, A, B, C, D, E, w8_t);
  w9_t = rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (F0, E, A, B, C, D, w9_t);
  wa_t = rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (F0, D, E, A, B, C, wa_t);
  wb_t = rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (F0, C, D, E, A, B, wb_t);
  wc_t = rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (F0, B, C, D, E, A, wc_t);
  wd_t = rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (F0, A, B, C, D, E, wd_t);
  we_t = rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (F0, E, A, B, C, D, we_t);
  wf_t = rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (F0, D, E, A, B, C, wf_t);
  w0_t = rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (F0, C, D, E, A, B, w0_t);
  w1_t = rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (F0, B, C, D, E, A, w1_t);
  w2_t = rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (F0, A, B, C, D, E, w2_t);
  w3_t = rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (F0, E, A, B, C, D, w3_t);
  w4_t = rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (F0, D, E, A, B, C, w4_t);
  w5_t = rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (F0, C, D, E, A, B, w5_t);
  w6_t = rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (F0, B, C, D, E, A, w6_t);
  w7_t = rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (F0, A, B, C, D, E, w7_t);
  w8_t = rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (F0, E, A, B, C, D, w8_t);
  w9_t = rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (F0, D, E, A, B, C, w9_t);
  wa_t = rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (F0, C, D, E, A, B, wa_t);
  wb_t = rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (F0, B, C, D, E, A, wb_t);

  #undef K
  #define K SHA1C03

  wc_t = rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (F2, A, B, C, D, E, wc_t);
  wd_t = rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (F2, E, A, B, C, D, wd_t);
  we_t = rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (F2, D, E, A, B, C, we_t);
  wf_t = rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (F2, C, D, E, A, B, wf_t);
  w0_t = rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (F2, B, C, D, E, A, w0_t);
  w1_t = rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (F2, A, B, C, D, E, w1_t);
  w2_t = rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (F2, E, A, B, C, D, w2_t);
  w3_t = rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (F2, D, E, A, B, C, w3_t);
  w4_t = rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (F2, C, D, E, A, B, w4_t);
  w5_t = rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (F2, B, C, D, E, A, w5_t);
  w6_t = rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (F2, A, B, C, D, E, w6_t);
  w7_t = rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (F2, E, A, B, C, D, w7_t);
  w8_t = rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (F2, D, E, A, B, C, w8_t);
  w9_t = rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (F2, C, D, E, A, B, w9_t);
  wa_t = rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (F2, B, C, D, E, A, wa_t);
  wb_t = rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (F2, A, B, C, D, E, wb_t);
  wc_t = rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (F2, E, A, B, C, D, wc_t);
  wd_t = rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (F2, D, E, A, B, C, wd_t);
  we_t = rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (F2, C, D, E, A, B, we_t);
  wf_t = rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (F2, B, C, D, E, A, wf_t);

  // Macros don't have scope, so this K was being preserved
  #undef K

  digest[0] += A;
  digest[1] += B;
  digest[2] += C;
  digest[3] += D;
  digest[4] += E;
}

#define def_hash(funcName, passTag, hashTag)    \
/* The main hashing function */                 \
void funcName(passTag const unsigned int *pass, int pass_len, hashTag unsigned int* hash)   \
{                                                                                       \
    /* pass is only given to SWAP
        and hash is just assigned to p, which is only accessed by p[i] =
        => both tags irrelevant! */     \
                                        \
    int plen=pass_len/4;                \
    if (mod(pass_len,4)) plen++;        \
                                        \
    hashTag unsigned int* p = hash;     \
                                        \
    unsigned int W[0x10]={0};           \
    int loops=plen;                     \
    int curloop=0;                      \
    unsigned int State[5]={0};          \
    State[0] = 0x67452301;              \
    State[1] = 0xefcdab89;              \
    State[2] = 0x98badcfe;              \
    State[3] = 0x10325476;              \
    State[4] = 0xc3d2e1f0;              \
                                        \
                                        \
    while (loops>0)     \
    {                   \
        W[0x0]=0x0;     \
        W[0x1]=0x0;     \
        W[0x2]=0x0;     \
        W[0x3]=0x0;     \
        W[0x4]=0x0;     \
        W[0x5]=0x0;     \
        W[0x6]=0x0;     \
        W[0x7]=0x0;     \
        W[0x8]=0x0;     \
        W[0x9]=0x0;     \
        W[0xA]=0x0;     \
        W[0xB]=0x0;     \
        W[0xC]=0x0;     \
        W[0xD]=0x0;     \
        W[0xE]=0x0;     \
        W[0xF]=0x0;     \
                        \
        for (int m=0;loops!=0 && m<16;m++)          \
        {                                           \
            W[m]^=SWAP(pass[m+(curloop*16)]);       \
            loops--;                                \
        }                                           \
                                                    \
        if (loops==0 && mod(pass_len,64)!=0)        \
        {                                           \
            unsigned int padding=0x80<<(((pass_len+4)-((pass_len+4)/4*4))*8);   \
            int v=mod(pass_len,64);                 \
            W[v/4]|=SWAP(padding);                  \
            if ((pass_len&0x3B)!=0x3B)              \
            {                                       \
                /* Let's add length */              \
                W[0x0F]=pass_len*8;                 \
            }                                       \
        }                                           \
                                                    \
        sha1_process2(W,State);                     \
        curloop++;                                  \
    }                                               \
                            \
    if (mod(plen,16)==0)    \
    {                       \
        W[0x0]=0x0;         \
        W[0x1]=0x0;         \
        W[0x2]=0x0;         \
        W[0x3]=0x0;         \
        W[0x4]=0x0;         \
        W[0x5]=0x0;         \
        W[0x6]=0x0;         \
        W[0x7]=0x0;         \
        W[0x8]=0x0;         \
        W[0x9]=0x0;         \
        W[0xA]=0x0;         \
        W[0xB]=0x0;         \
        W[0xC]=0x0;         \
        W[0xD]=0x0;         \
        W[0xE]=0x0;         \
        W[0xF]=0x0;         \
        if ((pass_len&0x3B)!=0x3B)  \
        {                           \
            unsigned int padding=0x80<<(((pass_len+4)-((pass_len+4)/4*4))*8); \
            W[0]|=SWAP(padding);    \
        }                           \
        /* Let's add length */      \
        W[0x0F]=pass_len*8;         \
                                    \
        sha1_process2(W,State);     \
    }                       \
                            \
    p[0]=SWAP(State[0]);    \
    p[1]=SWAP(State[1]);    \
    p[2]=SWAP(State[2]);    \
    p[3]=SWAP(State[3]);    \
    p[4]=SWAP(State[4]);    \
    return;                 \
}

def_hash(hash_global, __global, __global)
def_hash(hash_private, __private, __private)
def_hash(hash_glbl_to_priv, __global, __private)
def_hash(hash_priv_to_glbl, __private, __global)

#undef mod

#undef rotl32
#undef F0
#undef F1
#undef F2



/*
    pbkdf2 and HMAC implementation
    requires implementation of PRF (pseudo-random function),
      probably using HMAC and an implementation of hash_main
*/
/*
    REQ: outBuf.buffer must have space for ceil(dkLen / PRF_output_bytes) * PRF_output_bytes
    REQ: PRF implementation MUST allow that output may be the salt (m in hmac)
    inBuffer / pwdBuffer / the like are not const to allow for padding
*/

// Determine (statically) the actual required buffer size
// Correct for both 64 & 32 bit
//   Just allowing for MD padding: 2 words for length, 1 for the 1-pad = 3 words
#define sizeForHash(reqSize) (ceilDiv((reqSize) + 2 + 1, hashBlockSize) * hashBlockSize)

#if wordSize == 4
    __constant const unsigned int opad = 0x5c5c5c5c;
    __constant const unsigned int ipad = 0x36363636;
#elif wordSize == 8
    __constant const unsigned long opad = 0x5c5c5c5c5c5c5c5c;
    __constant const unsigned long ipad = 0x3636363636363636;
#endif

__constant const word xoredPad = opad ^ ipad;

// Slightly ugly: large enough for hmac_main usage, and tight for pbkdf2
#define m_buffer_size (saltBufferSize + 1)

void hmac(__global word *K, const word K_len_bytes, const word *m, const word m_len_bytes, __global word *output)
{
    // REQ: If K_len_bytes isn't divisible by 4/8, final word should be clean (0s to the end)
    // REQ: s digestSize is a multiple of 4/8 bytes

    /* Declare the space for input to the last hash function:
         Compute and write K_ ^ opad to the first block of this. This will be the only place that we store K_ */

    
    #define size_2 sizeForHash(hashBlockSize + hashDigestSize)
    word input_2[size_2] = {0};
    #undef size_2

    word end;
    if (K_len_bytes <= hashBlockSize_bytes)
    {
        end = ceilDiv(K_len_bytes, wordSize);
        // XOR with opad and slightly pad with zeros..
        for (int j = 0; j < end; j++){
            input_2[j] = K[j] ^ opad;
        }
    } else {
        end = hashDigestSize;
        // Hash K to get K'. XOR with opad..
        hash_glbl_to_priv(K, K_len_bytes, input_2);
        for (int j = 0; j < hashDigestSize; j++){
            input_2[j] ^= opad;
        }
    }
    // And if short, pad with 0s to the BLOCKsize, completing xor with opad
    for (int j = end; j < hashBlockSize; j++){
        input_2[j] = opad;
    }
    
    // Copy K' ^ ipad into the first block.
    // Be careful: hash needs a whole block after the end. ceilDiv from buffer_structs
    #define size_1 sizeForHash(hashBlockSize + m_buffer_size)

    // K' ^ ipad into the first block
    word input_1[size_1] = {0};
    #undef size_1
    for (int j = 0; j < hashBlockSize; j++){
        input_1[j] = input_2[j]^xoredPad;
    }
    

    // Slightly inefficient copying m in..
    word m_len_word = ceilDiv(m_len_bytes, wordSize);
    for (int j = 0; j < m_len_word; j++){
        input_1[hashBlockSize + j] = m[j];
    }

    // Hash input1 into the second half of input2
    word leng = hashBlockSize_bytes + m_len_bytes;
    hash_private(input_1, leng, input_2 + hashBlockSize);
    
    // Hash input2 into output!
    hash_priv_to_glbl(input_2, hashBlockSize_bytes + hashDigestSize_bytes, output);
}

#undef sizeForHash


void pbkdf2_iOS(__global char *inbuffer, ulong length, __global const char *salt, __global char *outbuffer){
    char saltbuf[24];
    *(ulong*)&saltbuf[0] = *(__global const ulong*)&salt[0];
    *(ulong*)&saltbuf[8] = *(__global const ulong*)&salt[8];
    *(uint*)&saltbuf[16] = *(__global const uint*)&salt[16];
    *(uint*)&saltbuf[20] = 0x01000000;

    hmac((__global word *)inbuffer, length, (const word *)saltbuf, 24, (__global word *)outbuffer);
    
    saltbuf[23] = 2;

    hmac((__global word *)inbuffer, length, (const word *)saltbuf, 24, (__global word *)&outbuffer[20]);
}

#pragma mark bitsliced AES
typedef ulong    word_t;
#define BLOCK_SIZE 128

void bs_sbox(__global word_t *U){
    word_t S[8];
    word_t
        T1,T2,T3,T4,T5,T6,T7,T8,
        T9,T10,T11,T12,T13,T14,T15,T16,
        T17,T18,T19,T20,T21,T22,T23,T24,
        T25, T26, T27;

    word_t
        M1,M2,M3,M4,M5,M6,M7,M8,
        M9,M10,M11,M12,M13,M14,M15,
        M16,M17,M18,M19,M20,M21,M22,
        M23,M24,M25,M26,M27,M28,M29,
        M30,M31,M32,M33,M34,M35,M36,
        M37,M38,M39,M40,M41,M42,M43,
        M44,M45,M46,M47,M48,M49,M50,
        M51,M52,M53,M54,M55,M56,M57,
        M58,M59,M60,M61,M62,M63;

    word_t
        L0,L1,L2,L3,L4,L5,L6,L7,L8,
        L9,L10,L11,L12,L13,L14,
        L15,L16,L17,L18,L19,L20,
        L21,L22,L23,L24,L25,L26,
        L27,L28,L29;

    T1 = U[7] ^ U[4];
    T2 = U[7] ^ U[2];
    T3 = U[7] ^ U[1];
    T4 = U[4] ^ U[2];
    T5 = U[3] ^ U[1];
    T6 = T1 ^ T5;
    T7 = U[6] ^ U[5];
    T8 = U[0] ^ T6;
    T9 = U[0] ^ T7;
    T10 = T6 ^ T7;
    T11 = U[6] ^ U[2];
    T12 = U[5] ^ U[2];
    T13 = T3 ^ T4;
    T14 = T6 ^ T11;
    T15 = T5 ^ T11;
    T16 = T5 ^ T12;
    T17 = T9 ^ T16;
    T18 = U[4] ^ U[0];
    T19 = T7 ^ T18;
    T20 = T1 ^ T19;
    T21 = U[1] ^ U[0];
    T22 = T7 ^ T21;
    T23 = T2 ^ T22;
    T24 = T2 ^ T10;
    T25 = T20 ^ T17;
    T26 = T3 ^ T16;
    T27 = T1 ^ T12;
    M1 = T13 & T6;
    M2 = T23 & T8;
    M3 = T14 ^ M1;
    M4 = T19 & U[0];
    M5 = M4 ^ M1;
    M6 = T3 & T16;
    M7 = T22 & T9;
    M8 = T26 ^ M6;
    M9 = T20 & T17;
    M10 = M9 ^ M6;
    M11 = T1 & T15;
    M12 = T4 & T27;
    M13 = M12 ^ M11;
    M14 = T2 & T10;
    M15 = M14 ^ M11;
    M16 = M3 ^ M2;
    M17 = M5 ^ T24;
    M18 = M8 ^ M7;
    M19 = M10 ^ M15;
    M20 = M16 ^ M13;
    M21 = M17 ^ M15;
    M22 = M18 ^ M13;
    M23 = M19 ^ T25;
    M24 = M22 ^ M23;
    M25 = M22 & M20;
    M26 = M21 ^ M25;
    M27 = M20 ^ M21;
    M28 = M23 ^ M25;
    M29 = M28 & M27;
    M30 = M26 & M24;
    M31 = M20 & M23;
    M32 = M27 & M31;
    M33 = M27 ^ M25;
    M34 = M21 & M22;
    M35 = M24 & M34;
    M36 = M24 ^ M25;
    M37 = M21 ^ M29;
    M38 = M32 ^ M33;
    M39 = M23 ^ M30;
    M40 = M35 ^ M36;
    M41 = M38 ^ M40;
    M42 = M37 ^ M39;
    M43 = M37 ^ M38;
    M44 = M39 ^ M40;
    M45 = M42 ^ M41;
    M46 = M44 & T6;
    M47 = M40 & T8;
    M48 = M39 & U[0];
    M49 = M43 & T16;
    M50 = M38 & T9;
    M51 = M37 & T17;
    M52 = M42 & T15;
    M53 = M45 & T27;
    M54 = M41 & T10;
    M55 = M44 & T13;
    M56 = M40 & T23;
    M57 = M39 & T19;
    M58 = M43 & T3;
    M59 = M38 & T22;
    M60 = M37 & T20;
    M61 = M42 & T1;
    M62 = M45 & T4;
    M63 = M41 & T2;
    L0 = M61 ^ M62;
    L1 = M50 ^ M56;
    L2 = M46 ^ M48;
    L3 = M47 ^ M55;
    L4 = M54 ^ M58;
    L5 = M49 ^ M61;
    L6 = M62 ^ L5;
    L7 = M46 ^ L3;
    L8 = M51 ^ M59;
    L9 = M52 ^ M53;
    L10 = M53 ^ L4;
    L11 = M60 ^ L2;
    L12 = M48 ^ M51;
    L13 = M50 ^ L0;
    L14 = M52 ^ M61;
    L15 = M55 ^ L1;
    L16 = M56 ^ L0;
    L17 = M57 ^ L1;
    L18 = M58 ^ L8;
    L19 = M63 ^ L4;
    L20 = L0 ^ L1;
    L21 = L1 ^ L7;
    L22 = L3 ^ L12;
    L23 = L18 ^ L2;
    L24 = L15 ^ L9;
    L25 = L6 ^ L10;
    L26 = L7 ^ L9;
    L27 = L8 ^ L10;
    L28 = L11 ^ L14;
    L29 = L11 ^ L17;
    S[7] = L6 ^ L24;
    S[6] = ~(L16 ^ L26);
    S[5] = ~(L19 ^ L28);
    S[4] = L6 ^ L21;
    S[3] = L20 ^ L22;
    S[2] = L25 ^ L29;
    S[1] = ~(L13 ^ L27);
    S[0] = ~(L6 ^ L23);

    for (int i=0; i<sizeof(S)/sizeof(*S); i++) {
        U[i] = S[i];
    }
}
#define A0  0
#define A1  8
#define A2  16
#define A3  24
#define R0          0
#define R1          8
#define R2          16
#define R3          24
#define B0          0
#define B1          32
#define B2          64
#define B3          96
#define R0_shift        (BLOCK_SIZE/4)*0
#define R1_shift        (BLOCK_SIZE/4)*1
#define R2_shift        (BLOCK_SIZE/4)*2
#define R3_shift        (BLOCK_SIZE/4)*3
#define B_MOD           (BLOCK_SIZE)
void bs_shiftmix(__global word_t * B){
    word_t Bp_space[BLOCK_SIZE];
    word_t * Bp = Bp_space;

    __global word_t * Br0 = B + 0;
    __global word_t * Br1 = B + 32;
    __global word_t * Br2 = B + 64;
    __global word_t * Br3 = B + 96;

    uchar offsetr0 = 0;
    uchar offsetr1 = 32;
    uchar offsetr2 = 64;
    uchar offsetr3 = 96;

        Br0 = B + offsetr0;
        Br1 = B + offsetr1;
        Br2 = B + offsetr2;
        Br3 = B + offsetr3;


    for (int i = 0; i < 4; i++){
        // B0
        //            2*A0        2*A1              A1           A2           A3
        word_t of =Br0[R0+7]^ Br1[R1+7];
        Bp[A0+0] =                         Br1[R1+0] ^ Br2[R2+0] ^ Br3[R3+0] ^ of;
        Bp[A0+1] = Br0[R0+0] ^ Br1[R1+0] ^ Br1[R1+1] ^ Br2[R2+1] ^ Br3[R3+1] ^ of;
        Bp[A0+2] = Br0[R0+1] ^ Br1[R1+1] ^ Br1[R1+2] ^ Br2[R2+2] ^ Br3[R3+2];
        Bp[A0+3] = Br0[R0+2] ^ Br1[R1+2] ^ Br1[R1+3] ^ Br2[R2+3] ^ Br3[R3+3] ^ of;
        Bp[A0+4] = Br0[R0+3] ^ Br1[R1+3] ^ Br1[R1+4] ^ Br2[R2+4] ^ Br3[R3+4] ^ of;
        Bp[A0+5] = Br0[R0+4] ^ Br1[R1+4] ^ Br1[R1+5] ^ Br2[R2+5] ^ Br3[R3+5];
        Bp[A0+6] = Br0[R0+5] ^ Br1[R1+5] ^ Br1[R1+6] ^ Br2[R2+6] ^ Br3[R3+6];
        Bp[A0+7] = Br0[R0+6] ^ Br1[R1+6] ^ Br1[R1+7] ^ Br2[R2+7] ^ Br3[R3+7];

        //            A0            2*A1        2*A2        A2       A3
        of = Br1[R1+7] ^ Br2[R2+7];
        Bp[A1+0] = Br0[R0+0]                         ^ Br2[R2+0] ^ Br3[R3+0] ^ of;
        Bp[A1+1] = Br0[R0+1] ^ Br1[R1+0] ^ Br2[R2+0] ^ Br2[R2+1] ^ Br3[R3+1] ^ of;
        Bp[A1+2] = Br0[R0+2] ^ Br1[R1+1] ^ Br2[R2+1] ^ Br2[R2+2] ^ Br3[R3+2];
        Bp[A1+3] = Br0[R0+3] ^ Br1[R1+2] ^ Br2[R2+2] ^ Br2[R2+3] ^ Br3[R3+3] ^ of;
        Bp[A1+4] = Br0[R0+4] ^ Br1[R1+3] ^ Br2[R2+3] ^ Br2[R2+4] ^ Br3[R3+4] ^ of;
        Bp[A1+5] = Br0[R0+5] ^ Br1[R1+4] ^ Br2[R2+4] ^ Br2[R2+5] ^ Br3[R3+5];
        Bp[A1+6] = Br0[R0+6] ^ Br1[R1+5] ^ Br2[R2+5] ^ Br2[R2+6] ^ Br3[R3+6];
        Bp[A1+7] = Br0[R0+7] ^ Br1[R1+6] ^ Br2[R2+6] ^ Br2[R2+7] ^ Br3[R3+7];

        //            A0             A1      2*A2        2*A3         A3
        of = Br2[R2+7] ^ Br3[R3+7];
        Bp[A2+0] = Br0[R0+0] ^ Br1[R1+0]                         ^ Br3[R3+0] ^ of;
        Bp[A2+1] = Br0[R0+1] ^ Br1[R1+1] ^ Br2[R2+0] ^ Br3[R3+0] ^ Br3[R3+1] ^ of;
        Bp[A2+2] = Br0[R0+2] ^ Br1[R1+2] ^ Br2[R2+1] ^ Br3[R3+1] ^ Br3[R3+2];
        Bp[A2+3] = Br0[R0+3] ^ Br1[R1+3] ^ Br2[R2+2] ^ Br3[R3+2] ^ Br3[R3+3] ^ of;
        Bp[A2+4] = Br0[R0+4] ^ Br1[R1+4] ^ Br2[R2+3] ^ Br3[R3+3] ^ Br3[R3+4] ^ of;
        Bp[A2+5] = Br0[R0+5] ^ Br1[R1+5] ^ Br2[R2+4] ^ Br3[R3+4] ^ Br3[R3+5];
        Bp[A2+6] = Br0[R0+6] ^ Br1[R1+6] ^ Br2[R2+5] ^ Br3[R3+5] ^ Br3[R3+6];
        Bp[A2+7] = Br0[R0+7] ^ Br1[R1+7] ^ Br2[R2+6] ^ Br3[R3+6] ^ Br3[R3+7];

        //             A0          2*A0           A1       A2      2*A3
        of = Br0[R0+7] ^ Br3[R3+7];
        Bp[A3+0] = Br0[R0+0] ^             Br1[R1+0] ^ Br2[R2+0]             ^ of;
        Bp[A3+1] = Br0[R0+1] ^ Br0[R0+0] ^ Br1[R1+1] ^ Br2[R2+1] ^ Br3[R3+0] ^ of;
        Bp[A3+2] = Br0[R0+2] ^ Br0[R0+1] ^ Br1[R1+2] ^ Br2[R2+2] ^ Br3[R3+1];
        Bp[A3+3] = Br0[R0+3] ^ Br0[R0+2] ^ Br1[R1+3] ^ Br2[R2+3] ^ Br3[R3+2] ^ of;
        Bp[A3+4] = Br0[R0+4] ^ Br0[R0+3] ^ Br1[R1+4] ^ Br2[R2+4] ^ Br3[R3+3] ^ of;
        Bp[A3+5] = Br0[R0+5] ^ Br0[R0+4] ^ Br1[R1+5] ^ Br2[R2+5] ^ Br3[R3+4];
        Bp[A3+6] = Br0[R0+6] ^ Br0[R0+5] ^ Br1[R1+6] ^ Br2[R2+6] ^ Br3[R3+5];
        Bp[A3+7] = Br0[R0+7] ^ Br0[R0+6] ^ Br1[R1+7] ^ Br2[R2+7] ^ Br3[R3+6];

        Bp += BLOCK_SIZE/4;

        offsetr0 = (offsetr0 + BLOCK_SIZE/4) & 0x7f;
        offsetr1 = (offsetr1 + BLOCK_SIZE/4) & 0x7f;
        offsetr2 = (offsetr2 + BLOCK_SIZE/4) & 0x7f;
        offsetr3 = (offsetr3 + BLOCK_SIZE/4) & 0x7f;

        Br0 = B + offsetr0;
        Br1 = B + offsetr1;
        Br2 = B + offsetr2;
        Br3 = B + offsetr3;
    }

    
    for (int i=0; i<sizeof(Bp_space)/sizeof(*Bp_space); i++) {
        B[i] = Bp_space[i];
    }
}

void bs_shiftrows(__global word_t * B){
    word_t Bp_space[BLOCK_SIZE];
    word_t * Bp = Bp_space;
    __global word_t * Br0 = B + 0;
    __global word_t * Br1 = B + 32;
    __global word_t * Br2 = B + 64;
    __global word_t * Br3 = B + 96;
    uchar offsetr0 = 0;
    uchar offsetr1 = 32;
    uchar offsetr2 = 64;
    uchar offsetr3 = 96;


    for(int i=0; i<4; i++)
    {
        Bp[B0 + 0] = Br0[0];
        Bp[B0 + 1] = Br0[1];
        Bp[B0 + 2] = Br0[2];
        Bp[B0 + 3] = Br0[3];
        Bp[B0 + 4] = Br0[4];
        Bp[B0 + 5] = Br0[5];
        Bp[B0 + 6] = Br0[6];
        Bp[B0 + 7] = Br0[7];
        Bp[B1 + 0] = Br1[0];
        Bp[B1 + 1] = Br1[1];
        Bp[B1 + 2] = Br1[2];
        Bp[B1 + 3] = Br1[3];
        Bp[B1 + 4] = Br1[4];
        Bp[B1 + 5] = Br1[5];
        Bp[B1 + 6] = Br1[6];
        Bp[B1 + 7] = Br1[7];
        Bp[B2 + 0] = Br2[0];
        Bp[B2 + 1] = Br2[1];
        Bp[B2 + 2] = Br2[2];
        Bp[B2 + 3] = Br2[3];
        Bp[B2 + 4] = Br2[4];
        Bp[B2 + 5] = Br2[5];
        Bp[B2 + 6] = Br2[6];
        Bp[B2 + 7] = Br2[7];
        Bp[B3 + 0] = Br3[0];
        Bp[B3 + 1] = Br3[1];
        Bp[B3 + 2] = Br3[2];
        Bp[B3 + 3] = Br3[3];
        Bp[B3 + 4] = Br3[4];
        Bp[B3 + 5] = Br3[5];
        Bp[B3 + 6] = Br3[6];
        Bp[B3 + 7] = Br3[7];

        offsetr0 = (offsetr0 + BLOCK_SIZE/16 + BLOCK_SIZE/4) & 0x7f;
        offsetr1 = (offsetr1 + BLOCK_SIZE/16 + BLOCK_SIZE/4) & 0x7f;
        offsetr2 = (offsetr2 + BLOCK_SIZE/16 + BLOCK_SIZE/4) & 0x7f;
        offsetr3 = (offsetr3 + BLOCK_SIZE/16 + BLOCK_SIZE/4) & 0x7f;

        Br0 = B + offsetr0;
        Br1 = B + offsetr1;
        Br2 = B + offsetr2;
        Br3 = B + offsetr3;

        Bp += 8;
    }
    for (int i=0; i<sizeof(Bp_space)/sizeof(*Bp_space); i++) {
        B[i] = Bp_space[i];
    }
}


void bs_addroundkey(__global word_t * B, __global const word_t * rk){
    for (int i = 0; i < BLOCK_SIZE; i++)
        B[i] ^= rk[i];
}

void bs_apply_sbox(__global word_t * input){
    for(int i=0; i < BLOCK_SIZE; i+=8){
        bs_sbox(input+i);
    }
}

void bs_cipher(__global word_t *state, __global const word_t (* rk)[BLOCK_SIZE]){
    bs_addroundkey(state,rk[0]);
    for (int round = 1; round < 10; round++){
        bs_apply_sbox(state);
        bs_shiftmix(state);
        bs_addroundkey(state,rk[round]);
    }
    bs_apply_sbox(state);
    bs_shiftrows(state);
    bs_addroundkey(state,rk[10]);
}

void bitsliced_cbc(word_t *iv, __global const word_t (* rk)[BLOCK_SIZE], __global word_t *state, ulong len){
    for (ulong i=0; i+0x10*8<=len*8; i+=0x10*8){
        if (i == 0){
            if (iv){
                for (int z=0; z<0x10*8; z++){
                    state[z] ^= iv[z];
                }
            }
        }else{
            for (int z=0; z<0x10*8; z++){
                state[i+z] ^= state[i - 0x10*8 + z];
            }
        }
 
        bs_cipher(&state[i], rk);
    }
}


#pragma mark MY STUFF
 /* ------ MY STUFF ------ */



__kernel void generateNumericPasswordBatch(ulong startPin, ulong length, __global char *pwbuffer, __global char *keybuffer, __global const char *salt){
    uint p = get_global_id(0) + get_global_id(1) * get_global_size(0);
        
    for (ulong g = 0; g < 8*sizeof(word_t); g++){
        ulong curPin = startPin + p*8*sizeof(word_t) + g;
        
        for (ulong i=1; i<=length; i++){
            int digit = curPin % 10;
            curPin /= 10;
            
            char c = '0' + digit;
            
            pwbuffer[(p*8*sizeof(word_t) + g)* PASSWORD_MAX_LENGTH + length - i] = c;
        }
        //        // --- TEST --- //
        pbkdf2_iOS((__global char *)&pwbuffer[(p*8*sizeof(word_t) + g)* PASSWORD_MAX_LENGTH], length, salt, &keybuffer[(p*8*sizeof(word_t)+g)* 40]);
    }
    
    
}

#define DERIVATION_BUFFER_SIZE  4096


#define WORD_SIZE (sizeof(word_t)*8)
__kernel void my_transpose(__global uchar *in, __global word_t *output, ulong bytelen){
    uint p = get_global_id(0) + get_global_id(1) * get_global_size(0);

    in += p*WORD_SIZE*bytelen;
    output += p*WORD_SIZE*bytelen/sizeof(*output);

    for (ulong bitpos=0; bitpos<bytelen*8; bitpos++) {
        word_t w = 0;
        for (word_t dstbyte = 0; dstbyte<WORD_SIZE; dstbyte++) {
            ulong srcpos = dstbyte*bytelen + bitpos/8;
            
            uchar bitshift = (bitpos % 8);
            
            uchar inByte = in[srcpos];
            
            word_t bit = (inByte>>bitshift)&1;
            w |= (bit << dstbyte);
        }
        output[bitpos] = w;
    }
}
__kernel void my_transpose_rev(__global word_t *input, __global uchar *out, ulong bytelen){
    uint p = get_global_id(0) + get_global_id(1) * get_global_size(0);
        
    input += p*WORD_SIZE*bytelen/sizeof(*input);
    out += p*WORD_SIZE*bytelen;

    for (ulong bitpos=0; bitpos<8*bytelen; bitpos++) {
        word_t w = input[bitpos];
        for (word_t dstbyte = 0; dstbyte< sizeof(word_t)*8; dstbyte++) {
            uchar bitshift = (bitpos % 8);
            uchar bit = (w & 1) << bitshift; w>>=1;
            
            ulong dstpos = dstbyte*bytelen + bitpos/8;
            out[dstpos] |= bit;
        }
    }
}


void transpose_uint(word_t *out, uint input){
    word_t one = ~0;
    for (word_t i=0; i<sizeof(uint)*8; i++) {
        out[i] = (input & 1) ? one : 0;input >>=1;
    }
}

uint AppleKeyStore_xorExpand_bitsliced(__global word_t* dst, uint dstLen, __global word_t* input, uint inLen, uint xorKey){
    __global word_t *dstEnd = &dst[dstLen * 8];
    
    word_t sliced_xor_key[sizeof(uint)*8];
    
    while (dst < dstEnd) {
        transpose_uint(sliced_xor_key, xorKey);
        for (ulong i = 0; i<inLen * 8; i++) {
            ulong xor_bit_pos = i % (sizeof(uint)*8);
            *dst = input[i] ^ sliced_xor_key[xor_bit_pos];
            dst++;
        }
        xorKey++;
    }
    
    return xorKey;
}

void AppleKeyStore_xorCompress_bitsliced(__global word_t* input, uint inputLen, __global word_t* output, uint outputLen){
    for (ulong i=0; i<inputLen*8; i++) {
        output[i % (outputLen*8)] ^= input[i];
    }
}

__kernel void AppleKeyStore_derivation(__global uchar *data, __global uchar *buffer2, __global uchar *buf1_arg, __global const word_t (* roundkey)[BLOCK_SIZE], uint iter){
    uint p = get_global_id(0) + get_global_id(1) * get_global_size(0);

#define dataLength 32
    
    const uint nBlocks = DERIVATION_BUFFER_SIZE / dataLength;    //4096/32=128
    
    data +=     p * 40 * WORD_SIZE;
    buffer2 +=  p * 40 * WORD_SIZE;
    buf1_arg += p * DERIVATION_BUFFER_SIZE * WORD_SIZE*sizeof(word_t);
    
    
    __global word_t *buf1 = (__global word_t *)buf1_arg;
    
    uint xorkey = 1;
    uint r4 = 0;


    word_t iv[0x10 * (sizeof(word_t)*8)] = {};
    
    while (iter > 0){
        xorkey = AppleKeyStore_xorExpand_bitsliced(buf1, DERIVATION_BUFFER_SIZE, (__global word_t *)buffer2, 32, xorkey);
        bitsliced_cbc(iv, roundkey, buf1, DERIVATION_BUFFER_SIZE);

        for (int i=0; i<0x10*8; i++) {
            iv[i] = buf1[DERIVATION_BUFFER_SIZE*8 - 0x10*8 + i];
        }

        r4 = nBlocks;
        if (r4 >= iter){
            r4 = iter;
        }
        
        AppleKeyStore_xorCompress_bitsliced((__global word_t *)buf1,  r4 * dataLength, (__global word_t *)data, dataLength);
        iter -= r4;        
    }

}
