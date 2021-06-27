//
//  UIDOGPU.hpp
//  uidogpu
//
//  Created by tihmstar on 10.07.20.
//  Copyright © 2020 tihmstar. All rights reserved.
//

#ifndef UIDOGPU_hpp
#define UIDOGPU_hpp

#ifdef __APPLE__
#include <OpenCL/opencl.h>
#else
#include <CL/cl.h>
#endif

#include <stdio.h>
#include <iostream>
#include "UIDO.hpp"

class UIDOGPU : UIDO{    
    int _deviceNum;
    cl_device_id _device_id;
    cl_context _context;
    cl_ulong _deviceWorkgroupSize;
    cl_program _program;
    cl_command_queue _command_queue;

    cl_ulong _deviceGroups;
    
    //kernels
    cl_kernel _kernel_generateNumericPasswordBatch;
    cl_kernel _kernel_my_transpose;
    cl_kernel _kernel_my_transpose_rev;
    cl_kernel _kernel_AppleKeyStore_derivation;
    cl_kernel _kernel_gpu_transpose;
    cl_kernel _kernel_gpu_transpose_rev;

    
    //aes
    cl_ulong _rk[11][128];
    cl_mem _argRK;
    cl_mem _argSalt;

    void deriveAppleKeyStore(cl_mem argKeyBuffer, cl_ulong argKeyBufferSize, cl_uint eventsCnt, cl_event *events, uint8_t **out);

    
    uint64_t generateNumericPasswordBatch(uint64_t startPin, uint64_t length, uint8_t **keysBuf);

public:
    UIDOGPU(std::string kbdumppath, uint8_t uidkey[0x10], int deviceNum, cl_device_id device_id);
    ~UIDOGPU();
    
    uint64_t numericBatchSizeForStartPin(uint64_t startPin) const;

    int deviceNum() const;
        
    std::string bruteforceNumericBatch(uint64_t startPin);
};


#endif /* UIDOGPU_hpp */
