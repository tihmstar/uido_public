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

    //aes
    cl_ulong _rk[11][128];
    cl_mem _argRK;
    cl_mem _argSalt;

    
    uint64_t generateNumericPasswordBatch(uint64_t startPin, uint64_t length, uint8_t **keysBuf);

public:
    UIDOGPU(std::string kbdumppath, uint8_t uidkey[0x10], int deviceNum, cl_device_id device_id);
        
    std::string bruteforceNumeric(uint64_t startPin, uint64_t endPin);
    
    ~UIDOGPU();
};


#endif /* UIDOGPU_hpp */
