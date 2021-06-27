//
//  UIDOGPU.cpp
//  uidogpu
//
//  Created by tihmstar on 10.07.20.
//  Copyright © 2020 tihmstar. All rights reserved.
//

#include "UIDOGPU.hpp"
#include <libgeneral/macros.h>
#include <future>
#include <functional>
#include <queue>
#include <thread>
#include <string.h>
#include <sys/fcntl.h>

extern "C"{
#include "bs.h"
#include "bsdcrypto/key_wrap.h"
};

#define PASSWORD_MAX_LENGTH 100
#define PARALLEL_PINS (_deviceWorkgroupSize*sizeof(gpu_word_t)*8)

typedef cl_ulong gpu_word_t;

UIDOGPU::UIDOGPU(std::string kbdumppath, uint8_t uidkey[0x10], int deviceNum, cl_device_id device_id)
: UIDO(uidkey, kbdumppath), _device_id(device_id), _deviceNum(deviceNum), _context{}, _deviceWorkgroupSize{}, _program{}, _command_queue{},
    _rk{}, _argRK{}
{
    char *kernelsource = NULL;
    FILE *kernelfile = NULL;
    cleanup([&]{
        safeFree(kernelsource);
        safeFreeCustom(kernelfile,fclose);
    });
    cl_int clret = 0;
    size_t kernelSourceSize = 0;
    
    bs_expand_key(_rk, uidkey);
    
    {
        char *value = NULL;
        cleanup([&]{
            safeFree(value);
        });
        size_t valueSize = 0;
        //print device info
        
        assure(!clGetDeviceInfo(_device_id, CL_DEVICE_NAME, 0, NULL, &valueSize));
        value = (char*) malloc(valueSize+1);
        memset(value, 0, valueSize+1);
        
        assure(!clGetDeviceInfo(_device_id, CL_DEVICE_NAME, valueSize, value, NULL));
        printf("CL_DEVICE_NAME: %s\n",value);
    }
    
    
    
    printf("[D-%d] starting device\n",_deviceNum);
    _context = clCreateContext(NULL, 1, &_device_id, NULL, NULL, &clret);assure(!clret);

    clret = clGetDeviceInfo(device_id, CL_DEVICE_MAX_WORK_GROUP_SIZE, sizeof(_deviceWorkgroupSize), &_deviceWorkgroupSize, NULL);assure(!clret);
    printf("[D-%d] deviceWorkgroupSize      =%llu\n",_deviceNum, _deviceWorkgroupSize);


    // Create a program from the kernel source
#ifdef XCODE
    assure(kernelfile = fopen("../../../uidogpu/kernel.cl", "r"));
#else
    assure(kernelfile = fopen("kernel.cl", "r"));
#endif
    
    fseek(kernelfile, 0, SEEK_END);
    kernelSourceSize = ftell(kernelfile);
    fseek(kernelfile, 0, SEEK_SET);
    assure(kernelsource = (char*)malloc(kernelSourceSize));
    
    assure(fread(kernelsource, 1, kernelSourceSize, kernelfile) == kernelSourceSize);
    
    _program = clCreateProgramWithSource(_context, 1, (const char**)&kernelsource, &kernelSourceSize, &clret);assure(!clret);

    clret = clBuildProgram(_program, 1, &device_id, NULL, NULL, NULL);
    if (clret != CL_SUCCESS) {
        // Determine the size of the log
        size_t log_size = 0;
        clret = clGetProgramBuildInfo(_program, device_id, CL_PROGRAM_BUILD_LOG, 0, NULL, &log_size);assure(!clret);

        // Allocate memory for the log
        char *log = (char *) malloc(log_size);

        // Get the log
        clret = clGetProgramBuildInfo(_program, device_id, CL_PROGRAM_BUILD_LOG, log_size, log, NULL);assure(!clret);

        // Print the log
        printf("%s\n", log);
        safeFree(log);
        assure(0);
    }
    assure(!clret);
    
    _command_queue = clCreateCommandQueue(_context, device_id, 0, &clret);assure(!clret);
    
    _argSalt = clCreateBuffer(_context, CL_MEM_READ_ONLY, sizeof(get_KeyBag().salt), NULL, &clret);assure(!clret);
    assure(!clEnqueueWriteBuffer(_command_queue, _argSalt, true, 0, sizeof(get_KeyBag().salt), get_KeyBag().salt, 0, NULL, NULL));

    
    _argRK = clCreateBuffer(_context, CL_MEM_READ_ONLY, sizeof(_rk), NULL, &clret);assure(!clret);
    assure(!clEnqueueWriteBuffer(_command_queue, _argRK, true, 0, sizeof(_rk), _rk, 0, NULL, NULL));
}



uint8_t *getpasscodeKey(void *keybuf, uint64_t code){
#warning DEBUG
    return &((uint8_t*)keybuf)[40*code];
}

uint64_t UIDOGPU::generateNumericPasswordBatch(uint64_t startPin, uint64_t length, uint8_t **keysBuf){
#define DERIVATION_BUFFER_SIZE  4096
#define word_t cl_ulong
    cl_event fillStringsEvent = NULL;
    cl_event fillKeysEvent = NULL;
    cl_event fillKeys2Event = NULL;
    cl_event fillKeysSlicedEvent = NULL;
    cl_event fillIVEvent = NULL;
    cl_event fillBuf1Event = NULL;
    
    cl_event generateEvent = NULL;
    cl_event transposeEvent = NULL;
    cl_event transposeRevEvent = NULL;
    cl_event copyBuffer2Event = NULL;
    cl_event appleDerivationEvent = NULL;

    
    cl_mem argPasswordStrings = NULL;
    cl_mem argKeyBuffer = NULL;
    cl_mem argKeyBufferSliced = NULL;
    cl_mem argIV = NULL;
    cl_mem argBuf1 = NULL;

    //kernels
    cl_kernel kernel_generateNumericPasswordBatch = NULL;
    cl_kernel kernel_my_transpose = NULL;
    cl_kernel kernel_my_transpose_rev = NULL;
    cl_kernel kernel_AppleKeyStore_derivation = NULL;
    
    cleanup([&]{
        safeFreeCustom(fillStringsEvent, clReleaseEvent);
        safeFreeCustom(fillKeysEvent, clReleaseEvent);
        safeFreeCustom(fillKeys2Event, clReleaseEvent);
        safeFreeCustom(fillKeysSlicedEvent, clReleaseEvent);
        safeFreeCustom(fillIVEvent, clReleaseEvent);
        safeFreeCustom(fillBuf1Event, clReleaseEvent);

        safeFreeCustom(generateEvent, clReleaseEvent);
        safeFreeCustom(transposeEvent, clReleaseEvent);
        safeFreeCustom(transposeRevEvent, clReleaseEvent);
        safeFreeCustom(copyBuffer2Event, clReleaseEvent);
        safeFreeCustom(appleDerivationEvent, clReleaseEvent);

        safeFreeCustom(argPasswordStrings, clReleaseMemObject);
        safeFreeCustom(argKeyBuffer, clReleaseMemObject);
        safeFreeCustom(argKeyBufferSliced, clReleaseMemObject);
        safeFreeCustom(argIV, clReleaseMemObject);
        safeFreeCustom(argBuf1, clReleaseMemObject);
        
        safeFreeCustom(kernel_generateNumericPasswordBatch, clReleaseKernel);
        safeFreeCustom(kernel_my_transpose, clReleaseKernel);
        safeFreeCustom(kernel_my_transpose_rev, clReleaseKernel);
        safeFreeCustom(kernel_AppleKeyStore_derivation, clReleaseKernel);
    });
    
    size_t work_size = _deviceWorkgroupSize;

    uint8_t zero[WORD_SIZE];
    memset(zero, 0, WORD_SIZE);

    cl_int clret = 0;

    cl_ulong argStartPin = startPin;
    cl_ulong argLength = length;

    size_t argPasswordStringsSize = PASSWORD_MAX_LENGTH * PARALLEL_PINS;
    size_t argKeyBufferSize = 40 * PARALLEL_PINS;

    size_t argBuf1Size = DERIVATION_BUFFER_SIZE * (sizeof(word_t)*8)*sizeof(word_t) * _deviceWorkgroupSize;


    printf("testing %llu pins...\n",PARALLEL_PINS);

    printf("Creating kernels ...\n");
    kernel_generateNumericPasswordBatch = clCreateKernel(_program, "generateNumericPasswordBatch", &clret);assure(!clret);
    kernel_my_transpose = clCreateKernel(_program, "my_transpose", &clret);assure(!clret);
    kernel_my_transpose_rev = clCreateKernel(_program, "my_transpose_rev", &clret);assure(!clret);
    kernel_AppleKeyStore_derivation = clCreateKernel(_program, "AppleKeyStore_derivation", &clret);assure(!clret);


    printf("Allocating buffers ...\n");
    argPasswordStrings = clCreateBuffer(_context, CL_MEM_READ_WRITE, argPasswordStringsSize, NULL, &clret);assure(!clret);
    argKeyBuffer = clCreateBuffer(_context, CL_MEM_READ_WRITE, argKeyBufferSize, NULL, &clret);assure(!clret);
    argKeyBufferSliced = clCreateBuffer(_context, CL_MEM_READ_WRITE, argKeyBufferSize, NULL, &clret);assure(!clret);
    argBuf1 = clCreateBuffer(_context, CL_MEM_READ_WRITE, argBuf1Size, NULL, &clret);assure(!clret);


    printf("Filling buffers ...\n");
    clret = clEnqueueFillBuffer(_command_queue, argPasswordStrings, zero, WORD_SIZE, 0, argPasswordStringsSize, 0, NULL, &fillStringsEvent);assure(!clret);
    clret = clEnqueueFillBuffer(_command_queue, argKeyBuffer, zero, WORD_SIZE, 0, argKeyBufferSize, 0, NULL, &fillKeysEvent);assure(!clret);
    clret = clEnqueueFillBuffer(_command_queue, argKeyBufferSliced, zero, WORD_SIZE, 0, argKeyBufferSize, 0, NULL, &fillKeysSlicedEvent);assure(!clret);
    clret = clEnqueueFillBuffer(_command_queue, argBuf1, zero, WORD_SIZE, 0, argBuf1Size, 0, NULL, &fillBuf1Event);assure(!clret);


    clret = clSetKernelArg(kernel_generateNumericPasswordBatch, 0, sizeof(cl_ulong), &argStartPin);assure(!clret);
    clret = clSetKernelArg(kernel_generateNumericPasswordBatch, 1, sizeof(cl_ulong), &argLength);assure(!clret);
    clret = clSetKernelArg(kernel_generateNumericPasswordBatch, 2, sizeof(cl_mem), &argPasswordStrings);assure(!clret);
    clret = clSetKernelArg(kernel_generateNumericPasswordBatch, 3, sizeof(cl_mem), &argKeyBuffer);assure(!clret);
    clret = clSetKernelArg(kernel_generateNumericPasswordBatch, 4, sizeof(cl_mem), &_argSalt);assure(!clret);

    {
        cl_event events[2] = {fillStringsEvent, fillKeysEvent};
        clret = clEnqueueNDRangeKernel(_command_queue, kernel_generateNumericPasswordBatch, 1, NULL, &work_size, NULL, sizeof(events)/sizeof(*events), events, &generateEvent);assure(!clret);
    }

    clret = clSetKernelArg(kernel_my_transpose, 0, sizeof(cl_mem), &argKeyBuffer);assure(!clret);
    clret = clSetKernelArg(kernel_my_transpose, 1, sizeof(cl_mem), &argKeyBufferSliced);assure(!clret);
    {
        cl_ulong keybytes = 40;
        clret = clSetKernelArg(kernel_my_transpose, 2, sizeof(cl_ulong), &keybytes);assure(!clret);
    }

    {
        cl_event events[2] = {generateEvent, fillKeysSlicedEvent};
        clret = clEnqueueNDRangeKernel(_command_queue, kernel_my_transpose, 1, NULL, &work_size, NULL, sizeof(events)/sizeof(*events), events, &transposeEvent);assure(!clret);
    }


    /*
     word_t *buffer2 = (word_t*)malloc(alloclen);
     memcpy(buffer2, data_sliced, alloclen);
     */
    clret = clEnqueueCopyBuffer(_command_queue, argKeyBufferSliced, argKeyBuffer, 0, 0, argKeyBufferSize, 1, &transposeEvent, &copyBuffer2Event);assure(!clret);


    clret = clSetKernelArg(kernel_AppleKeyStore_derivation, 0, sizeof(cl_mem), &argKeyBufferSliced);assure(!clret);
    clret = clSetKernelArg(kernel_AppleKeyStore_derivation, 1, sizeof(cl_mem), &argKeyBuffer);assure(!clret);
    clret = clSetKernelArg(kernel_AppleKeyStore_derivation, 2, sizeof(cl_mem), &argBuf1);assure(!clret);

    clret = clSetKernelArg(kernel_AppleKeyStore_derivation, 3, sizeof(cl_mem), &_argRK);assure(!clret);
    {
//#warning DEBUG
//        cl_ulong iter = 129;
        cl_ulong iter = get_KeyBag().iter;
        clret = clSetKernelArg(kernel_AppleKeyStore_derivation, 4, sizeof(cl_uint), &iter);assure(!clret);
    }


    {
        cl_event events[] = {copyBuffer2Event, fillBuf1Event};
        clret = clEnqueueNDRangeKernel(_command_queue, kernel_AppleKeyStore_derivation, 1, NULL, &work_size, NULL, sizeof(events)/sizeof(*events), events, &appleDerivationEvent);assure(!clret);
    }



    clret = clEnqueueFillBuffer(_command_queue, argKeyBuffer, zero, WORD_SIZE, 0, argKeyBufferSize, 1, &appleDerivationEvent, &fillKeys2Event);assure(!clret);


    clret = clSetKernelArg(kernel_my_transpose_rev, 0, sizeof(cl_mem), &argKeyBufferSliced);assure(!clret);
    clret = clSetKernelArg(kernel_my_transpose_rev, 1, sizeof(cl_mem), &argKeyBuffer);assure(!clret);
    {
        cl_ulong keybytes = 40;
        clret = clSetKernelArg(kernel_my_transpose_rev, 2, sizeof(cl_ulong), &keybytes);assure(!clret);
    }


    clret = clEnqueueNDRangeKernel(_command_queue, kernel_my_transpose_rev, 1, NULL, &work_size, NULL, 1, &fillKeys2Event, &transposeRevEvent);assure(!clret);


    printf("Generating pins ...\n");
    assure(!clWaitForEvents(1, &generateEvent));

    printf("Transposing state ...\n");
    assure(!clWaitForEvents(1, &transposeEvent));

    printf("Copying Buffer ...\n");
    assure(!clWaitForEvents(1, &copyBuffer2Event));

    printf("Running AES ...\n");
    assure(!clWaitForEvents(1, &appleDerivationEvent));

    printf("Transposing state back ...\n");
    assure(!clWaitForEvents(1, &transposeRevEvent));


    printf("Retrieving result ...\n");
    uint8_t *debug = (uint8_t*)malloc(argKeyBufferSize);
    clret = clEnqueueReadBuffer(_command_queue, argKeyBuffer, true, 0, argKeyBufferSize, debug, 0, NULL, NULL); assure(!clret);

    
//    {
//        int fd = open("dump.bin", O_CREAT | O_WRONLY, 0766);
//        write(fd, debug, argKeyBufferSize);
//        close(fd);
//    }
     
    
    *keysBuf = debug;
    return PARALLEL_PINS;
}


std::string UIDOGPU::bruteforceNumeric(uint64_t startPin, uint64_t endPin){
    uint8_t *keysBuf = NULL;
    cleanup([&]{
        safeFree(keysBuf);
    });
    constexpr uint64_t checkerThreadsCnt = sizeof(word_t)*8;
    uint64_t curpin = startPin;
    uint64_t pinLength = 0;
    {
        uint64_t endPinCpy = endPin-1;
        while (endPinCpy > 0) {
            endPinCpy /= 10;
            pinLength++;
        }
    }
    
    
    while (curpin < endPin) {
        size_t keysCnt = 0;
        std::queue<std::thread*> checkers;
        bool didFindPin = false;
        uint64_t pinIndex = 0;
        
        keysCnt = generateNumericPasswordBatch(curpin, pinLength, &keysBuf);

        printf("Starting checkerthreads...\n");
        for (uint64_t i=0; i<checkerThreadsCnt; i++) {
            checkers.push(new std::thread([this, keysBuf, keysCnt, i, &didFindPin, &pinIndex,endPin,curpin]{
                uint64_t checksPerThread = keysCnt/checkerThreadsCnt;   //1024
                uint64_t myIndex = i*checksPerThread;
                for (uint64_t z=0; z<checksPerThread && !didFindPin; z++) {
                    uint64_t myPinIndex = myIndex+z;
                    uint8_t *passcodeKey = &keysBuf[40*myPinIndex];
                    
                    if (curpin + myPinIndex > endPin) {
                        break;
                    }

                    if (AppleKeyStore_unlockKeybag(passcodeKey)) {
                        didFindPin = true;
                        pinIndex = myPinIndex;
                        printf("FOUND KEY at index=%llu\n",myPinIndex);
                        break;
                    }
                }
            }));
        }
        printf("Waiting for checkerthreads to finish...\n");
        
        for (uint64_t i=0; i<checkerThreadsCnt; i++) {
            auto t = checkers.front();
            checkers.pop();
            t->join();
            delete t;
        }
        printf("All checkerthreads finished\n");
        
        if (didFindPin) {
            uint64_t pin = curpin + pinIndex;
            size_t pinstrlen = endPin/10 + 2;
            char pinstrbuf[pinstrlen];
            memset(pinstrbuf, 0, pinstrlen);
            snprintf(pinstrbuf, pinstrlen, "%llu",pin);
            printf("Found PIN: %s\n",pinstrbuf);
            return pinstrbuf;
        }
        curpin +=keysCnt;
    }
    
    printf("Failed to find pin :(\n");
    return {};
}

UIDOGPU::~UIDOGPU(){
    
}
