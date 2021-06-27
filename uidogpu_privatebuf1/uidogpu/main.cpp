//
//  main.cpp
//  uidogpu
//
//  Created by tihmstar on 10.07.20.
//  Copyright © 2020 tihmstar. All rights reserved.
//

#include <stdio.h>
#include <string.h>
#include <libgeneral/macros.h>
#include "UIDOGPU.hpp"
#include <vector>
#include "UIDOGPUManager.hpp"

int main_r(int argc, const char * argv[]) {
    const char *uid_key_str = NULL;
    const char *kbdumpPath = NULL;
    const char *gpulist = NULL;
    uint8_t uid[0x10]; //128bit AES
    uint64_t startPin = 0;
    uint64_t endPin = 0;

    printf("UIDOGPU\n");
    
    if (argc < 4) {
        printf("UIDOGPU: <uid key> <kbdump> <startpin> <endpin> <GPU1,GPU2,GPU3...>\n");
        return -1;
    }
    
    uid_key_str = argv[1];
    
    for (int i=0; i<strlen(uid_key_str); i+=2) {
        unsigned int b;
        retassure(i/2<sizeof(uid), "UID key too long");
        retassure(sscanf(&uid_key_str[i], "%02x",&b) == 1, "failed to parse UID key");
        uid[i/2] = (uint8_t)b;
    }
    
    kbdumpPath = argv[2];
    
    assure(sscanf(argv[3], "%llu",&startPin) == 1);
    assure(sscanf(argv[4], "%llu",&endPin) == 1);

    gpulist = argv[5];


    

    // Get platform and device information
     cl_platform_id platform_id = NULL;
     cl_uint num_platforms = 0;
     cl_uint num_devices = 0;

    assure(!clGetPlatformIDs(1, &platform_id, &num_platforms));

    assure(!clGetDeviceIDs(platform_id, CL_DEVICE_TYPE_GPU, 0, NULL, &num_devices));

    cl_device_id device_ids[num_devices];
    assure(!clGetDeviceIDs(platform_id, CL_DEVICE_TYPE_GPU, num_devices, device_ids, &num_devices));


    const char *tmpgpu = gpulist-1;
    std::vector<int> gpuIDs;

    do{
        gpuIDs.push_back(atoi(tmpgpu+1));
    }while((tmpgpu = strchr(tmpgpu+1, ',')));
    
    std::vector<UIDOGPU *> gpus;
    for (int index : gpuIDs) {
        assure(index < num_devices);
        printf("Init GPU %d!\n",index);
        gpus.push_back(new UIDOGPU(kbdumpPath,uid,index,device_ids[index]));
    }
    
    
    UIDOGPUManager gpumanager(gpus);
    
    std::string pin = gpumanager.bruteforceNumericPin(startPin, endPin);
    
    if (pin.size()) {
        printf("found pin=%s\n",pin.c_str());
    }else{
        printf("failed to find pin\n");
    }

    for (auto gpu : gpus) {
        delete gpu;
    }
    gpus.clear();
    printf("done!\n");
    return 0;
}


int main(int argc, const char * argv[]) {
#ifdef DEBUG
    return main_r(argc, argv);
#else
    try {
        return main_r(argc, argv);
    } catch (tihmstar::exception &e) {
        printf("%s: failed with exception:\n",PACKAGE_NAME);
        e.dump();
        return e.code();
    }
#endif
}
