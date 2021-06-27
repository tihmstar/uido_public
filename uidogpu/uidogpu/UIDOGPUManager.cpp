//
//  UIDOGPUManager.cpp
//  uidogpu
//
//  Created by tihmstar on 03.08.20.
//  Copyright © 2020 tihmstar. All rights reserved.
//

#include "UIDOGPUManager.hpp"
#include <mutex>
#include <thread>

UIDOGPUManager::UIDOGPUManager(std::vector<UIDOGPU*> gpus)
: _gpus(gpus)
{
    
}

UIDOGPUManager::~UIDOGPUManager(){
    //
}

std::string UIDOGPUManager::bruteforceNumericPin(uint64_t startPin, uint64_t endPin){
    uint64_t curPin = startPin;
    std::mutex curPinLock;
    std::vector<std::thread *> workers;
    bool keepRunning = true;
    
    std::string foundPincode;
    
    printf("Bruteforcing numeric pins in the range (%llu  -  %llu)\n",startPin,endPin);
    
    for (auto g : _gpus) {
        workers.push_back(new std::thread([&](UIDOGPU *gpu){
            uint64_t myCurPin = 0;
            
            while (keepRunning) {
                curPinLock.lock();
                myCurPin = curPin;
                if (myCurPin >= endPin) {
                    curPinLock.unlock();
                    printf("[W-%d] Returning since there is no more work to do because curpin(%llu) is larger than endPin(%llu)\n",gpu->deviceNum(),myCurPin,endPin);
                    return;
                }
                curPin += gpu->numericBatchSizeForStartPin(myCurPin);
                curPinLock.unlock();
                printf("[W-%d] Got bruteforce batch (%llu  -  %llu)\n",gpu->deviceNum(),myCurPin,myCurPin+gpu->numericBatchSizeForStartPin(myCurPin));
                
                std::string myRealPin = gpu->bruteforceNumericBatch(myCurPin);
                if (myRealPin.size()) {
                    keepRunning = false;
                    printf("[W-%d] Found pin! The pin is \"%s\"\n",gpu->deviceNum(),myRealPin.c_str());
                    foundPincode = myRealPin;
                }
            }
            printf("[W-%d] Worker retireing\n",gpu->deviceNum());
        },g));
    }

    //wait for workers
    for (auto w : workers) {
        w->join();
        delete w;
    }
    workers.clear();
    
    if (foundPincode.size()) {
        printf("Found pin: %s\n",foundPincode.c_str());
        return foundPincode;
    }
    
    
    printf("Failed to find Pin in range (%llu  -  %llu)",startPin,endPin);
    return {};
}
