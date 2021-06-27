//
//  UIDOGPUManager.hpp
//  uidogpu
//
//  Created by tihmstar on 03.08.20.
//  Copyright © 2020 tihmstar. All rights reserved.
//

#ifndef UIDOGPUManager_hpp
#define UIDOGPUManager_hpp

#include "UIDOGPU.hpp"
#include <vector>

class UIDOGPUManager{
    std::vector<UIDOGPU*> _gpus;
public:
    UIDOGPUManager(std::vector<UIDOGPU*> gpus);
    ~UIDOGPUManager();

    std::string bruteforceNumericPin(uint64_t startPin, uint64_t endPin);
    
};

#endif /* UIDOGPUManager_hpp */
