#include "cache.h"
#define EPOCH_SIZE 2
#define CACHE_LINE_NUM 10
#define EPOCH_NUM
#define SUB_EPOCH_SIZE 10
// --- EPOCH_NUM to be calcualted using epoch size and num vertices?
uint32_t rerefMatrix[CACHE_LINE_NUM][EPOCH_NUM];

// get set and way location for this clineID for current and next epoch
// offset_within_line will be same right?
void clineID_to_reref(uint32_t clineID, uint32_t &way, uint32_t &set, uint32_t &offset_within_line, bool current){
    uint32_t line_size = 6; // log(64) assuming cache line size = 64
    offset_within_line = clineID%(line_size);

    uint32_t set_offset = (clineID>>line_size)%NUM_SET;
    uint32_t way_offset = (clineID>>line_size)/NUM_SET;
    
    if(current){
        set = curr_set_offset + set_base;
        way = curr_way_offset + way_base;
    }
    else{
        set = next_set_offset + set_base;
        way = next_way_offset + way_base;
    }
}

// reads the LLC and returns the reref entry for given clineID. If current=0 then returns for current epoch
// else for next epoch
void get_reref_entry(uint32_t clineID, Boolean current){
    uint32_t way, set, offset_within_line;
    clineID_to_reref(clineID, way, set, offset_within_line, current);
    // read llc at this way and set ainclude "cache.h"nd offset_within_line and return
    // that 1 byte (Assuming 8 bit qunaitazation, each cache line next ref info is 1 byte)
}

uint32_t msb(uint32_t entry){
    uint32_t pow = (1<<7);
    uint32_t ans = (entry/pow)%2;
    return ans;
}

uint32_t value(uint32_t entry){
    if (msb(entry) == 1){
        return entry - (1<<7);
    }
    else{
        return entry;
    }
}

uint32_t findNextRef(uint32_t clineID, uint32_t currDstID){
    uint32_t epochID = currDstID/EPOCH_SIZE;
    uint32_t currEntry = rerefMatrix[clineID][epochID];

    if(msb(currEntry) == 1){
        return value(currEntry);
    }
    else{
        uint32_t lastSubEpoch = value(currEntry);
        uint32_t epochStart = epochID*EPOCH_SIZE;
        uint32_t epochOffSet = currDstID - epochStart;
        uint32_t currSubEpoch = epochOffSet/SUB_EPOCH_SIZE;

        if (currSubEpoch <= lastSubEpoch){
            return 0;
        }
        else{
            if (epochID < (EPOCH_SIZE -1)){   
                uint32_t nextEntry = rerefMatrix[clineID][epochID+1];
                if (msb(nextEntry) == 1){
                    return 1 + value(nextEntry);
                 }
                 return 1;
            }
            else{
                return 1;
            }
        }
    }
}
