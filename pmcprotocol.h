#ifndef __PMCPROTOCOL_H__
#define __PMCPROTOCOL_H__

#include <stdint.h>
#include <sys/time.h>
//#include "nic.h"

typedef struct NICInfo
{
    char nicname[16];//NIC_NAME_MAXLENGTH];
    uint32_t nicip;
    uint8_t nicmac[6];
}__attribute__((packed)) NICInfo;

typedef struct pmc_pkthdr
{
    struct timeval ts;
    uint32_t caplen;
    uint32_t len;
}pmc_pkthdr;

enum PMC_OPCODIE
{
    CONNECT = 1,
    DISCONNECT,
    REFRESH,
    CAPTURE_START,
    CAPTURE_STOP
};

typedef struct PMCMessage
{
    uint16_t datalen;
    uint8_t opcode;
    uint8_t flags;
}PMCMessage;

#define FLAGMASK_SENDER         0b11000000
#define FLAG_SENDER_PROBE       0b10000000
#define FLAG_REPLY              0b00100000
#define FLAG_ERROR              0b00010000

#endif //__PMCPROTOCOL_H__
