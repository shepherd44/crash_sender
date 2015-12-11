#ifndef __NICINFO_H__
#define __NICINFO_H__

#include <stdint.h>
#include "inetproto.h"
#include "mylist.h"

typedef struct NICInfo
{
    char* Description;
    char* AdapterName;
    uint32_t Netmask;
    uint32_t GatewayIPAddress;
    uint32_t NICIPAddress;
    uint8_t NICMACAddress[6];
    ListHead list;
}NICInfo, *PNICInfo;

class CNICInfoList
{
private:
    ListHead m_ListHead;
    int m_ListSize;
public:
    CNICInfoList();
    ~CNICInfoList();

    void AddItem(const char *name, const char *des, uint32_t netmask, uint32_t gatewayip, uint32_t ip, const uint8_t *mac);
    void AddItem(const NICInfo *nicinfo);
    int IsInItem(const char *name);
    void RemoveItem(PListHead ph);
    void ClearList();
    // index는 0부터, last item index == size - 1
    NICInfo* At(int index);
    int GetSize() { return m_ListSize; }
};

#endif // _NICINFOLIST_H__
