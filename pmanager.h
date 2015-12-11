#ifndef __PMANAGER_H__
#define __PMANAGER_H__

#include <stdint.h>

class CPManager
{
private:
    uint32_t m_PMIpAddress;
    uint32_t m_CommandPort;
    uint32_t m_DataPort;
    int m_CommendSockdes;
    int m_DataSockdes;
public:
    CPManager(uint32_t, uint32_t, uint32_t);
    ~CPManager();
    void Initilize();
    int ConnectCommand();
    int ConnectData();

};
#endif
