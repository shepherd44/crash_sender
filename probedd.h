#ifndef __PROBE_H__
#define __PROBE_H__

#include "nicinfo.h"

enum PROBE_STATE
{
    BEGIN = 0,
    WAIT_MESSAGE,
    PROCESS_MESSAGE,
};

class CProbe
{
private:
    // 프로그램 상태
    PROBE_STATE m_ProbeState;
    // NIC Information 리스트 
    CNICInfoList m_NICInfoList;

public:
    // NIC Information List 생성
    int FindNetDevice();
    NICAddr *NICAddr;

    // 메시지 루프
    void StartMainLoop();

    CProbe();
    ~CProbe();
};

class CProbeInfo
{
private:

public:
    CProbeInfo();
    ~CProbeInfo();

};


#endif // __PROBE_H__
