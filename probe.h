#ifndef __PROBE_H__
#define __PROBE_H__

#include "nicinfo.h"

enum PROBE_STATE
{
    BEGIN,
    WAIT_MESSAGE,
    PROCESS_MESSAGE,
};

class CProbe
{
private:
    PROBE_STATE m_ProbeState;
    CNICInfoList m_NICInfoList;

public:
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
