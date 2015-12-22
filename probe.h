#ifndef __PROBE_H__
#define __PROBE_H__

#include "sniffer.h"
#include "nic.h"

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
    // STL list 사용
    CNICList m_NICList;

public:
    // NIC Information List 생성
    int FindNetDevice();

    // capture sender Thread
    void StartCaptureSender();
    void* CaptureSender();

    // Command 함수
    // Refresh
    // PManager에게 받은 Refresh 명령을 실행 후 응답 반환
    void ExcuteCommand(char *cmd);
    int Refresh();
    void SendNICInfo();
    // StartCapture
    // PManager에게 받은 StratCapture 명령을 실행 후 응답 반환
    void StartCapture(char *cmd);
    // EndCapture
    // PManager에게 받은 EndCapture 명령을 실행 후 응답 반환
    void EndCapture(char *cmd);
    // StartProbe
    // PManager에게 StartProbe Command 전달
    void StartProbe();
    // EndProbe
    // PManager에게 End Command 전달
    void EndProbe();

    // 생성자
    CProbe();
    // 소멸자
    ~CProbe();
};

extern CProbe pea;

#endif // __PROBE_H__
