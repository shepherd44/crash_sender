#ifndef _PCAPSOCKET_H__
#define _PCAPSOCKET_H__

#include <iostream>
#include <exception>

#define HAVE_REMOTE 1
#include "pcap.h"
#define PACKET_SNAP_LEN 65536
#define NICNAME_OFFSET  12

#include "inetproto.h"
#include "nicinfo.h"

class CWPcapSocket
{   
protected:
    // 네트워크 디바이스 리스트
    pcap_if_t *m_pAllNIC;
    // winpcap 디바이스 연결 소켓
    pcap_t *m_pCapHandler;  
    int m_CurSel;
    // NIC 정보 리스트 헤드
    CNICInfoList m_NICInfoList;
    // winpcap 에러 버퍼
    char m_ErrBuffer[PCAP_ERRBUF_SIZE];
    // 초기화 함수
    void SockInit();
public:
    // 작동중인 네트워크 디바이스 찾기
    void FindNetDevice();
    // pcap_t 네트워크 인터페이스 연결
    void OpenNetDevice(int index = 0);
    // 디바이스 이름으로 열기
    void OpenNetDevice(const char *nicname);
    // 연결 종료
    void CloseNetDevice();

    // 현재 장비의 NIC 갯수 반환
    int GetNICCount();
    // 현재 선택된 NIC 번호 가져오기
    // 없으면 -1 반환
    int GetCurrentSelectNICNum();
    // 현재 선택된 NIC 정보 구조체 가져오기
    // 선택된 NIC가 없으면 NULL 반환
    const NICInfo *GetCurrentSelectNICInfo();
    // 현재 선택된 NIC 이름 가져오기
    // 선택된 NIC가 없으면 NULL 반환
    char *GetCurrentSelectNICName();
    // 에러 버퍼 가져오기
    const char* GetErrorBuffer();
    // NIC정보 리스트 반환
    CNICInfoList *GetNICInfoList();
public:
    CWPcapSocket();
    virtual ~CWPcapSocket();
};

// Exception
class WPcapSocketException : public std::exception
{
public:
    WPcapSocketException(const char *message) { }
};

#endif  // __PCAPSOCKET_H__ //5536
