#ifndef __PCAPSOCKET_H__
#define __PCAPSOCKET_H__

#include <iostream>
#include <exception>

#define HAVE_REMOTE 1
#include "pcap.h"
#define PACKET_SNAP_LEN 65536
#define NICNAME_OFFSET  12

#include "inetproto.h"

// socket에서 인터페이스 정보 얻기
//  /usr/include/bits/ioctls.h 
//#define SIOCGIFNAME     0x8910          [> get iface name               <]
//#define SIOCSIFLINK     0x8911          [> set iface channel            <]
//#define SIOCGIFCONF     0x8912          [> get iface list               <]
//#define SIOCGIFFLAGS    0x8913          [> get flags                    <]
//#define SIOCSIFFLAGS    0x8914          [> set flags                    <]
//#define SIOCGIFADDR     0x8915          [> get PA address               <]
//#define SIOCSIFADDR     0x8916          [> set PA address               <]
//#define SIOCGIFDSTADDR  0x8917          [> get remote PA address        <]
//#define SIOCSIFDSTADDR  0x8918          [> set remote PA address        <]
//#define SIOCGIFBRDADDR  0x8919          [> get broadcast PA address     <]
//#define SIOCSIFBRDADDR  0x891a          [> set broadcast PA address     <]
//#define SIOCGIFNETMASK  0x891b          [> get network PA mask          <]
//#define SIOCSIFNETMASK  0x891c          [> set network PA mask          <]
//#define SIOCGIFMETRIC   0x891d          [> get metric                   <]
//#define SIOCSIFMETRIC   0x891e          [> set metric                   <]
//#define SIOCGIFMEM      0x891f          [> get memory address (BSD)     <]
//#define SIOCSIFMEM      0x8920          [> set memory address (BSD)     <]
//#define SIOCGIFMTU      0x8921          [> get MTU size                 <]
//#define SIOCSIFMTU      0x8922          [> set MTU size                 <]
//#define SIOCSIFNAME     0x8923          [> set interface name           <]
//#define SIOCSIFHWADDR   0x8924          [> set hardware address         <]

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
