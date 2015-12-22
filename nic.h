#ifndef __NIC_H__
#define __NIC_H__

#include <stdint.h>
#include <list>
#include "pmcprotocol.h"

#define NIC_NAME_MAXLENGTH  16
#define NIC_DESCRIPTION_MAXLENGTH 128

enum NIC_STATE
{
    IDLE = 0,   // 일반 상태
    DISCONNET,  // IPv4 DISCONNET
    CAPTURE,    // 캡처 중
};

typedef struct NICAddr
{
    // 우선 IPV4만 처리
    //struct NICInfo *next;
    int familly;
    uint32_t ipaddr;
    uint32_t netmask;
}NICAddr;

// NIC class
// sniffer의 위치 생각
class CNIC
{
private:
    char m_NICName[NIC_NAME_MAXLENGTH];
    char m_NICDescription[NIC_DESCRIPTION_MAXLENGTH];

    uint8_t m_MACAddress[6];
    NICAddr *m_NICAddr;
    // NIC 상태(현재 프로그램에서의 상태)
    NIC_STATE m_NICState;

public:
    // 캡처 시작
    void StartCapture();
    // 캡처 종료
    void EndCapture();
    // MAC 주소 셋팅
    void SetMACAddr(uint8_t *mac);
    NICInfo ToNICInfo();

    // 프로토콜 주소 셋팅
    char *GetNICName() { return m_NICName; }
    NICAddr *GetNICAddr() { return m_NICAddr; }
    uint8_t *GetMACAddr() { return m_MACAddress; }
    void SetNICAddr(NICAddr *NICAddr);

    // 갱신
    int Refresh();
    CNIC();
    CNIC(char *nicname, char *nicdes);
    // 복사 생성자
    CNIC(CNIC const & nic);
    ~CNIC();
};

// NIC List Class
class CNICList
{
private:
    std::list<CNIC> m_ListHead;
public:
    void PushBack(CNIC &nic);
    void InsertItem(int index, CNIC &nic);
    int GetListSize();
    // devname을 받아서 NIC생성하여 추가
    int AddNewNIC(char *devname, char* devdes);
    CNIC &At(int index);
    int FindNICFromMAC(uint8_t *mac);
    int MACcmp(uint8_t *mac1, uint8_t *mac2);

    CNICList();
    ~CNICList();
};
#endif //__NIC_H__
