#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <net/if.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <exception>
#include <iostream>
#include <errno.h>

#include <arpa/inet.h>
#include "nic.h"

// 생성자
// 초기화 진행
CNIC::CNIC()
{
    memset(m_NICName, '\0', NIC_NAME_MAXLENGTH);
    memset(m_NICDescription, '\0', NIC_DESCRIPTION_MAXLENGTH);
    m_NICAddr = NULL;
    m_NICState = IDLE;
}

CNIC::CNIC(char *nicname, char *nicdes)
{
    memset(m_NICName, '\0', NIC_NAME_MAXLENGTH);
    memset(m_NICDescription, '\0', NIC_DESCRIPTION_MAXLENGTH);

    strncpy(m_NICName, nicname, NIC_NAME_MAXLENGTH);
    if(nicdes != NULL)
        strncpy(m_NICDescription, nicdes, NIC_DESCRIPTION_MAXLENGTH);
    
    m_NICAddr = NULL;
    m_NICState = IDLE;
}

// 복사 생성자
CNIC::CNIC(CNIC const &nic)
{
    memcpy(m_NICName, nic.m_NICName, NIC_NAME_MAXLENGTH);
    memcpy(m_NICDescription, nic.m_NICDescription, NIC_DESCRIPTION_MAXLENGTH);
    memcpy(m_MACAddress, nic.m_MACAddress, 6);
    m_NICState = nic.m_NICState;
    m_NICAddr = new NICAddr;  
    memcpy(m_NICAddr, nic.m_NICAddr, sizeof(NICAddr));
}

// 소멸자
CNIC::~CNIC()
{
    NICAddr *nextaddr;
    if(m_NICAddr != NULL)
    {
        delete m_NICAddr;
    }
    
}

void CNIC::SetNICAddr(NICAddr *nicaddr )
{
    if(m_NICAddr == NULL)
    {
        m_NICAddr = new NICAddr;

    }
    else
    {
        delete m_NICAddr;
        m_NICAddr = new NICAddr;
    }
    memcpy(m_NICAddr, nicaddr, sizeof(NICAddr));
}
void CNIC::SetMACAddr(uint8_t *mac)
{
    memcpy(m_MACAddress, mac, 6);
}

// 변경된 것 있으면 1
// 변경된 것 없으면 0
// 디바이스를 찾을 수 없으면 -1
int CNIC::Refresh()
{
    bool ret = 0;
    struct ifreq ifrq;
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    // MAC 주소 셋팅
    memcpy(&ifrq.ifr_name, m_NICName, NIC_NAME_MAXLENGTH);
    if(ioctl(sockfd, SIOCGIFHWADDR, (char *)&ifrq) < 0)
    {
        // ENODEV(19): 해당 디바이스 없음
        // pcap으로 찾은 dev지만 ioctl결과 해당 디바이스를 찾을 수 없다고 나옴 제외
        if(errno == 19)
        {
            fprintf(stderr, "Error: %sioctl SIOCGIFHWADDR error, errno:%d\n",ifrq.ifr_name , errno);
            return -1;
        }
    }
    else
    {
        // 맥주소 변환 확인
        SetMACAddr((uint8_t *)ifrq.ifr_hwaddr.sa_data);
    }

    // NICAddr 없으면 생성
    if(m_NICAddr == NULL)
    {
        ret = 1;
        m_NICAddr = new NICAddr;
        memset(m_NICAddr, 0, sizeof(NICAddr));
        m_NICAddr->familly = AF_INET;
    }

    // IP 주소
    if(ioctl(sockfd, SIOCGIFADDR, (char *)&ifrq) < 0)
    {
        if(errno == 19)
        {
            fprintf(stderr, "Error: %sioctl SIOCGIFADDR error, errno:%d\n",ifrq.ifr_name , errno);
            return -1;
        }
    }
    else
    {
        // IP 주소 변환 확인
        uint32_t ip = ((struct sockaddr_in *)&ifrq.ifr_addr)->sin_addr.s_addr;
        if(m_NICAddr->ipaddr != ip)
        {
            ret = 1;
            m_NICAddr->ipaddr = ip;
        }
    }

    // Netmask
    if(ioctl(sockfd, SIOCGIFNETMASK, (char *)&ifrq) < 0)
    {
        if(errno == 19)
        {
            fprintf(stderr, "Error: %sioctl SIOCGIFNETMASK error, errno:%d\n",ifrq.ifr_name , errno);
            return -1;
        }
    }
    else
    {
        // 넷마스크 변환 확인
        uint32_t netmask = ((struct sockaddr_in *)&ifrq.ifr_addr)->sin_addr.s_addr;
        if(m_NICAddr->netmask != netmask)
        {
            ret = 1;
            m_NICAddr->netmask = netmask;
        }
    }

    return ret;
}

void CNIC::StartCapture()
{
    
}

void CNIC::EndCapture()
{

}

NICInfo CNIC::ToNICInfo()
{
    NICInfo nicinfo;
    memcpy(nicinfo.nicname, m_NICName, NIC_NAME_MAXLENGTH);
    memcpy(nicinfo.nicmac, m_MACAddress, 6);
    if(m_NICAddr != NULL)
        nicinfo.nicip = m_NICAddr->ipaddr;
    else
        nicinfo.nicip = 0;

    return nicinfo;
}

//==============================================
// niclist
// 생성자
CNICList::CNICList()
{

}

// 소멸자
CNICList::~CNICList()
{

}

// PushBack
// @ nic: 삽입 대상
void CNICList::PushBack(CNIC& nic)
{
    m_ListHead.push_back(nic);
}

void CNICList::InsertItem(int index, CNIC& nic)
{

}

int CNICList::GetListSize()
{
    return m_ListHead.size();
}

CNIC &CNICList::At(int index)
{
    std::list<CNIC>::iterator li = m_ListHead.begin();
    for(int i = 0; i < index; i++)
        li++;
    return *li;
}

int CNICList::AddNewNIC(char *devname, char *devdes)
{
    int sockfd = socket(AF_INET, SOCK_DGRAM , 0);
    struct ifreq ifrq;
    CNIC nictemp(devname, devdes);
    // MAC 주소 가져오기 
    memcpy(&ifrq.ifr_name, devname, NIC_NAME_MAXLENGTH);
    if(ioctl(sockfd, SIOCGIFHWADDR, (char *)&ifrq) < 0)
    {
        //ioctl 예외처리 필요
        // ENODEV: 해당 디바이스 없음
        // pcap으로 찾은 dev지만 ioctl결과 해당 디바이스를 찾을 수 없다고 나옴 제외
        if(errno == 19)
        {
            fprintf(stderr, "Error: %sioctl SIOCGIFHWADDR error, errno:%d\n",ifrq.ifr_name , errno);
            return -1;
        }
    }
    else
        nictemp.SetMACAddr((uint8_t *)ifrq.ifr_hwaddr.sa_data);
    // NICAddr 생성
    NICAddr nicaddr;
    nicaddr.familly = AF_INET;

    if(ioctl(sockfd, SIOCGIFADDR, (char *)&ifrq) < 0)
    {

    }
    else
        nicaddr.ipaddr = ((struct sockaddr_in *)&ifrq.ifr_addr)->sin_addr.s_addr;
    nicaddr.netmask = 0;
    nictemp.SetNICAddr(&nicaddr);
    // 리스트에 삽입
    m_ListHead.push_back(nictemp);
}

// 해당 MAC을 가진 NIC 찾기
int CNICList::FindNICFromMAC(uint8_t *mac)
{
    int ret, i;
    uint8_t *mactemp;
    std::list<CNIC>::iterator sli, eli;
    sli = m_ListHead.begin();
    eli = m_ListHead.end();
    for(i = 0; sli != eli; sli++, i++)
    {
        mactemp = sli->GetMACAddr();
        if(MACcmp(mactemp, mac) == 0)
            return i;
    }
    return -1;
}

// MAC 비교
// 같으면 0, 틀리면 -1 반환
int CNICList::MACcmp(uint8_t *mac1, uint8_t *mac2)
{
    for(int i = 0; i < 6; i++)
    {
        if(mac1[i] == mac2[i])
            continue;
        else
            return -1;
    }
    return 0;
}
