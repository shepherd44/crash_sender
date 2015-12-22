#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <net/if.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <exception>
#include <iostream>
#include <errno.h>
#include <arpa/inet.h>

#include "sniffer.h"
#include "probe.h"
#include "pmanager.h"
#include "pmcprotocol.h"
#include "pcap.h"

//==========================================
//CProbe
CProbe pea;

CProbe::CProbe()
{
    m_ProbeState = BEGIN;

}

CProbe::~CProbe()
{

}

void CProbe::ExcuteCommand(char *cmd)
{
    PMCMessage *pmcmsg = (PMCMessage*)cmd;
    switch(pmcmsg->opcode)
    {
        case CONNECT:
            printf("[Command] recv connect message\n");
            // 데이터 포트 연결
            if(CPManager::Instance().ConnectData() < 0)
            {
                // 연결 실패 메시지 전송
                printf("DataConnect Error\n");
                
            }
            // 연결이 되지 않으면 에러 코드 전송
            // 연결된 후 NIC 정보 보내기
            SendNICInfo();
            break;
        case DISCONNECT:
            printf("[Command] recv disconnect message\n");
            // 데이터 포트 연결 해제
            CPManager::Instance().DisconnectData();
            // Probe Stop 메시지 전송
            EndProbe();
            // 커맨드 포트 연결 해제
            CPManager::Instance().DisconnectCommand();
            break;
        //case REFRESH:
            //printf("[Command] recv Refresh message\n");
            //printf("          this Command is not valid command\n");
            //break;
        case CAPTURE_START:
            printf("[Command] recv capture start message\n");
            // 캡처 시작
            StartCapture(cmd);
            break;
        case CAPTURE_STOP:
            printf("[Command] recv stop message\n");
            //캡처 정지
            EndCapture(cmd);
            break;
        default:
            printf("[Command] recv unkown message\n");
            break;
    }
}
// Net Device 찾기
// 주소까지 찾아서 채워넣음.
int CProbe::FindNetDevice()
{
    pcap_if_t *alldevs;
    pcap_if_t *nextdev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_addr_t *pcapaddr;
    int sockfd;
    struct ifreq ifrq;

    // pcap 이용 NIC 찾기
    if(pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr, "[PCAP Error] fail pcap_findalldevs: %s\n", errbuf);
        return -1;
    }

    // list에 디바이스 정보 채우기
    // 정보 채우기 전에 내부에 존재하는 디바이스 리스트 확인
    // any=모든 NIC에게서 패킷 받기(해당 이름은 생략)
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    int ret;
    for(nextdev = alldevs ; nextdev != NULL ; nextdev = nextdev->next)
    {
        if((strncmp(nextdev->name, "any", strlen(nextdev->name)) == 0) ||
           (strncmp(nextdev->name, "lo" , strlen(nextdev->name)) == 0))
        {
            continue;
        }
        // CNIC 생성
        CNIC nictemp(nextdev->name, nextdev->description);
        ret = nictemp.Refresh();
        // ret == -1 -> 해당 이름의 디바이스를 찾을 수 없음
        if(ret == -1)
            continue;
        // 리스트에 삽입
        m_NICList.PushBack(nictemp);
    }

    return 0;
}


int CProbe::Refresh()
{
    bool issend = false;
    // pcap으로 이더넷 목록 새로 받기
    pcap_if_t *alldevs;
    pcap_if_t *nextdev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_addr_t *pcapaddr;
    int sockfd;
    struct ifreq ifrq;

    // pcap 이용 NIC 찾기
    if(pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr, "[pcap Error]: fail pcap_findalldevs: %s\n", errbuf);
        return -1;
    }

    // 목록 비교
    int nicnum = m_NICList.GetListSize();
    int i;
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    for(nextdev = alldevs ; nextdev != NULL ; nextdev = nextdev->next)
    {
        // 찾은 dev가 리스트에 있는지 확인
        for(i = 0; i < nicnum; i++)
        {
           NICInfo nicinfo =  m_NICList.At(i).ToNICInfo();
           if(strncmp((char*)nicinfo.nicname, nextdev->name, strlen(nextdev->name)) != 0)
               continue;
        }
        // 리스트 안에 해당 디바이스 네임 없으므로 새로 추가
        if(i == nicnum)
        {
            CNIC nictemp(nextdev->name, nextdev->description);
            nictemp.Refresh();
            // 리스트에 삽입
            m_NICList.PushBack(nictemp);
            issend = true;
        }
        // 있다면 ip주소 갱신
        else
        {
            int ret = m_NICList.At(i).Refresh();
            if(ret == 1)
                issend = true;
        }
    }
    // 갱신 되었다면 전송
    if(issend)
    {
       SendNICInfo(); 
    }
    return 0;
}

void CProbe::SendNICInfo()
{
    uint8_t *message;
    int packetsize;
    int nicnum = m_NICList.GetListSize();
    NICInfo *nicinfo, *nicptr;
    nicinfo = new NICInfo[nicnum];
    packetsize = sizeof(PMCMessage) + (nicnum * sizeof(NICInfo));
    message = new uint8_t[packetsize];

    // 패킷 헤더 셋팅
    PMCMessage *temp = (PMCMessage *)message;
    temp->datalen = htons(nicnum * sizeof(NICInfo));
    temp->opcode = REFRESH;
    temp->flags = 0 | FLAG_SENDER_PROBE;
    // NICInfo 셋팅
    nicptr = (NICInfo*)(message +sizeof(PMCMessage));
    for(int i = 0; i < nicnum ; i++)
    {
        NICInfo nictemp = m_NICList.At(i).ToNICInfo();
        memcpy(nicptr + i, &nictemp, sizeof(NICInfo));
    }

    // NIC Info 전송
    CPManager::Instance().SendMessage((char*)message, packetsize);
    delete []nicinfo;
    delete []message;
}

void CProbe::StartCapture(char *cmd)
{
    // NIC 확인
    int nicnum, ret;
    PMCMessage *message = (PMCMessage *)cmd;
    uint8_t *data;
    int datalen = ntohs(message->datalen);
    if(datalen == 0)
        return;
    else
    {
        data = (uint8_t*)(cmd + sizeof(PMCMessage));
        printf("data:");
        for(int i=0;i<6;i++)
            printf("%02x ", data[i]);
        printf("\n");
        nicnum = datalen / 6;
        printf("nicnum: %d\n", nicnum);
    }   

    // 받은 MAC주소의 NIC을 확인하고 스니퍼 생성
    for(int i = 0; i < nicnum; i++)
    {
        int nicindex = m_NICList.FindNICFromMAC(data);
        if(nicindex != -1)
        {
            CNIC &nictemp = m_NICList.At(nicindex);
            // sniffer 생성
            ret = g_SnifferLoop.CreateSniffer(nictemp.GetNICName(), nictemp.GetMACAddr(), nictemp.GetNICAddr()->netmask);
            // 이미 sniffer가 존재함
            if(ret == 1)
            {
                printf("[Command] Sniffer already exist: %s\n", nictemp.GetNICName());
                break;
            }
            // 스니퍼 생성 실패(현재는 없는 경우)
            else if(ret == -1)
            {
                printf("[Command] Create Sniffer Fail: %s\n", nictemp.GetNICName());
                break;
            }
            // 스니퍼 생성 성공
            else if(ret == 0)
            {
                printf("[Command] Create Sniffer: %s\n", nictemp.GetNICName());
                break;
            }
        }
        // NIC 정보에 존재하지 않는 맥주소를 받을 경우
        else
            printf("[Command] unkown MACAddress\n");
    }
}

void CProbe::EndCapture(char *cmd)
{
    int nicnum, ret;
    PMCMessage *message = (PMCMessage *)cmd;
    uint8_t *data;
    int datalen = ntohs(message->datalen);
    if(datalen == 0)
        return;
    else
    {
        data = (uint8_t*)(cmd + sizeof(PMCMessage));
        nicnum = datalen / 6;
    }   

    // 받은 MAC주소의 NIC을 확인하고 스니퍼 생성
    for(int i = 0; i < nicnum; i++)
    {
        int nicindex = m_NICList.FindNICFromMAC(data);
        if(nicindex != -1)
        {
            CNIC &nictemp = m_NICList.At(nicindex);
            // sniffer 생성
            ret = g_SnifferLoop.RemoveSniffer(nictemp.GetNICName(), strlen(nictemp.GetNICName()));
            if(ret == -1)
            {
                printf("[Command] Remove Sniffer Fail: %s\n", nictemp.GetNICName());
                break;
            }
            else if(ret == 0)
            {
                printf("[Command] Remove Sniffer: %s\n", nictemp.GetNICName());
                break;
            }
        }
        else
            printf("[Command] unkown MACAddress\n");
    }
}

void CProbe::StartProbe()
{   
    // PManager에게 Probe 시작 했다는 메시지 전달
    PMCMessage pmcmsg;
    pmcmsg.opcode = CONNECT;
    pmcmsg.datalen = 0;
    pmcmsg.flags = (0 | FLAG_SENDER_PROBE);

    CPManager::Instance().SendMessage((char*)&pmcmsg, sizeof(PMCMessage));
}

void CProbe::EndProbe()
{
    // PManager에게 Probe가 정지한다는 메시지 전달
    PMCMessage pmcmsg;
    pmcmsg.opcode = DISCONNECT;
    pmcmsg.datalen = 0;
    pmcmsg.flags = (0 | FLAG_SENDER_PROBE );
    CPManager::Instance().SendMessage((char*)&pmcmsg, sizeof(PMCMessage));
}
