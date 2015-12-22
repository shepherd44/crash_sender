#include <stdint.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <list>
#include "sniffer.h"
#include "pmanager.h"


CSniffer::CSniffer()
{
    m_PcapHandler = NULL;
    memset(m_ErrBuf, '\0', PCAP_ERRBUF_SIZE);
    memset(m_DevName, '\0', 16);
    memset(m_MACAddr, 0, 6);
    m_Netmask = 0;
}
CSniffer::CSniffer(CSniffer const &sniffer)
{
    m_PcapHandler = sniffer.m_PcapHandler;
    memset(m_ErrBuf, '\0', PCAP_ERRBUF_SIZE);
    memcpy(m_DevName, sniffer.m_DevName, 16);
    memcpy(m_MACAddr, sniffer.m_MACAddr, 6);
    m_Netmask = sniffer.m_Netmask; 
}

CSniffer::CSniffer(char *devname, uint8_t *macaddr, uint32_t netmask)
{
    m_PcapHandler = NULL;
    memcpy(m_DevName, devname, sizeof(NICInfo));
    memcpy(m_MACAddr, macaddr, 6);
    m_Netmask = netmask;
    memset(m_ErrBuf, '\0', PCAP_ERRBUF_SIZE);
}

CSniffer::~CSniffer()
{
//    if(m_PcapHandler != NULL)
//        StopCapture();
}

int CSniffer::StartCapture()
{
    // pcap_open -> pcap_compile -> pcap_setfilter
    // 위 과정을 진행하면 캡처 시작
    // filter는 모든 패킷을 받기 위해 ""으로 셋팅
    struct bpf_program fp;
    char *filter = (char*)"not (port 11112)";

    if(m_PcapHandler == NULL)
    {
        m_PcapHandler = pcap_open_live(m_DevName, PACKETBUF_SIZE, PROMISCUOUS, -1, m_ErrBuf );
    }
    else
    {
        fprintf(stderr, "Sniffer Error: already exist pcap handler\n");
        return -1;
    }
    //m_PcapHandler = pcap_open_live("eth1", PACKETBUF_SIZE, PROMISCUOUS, -1, m_ErrBuf );
    if(m_PcapHandler == NULL)
    {
        fprintf(stderr, "PCAP Error: %s\n", m_ErrBuf);
        return -1;
    }

    if(pcap_compile(m_PcapHandler, &fp, filter, 0, m_Netmask) == -1) 
    {
        fprintf(stderr, "PCAP Error: compile\n");
        return -1;
    }

    if(pcap_setfilter(m_PcapHandler, &fp) == -1)
    {
        fprintf(stderr, "PCAP_Error: setfileter\n");
        return -1;
    }
    //pcap_freecode(&fp);
}

void CSniffer::StopCapture()
{
    // pcap_close를 통해 핸들 삭제로 캡처 종료
    if(m_PcapHandler != NULL)
    {
        pcap_close(m_PcapHandler);
        m_PcapHandler = NULL;
    }

}

uint32_t CSniffer::GetNextPacket(uint8_t *data, struct pcap_pkthdr *pkt_hdr)
{
    uint8_t *temp = (uint8_t*)pcap_next(m_PcapHandler, pkt_hdr);
    if(temp == NULL)
    {
        return 0;
    }
    else
    {
        memcpy(data, (char *)m_MACAddr, 6);
        memcpy(data + 6, (char *)pkt_hdr, sizeof(struct pcap_pkthdr));
        memcpy(data + 6 + sizeof(struct pcap_pkthdr), temp, pkt_hdr->len);
        return pkt_hdr->len;
    }
}


//-----------------------------------------------
// CCaptureLoop

CCaptureLoop g_SnifferLoop;

CCaptureLoop::CCaptureLoop()
{
    // mutex 생성
    pthread_mutex_init(&m_CaptureMutex, NULL);
    pthread_cond_init(&m_CaptureCond, NULL);

    m_CaptureSenderThread = NULL;
    m_SnifferNum = 0;
    m_IsStop = false;
}

CCaptureLoop::~CCaptureLoop()
{
    // mutex 해제
    pthread_mutex_destroy(&m_CaptureMutex);
    pthread_cond_destroy(&m_CaptureCond);

}

int CCaptureLoop::CreateCaptureThread()
{
    int tid;
    // 스레드 생성
    m_IsStop = false;
    tid = pthread_create(&m_CaptureSenderThread, NULL, CaptureLoop, (void *)this);
    if(tid < 0)
    {
        fprintf(stderr, "Error: capture thread create fail,errno: %d\n", errno);
        return -1;
    }
}

void CCaptureLoop::StopCaptureThread()
{
    int status;
    // 캡처 스레드 정지
    m_IsStop = true;
    pthread_cond_signal(&m_CaptureCond);
    sleep(0);
    // Sniffer thread 종료 기다리기
    pthread_join(m_CaptureSenderThread, (void **)&status);
}

// static CaptureLoop()
// 캡처 루프 함수
// @data: 파라미터
void *CCaptureLoop::CaptureLoop(void *data)
{
    // 파라미터
    CCaptureLoop *caploop = (CCaptureLoop *)data;
    pthread_mutex_t *mlock = caploop->GetCaptureMutexPtr();
    pthread_cond_t *mcond = caploop->GetCaptureCondPtr();
    bool *stopptr = caploop->GetIsStopPtr();
    int *sniffernum = caploop->GetSnifferNumPtr();
    std::list<CSniffer> *snifferlist = caploop->GetSnifferListPtr();
    std::list<CSniffer> *removesnifferlist = caploop->GetRemoveSnifferListPtr();

    printf("[Capture Thread] Start Capture Loop\n");
    std::list<CSniffer>::iterator sli, eli;

    uint8_t packet[3000];
    struct pcap_pkthdr h;
    uint32_t ret;
    // 캡처 루프 시작
    while(*stopptr == false)
    {
        // Remove Sniffer List에 Sniffer 제거
        sli = removesnifferlist->begin();
        eli = removesnifferlist->end();
        for(;sli != eli; sli = removesnifferlist->begin())
        {
            sli->StopCapture();
            removesnifferlist->pop_front();
        }

        // 캡처 락
        printf("sniffer num : %d \n", *sniffernum);
        printf("[Capture Loop] Lock\n");
        pthread_cond_wait(mcond, mlock);
        printf("[Capture Loop] UnLock\n");
        // 캡처 뮤텍스로 Capture start 명령을 받으면 시작
        if(*stopptr)
            break;
        
        // 캡처 시작
        int i=0;
        while(*sniffernum > 0)
        {
            if(*stopptr)
            {
                printf("stopptr\n");
                break;
            }
            sli = snifferlist->begin();
            eli = snifferlist->end();
            if(sli == eli)
            {
                printf("empty sniffer\n", h.len + 30);
                break;
            }
            for(int i = 0; i < *sniffernum ; i++)
            {
                ret = sli->GetNextPacket((uint8_t*)packet, &h);
                if(ret == 0)
                    continue;
                //for(uint32_t i=30;i<(h.len + 30);i++)
                //{
                    //if(i%10 == 0)
                        //printf("\n");
                    //printf("%02d ", packet[i]);
                //}
                //printf("\n");
                //printf("SendData: len: %d\n", h.len + 30);
                CPManager::Instance().SendData((char *)packet, h.len + 30);
            }
        }
    }
    printf("[Capture Thread] End Capture Loop\n");
    return NULL;
}

int CCaptureLoop::CreateSniffer(char *devname, uint8_t *macaddr, uint32_t netmask)
{
    // devname의 스니퍼가 존재하는지 검색
    std::list<CSniffer>::iterator sli = m_SnifferList.begin();
    std::list<CSniffer>::iterator eli = m_SnifferList.end();
    for(; sli != eli ; sli++)
    {
        if(strncmp(sli->GetDevName(), devname, strlen(devname)) == 0)
            return 1;
    }
    // 스니퍼 생성
    CSniffer sniffer(devname, macaddr, netmask);
    // 스니퍼 리스트에 등록
    m_SnifferList.push_back(sniffer);
    m_SnifferNum = m_SnifferList.size();
    m_SnifferList.back().StartCapture();
    // 락 해제(Mutex signal 신호)
    pthread_cond_signal(&m_CaptureCond);
    return 0;
}

int CCaptureLoop::RemoveSniffer(char *devname, int namelen)
{
    if(namelen > 16)
        return -1;
    std::list<CSniffer>::iterator sli = m_SnifferList.begin();
    std::list<CSniffer>::iterator eli = m_SnifferList.end();
    char *snifferdevname;
    // 스니퍼 이름 확인
    // 동일한 NIC이름 가지고 있으면 정지
    for(;sli != eli ; sli++)
    {
        snifferdevname = sli->GetDevName();
        if(strncmp(snifferdevname, devname, namelen)  == 0)
        {
            m_SnifferNum--;
            m_RemoveSnifferList.push_back(*sli);
            m_SnifferList.erase(sli);
            return 0;
        }
    }
}
