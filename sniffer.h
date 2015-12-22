//================================================
// sniffer with libpcap
//                   JaeMoo Han
//================================================
#ifndef __SNIFFER_H__
#define __SNIFFER_H__

#include <stdint.h>
#include <pthread.h>
#include <list>
#include <pthread.h>

#include "pmcprotocol.h"
#include "pcap.h"

#define PROMISCUOUS     1
#define NONPROMISCUOUS  0
#define PACKETBUF_SIZE  65535

typedef void(*capture_callback)(const u_char *, const u_char *, const u_char *);

struct PCapLoopParam
{
    bool *param_stop;
    pcap_t *param_pcaphandle;
};

// NIC sniffer
// NIC 리스트가 등록되면 캡처 시작
// NIC 리스트가 비워져 있으면 캡처 중지
class CSniffer
{
private:
    // pcap 캡처 핸들러
    pcap_t *m_PcapHandler;
    // Pcap 캡처에 필요한 디바이스 이름과, 넷마스크
    // SnifferInfo
    char m_DevName[16];
    uint8_t m_MACAddr[6];
    uint32_t m_Netmask;
    ////
    // Error Buf
    char m_ErrBuf[PCAP_ERRBUF_SIZE];

public:
    // 캡처 시작(pcap_open_live)
    int StartCapture(); //, uint8_t *param, capture_callback callback );
    // 캡처 정지(pcap_close)
    void StopCapture();
    uint32_t GetNextPacket(uint8_t *data, struct pcap_pkthdr *pkt_hdr);
    // 캡처된 다음 패킷 가져오기(pcap_next)
    pcap_t *GetPcapHandler() { return m_PcapHandler; }
    char *GetDevName() { return m_DevName; }

    CSniffer();
    CSniffer(CSniffer const &sniffer);
    CSniffer(char *devname, uint8_t *MACAddr, uint32_t netmask);
    ~CSniffer();
};

// 캡처 루프
// 스니퍼가 등록되면 해당 스니퍼에서 패킷을 받아 
class CCaptureLoop
{
private:
    // thread
    pthread_t m_CaptureSenderThread;
    std::list<CSniffer> m_SnifferList;
    int m_SnifferNum;
    bool m_IsStop;
    pthread_mutex_t m_CaptureMutex;
    pthread_cond_t m_CaptureCond;

    std::list<CSniffer> m_RemoveSnifferList;
public:
    // 캡처 스레드 생성
    int CreateCaptureThread();
    // 캡처 스레드 종료
    void StopCaptureThread();
    // 캡처 루프
    // 캡처 루프는 등록된 Sniffer 리스트에서 캡처된 패킷을 받아
    // PManager의 데이터 포트로 전송한다.
    static void *CaptureLoop(void *data);
    // Sniffer 생성
    // 성공 시 0 반환
    // 이미 스니퍼가 있다면 1반환
    // 스니퍼 생성에 실패 시 -1 반환
    int CreateSniffer(char *devname, uint8_t *macaddr, uint32_t netmask);
    // 스니퍼 제거
    // 제거 성공시 1반환
    // 등록되지 않은 스니퍼일 경우 1반환
    int RemoveSniffer(char *devname, int namelen);

    // Get Member Pointer
    bool *GetIsStopPtr() { return &m_IsStop; }
    int *GetSnifferNumPtr() { return &m_SnifferNum; }
    std::list<CSniffer> *GetSnifferListPtr() {return &m_SnifferList; }
    std::list<CSniffer> *GetRemoveSnifferListPtr() {return &m_RemoveSnifferList; }
    pthread_mutex_t *GetCaptureMutexPtr() { return &m_CaptureMutex; }
    pthread_cond_t *GetCaptureCondPtr() { return &m_CaptureCond; }

    CCaptureLoop();
    ~CCaptureLoop();
};

// Capture Loop 전역 변수
extern CCaptureLoop g_SnifferLoop;

#endif // __SNIFFER_H__
