#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "nicinfo.h"

CNICInfoList::CNICInfoList()
{
    m_ListSize = 0;
    m_ListHead = LIST_HEAD_INIT(m_ListHead);
}

CNICInfoList::~CNICInfoList()
{
    ClearList();
}

void CNICInfoList::AddItem(const char *name, const char *des, uint32_t netmask, uint32_t gatewayip, uint32_t ip, const uint8_t *mac)
{
    int len = 0;
    NICInfo *temp = new NICInfo;
    memset(temp, 0, sizeof(NICInfo));
    // 리스트에 삽입
    ListAddTail(&temp->list, &m_ListHead);

    // 값 셋팅
    len = strlen(name) + 1;
    temp->AdapterName = new char[len];
    memcpy(temp->AdapterName, name, len);

    len = strlen(des) + 1;
    temp->Description = new char[len];
    memcpy(temp->Description, des, len);

    temp->Netmask = netmask;
    temp->GatewayIPAddress = gatewayip;
    temp->NICIPAddress = ip;

    memcpy(temp->NICMACAddress, mac, MACADDRESS_LENGTH);

    // 리스트 사이즈 증가
    m_ListSize++;
}

void CNICInfoList::AddItem(const NICInfo *nicinfo)
{
    int len;
    NICInfo *temp = new NICInfo;
    memcpy(temp, nicinfo, sizeof(nicinfo));
    ListAddTail(&temp->list, &m_ListHead);
    m_ListSize++;
}

int CNICInfoList::IsInItem(const char *name)
{
    int ret = 0;
    PListHead ph = m_ListHead.next;
    NICInfo *item;
    for (; ph != &m_ListHead; ph = ph->next, ret++)
    {
        item = (NICInfo *)GET_LIST_ITEM(ph, NICInfo, list);
        if (strcmp(item->AdapterName, name) == 0)
            return ret;
    }
    return -1;
}

void CNICInfoList::RemoveItem(PListHead ph)
{
    ListDelete(ph);
    NICInfo *item = GET_LIST_ITEM(ph, NICInfo, list);
    delete(item->Description);
    delete(item->AdapterName);
    delete(item);
    m_ListSize--;
}

void CNICInfoList::ClearList()
{
    PListHead ph = m_ListHead.next;
    for (; ph != &m_ListHead; ph = m_ListHead.next)
    {
        RemoveItem(ph);
    }

}

// index는 0부터, last item index == size - 1
NICInfo* CNICInfoList::At(int index)
{
    if (index >= m_ListSize)
        return NULL;
    PListHead hp = m_ListHead.next;
    for (int i = 0; i < index; i++)
        hp = hp->next;
    return GET_LIST_ITEM(hp, NICInfo, list);
}
