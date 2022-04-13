#define _CRT_SECURE_NO_WARNINGS

#include "Sniffer.h"

#include <iostream>
#include <string>
#include <functional>
#include <vector>

char logbuf[1024];

#define LOG(buf, ...) \
sprintf_s(buf, __VA_ARGS__); \
Sniffer::logging(buf);

function<void(const QString&)> Sniffer::logger;

int Sniffer::init() {
    pcap_if_t* alldevs;
    if (-1 == (ret_val = pcap_findalldevs(&alldevs, const_cast<char*>(errbuf)))) {
        LOG(logbuf, "Error in pcap_findalldevs: %s", errbuf);
        return -1;
    }
    for (auto d = alldevs; d != nullptr; d = d->next) {
        dev_list.push_back(*d);
    }
    return 0;
}

int Sniffer::activate() {
    /* Open the adapter */
    ad_handler = pcap_open_live(
        dev->name,  // name of the device
        65536,      // portion of the packet to capture. 
                    // 65536 grants that the whole packet will be captured on all the MACs.
        1,	        // promiscuous mode (nonzero means promiscuous)
        1000,       // read timeout
        errbuf      // error buffer
    );
    if (ad_handler == nullptr) {
        LOG(logbuf, "Unable to open the adapter. %s is not supported by WinPcap", dev->name);
        return -1;
    }
    return 0;
}

void Sniffer::packet_handler(u_char* param, const pcap_pkthdr* header, const u_char* pkt_data) {
    struct tm* ltime;
    char timestr[16];
    time_t local_tv_sec;

    /*
    * unused parameters
    */
    (VOID)(param);
    (VOID)(pkt_data);

    /* convert the timestamp to readable format */
    local_tv_sec = header->ts.tv_sec;
    ltime = localtime(&local_tv_sec);
    strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

    printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
}

inline vector<AdapterInfo> Sniffer::getAdapterInfo() {
    vector<AdapterInfo> res;
    bpf_u_int32 net;
    bpf_u_int32 mask;
    in_addr net_addr;
    in_addr mask_addr;
    for (const auto& adapter : this->dev_list) {
        pcap_lookupnet(adapter.name, &net, &mask, errbuf);
        net_addr.s_addr = net;
        mask_addr.s_addr = mask;
        res.emplace_back(adapter.name, net_addr, mask_addr, adapter.description);
    }
    return res;
}

void Sniffer::showAdapters(bool detail) {
    const auto adapters = this->getAdapterInfo();
    for (int i = 0; i < adapters.size(); i++) {
        const auto& adapter = adapters[i];
        LOG(logbuf, "%d. %s(%s)", i, adapters[i].name.data(), adapter.description.data());
        const auto addrsInfo = getAddressInfo(i);
        for (const auto& addrInfo : addrsInfo) {
            addrInfo.show();
        }
    }
}

inline vector<AddressInfo> Sniffer::getAddressInfo(uint32_t idx) {
    vector<AddressInfo> res;
    for (auto a = this->dev_list[idx].addresses; a != nullptr; a = a->next) {
        res.push_back(AddressInfo(a));
    }
    return res;
}

inline AddressInfo::AddressInfo(pcap_addr* addr) {
    pcap_addr_t* a = addr;
    this->family = a->addr->sa_family;
    switch (a->addr->sa_family)
    {
    case AF_INET:
        if (a->addr)
            this->addr = ((sockaddr_in*)a->addr)->sin_addr.s_addr;
        if (a->netmask)
            this->netmask = ((sockaddr_in*)a->netmask)->sin_addr.s_addr;
        if (a->broadaddr)
            this->broad_addr = ((sockaddr_in*)a->broadaddr)->sin_addr.s_addr;
        if (a->dstaddr)
            this->dst_addr = ((sockaddr_in*)a->dstaddr)->sin_addr.s_addr;
        break;
    case AF_INET6:
        if (a->addr)
            this->ipv6Addr = *a->addr;
        break;
    default:
        LOG(logbuf, "\tAddress Family Name: Unknown");
        break;
    }
}

inline void AddressInfo::show() const {
    char ip6str[128];
    switch (family)
    {
    case AF_INET:
        LOG(logbuf, "\tAddress Family Name: AF_INET");

        LOG(logbuf, "\tAddress Family Name: AF_INET");
        LOG(logbuf, "\tAddress: %s", iptos(this->addr));
        LOG(logbuf, "\tNetmask: %s", iptos(this->netmask));
        LOG(logbuf, "\tBroadcast Address: %s", iptos(this->broad_addr));
        LOG(logbuf, "\tDestination Address: %s", iptos(this->dst_addr));
        break;
    case AF_INET6:
        LOG(logbuf, "\tAddress Family Name: AF_INET6");
        LOG(logbuf, "\tAddress: %s",
            ip6tos(const_cast<sockaddr*>(&this->ipv6Addr), ip6str, sizeof(ip6str)));
        break;
    default:
        break;
    }
}
