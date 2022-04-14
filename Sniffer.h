#pragma once

#include <pcap.h>
#undef inline

#include "Utils.h"

#include <iostream>
#include <sstream>
#include <string>
#include <functional>
#include <vector>
#include <atomic>
#include <thread>
#include <qstring.h>

#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#else
#include <winsock.h>
#endif

class Sniffer;
class AddressInfo;


using std::string;
using std::vector;
using std::ostringstream;
using std::function;


class AdapterInfo {
public:
    string name;
    in_addr addr;
    in_addr mask;
    string description;
    AdapterInfo(const string& _name, in_addr _addr, in_addr _mask, const string& _description)
        : name(_name), addr(_addr), mask(_mask), description(_description)
    {}
    string toString() {
        ostringstream ostr;
        ostr << this->name << " " << this->description;
        return ostr.str();
    }
};

class Filter {
public:
    string ip_src;
    string ip_dst;
    uint16_t port_src;
    uint16_t port_dst;
    Filter(const string& _ip_src, const string& _ip_dst,
        uint16_t _port_src, uint16_t _port_dst)
        : ip_src(_ip_src), ip_dst(_ip_dst),
        port_src(_port_src), port_dst(_port_dst)
    {}
};

class Sniffer
{
private:
    pcap_t* ad_handler;     // adapter handler, create by pcap_open_live
    pcap_if_t* dev;         // selected adapter
    pcap_if_t* alldevs;      // adapter list
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 ip;
    bpf_u_int32 netmask;
    string filter_expr;
    struct bpf_program fp;
    vector<pcap_if_t> dev_list;
    int ret_val;
    std::atomic<bool> running;
    static function<void(const QString&)> logger;
    std::shared_ptr<std::thread> cap;
public:
    Sniffer()
        : ad_handler(nullptr), dev(nullptr),
        ip(0), netmask(0), filter_expr(), fp(), ret_val(), running(false)
    {
        init();
    }
    ~Sniffer()
    {
        pcap_close(this->ad_handler);
        pcap_freealldevs(this->alldevs);
    }

    int init();

    int activate();

    int setAdapter(uint32_t idx) {
        if (idx < 0 || idx > this->dev_list.size())
            return -1;
        this->dev = &this->dev_list[idx];
        return 0;
    }

    void setFilter(const string& filter) {
        this->filter_expr = filter;
    }

    int applyFilter() {
        //int pcap_compile(
        //    pcap_t *p, 
        //    struct bpf_program *fp, 
        //    const char* str, 
        //    int optimize, 
        //    bpf_u_int32 netmask
        //);

        if ((ret_val = pcap_compile(ad_handler, &fp, filter_expr.data(), 1, netmask)) < 0) {
            fprintf(stderr, "Error compiling filter: %s: wrong syntax.\n", filter_expr.data());
            return ret_val;
        }
        if ((ret_val = pcap_setfilter(ad_handler, &fp)) < 0) {
            fprintf(stderr, "Error setting the filter: %s\n", filter_expr.data());
            return ret_val;
        }
        return ret_val;
    }

    int captureNext(pcap_pkthdr** header, const u_char** pkt_data) {
        qDebug("captureNext begin");
        ret_val = pcap_next_ex(ad_handler, header, pkt_data);
        qDebug("pcap_next_ex returned: %d", ret_val);
        qDebug("captureNext end");

        return ret_val;
    }

    int startCapture(function<void(pcap_pkthdr**, const u_char**)> cb) {
        qDebug("dev = %p", dev);

        running.store(true);
        this->cap.reset(new std::thread(
            [this, cb]() {
                qDebug("another thread begin");
                pcap_pkthdr* header;
                const u_char* pkt_data;
                while (running) {
                    if (captureNext(&header, &pkt_data) == 0)
                        continue;
                    qDebug("capture a new packet");
                    if (cb)
                        cb(&header, &pkt_data);
                }
                qDebug("another thread end");
            }
        ));
        return 0;
    }

    int stopCapture() {
        qDebug("stopCapture begin");
        running.store(false);
        if (this->cap) {
            this->cap->join();
        }
        qDebug("stopCapture end");
        return 0;
    }

    static void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);

    vector<AdapterInfo> getAdapterInfo();

    void showAdapters(bool detail = false);

    vector<AddressInfo> getAddressInfo(uint32_t idx);

    static void setLogger(function<void(const QString&)> _logger) {
        Sniffer::logger = _logger;
    }

    static void logging(const char* str) {
        if (logger)
            logger(str);
    }
};

class AddressInfo {
public:
    bool loop_back; // Loopback Address
    USHORT family;     // Address Family
    union
    {
        struct {
            u_long addr;
            u_long netmask;
            u_long broad_addr;
            u_long dst_addr;
        };
        sockaddr ipv6Addr;
    };

    AddressInfo(pcap_addr* addr);

    void show() const;
};
