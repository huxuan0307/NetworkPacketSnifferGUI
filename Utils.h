#pragma once

#include "pcap.h"

#define IPTOSBUFFERS	12
char* iptos(u_long in);

char* ip6tos(struct sockaddr* sockaddr, char* address, int addrlen);

class Time : public tm {
public:
    int tv_usec;
    Time(tm _tm, int _usec) : tm(_tm), tv_usec(_usec) {}
};

