#pragma once

#include "pcap.h"

#define IPTOSBUFFERS	12
char* iptos(u_long in);

char* ip6tos(struct sockaddr* sockaddr, char* address, int addrlen);

