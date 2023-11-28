#include <Winsock2.h>
#include <Windows.h>
#include <iostream>
#include <ws2tcpip.h>
#include "pcap.h"
#include "stdio.h"
#include <time.h>
#include <string>
#pragma comment(lib, "Packet.lib")
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma warning( disable : 4996 )
#define _WINSOCK_DEPRECATED_NO_WARNINGS
using namespace std;

struct EthernetFrame_t
{
    BYTE DestMAC[6];
    BYTE SrcMAC[6];
    WORD FrameType;
};

struct ARPMessage_t
{
    EthernetFrame_t EthernetFrame;
    WORD HardwareType;
    WORD ProtocolType;
    BYTE HLen;
    BYTE PLen;
    WORD Operation;
    BYTE SenderHa[6];
    DWORD SenderIP;
    BYTE TargetHa[6];
    DWORD TargetIP;
};

void printMAC(BYTE MAC[6])
{
    for (int i = 0; i < 6; i++)
    {
        if (i < 5)
            printf("%02x:", MAC[i]);
        else
            printf("%02x", MAC[i]);
    }
}

void printIP(DWORD IP)
{
    BYTE* p = (BYTE*)&IP;
    for (int i = 0; i < 3; i++)
    {
        cout << dec << (int)*p << ".";
        p++;
    }
    cout << dec << (int)*p;
}

bool setFilter(pcap_t* pcap_handle, pcap_if_t* device)
{
    u_int netmask;
    netmask = ((sockaddr_in*)(device->addresses->netmask))->sin_addr.S_un.S_addr;

    bpf_program filter;
    char packet_filter[] = "ether proto \\arp";

    if (pcap_compile(pcap_handle, &filter, packet_filter, 1, netmask) < 0)
    {
        cout << "Unable to compile packet filter." << endl;
        return false;
    }

    if (pcap_setfilter(pcap_handle, &filter) < 0)
    {
        cout << "Filter setting error." << endl;
        return false;
    }

    return true;
}

int main()
{
    pcap_if_t* all_devices;
    pcap_if_t* current_device;
    pcap_addr_t* address;
    char error_buffer[PCAP_ERRBUF_SIZE];
    ARPMessage_t arp_message;
    ARPMessage_t* received_packet;
    struct pcap_pkthdr* packet_header;
    const u_char* packet_data;

    int device_index = 0;
    DWORD sender_ip;
    DWORD target_ip;

    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &all_devices, error_buffer) == -1)
    {
        cout << "Error occurred while obtaining the network interface: " << error_buffer << endl;
        return 0;
    }

    for (current_device = all_devices; current_device != NULL; current_device = current_device->next)
    {
        cout << "Network Card " << device_index + 1 << "\t" << current_device->description << endl;
        device_index++;
    }

    int selected_device;
    cout << "Enter the number of the network card to be opened: ";
    cin >> selected_device;
    current_device = all_devices;

    for (int i = 1; i < selected_device; i++)
    {
        current_device = current_device->next;
    }

    pcap_t* pcap_handle = pcap_open(current_device->name, 1024, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, error_buffer);

    if (pcap_handle == NULL)
    {
        cout << "An error occurred while opening the network card: " << error_buffer << endl;
        return 0;
    }
    else
    {
        cout << "Successfully opened" << endl;
    }

    if (!setFilter(pcap_handle, current_device))
    {
        pcap_freealldevs(all_devices);
        return 0;
    }

    for (int i = 0; i < 6; i++)
    {
        arp_message.EthernetFrame.DestMAC[i] = 0xFF;
        arp_message.EthernetFrame.SrcMAC[i] = 0x88;
        arp_message.TargetHa[i] = 0;
        arp_message.SenderHa[i] = 0x88;
    }

    arp_message.EthernetFrame.FrameType = htons(0x0806);
    arp_message.HardwareType = htons(0x0001);
    arp_message.ProtocolType = htons(0x0800);
    arp_message.HLen = 6;
    arp_message.PLen = 4;
    arp_message.Operation = htons(0x0001);
    sender_ip = arp_message.SenderIP = htonl(0x70707070);

    for (address = current_device->addresses; address != NULL; address = address->next)
    {
        if (address->addr->sa_family == AF_INET)
        {
            target_ip = arp_message.TargetIP = inet_addr(inet_ntoa(((struct sockaddr_in*)(address->addr))->sin_addr));
        }
    }

    pcap_sendpacket(pcap_handle, (u_char*)&arp_message, sizeof(ARPMessage_t));
    cout << "ARP request sent successfully" << endl;

    while (true)
    {
        int result = pcap_next_ex(pcap_handle, &packet_header, &packet_data);

        if (result == -1)
        {
            cout << "An error occurred while capturing the packet: " << error_buffer << endl;
            return 0;
        }
        else
        {
            if (result == 0)
            {
                cout << "No datagrams captured" << endl;
            }
            else
            {
                received_packet = (ARPMessage_t*)packet_data;
                if (received_packet->TargetIP == sender_ip && received_packet->SenderIP == target_ip)
                {
                    printIP(received_packet->SenderIP);
                    cout << "->";
                    printMAC(received_packet->SenderHa);
                    cout << endl;
                    break;
                }
            }
        }
    }

    cout << "Send a packet to the network, enter the requested IP address: ";
    char requested_ip[32];
    cin >> requested_ip;
    target_ip = arp_message.TargetIP = inet_addr(requested_ip);
    sender_ip = arp_message.SenderIP = received_packet->SenderIP;

    for (int i = 0; i < 6; i++)
    {
        arp_message.SenderHa[i] = arp_message.EthernetFrame.SrcMAC[i] = received_packet->SenderHa[i];
    }

    if (pcap_sendpacket(pcap_handle, (u_char*)&arp_message, sizeof(ARPMessage_t)) != 0)
    {
        cout << "ARP request sent failure" << endl;
    }
    else
    {
        cout << "ARP request sent successfully" << endl;

        while (true)
        {
            int result = pcap_next_ex(pcap_handle, &packet_header, &packet

_data);

            if (result == -1)
            {
                cout << "An error occurred while capturing the packet: " << error_buffer << endl;
                return 0;
            }
            else
            {
                if (result == 0)
                {
                    cout << "No datagrams captured" << endl;
                }
                else
                {
                    received_packet = (ARPMessage_t*)packet_data;
                    if (received_packet->TargetIP == sender_ip && received_packet->SenderIP == target_ip)
                    {
                        cout << "The requested IP corresponds to its MAC address as follows:" << endl;
                        printIP(received_packet->SenderIP);
                        cout << "->";
                        printMAC(received_packet->SenderHa);
                        cout << endl;
                        break;
                    }
                }
                
            }


        }
    }

    pcap_freealldevs(all_devices);
}