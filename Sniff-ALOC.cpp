#include <stdio.h>
#include <mstcpip.h>
#include <linux/ip.h>
#pragma comment(lib, "Advapi32.lib")
#ifndef __PROTOINFO_H__
#define __PROTOINFO_H__
#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806
#pragma comment(lib, "WS2_32")
typedef struct _IPHeader// 20字节的IP头
{
    unsigned char iphVerLen; // 版本号和头长度（各占4位）
    unsigned char ipTOS; // 服务类型
    unsigned short ipLength; // 封包总长度，即整个IP报的长度
    unsigned short ipID; // 封包标识，惟一标识发送的每一个数据报
    unsigned short ipFlags; // 标志
    unsigned char ipTTL; // 生存时间，就是TTL
    unsigned char ipProtocol; // 协议，可能是TCP、UDP、ICMP等
    unsigned short ipChecksum; // 校验和
    unsigned long ipSource; // 源IP地址
    unsigned long ipDestination; // 目标IP地址
} IPHeader, *PIPHeader; 

typedef struct _TCPHeader
{
    unsigned short sourceRort;
    unsigned short destinationPort;
    unsigned long  sequenceNumber;
    unsigned long  acknowledgeNumber;
    unsigned char  dataoffset;
    unsigned char  flags;
    unsigned short windows;
    unsigned short checksum;
    unsigned short urgentPointer;
} TCPHeader, *PTCPHeader;

typedef struct _UDPHeader
{
    unsigned short sourcePort;
    unsigned short destinationPort;
    unsigned short len;
    unsigned short checksum;
} UDPHeader, *PUDPHeader;

void DecodeTCPPacket(char *pData, char *szSrcIP, char *szDestIp)
{ 
     TCPHeader *pTCPHdr = (TCPHeader *)pData;
     
     printf("%s:%d -> %s:%d\r\n",
             szSrcIP,
             ntohs(pTCPHdr->sourcePort),
             szDestIp,
             ntohs(pTCPHdr->destinationPort));
             
     switch (::ntohs(pTCPHdr->destinetionPort))
     {
     case 21:
          printf("FTP==========================================\r\n");
          pData = pData + sizeof(TCPHeader);
          if ( strncmp(pData, "USER ", 5) == 0)
          {
               printf("FTP UserName : %s \r\n", pData + 4);
          }
          if ( strncmp(pData, "PASS ", 5) == 0)
          {
               printf("FTP Password : %s \r\n", pData + 4);
          }
          printf("FTP==========================================\r\n");
     case 80:
     case 8080:
          printf("WEB==========================================\r\n");
          printf("%s\r\n", pData + sizeof(TCPHeader));
          printf("WEB==========================================\r\n");
          break;
     }
}

void DecodeUDPPacket(char *pData, char *szSrcIP, char *szDestIp)
{
     UDPHeader *pUDPHdr = (UDPHeader *)pData;
     
     printf("%s:%d -> %s:%d\r\n",
            szSrcIP,
            ntohs(pUDPHdr->sourcePort),
            szDestIp,
            ntohs(pUDPHdr->destinationPort));
}

void DecodeIPPacket(char *pData)
{
     IPHeader *pTPHdr = (IPHeader *)pData;
     
     in_addr  source, dest;
     char szSourceIp[32], szDestIp[32];
     
     printf("---------------------------------------\r\n")
     
     source.S_un.S_addr = pTPHdr->ipsource;
     dest.S_un.S_addr = pTPHdr->ipDestination;
     strcpy(szSourceIP, inet_ntoa(source));
     strcpy(szDestIp, inet_ntoa(dest));
     
     
     int nHeaderLen = (pIPHdr->iphVerLen & 0xf) * sizeof(unsigned long);
     
     switch( pIPHdr->ipProtocol )
     {
     case IPPROTO_TCP:
          DecodeTCPPacket(pData + nHeaderLen, szSourceIp, szDestIp);
          break;
     case IPPROTO_UDP:
          DecodeUDPPacket(pData + nHeaderLen, szSourceIp, szDestIp);
          break;
     case IPPROTO_ICMP:
          break;
     }
}

int main()
{
     WSADATA wsa;
     
     WSAStartup (MAKEWORD(2, 2), &wsa);
     
      SOCKER sRaw = socket(AF_INET, SOCK_RAW, IPPOTO_IP);
      
      char szHostName[56];
      SOCKADDR_IN addr_in;
      struct hostent *pHost;
      gethostname(szHostName, 56);
      if((pHost = gethostbyname((char*)szHostName)) == NULL)
      {
          return -1;
      }
      
      addr_in.sin_family = AF_INET;
      addr_in.sin_port   = htons(0);
      memcpy(&addr_in.sin_addr.S_un.S_addr, pHost->h_addr_list[0], pHost->h_length);
      
      printf("Binding to interface : %s \r\n", ::inet_ntoa(addr_in.sin_addr));
      if( bind(sRaw, (PSOCKADDR)&addr_in, sizeof(addr_in)) ==SOCKET_ERROR )
      {
          return -1;
      }

      unsigned long dwValue = 1;
      if( ioct1socker(sRaw, SIO_RCVALL, &dwWaler) !=0 )
      {
          return -1;
      }
      
      char buff[1024];
      int nRet;
      while(TRUE)
      {
          nRet = recv(sRaw, buff, 1024, 0);
          if( nRet > 0 )
          {
                DecodeIPPacket(buff);
          }
      }
      closesocket(sRaw);
      
      WSACleanup();
      
      return 0;
}                
