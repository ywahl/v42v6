//necessary for RTD_NEXT symbol
#define _GNU_SOURCE


#include <unistd.h>
#include <stdio.h>
#include <dlfcn.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <net/if.h>
#include <stdarg.h>
#include <ctype.h>


FILE *fout = NULL;
int foutFd;
int curPid = 0;
int exiting = 0;

static int (*origSocket)(int domain, int type, int protocol);
static int (*origConnect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
static int (*origBind)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
static int (*origIoctl)(int d, unsigned long int request, ...);
static int (*origClose)(int fd);

struct map4to6 {
  unsigned long ip4;
  struct in6_addr ip6;
};

#define ETHNAME_MAX_SIZE 24

struct ethtoip {
  char ethName[ETHNAME_MAX_SIZE];
  unsigned long ip4;
};


struct map4to6 mappings[50];
struct ethtoip ioctlMappings[50];
int sz_map;
int sz_ioctl_map;


#ifndef __DEBUG__
#define FPRINTF(x, ...) 
#define FFLUSH(x)
#else
#define FPRINTF(x, ...) fprintf(x, __VA_ARGS__) 
#define FFLUSH(x) fflush(x)
#endif //__DEBUG__


int addressMapping(char *str1, char *str2, struct map4to6 *cur_map_item)
{
  char *ipv4 = str1;
  char *ipv6 = str2;

  if (ipv6 == NULL) {
    FPRINTF(fout, "no ipv6 addr for %s\n", ipv4);
    return -1;
  }

  if (inet_pton(AF_INET, ipv4, (void *)&cur_map_item->ip4) != 1) {
    FPRINTF(fout, "not valid ipv4 %s\n", ipv4);
    return -1;
  }

  if (inet_pton(AF_INET6, ipv6, (void *)&cur_map_item->ip6) != 1) {
    FPRINTF(fout, "not valid ipv4 %s\n", ipv6);
    return -1;
  }
  FPRINTF(fout, "ipv6map ip4=%lx\n", cur_map_item->ip4);
  return 0;
}

int ioctlMapping(char *str1, char *str2, struct ethtoip *cur_map_item)
{
  char *ipv4 = str2;

  if (ipv4 == NULL) {
    FPRINTF(fout, "no ipv4 addr for dev=%s\n", str1);
    return -1;
  }

  if (inet_pton(AF_INET, ipv4, (void *)&cur_map_item->ip4) != 1) {
    FPRINTF(fout, "not valid ipv4 %s\n", ipv4);
    return -1;
  }

  strncpy(cur_map_item->ethName, str1, ETHNAME_MAX_SIZE);
  FPRINTF(fout, "ioctlmap dev=%s ==> ip4=%lx\n", cur_map_item->ethName, cur_map_item->ip4);
  return 0;
}

int parseConfigFile(const char *path, struct map4to6 *map, int max)
{
  FILE *fconfig;
  fconfig = fopen(path, "r");
  if (fconfig == NULL) {
    FPRINTF(fout, "no config file found at %s\n", path);
    FFLUSH(fout);
    return -1;
  }
  char buffer[128];
  char *str1;
  char *str2;
  char *save_ptr;
  struct map4to6 *cur_map_item = map;
  struct ethtoip *cur_ioctlmap_item  = ioctlMappings;

  while(fgets(buffer, 127, fconfig) != NULL) {
    if (buffer[0] == '#')
      continue;
    str1 = strtok_r(buffer, " \n\t", &save_ptr);
    if (str1 == NULL)
      continue;
    str2 = strtok_r(NULL, " \n\t", &save_ptr);
    if (str2 == NULL)
      continue;
    if (isdigit(str1[0])) {
      if (addressMapping(str1, str2, cur_map_item) != 0)
	return -1;
      cur_map_item++;
      sz_map++;
    } else {
      if (ioctlMapping(str1, str2, cur_ioctlmap_item) != 0)
	return -1;
      cur_ioctlmap_item++;
      sz_ioctl_map++;
    }
  }
  FPRINTF(fout, "parseConfig num of mappings ip mapping=%d eth mapping=%d\n", sz_map, sz_ioctl_map++);
  FFLUSH(fout);
  return 0;
}

struct in6_addr *getMapping(struct map4to6 *map, unsigned long ip4, int size)
{
  struct map4to6 *cur_map_item = map;

  for(int i = 0; i < size; i++) {
    if (cur_map_item->ip4 == ip4)
      return &cur_map_item->ip6;
    cur_map_item++;
  }

  return NULL;
}

void fillsockaddr_in6(struct sockaddr_in6 *addr6, struct in6_addr *pip6, int port)
{
  memset(addr6, 0, sizeof(struct sockaddr_in6));
  addr6->sin6_family = AF_INET6;
  addr6->sin6_port = port;
  memcpy(&addr6->sin6_addr, pip6, sizeof(struct in6_addr));
}

int socket(int domain, int type, int protocol)
{
  int s;
  FPRINTF(fout, "socket d=%d t=%d p=%d", domain, type, protocol);
  if (domain == AF_INET)
    domain = AF_INET6;
  s = origSocket(domain, type, protocol);
  FPRINTF(fout, " returned s=%d\n", s);
  FFLUSH(fout);
  return s;
}


unsigned char ip4ip6format[] = {0x0, 0x0, 0x0, 0x0, 
			      0x0, 0x0, 0x0, 0x0,
			      0x0, 0x0, 0xff, 0xff
};

void getIp4Ip6Format(struct in6_addr *pip6, unsigned ip4_addr)
{
  unsigned char *ptr = (unsigned char *)pip6;
  memcpy(pip6, ip4ip6format, sizeof(ip4ip6format));
  unsigned *ptr_u32 = (unsigned *)(ptr + 12);
  *ptr_u32 = ip4_addr;
}


void getIp6AddrFromIp6(struct sockaddr_in6 *paddr6, const struct sockaddr_in6 *addr)
{
  char *ptr = (char *) &(addr->sin6_addr);
  //Check if it is an IP4 address encapsulated in ip6
  if (memcmp(ptr, ip4ip6format, sizeof(ip4ip6format))) {
    FPRINTF(fout, "getIp6AddrFromIp6: no need mapping real IP6 address\n");
    FFLUSH(fout);
    memcpy(paddr6, addr, sizeof(struct sockaddr_in6));
    return;
  }
  unsigned ip4_addr = *(unsigned *)(ptr + 12);
  struct in6_addr *pip6;
  struct in6_addr ip6;
  FPRINTF(fout, "getIp6AddrFromIp6: IPv4 in IPv6 format %x\n", ip4_addr);
  FFLUSH(fout);
  pip6 = getMapping(mappings, ip4_addr, sz_map);
  if (pip6 == NULL) {
    FPRINTF(fout, "no mapping for %x, default ip4 mapping\n", ip4_addr);
    FFLUSH(fout);
    pip6 = &ip6;
    getIp4Ip6Format(pip6, ip4_addr);
  }
  fillsockaddr_in6(paddr6, pip6, addr->sin6_port);
}


void getIp6Addr(struct sockaddr_in6 *paddr6, const struct sockaddr *addr)
{
  struct sockaddr_in *pAddr_in = (struct sockaddr_in*)addr;
  int port = ntohs(pAddr_in->sin_port);
  unsigned ip4_addr = pAddr_in->sin_addr.s_addr;
  FPRINTF(fout, "ipv4 connect %x %d\n", ip4_addr, port);
  struct in6_addr *pip6;
  struct in6_addr ip6;
  pip6 = getMapping(mappings, ip4_addr, sz_map);
  if (pip6 == NULL) {
    FPRINTF(fout, "no mapping for %x, default ip4 mapping\n", ip4_addr);
    FFLUSH(fout);
    pip6 = &ip6;
    getIp4Ip6Format(pip6, ip4_addr);
  }
  fillsockaddr_in6(paddr6, pip6, pAddr_in->sin_port);
}


int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
  FPRINTF(fout, "connect pid=%d s=%d len=%d\n", getpid(), sockfd, addrlen);
  if (addr->sa_family == AF_INET) {
    struct sockaddr_in6 addr6;
    getIp6Addr(&addr6, addr);
    FFLUSH(fout);
    return origConnect(sockfd, (struct sockaddr *)&addr6, sizeof(struct sockaddr_in6));
  }
  else if (addr->sa_family == AF_INET6) {
    struct sockaddr_in6 addr6;
    getIp6AddrFromIp6(&addr6, (const struct sockaddr_in6 *)addr);
    FFLUSH(fout);
    return origConnect(sockfd, (struct sockaddr *)&addr6, sizeof(struct sockaddr_in6));
  }
  FFLUSH(fout);
  return origConnect(sockfd, addr, addrlen);
}


int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
  FPRINTF(fout, "bind s=%d len=%d\n", sockfd, addrlen);
  if (addr->sa_family == AF_INET) {
    struct sockaddr_in6 addr6;
    getIp6Addr(&addr6, addr);
    return origBind(sockfd, (struct sockaddr *)&addr6, sizeof(struct sockaddr_in6));
  }
  else if (addr->sa_family == AF_INET6) {
    struct sockaddr_in6 addr6;
    getIp6AddrFromIp6(&addr6, (const struct sockaddr_in6 *)addr);
    return origBind(sockfd, (struct sockaddr *)&addr6, sizeof(struct sockaddr_in6));
  }  
  FFLUSH(fout);
  return origBind(sockfd, addr, addrlen);
}

int getIoctlAddr(const char *ifName, unsigned long *pip4)
{
  for (int i = 0; i < sz_ioctl_map; i++) {
    if (strncmp(ifName, ioctlMappings[i].ethName, ETHNAME_MAX_SIZE) == 0) {
      *pip4 = ioctlMappings[i].ip4;
      return 0;
    }
  }
  return -1;
}

int ioctl(int d, unsigned long int request, ...)
{
  va_list ap;
  void *ptr;
  va_start(ap, request);
  ptr = va_arg(ap, void *);
  va_end(ap);
  FPRINTF(fout, "ioctl call %d req=%ld\n", d, request);
  FFLUSH(fout);
  if (request == SIOCGIFADDR) {
    struct ifreq *pifr = (struct ifreq *)ptr;
    struct sockaddr_in *pAddr_in = (struct sockaddr_in *)&pifr->ifr_addr;
    if (getIoctlAddr(pifr->ifr_name, (unsigned long *) &pAddr_in->sin_addr.s_addr) != 0) {
      errno = ENODEV;
      return -1;
    }
    return 0;
  }
  return origIoctl(d, request, ptr);
}

#ifdef __DEBUG__
int close(int fd)
{
  if (fd == foutFd && !exiting) {
    int npid = getpid();
    FPRINTF(fout, "closing log file curPid=%d newPid=%d\n", curPid, npid);
    FFLUSH(fout);    
    if (curPid != npid) {
      int ret = origClose(fd);
      //most probably process forked
      //reopen new log file
      fout = fopen("/tmp/ipv4tov6.txt", "a");
      foutFd = fileno(fout);
      curPid = npid;
      FPRINTF(fout, "process forked %u openened\n", curPid);
      FFLUSH(fout);
      return ret;
    }
  }
  return origClose(fd);
}
#endif /* __DEBUG__ */

#ifndef __MAIN__

__attribute__((constructor)) void init(void) 
{
  fout = fopen("/tmp/ipv4tov6.txt", "a");
  foutFd = fileno(fout);
  curPid = getpid();
  FPRINTF(fout, "process %u openened\n", curPid);
  FFLUSH(fout);
  parseConfigFile("/etc/ip4to6.txt", mappings, 50);
  origSocket = dlsym(RTLD_NEXT, "socket");
  origConnect = dlsym(RTLD_NEXT, "connect");
  origBind = dlsym(RTLD_NEXT, "bind");
  origIoctl = dlsym(RTLD_NEXT, "ioctl");
#ifdef __DEBUG__
  origClose = dlsym(RTLD_NEXT, "close");
#endif /* __DEBUG__  */
}

__attribute__((destructor))  void fini(void) 
{
  exiting = 1;
  fclose(fout);
}

#else
int main(int argc, const char *argv[])
{
  fout = stdout;
  int ret = parseConfigFile("/etc/ip4to6.txt", mappings, 50);
  FPRINTF(fout, "AF_INET=%d\n", AF_INET);
  FPRINTF(fout, "AF_INET6=%d\n", AF_INET6);
  FPRINTF(fout, "AF_UNIX=%d\n", AF_UNIX);
  FPRINTF(fout, "PF_INIT=%d\n", PF_INET);
  FPRINTF(fout, "sizeof(sockaddr_in)=%d\n", (int)sizeof(struct sockaddr_in));
  FPRINTF(fout, "sizeof(sockaddr_in6)=%d\n", (int)sizeof(struct sockaddr_in6));
  FPRINTF(fout, "sizeof(sockaddr_un)=%d\n", (int)sizeof(struct sockaddr_un));      
  printf("ret = %d\n", ret);
  unsigned char *ip6addr = (unsigned char *)&mappings[2].ip6;
  for (int i = 0; i < sizeof(struct in6_addr); i++) {
    printf("%d %x\n", i, ip6addr[i] & 0xff);
  }
  unsigned char *ip4addr = (unsigned char *)&mappings[2].ip4;
  for (int i = 0; i < 4; i++) {
    printf("%d %x\n", i, ip4addr[i] & 0xff);
  }
  return 0;
}



#endif
