 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <unistd.h>
 #include <sys/socket.h>
 #include <arpa/inet.h>
 #include <netinet/in.h>
 #include <netinet/ip_icmp.h>
 #include <sys/time.h>
 
 /* icmp报文长度 */
 #define ICMP_PACKET_LEN sizeof(struct icmp)
 
 void err_exit(const char *err_msg)
 {
     perror(err_msg);
     exit(1);
 }
 
 /* 校验和 */
 unsigned short check_sum(unsigned short *addr, int len)
 {
     int nleft = len;
     int sum = 0;
     unsigned short *w = addr;
     unsigned short answer = 0;
 
     while(nleft > 1)
     {
         sum += *w++;
         nleft -= 2;
     }
     if(nleft == 1)
     {
         *(unsigned char *)(&answer) = *(unsigned char *)w;
         sum += answer;
     }
 
     sum = (sum >> 16) + (sum & 0xffff);
     sum += (sum >> 16);
     answer = ~sum;
 
     return answer;
 }
 
 /* 填充icmp报文 */
 struct icmp *fill_icmp_packet(int icmp_type, int icmp_sequ)
 {
     struct icmp *icmp_packet;
 
     icmp_packet = (struct icmp *)malloc(ICMP_PACKET_LEN);
     icmp_packet->icmp_type = ICMP_ECHOREPLY;
     icmp_packet->icmp_code = 0;
     icmp_packet->icmp_cksum = 0;
     icmp_packet->icmp_id = htons(getpid());
     icmp_packet->icmp_seq = icmp_sequ;
     /* 发送时间 */
     gettimeofday((struct timeval *)icmp_packet->icmp_data, NULL);
     /* 校验和 */
     icmp_packet->icmp_cksum = check_sum((unsigned short *)icmp_packet, ICMP_PACKET_LEN);
  
      return icmp_packet;
  }
  
  /* 发送icmp请求 */
  void icmp_request(const char *dst_ip, int icmp_type, int icmp_sequ)
  {
      struct sockaddr_in dst_addr;
      struct icmp *icmp_packet;
      int sockfd, ret_len;
      char buf[ICMP_PACKET_LEN];
  
      /* 请求的地址 */
      bzero(&dst_addr, sizeof(struct sockaddr_in));
      dst_addr.sin_family = AF_INET;
      dst_addr.sin_addr.s_addr = inet_addr(dst_ip);
  
      if ((sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1)
          err_exit("sockfd()");
  
      /* icmp包 */
      icmp_packet = fill_icmp_packet(icmp_type, icmp_sequ);
      memcpy(buf, icmp_packet, ICMP_PACKET_LEN);
  
      /* 发送请求 */
      ret_len = sendto(sockfd, buf, ICMP_PACKET_LEN, 0, (struct sockaddr *)&dst_addr, sizeof(struct sockaddr_in));
     if (ret_len > 0)
         printf("sendto() ok!!!\n");
 
     close(sockfd);
 }
 
 int main(int argc, const char *argv[])
 {
     if (argc != 2)
     {
         printf("usage:%s dst_ip\n", argv[0]);
         exit(1);
     }
 
     /* 发送icmp请求 */
     icmp_request(argv[1], 8, 1);
 
     return 0;
 }
