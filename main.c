#include        <sys/types.h>   /* basic system data types */
#include        <sys/socket.h>  /* basic socket definitions */
#include        <netinet/in.h>  /* sockaddr_in{} and other Internet defns */
#include        <arpa/inet.h>   /* inet(3) functions */
#include        <errno.h>
#include        <stdio.h>
#include        <stdlib.h>
#include        <string.h>
#include        <unistd.h>
#include        <time.h>
#include        <sys/select.h>
#include        <unistd.h>
#include        <fcntl.h>
#include        <netdb.h>
#include        <linux/icmp.h>
#include        <linux/errqueue.h>

#define SA      struct sockaddr
#define	BUFSIZE		1024

void fill_ports(unsigned int *ports, unsigned int n){
    for(unsigned int i = 0; i < n; ++i){
        ports[i] = i + 1;
    }
    return;
}

void scan_udp(unsigned int *ports, unsigned int n,struct sockaddr_in *target, struct timeval *timeout){

    int err, con, r; //zmienna przechowywyująca zmienną deskryptora
    fd_set recv_set, send_set;
    int send, recv, reply, ttl = 20;
    socklen_t size;
	char buffer[BUFSIZE], sendbuf[BUFSIZE];
    struct icmphdr icmph;                   /* ICMP header */
    uint16_t port = 0 ;
    int result = 0;
    //wyzerowanie struktury dopowiedzialenj za opóźnienie
    bzero(timeout, sizeof(timeout));
    timeout->tv_sec = 3;
    timeout->tv_usec = 0;

        
    if ((send = socket(AF_INET, SOCK_DGRAM, 0)) < 0)  //stworzenie socketu UDP
    {
        printf("Nie mozna utworzyc socket() send \n");
        return;
    }

    if ((recv = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)  //stworzenie socketu ICMP
    {
        printf("Nie mozna utworzyc socket() recv \n%s\n", strerror(errno));
        return;
    }

    if (setsockopt(send, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0)  //definicja time to life
    {
        printf("Could not process setsockopt().\n%s\n",strerror(errno));
        return;
    }

    printf("Skan UDP:\n");
    for(unsigned int i = 0; i < n ; ++i){
        
        bzero(&buffer, sizeof(buffer));
        bzero(&sendbuf, sizeof(sendbuf));
        bzero(&icmph, sizeof(icmph));
        port = 0;

        if(i == 0){ r = 66;}
        if(i == 1){ r = 67;}
        if(i == 2){ r = 136;}
        if(i > 2){
            r = rand() % 1023; 
            while(ports[r] == 0){
                r = rand() % 1023;
            }
        }

        target->sin_port = htons(ports[r]);

        size = sizeof(*target);

        if (sendto(send, sendbuf, sizeof(sendbuf), 0, (SA *) target, size)  < 0)
        {
            printf("Could not process sendto()\n%s\n", strerror(errno));
            return;
        }

        bzero(&send_set, sizeof(send_set));
        FD_SET(send,&send_set);


        bzero(&recv_set, sizeof(recv_set));
        FD_SET(recv,&recv_set);
        usleep(100000);

        timeout->tv_sec = 0;
        timeout->tv_usec = 500000;  

        result = select(recv + 1, &recv_set, NULL, NULL, timeout);
        
        if(result == 0){

            int re = 0;
            while(re != 8){
                if (sendto(send, sendbuf, sizeof(sendbuf), 0, (SA *) target, size)  < 0)
                {
                    printf("Could not process sendto()\n%s\n", strerror(errno));
                    return;
                }
                usleep(100000);
                timeout->tv_sec = 0;
                timeout->tv_usec = 50000;  
                result = select(recv + 1, &recv_set, NULL, NULL, timeout);
                if(result > 0){break;}
                ++re;
            }
            if(result == 0){
                printf("Port %d jest otwarty\n", ports[r]);
            }
        }else if(result < 0){
            printf("Blad funkcji select() %s", strerror(errno));
            return;
        }else{

            result = recvfrom(recv, &buffer, sizeof(buffer), 0, (SA*)target, &size);
            //printf("%d\n", result);
            if(result < 0){
                printf("Blad funkcji recvfrom: %s", strerror(errno));
                return;
            }   

            memcpy( &icmph, &buffer[20] , sizeof(icmph));
            icmph.checksum = ntohs(icmph.checksum);

            memcpy( &port, &buffer[50] , 2);
            port = ntohs(port);

            if(icmph.type == ICMP_DEST_UNREACH && icmph.code == ICMP_PORT_UNREACH && ports[r] == port){
                //printf("Port %d jest zamkniety\n", ports[r]);
            }
            //++pause;
        }
        ports[r] = 0;
    }
    printf("Koniec skanu UDP:\n\n");
    close(send);
    close(recv);
    return;

}

void scan_tcp(unsigned int *ports, unsigned int n,struct sockaddr_in *target, struct timeval *timeout){
    int sockfd, r, result;
    fd_set fdset;

    //wyzerowanie struktury dopowiedzialenj za opóźnienie
    bzero(timeout, sizeof(timeout));
    printf("Skan TCP:\n");
    for(unsigned int i = 0; i < n ; ++i) {

        //Otworzenie socketu
        if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0){

            printf("Błąd socketu\n");
            fprintf(stderr, "socket error : %s\n", strerror(errno));
            return;
        }
        
	    //sprawzenie czy zostal wybrany dobry port
	    //ponaiwanie losowan
        if(i == 0){ r = 21;};
        if(i == 1){ r = 22;}
        if(i == 2){ r = 24;}
        if(i == 3){ r = 52;}
        if(i == 4){ r = 66;}
        if(i == 5){ r = 67;}
        if(i == 6){ r = 79;}
        if(i == 7){ r = 109;}
        if(i == 8){ r = 142;}
        if(i == 9){ r = 442;}
        if(i > 9){
            r = rand() % 1023; 
            while(ports[r] == 0){
                r = rand() % 1023;
            }
        }

        //ustawienie gniazda w tryb nieblokujacy
        fcntl(sockfd, F_SETFL, O_NONBLOCK);

        //uzupelnienie pola odpowiadajacego za port
        target->sin_port = htons(ports[r]);

        int opt = 1;
        //ustawienie opcji SO_REUSEADDR
        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
            fprintf(stderr, "socket error : %s\n", strerror(errno));
            printf("Wystąpił błąd przy ustawaianiu opcjii SO_REUSEADDR\n");
            return;
        }

        FD_ZERO(&fdset);
        FD_SET(sockfd, &fdset);

        connect(sockfd, (SA *) target, sizeof(*target));
        if( errno != EINPROGRESS){
            ports[r] = 0;
	        close(sockfd);
            continue;
        }

        int so_error;
        socklen_t len = sizeof(so_error);

        timeout->tv_sec = 0;
        timeout->tv_usec = 300000;

        if ((result = select(sockfd + 1, NULL, &fdset, NULL, timeout)) == 1){
            getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len);
            if (so_error == 0) {
                printf("Port %d jest otwarty\n", ports[r]);
            }
        }//else if(result == 0){
         //   int re = 0;
         //   while(re != 5){
         //       timeout->tv_sec = 0;
         //       timeout->tv_usec = 100000;
         //       result = select(sockfd + 1, NULL, &fdset, NULL, timeout);
         //       if(result == 1){
         //           getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len);
         //           if (so_error == 0) {
         //               printf("Port %d jest otwarty\n", ports[r]);
         //               break;
         //           }
         //       }
         //       ++re;
         //   }
        //}
        //printf(" %d\n", i);
	ports[r] = 0;
	close(sockfd);
    }
    printf("Koniec skanu TCP:\n\n");
}

int main(int argc, char** argv) {

    unsigned int ports[1023], mode = 0;
    int err, con; //zmienna przechowywyująca zmienną deskryptora
    struct sockaddr_in target_addr; //struktura adresowa
    struct timeval timeout; // struktura czasowa
    time_t start, end, tim1, tim2;
    double seconds;
    struct hostent *res;
    char str[INET_ADDRSTRLEN];

    printf("\n");

    if (argc < 2) {
        printf("Nie poprawny argument\n");
        return 1;
    }else if(argc == 2){
        mode = 0;
    }else if(argc == 3){
        if(argv[1][0] == '-' && argv[1][1] == 't'){
            mode = 1;
        }else if(argv[1][0] == '-' && argv[1][1] == 'u'){
            mode = 2;
        }else{
            printf("Zly argument. Oczekiwane -t (tcp only), -u (udp only)\n");
            return 1;
        }
    }

    //wyzerowanei struktury adresowej
    bzero(&target_addr, sizeof(target_addr));

    //ustawienie odpowiedniej rodzinny adresu
    target_addr.sin_family = AF_INET;

    //rozpoznawanie czy wprowadzony został adres IPv4 czy domena
    if(argc == 2){
        if (argv[1][0] == '1' || argv[1][0] == '2' || argv[1][0] == '3' || argv[1][0] == '4' || argv[1][0] == '5' || argv[1][0] == '6' || argv[1][0] == '7' || argv[1][0] == '8' || argv[1][0] == '9') {
            if ((err = inet_pton(AF_INET, argv[1], &target_addr.sin_addr)) <= 0) {
                printf("Błąd funckji inet_pton\n");
                return 1;
            }
            printf("Podano adres IPv4: %s\n", argv[1]);
        }
        else {
            res = gethostbyname2(argv[1],AF_INET);
            *str = *res->h_addr_list[0];
            printf("Podano DNS: %s\n", res->h_name);
            inet_ntop(AF_INET, res->h_addr_list[0], str, sizeof(str));
            printf("%s\n", str);
            if ((err = inet_pton(AF_INET, str, &target_addr.sin_addr)) <= 0) {
                printf("Błąd funckji inet_pton\n");
                return 1;
            }
        }
    }else if(argc == 3){
        if (argv[2][0] == '1' || argv[2][0] == '2' || argv[2][0] == '3' || argv[2][0] == '4' || argv[2][0] == '5' || argv[2][0] == '6' || argv[2][0] == '7' || argv[2][0] == '8' || argv[2][0] == '9') {
            if ((err = inet_pton(AF_INET, argv[2], &target_addr.sin_addr)) <= 0) {
                printf("Błąd funckji inet_pton\n");
                return 1;
            }
            printf("Podano adres IPv4: %s\n", argv[2]);
        }
        else {
            res = gethostbyname2(argv[2],AF_INET);
            *str = *res->h_addr_list[0];
            printf("Podano DNS: %s\n", res->h_name);
            inet_ntop(AF_INET, res->h_addr_list[0], str, sizeof(str));
            printf("%s\n", str);
            if ((err = inet_pton(AF_INET, str, &target_addr.sin_addr)) <= 0) {
                printf("Błąd funckji inet_pton\n");
                return 1;
            }
        }        
    }

    printf("Start skanowania:\n\n");

    start = time(NULL);

    switch(mode){
        case 0:
            //wypelnienie talicy portow
            fill_ports(ports, sizeof(ports)/sizeof(ports[0]));
            scan_tcp(ports, sizeof(ports)/sizeof(ports[0]), &target_addr,&timeout);
            fill_ports(ports, sizeof(ports)/sizeof(ports[0]));
            scan_udp(ports, sizeof(ports)/sizeof(ports[0]), &target_addr,&timeout);
            break;
        case 1:
            fill_ports(ports, sizeof(ports)/sizeof(ports[0]));
            scan_tcp(ports, sizeof(ports)/sizeof(ports[0]), &target_addr,&timeout);
            break;
        case 2:
            fill_ports(ports, sizeof(ports)/sizeof(ports[0]));
            scan_udp(ports, sizeof(ports)/sizeof(ports[0]), &target_addr,&timeout);
            break;
        default:
            printf("Nie poprawny argument\n");
            return 1;
    }
    
    end = time(NULL);
    seconds = difftime(end,start);
    printf("Skanowanie zakończone\nSkan trwał: %f s\n", seconds);
    return 0;
    
}
