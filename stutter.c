/*
 * Copyright (c) 2009-2010 Janne Johansson <jj@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */


#include <err.h>
#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>

#include "myproposal.h"  // taken from real SSH5.6

void keep_busy(int, int);

// #define JJDEBUG 1

const char *mystring="SSH-2.0-OpenSSH_5.3\r\n";
char proposal_buffer[35000];


int
main()
{
  int s, s2, sockaddr_len, one=1;
  int fake_packet_len, proposals;
  int buffer_pointer, temp_int;

  pid_t mypid;
  struct sockaddr_in min_sockaddr;
  struct sigaction mysig;
  char kexinit_buffer[4096];

  s = socket(AF_INET, SOCK_STREAM, 0);
  if (s == NULL) {
    err(1,"socket() call failed");
  }

  if (setsockopt(s, SOL_SOCKET, SO_RCVBUF,
		 &one, sizeof(one))) {
    err(1,"setsockopt() RCVBUF call failed");
  }

  if (setsockopt(s, SOL_SOCKET, SO_REUSEPORT,
		 &one, sizeof(one))) {
    err(1,"setsockopt() REUSEADDR call failed");
  }

  //if (setsockopt(s, SOL_SOCKET, SO_SNDBUF,
  //		 &one, sizeof(one))) {
  //  err(1,"setsockopt() SNDBUF call failed");
  //}
  
  sockaddr_len = sizeof(min_sockaddr);

  memset (&min_sockaddr, 0, sockaddr_len);

  min_sockaddr.sin_len=sockaddr_len;
  min_sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  min_sockaddr.sin_family=AF_INET;
  min_sockaddr.sin_port = htons(9876);

#if JJDEBUG
  printf("port=%d\n", ntohs(min_sockaddr.sin_port));
#endif

  if (bind(s, (struct sockaddr *)&min_sockaddr, sockaddr_len)) {
    err(1,"bind() call failed");
  }
  
  if (listen(s, 100)) {
    err(1,"listen() call failed");
  }

  /* set up sigaction to prevent zombies, I dont want to know about
     nor reap children processes */

  sigemptyset(&mysig.sa_mask);
  mysig.sa_flags = SA_NOCLDSTOP|SA_NOCLDWAIT;
  mysig.sa_handler = SIG_IGN;
  sigaction(SIGCHLD, &mysig, NULL);

  /* Calculate the fake proposal packet once */

  temp_int=0;
  kexinit_buffer[0]=20;  // SSH_MSG_KEXINIT = 20
  bcopy(mystring, &kexinit_buffer[1], 16); // using SSH2.0-  as 'random bytes'
  buffer_pointer=17;  // we have written 17 bytes into it

  for (proposals=0; proposals < sizeof(myproposal)/sizeof(*myproposal); proposals++)
    {
      int prop_len=strlen(myproposal[proposals]);

      temp_int=htonl(prop_len);
      bcopy(&temp_int, &kexinit_buffer[buffer_pointer], 4);
      buffer_pointer += 4;
      if (prop_len) {
	bcopy(myproposal[proposals],
	      &kexinit_buffer[buffer_pointer], prop_len);
      }
      buffer_pointer += prop_len;
#ifdef JJDEBUG
      printf("prop len %d, hex %x\n",prop_len, prop_len);
	printf("size now is: %d\n",buffer_pointer);
#endif // JJDEBUG
    }
  kexinit_buffer[buffer_pointer++]=0; // boolean for kex-packet-follows

  temp_int=0;
  bcopy(&kexinit_buffer[buffer_pointer], &temp_int, 4); // last 4 zero bytes.
  buffer_pointer += 4;

  // now we know the packet length.
  temp_int=htonl(1+16+1+4 + buffer_pointer);
#ifdef JJDEBUG
  printf("kexinit size %d, buffer pointer %d + 22\n",
	 ntohl(temp_int), buffer_pointer);
#endif // JJDEBUG
  // KEXINIT + cookie + boolean + reserved uint32 + the payload
  bcopy(&temp_int, &proposal_buffer[0], 4);


  fake_packet_len=(((1+16+1+4 + buffer_pointer + 4 + 1)/8)+1)*8;
#ifdef JJDEBUG
  printf("packet_len is now thought to be %d\n", fake_packet_len);
#endif // JJDEBUG
  
  // minimum random padding (4) plus the lenght byte for it,
  // then rounded to nearest multiple of eight

  //padding_length is the even-8-byte-len minus the real length
  proposal_buffer[4]=fake_packet_len - (1+16+1+4 + buffer_pointer + 4 + 1);
#ifdef JJDEBUG
  printf("padding size %d\n",
	 fake_packet_len - (1+16+1+4 + buffer_pointer + 4 + 1));
#endif // JJDEBUG

  // packet_len includes the calculated padding length

  // add the kexinit payload 
  bcopy(&kexinit_buffer[0], &proposal_buffer[5], buffer_pointer);
#ifdef JJDEBUG
      printf("kexinit size is: %d\n",buffer_pointer);
#endif // JJDEBUG
  // add padding (the fixed OpenSSH version string comes handy again)
  bcopy(mystring, &proposal_buffer[5+buffer_pointer],
	(size_t)proposal_buffer[4]);


  // final size calculation of the complete SSH packet.
  // size should be 1 for the padding length byte, plus
  // the kexinit packet (buffer_pointer), plus the random
  // padding (stored in the fifth byte already), plus 4 for
  // the empty MAC checksum.
#ifdef JJDEBUG
  printf("SSH packet size %d\n", fake_packet_len);
#endif // JJDEBUG
  temp_int=htonl(fake_packet_len);
  bcopy(&temp_int, &proposal_buffer[0], sizeof(temp_int));

  // now the packet is good to send.

  /* start the loop */
  mypid=getpid();

  while (1) {

    s2 = accept(s, (struct sockaddr *)&min_sockaddr, &sockaddr_len);
    if (s2 != -1) {
      switch (fork()) {
      case 0:
	keep_busy(s2, fake_packet_len);
	_exit(0);
      case -1:
	/* in case we cant fork, no action right now */
	break;
      default:
	/* we are the parent, close the for-the-child socket and 
	   run the loop again */
	close(s2);
	break;
      }
    } else {
      err(1,"accept() call failed");
    }
  }

  if (errno)
    {
      perror("exiting");
    }
  return (0);
}

void
keep_busy(int s2, int buffer_size) {

  int socklen, gai_return;
  time_t now, then;
  //  double timediff;
  struct sockaddr_storage peersock;
  char buf[35000];
  char remotename[NI_MAXHOST];

  if (chdir("/var/empty")==0 && s2 > 2) {
    daemon(0,0);
  }

  setpriority(PRIO_PROCESS, 0, 10);

  socklen=sizeof(peersock);
  if(getpeername(s2, (struct sockaddr *)&peersock, &socklen)==0) {
    gai_return=getnameinfo((struct sockaddr *)&peersock, peersock.ss_len,
			   remotename, sizeof(remotename),
			   NULL, 0, NI_NUMERICHOST);
    if (gai_return) {
      snprintf(remotename, sizeof(remotename), "%s",
	       gai_strerror(gai_return));
      syslog(LOG_WARNING, "%s", remotename);
    }
  } else {
    syslog(LOG_INFO, "got no peername");
  }

  if (time(&now) != -1 ) {
    strftime(buf, sizeof(buf), "%F %T", localtime(&now));
    syslog(LOG_INFO, "caught %s at %s, pid %d",
	   remotename, buf, getpid());
    memset (&buf, 0, sizeof(buf));
  }

  memset (&buf, 0, sizeof(buf));
  snprintf(buf, strlen(mystring), "%s", mystring);

  write(s2,&buf,strlen(mystring));
  memset (&buf, 0, sizeof(buf));

  /* old "repeat what the other side said" code
  retcode=0;
  while ((loops < 5) && (retcode != -1))
    {
      switch(retcode) 
	{
	case 0:
	  sleep(1);
	  loops++;
	  break;
	default:
	  write(s2,&buf,retcode);
#if JJDEBUG
	  printf("%c\n", buf[0]);
#endif
	  sleep(1);
	  break;
	}
      retcode=read(s2, &buf, 1);
    }
  */

  write(s2, &proposal_buffer, buffer_size);
  //when they respond to this, it will hopefully take a lot of time
  
  while (read(s2, buf, 1) == 1) {
    sleep(1);
#ifdef JJDEBUG
    printf("got this byte %x", buf[0]);
#endif
  }

  if(getpeername(s2, (struct sockaddr *)&peersock, &socklen)==0) {
    getnameinfo((struct sockaddr *)&peersock, socklen,
		remotename, sizeof(remotename),
		NULL, 0, 0);
  }

  if (time(&then) != -1 ) {
    memset (&buf, 0, sizeof(buf));
    strftime(buf, sizeof(buf), "%F %T", localtime(&then));
    syslog(LOG_INFO, "exited at %s, kept %s busy for %d seconds, pid %d",
	   buf, remotename, (int)difftime(then, now), getpid());
  }
}
