/*
 * Copyright (c) 2009 Janne Johansson <jj@openbsd.org>
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


#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
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

void keep_busy(int);

// #define JJDEBUG 1


int
main()
{
  int s, s2, sin_len, sockaddr_len, result, one=1;
  pid_t mypid, forkpid;
  struct sockaddr_in min_sockaddr;
  struct sigaction mysig;

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

  mypid=getpid();

  while (1) {

    s2 = accept(s, (struct sockaddr *)&min_sockaddr, &sockaddr_len);
    if (s2 != -1) {
      switch (fork()) {
      case 0:
	keep_busy(s2);
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
keep_busy(int s2) {

  int retcode, socklen, gai_return, loops=0;
  time_t now, then;
  //  double timediff;
  const char *mystring="SSH-2.0-OpenSSH_5.3\r\n";
  struct sockaddr_storage peersock;
  char buf[64];
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
      retcode=read(s2, buf, 1);
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
