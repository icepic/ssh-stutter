
SSH_INCLUDES ?= /usr/src/usr.bin/ssh

all: ssh-stutter


ssh-stutter: stutter.c
	$(CC) $(CFLAGS) -g -I ${SSH_INCLUDES} -o ssh-stutter stutter.c

debug: stutter.c
	$(CC) $(CFLAGS) -Wall -g -I ${SSH_INCLUDES} -DJJDEBUG -o ssh-stutter stutter.c
