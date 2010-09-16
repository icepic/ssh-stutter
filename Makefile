
all: ssh-stutter


ssh-stutter: stutter.c
	$(CC) $(CFLAGS) -g -o ssh-stutter stutter.c

debug: stutter.c
	$(CC) $(CFLAGS) -Wall -g -DJJDEBUG -o ssh-stutter stutter.c
