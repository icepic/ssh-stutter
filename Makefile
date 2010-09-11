
all: ssh-stutter


ssh-stutter: stutter.c

debug: stutter.c
	$(CC) $(CFLAGS) -DJJDEBUG -o ssh-stutter stutter.c
