CC=gcc
CFLAGS=-Wall -Werror -Wextra -O4
LIBS=-lpthread

EXEC:=harnass

all: $(EXEC)

$(EXEC): harnass.c
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

clean:
	rm -f $(EXEC)
