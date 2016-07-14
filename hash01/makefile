.PHONY:clean all
CC=gcc
CFLAGS=-Wall -g
BIN= hash01
OBJS= hash_test.o
LIBS=-std=c99
$(BIN):$(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)
	
%.o:%.c
	$(CC) $(CFLAGS) -c $< -o $@ -std=c99

clean:
	rm -f *.o $(BIN)



