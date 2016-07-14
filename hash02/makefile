.PHONY:clean all
CC=gcc
CFLAGS=-Wall -g
BIN= main
OBJS= main.o hash.o 
LIBS=
$(BIN):$(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)
	
%.o:%.c
	$(CC) $(CFLAGS) -c $< -o $@ 

clean:
	rm -f *.o $(BIN)



