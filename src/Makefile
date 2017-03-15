

server_app = server
client_app = client

CFLAGS = -g

all: $(server_app) $(client_app)

server: $(server_obj)
client: $(client_obj)

server_obj: server.o debug.h
	$(CC) -o $(CFLAGS) $(server_app)

client_obj: client.o debug.h
	$(CC) -o $(CFLAGS) $(client_app)


clean:
	rm -rf *.o
