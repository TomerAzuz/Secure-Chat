.PHONY: all clean

CFLAGS=-g -Wall -Werror -UDEBUG
LDLIBS=-lsqlite3 -lcrypto -lssl

all: client server chat.db

clean:
	rm -f server client *.o chat.db

chat.db:
	sqlite3 chat.db "CREATE TABLE users(username TEXT NOT NULL, pwd TEXT NOT NULL);\
					 CREATE TABLE msgs(id INTEGER PRIMARY KEY, msg TEXT NOT NULL, \
					 				   sender TEXT, timestamp TEXT NOT NULL);"

ui.o: ui.c ui.h api.h

client.o: client.c api.h ui.h util.h sanitizer.h parser.h

sanitizer.o: sanitizer.c sanitizer.h api.h parser.h

parser.o: parser.c parser.h sanitizer.h api.h

api.o: api.c api.h

database.o: database.c database.h api.h

server.o: server.c util.h

util.o: util.c util.h

worker.o: worker.c util.h worker.h parser.h

client: client.o api.o ui.o util.o sanitizer.o parser.o

server: server.o api.o util.o worker.o database.o



