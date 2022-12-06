.PHONY: all clean ttp

CFLAGS=-g -Wall -Werror -UDEBUG
LDLIBS=-lsqlite3 -lcrypto -lssl

all: ttp client server chat.db

clean:
	rm -f server client *.o chat.db
	rm -r -f keys

ttp: clean ./ttp/ttp.sh ./ttp/gen_server_keys.sh ./ttp/gen_client_keys.sh ./ttp/gen_aes.sh
	chmod +x ./ttp/ttp.sh ./ttp/gen_server_keys.sh ./ttp/gen_client_keys.sh
	./ttp/ttp.sh
	./ttp/gen_server_keys.sh

chat.db:
	sqlite3 chat.db "CREATE TABLE users(username TEXT NOT NULL, pwd TEXT NOT NULL, \
									    salt TEXT NOT NULL, online INTEGER NOT NULL);\
					 CREATE TABLE msgs(id INTEGER PRIMARY KEY, msg TEXT NOT NULL, \
					 				   sender TEXT NOT NULL, recipient TEXT, \
					 				   timestamp TEXT NOT NULL, sig TEXT NOT NULL, key1 TEXT, key2 TEXT);"

ui.o: ui.c ui.h api.h

client.o: client.c api.h ui.h util.h sanitizer.h parser.h crypto.h

sanitizer.o: sanitizer.c sanitizer.h api.h parser.h

parser.o: parser.c parser.h sanitizer.h api.h

ssl-nonblock.o: ssl-nonblock.c ssl-nonblock.h

api.o: api.c api.h ssl-nonblock.o

database.o: database.c database.h api.h crypto.h

server.o: server.c util.h

util.o: util.c util.h

crypto.o: crypto.c crypto.h api.h

worker.o: worker.c util.h worker.h parser.h

client: client.o api.o ui.o util.o sanitizer.o parser.o ssl-nonblock.o crypto.o

server: server.o api.o util.o worker.o database.o ssl-nonblock.o crypto.o