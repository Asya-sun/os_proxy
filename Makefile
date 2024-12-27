CC=gcc
FLAGS=-Wall -O2
LIBS=./llhttp/build/libllhttp.a -lpthread
TARGET=run
INCLUDES=-I./llhttp/build/
OBJECTS=proxy.o client.o logger/logger.o http_utils/http_utils.o hashmap/hashmap.o

all: main

main: $(OBJECTS) libllhttp
	$(CC) $(FLAGS) -o $(TARGET) $(OBJECTS) $(LIBS)

# Правила для компиляции объектных файлов
%.o: %.c 
	$(CC) $(FLAGS) $(INCLUDES) -c $< -o $@

logger/logger.o: logger/logger.c
	$(CC) $(FLAGS) $(INCLUDES) -c logger/logger.c -o logger/logger.o

http_utils/http_utils.o: http_utils/http_utils.c
	$(CC) $(FLAGS) $(INCLUDES) -c http_utils/http_utils.c -o http_utils/http_utils.o

hashmap/hashmap.o: hashmap/hashmap.c
	$(CC) $(FLAGS) $(INCLUDES) -c hashmap/hashmap.c -o hashmap/hashmap.o

libllhttp: ./llhttp/build/libllhttp.a

./llhttp/build/libllhttp.a:
	(cd llhttp && npm ci && make)

clean:
	rm -f $(TARGET)
	rm -f $(OBJECTS)