# TARGET = run
# SRCS = http_parser/http_request_parser.c main_3.c hashmap/hashmap.c proxy/client.c logger/logger.c

# CC=gcc
# RM=rm
# CFLAGS= -g -Wall
# LIBS=-lpthread
# INCLUDE_DIR="."

# all:  ${TARGET} 

# ${TARGET}: http_parser/http_request_parser.h hashmap/hashmap.h proxy/client.h logger/logger.h ${SRCS}
# 	${CC} ${CFLAGS} -I${INCLUDE_DIR} ${SRCS} ${LIBS} -o ${TARGET}


# clean:
# 	${RM} -f *.o ${TARGET}


# ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
# CC=gcc
# FLAGS=-Wall -O2
# LIBS=./llhttp/build/libllhttp.a -lpthread
# TARGET=proxy
# INCLUDES=-I./llhttp/build/
# # OBJECTS=main.o log.o hash.o hashmap.o sieve.o http.o net.o stream.o buffer.o proxy.o
# OBJECTS=proxy.o client.o logger/logger.o http_utils/http_utils.o

# all: main

# main: $(OBJECTS) libllhttp
# 	$(CC) $(FLAGS) -o $(TARGET) $(OBJECTS) $(LIBS) 

# $(OBJECTS): %.o: %.c 
# 	$(CC) $(FLAGS) $(INCLUDES) -c $<

# libllhttp: ./llhttp/build/libllhttp.a

# ./llhttp/build/libllhttp.a:
# 	(cd llhttp && npm ci && make)

# clean:
# 	rm -f $(TARGET)
# 	rm -f $(OBJECTS)
# 	(cd llhttp && make clean)


CC=gcc
FLAGS=-Wall -O2
LIBS=./llhttp/build/libllhttp.a -lpthread
TARGET=run
INCLUDES=-I./llhttp/build/
OBJECTS=proxy.o client.o logger/logger.o http_utils/http_utils.o

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

libllhttp: ./llhttp/build/libllhttp.a

./llhttp/build/libllhttp.a:
	(cd llhttp && npm ci && make)

clean:
	rm -f $(TARGET)
	rm -f $(OBJECTS)