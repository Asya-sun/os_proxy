#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include "logger.h"

// Структура логгера
typedef struct Logger {
    FILE *file;  // Указатель на файл для логирования
} Logger;

// Функция для создания логгера
Logger* createLogger(const char *filename) {
    Logger *logger = (Logger*)malloc(sizeof(Logger));
    if (logger == NULL) {
        perror("Unable to allocate memory for logger");
        return NULL;
    }
    logger->file = fopen(filename, "a");
    if (logger->file == NULL) {
        perror("Unable to open log file");
        free(logger);
        return NULL;
    }
    return logger;
}

// Функция для закрытия логгера
void closeLogger(Logger *logger) {
    if (logger != NULL) {
        if (logger->file != NULL) {
            fclose(logger->file);
        }
        free(logger);
    }
}

// Функция для преобразования уровня логирования в строку
const char* logLevelToString(LogLevel level) {
    switch (level) {
        case INFO:   return "INFO";
        case WARNING: return "WARNING";
        case ERROR:   return "ERROR";
        case FATAL:   return "FATAL";
        default:      return "UNKNOWN";
    }
}

// Основная функция логирования
void elog(Logger *logger, LogLevel level, const char *message, ...) {
    if (logger == NULL || logger->file == NULL) {
        fprintf(stderr, "Logger is not initialized\n");
        return;
    }

    // Получаем текущее время
    time_t rawtime;
    time(&rawtime);
    struct tm *timeinfo = localtime(&rawtime);

    // Форматируем строку времени
    char timeBuffer[20];
    strftime(timeBuffer, sizeof(timeBuffer), "%Y-%m-%d %H:%M:%S", timeinfo);

    // Выводим уровень и время, затем сообщение
    fprintf(logger->file, "[%s] [%s] ", timeBuffer, logLevelToString(level));

    va_list args;
    va_start(args, message);
    vfprintf(logger->file, message, args);
    va_end(args);

    fprintf(logger->file, "\n");
    fflush(logger->file); // Сбрасываем буфер, чтобы избежать задержки записи
}
