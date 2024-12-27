#ifndef LOGGER_H
#define LOGGER_H
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>

typedef struct Logger Logger;

typedef enum {
    INFO = 1,
    WARNING = 2,
    ERROR = 3,
    FATAL = 4
} LogLevel;

// Функция для создания логгера
Logger* createLogger(const char *filename);

// Функция для закрытия логгера
void closeLogger(Logger *logger);

// Основная функция логирования
void elog(Logger *logger, LogLevel level, const char *message, ...);


#endif //LOGGER_H




// // Пример использования логгера
// int main() {
//     Logger *logger = createLogger("logfile.txt");
//     if (logger == NULL) {
//         return 1; // Ошибка при создании логгера
//     }

//     elog(logger, INFO, "Это информационное сообщение.");
//     elog(logger, WARNING, "Это предупреждение.");
//     elog(logger, ERROR, "Произошла ошибка: %d", -1);
//     elog(logger, FATAL, "Критическая ошибка: %s", "системный сбой");

//     closeLogger(logger); // Закрываем логгер
//     return 0;
// }