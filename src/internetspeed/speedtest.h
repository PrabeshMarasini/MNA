#ifndef SPEEDTEST_H
#define SPEEDTEST_H

#include <stddef.h>

typedef struct {
    size_t size;
} MemoryStruct;

double test_download_speed(void);
double test_upload_speed(void);
int run_speedtest(void);

#endif