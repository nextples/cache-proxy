#include <stdio.h>
#include <stdlib.h>

#include "../include/proxy.h"
#include "../include/logger.h"

int main(void) {
    logger_init("/home/maksim/CLionProjects/cache-proxy/logs/cache-proxy.log", LOG_LEVEL_DEBUG, 1);
    run_proxy();

    exit(EXIT_SUCCESS);
}