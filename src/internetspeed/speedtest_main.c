#include "speedtest.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc > 1 && strcmp(argv[1], "--download-only") == 0) {
        // Download test only
        double download_speed = test_download_speed();
        printf("DOWNLOAD_RESULT:%.2f\n", download_speed);
        return 0;
    } else if (argc > 1 && strcmp(argv[1], "--upload-only") == 0) {
        // Upload test only
        double upload_speed = test_upload_speed();
        printf("UPLOAD_RESULT:%.2f\n", upload_speed);
        return 0;
    } else {
        // Full test
        return run_speedtest();
    }
}