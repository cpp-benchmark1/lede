#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

int main() {
    printf("Starting time processing application...\n");
    
    // Get current time
    time_t currentTime = time(NULL);
    printf("Current time retrieved: %ld\n", currentTime);
    
    // Save timestamp to environment variable
    char envValue[32];
    snprintf(envValue, sizeof(envValue), "%ld", currentTime);
    setenv("TIMESTAMP", envValue, 1);
    printf("Timestamp saved to environment: %s\n", envValue);
    
    // Save time validation to file
    FILE* timeFile = fopen("/tmp/time_validation.txt", "w");
    if (timeFile != NULL) {
        fprintf(timeFile, "timestamp=%ld\n", currentTime);
        fclose(timeFile);
        printf("Time validation saved to file\n");
    }
    
    // SINK CWE 676
    struct tm* timeinfo = gmtime(&currentTime);
    
    printf("UTC time: %s", asctime(timeinfo));
    printf("Year: %d, Month: %d, Day: %d\n", 
           timeinfo->tm_year + 1900, 
           timeinfo->tm_mon + 1, 
           timeinfo->tm_mday);
    
    return 0;
}