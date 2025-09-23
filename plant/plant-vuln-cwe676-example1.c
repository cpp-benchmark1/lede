#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

// Function to get current time
time_t getCurrentTime() {
    time_t current_time = time(NULL);
    printf("Current time retrieved: %ld\n", current_time);
    return current_time;
}

// Function to process time data and save to environment
void processTimeData(time_t timestamp) {
    if (timestamp > 0) {
        printf("Processing time data: %ld\n", timestamp);
        
        // Save timestamp to environment variable
        char envValue[32];
        snprintf(envValue, sizeof(envValue), "%ld", timestamp);
        setenv("TIMESTAMP", envValue, 1);
        printf("Timestamp saved to environment: %s\n", envValue);
    }
}

// Function to validate time and save to file (contains the sink)
void validateTime(time_t timestamp) {
    if (timestamp > 0) {
        printf("Validating time: %ld\n", timestamp);
        
        // Save time validation to file
        FILE* timeFile = fopen("/tmp/time_validation.txt", "w");
        if (timeFile != NULL) {
            fprintf(timeFile, "timestamp=%ld\n", timestamp);
            fclose(timeFile);
            printf("Time validation saved to file\n");
        }
        
        // SINK CWE 676
        struct tm* timeinfo = gmtime(&timestamp);
        
        // Use the potentially dangerous function result
        printf("UTC time: %s", asctime(timeinfo));
        printf("Year: %d, Month: %d, Day: %d\n", 
               timeinfo->tm_year + 1900, 
               timeinfo->tm_mon + 1, 
               timeinfo->tm_mday);
    }
}

int main() {
    printf("Starting time processing application...\n");
    
    // Get current time
    time_t currentTime = getCurrentTime();
    
    // Process time data
    processTimeData(currentTime);
    
    // Validate time with conditional call
    if (currentTime % 2 == 0) {
        printf("Time is even, proceeding with validation\n");
        validateTime(currentTime);
    } else {
        printf("Time is odd, skipping validation\n");
    }
    
    return 0;
}