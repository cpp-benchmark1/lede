#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Declare gets function
extern char* gets(char*);

int main() {
    printf("Starting environment configuration application...\n");
    
    char envBuffer[128];
    
    printf("Enter environment variable value: ");
    fflush(stdout);
    
    // SINK CWE 242
    char* result = gets(envBuffer);
    
    if (result != NULL) {
        printf("Environment data received: %s\n", envBuffer);
        
        // Save directly to environment variable without validation
        setenv("USER_CONFIG", envBuffer, 1);
        printf("Environment variable USER_CONFIG set to: %s\n", envBuffer);
        
        // Verify the environment variable was set
        char* envValue = getenv("USER_CONFIG");
        if (envValue != NULL) {
            printf("Verification: USER_CONFIG = %s\n", envValue);
        }
    } else {
        printf("Failed to read environment data\n");
        return 1;
    }
    
    return 0;
}