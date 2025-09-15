#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Declare gets function
extern char* gets(char*);

int main() {
    printf("Starting configuration application...\n");
    

    char configBuffer[128];
    
    printf("Enter configuration data: ");
    fflush(stdout);
    
    // SINK CWE 242
    char* result = gets(configBuffer);
    
    if (result != NULL) {
        printf("Configuration data received: %s\n", configBuffer);
        
        // Save configuration to file without validation
        FILE* configFile = fopen("config.txt", "w");
        if (configFile != NULL) {
            fprintf(configFile, "configuration=%s\n", configBuffer);
            fclose(configFile);
            printf("Configuration saved to config.txt\n");
        } else {
            printf("Failed to open config.txt for writing\n");
        }
    } else {
        printf("Failed to read configuration data\n");
        return 1;
    }
    
    return 0;
}