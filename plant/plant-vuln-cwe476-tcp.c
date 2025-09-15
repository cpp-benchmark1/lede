#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>

// Function to receive network data via TCP
char* receiveNetworkData() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[1024] = {0};
    
    // Create socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        return NULL;
    }
    
    // Set socket options
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt");
        return NULL;
    }
    
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(8080);
    
    // Bind socket
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        return NULL;
    }
    
    // Listen for connections
    if (listen(server_fd, 3) < 0) {
        perror("listen");
        return NULL;
    }
    
    printf("TCP Server listening on port 8080...\n");
    
    // Accept connection
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
        perror("accept");
        return NULL;
    }
    
    // Read data from client
    int valread = read(new_socket, buffer, 1024);
    char* receivedData = malloc(valread + 1);
    strncpy(receivedData, buffer, valread);
    receivedData[valread] = '\0';
    
    close(new_socket);
    close(server_fd);
    
    return receivedData;
}

// Function to parse config ID and save to environment
int parseConfigId(char* data, int** configPtr) {
    if (data == NULL) {
        printf("Error: No config data received\n");
        return -1;
    }
    
    // Simulate config ID parsing
    if (strlen(data) > 0) {
        printf("Parsing config ID: %s\n", data);
        int configId = atoi(data);
        
        // Allocate memory for config ID
        *configPtr = malloc(sizeof(int));
        if (*configPtr != NULL) {
            **configPtr = configId;
            
            // Save to environment variable
            char envValue[32];
            snprintf(envValue, sizeof(envValue), "%d", configId);
            setenv("CONFIG_ID", envValue, 1);
            printf("Config ID saved to environment: %s\n", envValue);
            
            return configId;
        }
    }
    
    return -1;
}

// Function to validate config and save to file
int validateConfig(int* configPtr) {
    if (configPtr == NULL) {
        printf("Error: Config pointer is NULL\n");
        return -1;
    }
    
    // Simulate validation
    if (*configPtr > 0) {
        printf("Config ID %d appears valid\n", *configPtr);
        
        // Save configuration to file
        FILE* configFile = fopen("/tmp/config.txt", "w");
        if (configFile != NULL) {
            fprintf(configFile, "config_id=%d\n", *configPtr);
            fclose(configFile);
            printf("Config saved to file\n");
        }
        
        return 0;
    }
    
    return -1;
}

// Function to process configuration and set pointer to NULL (contains the sink)
void processConfiguration(char* networkData) {
    if (networkData == NULL) {
        printf("Error: No network data for processing\n");
        return;
    }
    
    printf("Processing configuration from network data: %s\n", networkData);
    
    // Validate config
    int configId = atoi(networkData);
    if (configId > 0) {
        printf("Config ID %d valid\n", configId);
        
        // Save configuration to file
        FILE* configFile = fopen("/tmp/config.txt", "w");
        if (configFile != NULL) {
            fprintf(configFile, "config_id=%d\n", configId);
            fclose(configFile);
            printf("Config saved to file\n");
        }
    }
    
    // Set pointer to NULL after processing
    networkData = NULL;
    printf("Network data pointer set to NULL after processing\n");
    
    // SINK CWE 476
    char config = *networkData;
    printf("Log Config value after processing: %c\n", config);
}

int main() {
    printf("Starting configuration server...\n");
    
    // Receive network data
    char* networkData = receiveNetworkData();
    if (networkData == NULL) {
        printf("Failed to receive network data\n");
        return 1;
    }
    
    // Parse config ID from network data
    int* configPtr = NULL;
    int configId = parseConfigId(networkData, &configPtr);
    
    // Process configuration
    processConfiguration(networkData);
    
    free(networkData);
    return 0;
}