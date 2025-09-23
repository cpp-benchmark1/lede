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

// Function to parse configuration index
int parseConfigIndex(char* data) {
    if (data == NULL) {
        printf("Error: No data received\n");
        return -1;
    }
    
    // Simulate configuration parsing
    if (strlen(data) > 0) {
        printf("Parsing configuration data: %s\n", data);
        return atoi(data);
    }
    
    return -1;
}

// Function to validate configuration range
int validateConfigRange(int configIndex) {
    if (configIndex < 0) {
        printf("Error: Invalid configuration index\n");
        return -1;
    }
    
    // Simulate range validation (but don't actually check upper bound)
    if (configIndex >= 0) {
        printf("Configuration index %d appears valid\n", configIndex);
        return configIndex;
    }
    
    return -1;
}

// Function to process configuration (contains the sink)
void processConfiguration(int configIndex) {
    // Configuration array with limited size
    char* configs[] = {"config1", "config2", "config3", "config4", "config5"};
    int configCount = 5;
    
    if (configIndex < 0) {
        printf("Error: Configuration index is negative\n");
        return;
    }
    
    // Simulate additional processing
    if (configIndex >= 0) {
        printf("Processing configuration at index %d\n", configIndex);
        
        // SINK CWE 125
        printf("Configuration value: %s\n", configs[configIndex]);
    }
}

// Function to handle configuration request
void handleConfigRequest(int configIndex) {
    if (configIndex < 0) {
        printf("Error: Invalid configuration index in request handler\n");
        return;
    }
    
    // Simulate request validation
    if (configIndex >= 0) {
        printf("Handling configuration request for index %d\n", configIndex);
        processConfiguration(configIndex);
    }
}

int main() {
    printf("Starting configuration server...\n");
    
    // Receive network data
    char* networkData = receiveNetworkData();
    if (networkData == NULL) {
        printf("Failed to receive network data\n");
        return 1;
    }
    
    // Parse configuration index from network data
    int configIndex = parseConfigIndex(networkData);
    
    // Validate configuration range
    int validatedIndex = validateConfigRange(configIndex);
    
    // Handle configuration request
    handleConfigRequest(validatedIndex);
    
    free(networkData);
    return 0;
}