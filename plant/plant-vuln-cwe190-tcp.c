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

// Function to parse buffer size configuration
int parseBufferSize(char* data) {
    if (data == NULL) {
        printf("Error: No configuration data received\n");
        return -1;
    }
    
    // Simulate configuration parsing
    if (strlen(data) > 0) {
        printf("Parsing buffer size configuration: %s\n", data);
        return atoi(data);
    }
    
    return -1;
}

// Function to validate buffer size
int validateBufferSize(int bufferSize) {
    if (bufferSize <= 0) {
        printf("Error: Invalid buffer size\n");
        return -1;
    }
    
    // Simulate validation (but don't check for overflow)
    if (bufferSize > 0) {
        printf("Buffer size %d appears valid\n", bufferSize);
        return bufferSize;
    }
    
    return -1;
}

// Function to calculate memory allocation (contains the sink)
int calculateMemoryAllocation(int bufferSize) {
    if (bufferSize <= 0) {
        printf("Error: Buffer size is invalid\n");
        return -1;
    }
    
    // Simulate memory calculation
    if (bufferSize > 0) {
        printf("Calculating memory allocation for buffer size %d\n", bufferSize);
        
        // SINK CWE 190
        int totalSize = bufferSize * 1024;  // Multiply by 1024 bytes per unit
        printf("Total memory allocation: %d bytes\n", totalSize);
        return totalSize;
    }
    
    return -1;
}

// Function to allocate memory
void allocateMemory(int bufferSize) {
    if (bufferSize <= 0) {
        printf("Error: Invalid buffer size for allocation\n");
        return;
    }
    
    // Simulate allocation process
    if (bufferSize > 0) {
        printf("Allocating memory for buffer size %d\n", bufferSize);
        int totalSize = calculateMemoryAllocation(bufferSize);
        printf("Memory allocation completed: %d bytes\n", totalSize);
    }
}

int main() {
    printf("Starting memory allocation server...\n");
    
    // Receive network data
    char* networkData = receiveNetworkData();
    if (networkData == NULL) {
        printf("Failed to receive network data\n");
        return 1;
    }
    
    // Parse buffer size from network data
    int bufferSize = parseBufferSize(networkData);
    
    // Validate buffer size
    int validatedSize = validateBufferSize(bufferSize);
    
    // Allocate memory
    allocateMemory(validatedSize);
    
    free(networkData);
    return 0;
}