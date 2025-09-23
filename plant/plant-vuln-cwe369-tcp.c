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

// Function to parse thread count
int parseThreadCount(char* data) {
    if (data == NULL) {
        printf("Error: No thread data received\n");
        return 0;
    }
    
    // Simulate thread count parsing
    if (strlen(data) > 0) {
        printf("Parsing thread count: %s\n", data);
        return atoi(data);
    }
    
    return 0;
}

// Function to validate thread count
int validateThreadCount(int threadCount) {
    if (threadCount < 0) {
        printf("Error: Thread count cannot be negative\n");
        return 0;
    }
    
    // Simulate validation (but don't check for zero)
    if (threadCount >= 0) {
        printf("Thread count %d appears valid\n", threadCount);
        return threadCount;
    }
    
    return 0;
}

// Function to calculate work per thread (contains the sink)
int calculateWorkPerThread(int threadCount) {
    if (threadCount < 0) {
        printf("Error: Thread count is negative\n");
        return -1;
    }
    
    // Simulate work calculation
    if (threadCount >= 0) {
        printf("Calculating work per thread for %d threads\n", threadCount);
        
        int totalWork = 1000;  // Total work units
        
        // SINK CWE 369
        int workPerThread = totalWork / threadCount;
        printf("Work per thread: %d\n", workPerThread);
        return workPerThread;
    }
    
    return -1;
}

// Function to distribute work
void distributeWork(int threadCount) {
    if (threadCount < 0) {
        printf("Error: Invalid thread count for work distribution\n");
        return;
    }
    
    // Simulate work distribution
    if (threadCount >= 0) {
        printf("Distributing work among %d threads\n", threadCount);
        int workPerThread = calculateWorkPerThread(threadCount);
        printf("Work distribution completed: %d units per thread\n", workPerThread);
    }
}

int main() {
    printf("Starting work distribution server...\n");
    
    // Receive network data
    char* networkData = receiveNetworkData();
    if (networkData == NULL) {
        printf("Failed to receive network data\n");
        return 1;
    }
    
    // Parse thread count from network data
    int threadCount = parseThreadCount(networkData);
    
    // Validate thread count
    int validatedThreadCount = validateThreadCount(threadCount);
    
    // Distribute work
    distributeWork(validatedThreadCount);
    
    free(networkData);
    return 0;
}