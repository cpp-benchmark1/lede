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

// Function to parse thread count and save to environment
int parseThreadCount(char* data) {
    if (data == NULL) {
        printf("Error: No thread data received\n");
        return -1;
    }
    
    // Simulate thread count parsing
    if (strlen(data) > 0) {
        printf("Parsing thread count: %s\n", data);
        int threadCount = atoi(data);
        
        // Save to environment variable for configuration
        char envValue[32];
        snprintf(envValue, sizeof(envValue), "%d", threadCount);
        setenv("THREAD_COUNT", envValue, 1);
        printf("Thread count saved to environment: %s\n", envValue);
        
        return threadCount;
    }
    
    return -1;
}

// Function to validate thread configuration and save to file
int validateThreadConfig(int threadCount) {
    if (threadCount < 0) {
        printf("Error: Invalid thread count\n");
        return -1;
    }
    
    // Simulate validation
    if (threadCount >= 0) {
        printf("Thread count %d appears valid\n", threadCount);
        
        // Save configuration to file
        FILE* configFile = fopen("/tmp/thread_config.txt", "w");
        if (configFile != NULL) {
            fprintf(configFile, "thread_count=%d\n", threadCount);
            fclose(configFile);
            printf("Thread configuration saved to file\n");
        }
        
        return threadCount;
    }
    
    return -1;
}

// Function to prepare thread execution (contains the sink)
void prepareThreadExecution(int threadCount) {
    if (threadCount < 0) {
        printf("Error: Thread count is negative\n");
        return;
    }
    
    // Simulate thread preparation
    if (threadCount >= 0) {
        printf("Preparing execution for %d threads\n", threadCount);
        
        // SINK CWE 606
        for (int i = 0; i < threadCount; i++) {
            // Set thread environment variable
            char envVar[32];
            snprintf(envVar, sizeof(envVar), "THREAD_%d", i);
            setenv(envVar, "active", 1);
        }
        
        printf("All %d threads prepared\n", threadCount);
    }
}

// Function to execute thread tasks
void executeThreadTasks(int threadCount) {
    if (threadCount < 0) {
        printf("Error: Invalid thread count for task execution\n");
        return;
    }
    
    // Simulate task execution
    if (threadCount >= 0) {
        printf("Executing tasks for %d threads\n", threadCount);
        prepareThreadExecution(threadCount);
    }
}

int main() {
    printf("Starting thread management server...\n");
    
    // Receive network data
    char* networkData = receiveNetworkData();
    if (networkData == NULL) {
        printf("Failed to receive network data\n");
        return 1;
    }
    
    // Parse thread count from network data
    int threadCount = parseThreadCount(networkData);
    
    // Validate thread configuration
    int validatedThreadCount = validateThreadConfig(threadCount);
    
    // Execute thread tasks
    executeThreadTasks(validatedThreadCount);
    
    free(networkData);
    return 0;
}