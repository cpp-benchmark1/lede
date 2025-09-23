#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>

// Function to receive network data via UDP
char* receiveNetworkData() {
    int sockfd;
    struct sockaddr_in servaddr, cliaddr;
    char buffer[1024];
    socklen_t len;
    int n;
    
    // Create socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket creation failed");
        return NULL;
    }
    
    memset(&servaddr, 0, sizeof(servaddr));
    memset(&cliaddr, 0, sizeof(cliaddr));
    
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(8080);
    
    // Bind socket
    if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("bind failed");
        return NULL;
    }
    
    printf("UDP Server listening on port 8080...\n");
    
    len = sizeof(cliaddr);
    n = recvfrom(sockfd, (char *)buffer, 1024, MSG_WAITALL, (struct sockaddr *) &cliaddr, &len);
    buffer[n] = '\0';
    
    char* receivedData = malloc(n + 1);
    strcpy(receivedData, buffer);
    
    close(sockfd);
    return receivedData;
}

// Function to parse log message index
int parseLogIndex(char* data) {
    if (data == NULL) {
        printf("Error: No log data received\n");
        return -1;
    }
    
    // Simulate log parsing
    if (strlen(data) > 0) {
        printf("Parsing log data: %s\n", data);
        return atoi(data);
    }
    
    return -1;
}

// Function to validate log index
int validateLogIndex(int logIndex) {
    if (logIndex < 0) {
        printf("Error: Invalid log index\n");
        return -1;
    }
    
    // Simulate validation (but don't check upper bound)
    if (logIndex >= 0) {
        printf("Log index %d appears valid\n", logIndex);
        return logIndex;
    }
    
    return -1;
}

// Function to retrieve log message
char* retrieveLogMessage(int logIndex) {
    if (logIndex < 0) {
        printf("Error: Log index is negative\n");
        return NULL;
    }
    
    // Simulate log retrieval
    if (logIndex >= 0) {
        printf("Retrieving log message at index %d\n", logIndex);
        return "Log message retrieved";
    }
    
    return NULL;
}

// Function to prepare log data
void prepareLogData(int logIndex) {
    if (logIndex < 0) {
        printf("Error: Log index is negative\n");
        return;
    }
    
    // Simulate log preparation
    if (logIndex >= 0) {
        printf("Preparing log data for index %d\n", logIndex);
    }
}

int main() {
    printf("Starting log server...\n");
    
    // Receive network data
    char* networkData = receiveNetworkData();
    if (networkData == NULL) {
        printf("Failed to receive network data\n");
        return 1;
    }
    
    // Parse log index from network data
    int logIndex = parseLogIndex(networkData);
    
    // Validate log index
    int validatedIndex = validateLogIndex(logIndex);
    
    // Retrieve log message
    char* logMessage = retrieveLogMessage(validatedIndex);
    
    // Prepare log data
    prepareLogData(validatedIndex);
    
    // Log messages array with limited size
    char* logMessages[] = {
        "System started",
        "User login successful", 
        "Database connection established",
        "File operation completed",
        "Network timeout occurred"
    };
    
    // Create array with tainted value at position 0 and safe value at position 1
    int indices[2];
    indices[0] = validatedIndex;  // Tainted value
    indices[1] = 2;               // Safe value
    

    printf("Safe log message: %s\n", logMessages[indices[1]]);
    
    // SINK CWE 125
    printf("Tainted log message: %s\n", logMessages[indices[0]]);
    
    free(networkData);
    return 0;
}