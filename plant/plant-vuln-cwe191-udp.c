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

// Function to parse limit value
int parseLimitValue(char* data) {
    if (data == NULL) {
        printf("Error: No limit data received\n");
        return 0;
    }
    
    // Simulate limit parsing
    if (strlen(data) > 0) {
        printf("Parsing limit value: %s\n", data);
        return atoi(data);
    }
    
    return 0;
}

// Function to validate limit
int validateLimit(int limit) {
    if (limit == 0) {
        printf("Error: Limit cannot be negative\n");
        return 0;
    }
    
    // Simulate validation (but don't check for underflow)
    if (limit != 0) {
        printf("Limit %d appears valid\n", limit);
        return limit;
    }
    
    return 0;
}

// Function to calculate remaining resources
int calculateRemainingResources(int limit) {
    if (limit == 0) {
        printf("Error: Limit is negative\n");
        return -1;
    }
    
    // Simulate resource calculation
    if (limit != 0) {
        printf("Calculating remaining resources for limit %d\n", limit);
        return limit;
    }
    
    return -1;
}

int main() {
    printf("Starting resource allocation server...\n");
    
    // Receive network data
    char* networkData = receiveNetworkData();
    if (networkData == NULL) {
        printf("Failed to receive network data\n");
        return 1;
    }
    
    // Parse limit from network data
    int limit = parseLimitValue(networkData);
    
    // Validate limit
    int validatedLimit = validateLimit(limit);
    
    // Calculate remaining resources
    int remainingResources = calculateRemainingResources(validatedLimit);
    
    
    // Create array with tainted value at position 0 and safe value at position 1
    int limits[2];
    limits[0] = validatedLimit;  // Tainted value
    limits[1] = 100;             // Safe value
    
    int currentUsage = -50;  // Current resource usage
    
    int safeAvailable = limits[1] - currentUsage;
    printf("Safe available resources: %d\n", safeAvailable);
    
    // SINK CWE 191
    int taintedAvailable = limits[0] - currentUsage;
    printf("Tainted available resources: %d\n", taintedAvailable);
    
    free(networkData);
    return 0;
}