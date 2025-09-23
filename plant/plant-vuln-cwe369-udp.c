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

// Function to parse batch size
int parseBatchSize(char* data) {
    if (data == NULL) {
        printf("Error: No batch data received\n");
        return 0;
    }
    
    // Simulate batch size parsing
    if (strlen(data) > 0) {
        printf("Parsing batch size: %s\n", data);
        return atoi(data);
    }
    
    return 0;
}

// Function to validate batch size
int validateBatchSize(int batchSize) {
    if (batchSize < 0) {
        printf("Error: Batch size cannot be negative\n");
        return 0;
    }
    
    // Simulate validation (but don't check for zero)
    if (batchSize >= 0) {
        printf("Batch size %d appears valid\n", batchSize);
        return batchSize;
    }
    
    return 0;
}

// Function to calculate processing time
int calculateProcessingTime(int batchSize) {
    if (batchSize < 0) {
        printf("Error: Batch size is negative\n");
        return -1;
    }
    
    // Simulate processing time calculation
    if (batchSize >= 0) {
        printf("Calculating processing time for batch size %d\n", batchSize);
        return batchSize;
    }
    
    return -1;
}


int main() {
    printf("Starting batch processing server...\n");
    
    // Receive network data
    char* networkData = receiveNetworkData();
    if (networkData == NULL) {
        printf("Failed to receive network data\n");
        return 1;
    }
    
    // Parse batch size from network data
    int batchSize = parseBatchSize(networkData);
    
    // Validate batch size
    int validatedBatchSize = validateBatchSize(batchSize);
    
    // Calculate processing time
    int processingTime = calculateProcessingTime(validatedBatchSize);
    
    
    // Create array with tainted value at position 0 and safe value at position 1
    int batchSizes[2];
    batchSizes[0] = validatedBatchSize;  // Tainted value
    batchSizes[1] = 10;                  // Safe value
    
    int totalItems = 500;  // Total items to process
    
    int safeItemsPerBatch = totalItems / batchSizes[1];
    printf("Safe items per batch: %d\n", safeItemsPerBatch);
    
    // SINK CWE 369
    int taintedItemsPerBatch = totalItems / batchSizes[0];
    printf("Tainted items per batch: %d\n", taintedItemsPerBatch);
    
    free(networkData);
    return 0;
}