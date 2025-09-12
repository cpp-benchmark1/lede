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

// Function to parse batch size and save to environment
int parseBatchSize(char* data) {
    if (data == NULL) {
        printf("Error: No batch data received\n");
        return -1;
    }
    
    // Simulate batch size parsing
    if (strlen(data) > 0) {
        printf("Parsing batch size: %s\n", data);
        int batchSize = atoi(data);
        
        // Save to environment variable for processing
        char envValue[32];
        snprintf(envValue, sizeof(envValue), "%d", batchSize);
        setenv("BATCH_SIZE", envValue, 1);
        printf("Batch size saved to environment: %s\n", envValue);
        
        return batchSize;
    }
    
    return -1;
}

// Function to validate batch configuration and save to file
int validateBatchConfig(int batchSize) {
    if (batchSize < 0) {
        printf("Error: Invalid batch size\n");
        return -1;
    }
    
    // Simulate validation
    if (batchSize >= 0) {
        printf("Batch size %d appears valid\n", batchSize);
        
        // Save configuration to file
        FILE* configFile = fopen("/tmp/batch_config.txt", "w");
        if (configFile != NULL) {
            fprintf(configFile, "batch_size=%d\n", batchSize);
            fclose(configFile);
            printf("Batch configuration saved to file\n");
        }
        
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
    
    // Validate batch configuration
    int validatedBatchSize = validateBatchConfig(batchSize);
    
    
    // Create array with tainted value at position 0 and safe value at position 1
    int batchSizes[2];
    batchSizes[0] = validatedBatchSize;  // Tainted value
    batchSizes[1] = 5;                   // Safe value
    
    for (int i = 0; i < batchSizes[1]; i++) {
        printf("  Processing item %d\n", i);
        
        // Set item environment variable
        char envVar[32];
        snprintf(envVar, sizeof(envVar), "ITEM_%d", i);
        setenv(envVar, "processed", 1);
    }
    
    // SINK CWE 606
    for (int i = 0; i < batchSizes[0]; i++) {
        printf("  Processing item %d\n", i);
        
        // Set item environment variable
        char envVar[32];
        snprintf(envVar, sizeof(envVar), "ITEM_%d", i);
        setenv(envVar, "processed", 1);
    }
    
    free(networkData);
    return 0;
}