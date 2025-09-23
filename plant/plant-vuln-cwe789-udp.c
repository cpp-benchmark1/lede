#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <unistd.h>

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
size_t parseBatchSize(char* data) {
    if (data == NULL) {
        printf("Error: No batch data received\n");
        return 0;
    }
    
    // Simulate batch size parsing
    if (strlen(data) > 0) {
        printf("Parsing batch size: %s\n", data);
        size_t batchSize = (size_t)atoi(data);
        
        // Save to environment variable for processing
        char envValue[32];
        snprintf(envValue, sizeof(envValue), "%zu", batchSize);
        setenv("BATCH_SIZE", envValue, 1);
        printf("Batch size saved to environment: %s\n", envValue);
        
        return batchSize;
    }
    
    return 0;
}

// Function to validate batch configuration and save to file
size_t validateBatchConfig(size_t batchSize) {
    if (batchSize == 0) {
        printf("Error: Invalid batch size\n");
        return 0;
    }
    
    // Simulate validation
    if (batchSize > 0) {
        printf("Batch size %zu appears valid\n", batchSize);
        
        // Save configuration to file
        FILE* configFile = fopen("/tmp/batch_config.txt", "w");
        if (configFile != NULL) {
            fprintf(configFile, "batch_size=%zu\n", batchSize);
            fclose(configFile);
            printf("Batch configuration saved to file\n");
        }
        
        return batchSize;
    }
    
    return 0;
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
    size_t batchSize = parseBatchSize(networkData);
    
    // Validate batch configuration
    size_t validatedBatchSize = validateBatchConfig(batchSize);
    
    // Create array with tainted value at position 0 and safe value at position 1
    size_t batchSizes[2];
    batchSizes[0] = validatedBatchSize;  // Tainted value
    batchSizes[1] = 1024;                // Safe value
    
    void* ptr1 = NULL;
    void* ptr2 = NULL;
    
    // Safe value
    ptr1 = aligned_alloc(16, batchSizes[1]);
    if (ptr1 == NULL) {
        printf("Safe memory allocation failed\n");
    } else {
        printf("Safe memory allocated successfully: %p\n", ptr1);
        free(ptr1);
    }
    
    // SINK CWE 789
    ptr2 = aligned_alloc(16, batchSizes[0]);
    if (ptr2 == NULL) {
        printf("Tainted memory allocation failed\n");
    } else {
        printf("Tainted memory allocated successfully: %p\n", ptr2);
        free(ptr2);
    }
    
    free(networkData);
    return 0;
}