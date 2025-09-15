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

// Function to parse processing index and save to environment
int parseProcessingIndex(char* data, int** indexPtr) {
    if (data == NULL) {
        printf("Error: No processing data received\n");
        return -1;
    }
    
    // Simulate processing index parsing
    if (strlen(data) > 0) {
        printf("Parsing processing index: %s\n", data);
        int processingIndex = atoi(data);
        
        // Allocate memory for processing index
        *indexPtr = malloc(sizeof(int));
        if (*indexPtr != NULL) {
            **indexPtr = processingIndex;
            
            // Save to environment variable
            char envValue[32];
            snprintf(envValue, sizeof(envValue), "%d", processingIndex);
            setenv("PROCESSING_INDEX", envValue, 1);
            printf("Processing index saved to environment: %s\n", envValue);
            
            return processingIndex;
        }
    }
    
    return -1;
}

int main() {
    printf("Starting processing server...\n");
    
    // Receive network data
    char* networkData = receiveNetworkData();
    if (networkData == NULL) {
        printf("Failed to receive network data\n");
        return 1;
    }
    
    // Parse processing index from network data
    int* indexPtr = NULL;
    int processingIndex = parseProcessingIndex(networkData, &indexPtr);
    
    // Process network data
    printf("Processing network data: %s\n", networkData);
    
    // Set pointer to NULL after processing
    networkData = NULL;
    printf("Network data pointer set to NULL after processing\n");
    
    char* pointers[2];
    pointers[0] = networkData; 
    pointers[1] = malloc(10); 
    if (pointers[1] != NULL) {
        strcpy(pointers[1], "safe_data");  // Safe value
    }
    
    if (pointers[1] != NULL) {
        printf("Safe pointer value: %s\n", pointers[1]);
    }
    
    // SINK CWE 476
    char config = *pointers[0];
    printf("Tainted pointer value: %c\n", config);
    
    free(networkData);
    if (pointers[1] != NULL) {
        free(pointers[1]);
    }
    return 0;
}