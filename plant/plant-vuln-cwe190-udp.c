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

// Function to parse score value
int parseScoreValue(char* data) {
    if (data == NULL) {
        printf("Error: No score data received\n");
        return -1;
    }
    
    // Simulate score parsing
    if (strlen(data) > 0) {
        printf("Parsing score data: %s\n", data);
        return atoi(data);
    }
    
    return -1;
}

// Function to validate score
int validateScore(int score) {
    if (score < 0) {
        printf("Error: Invalid score value\n");
        return -1;
    }
    
    // Simulate validation (but don't check for overflow)
    if (score >= 0) {
        printf("Score %d appears valid\n", score);
        return score;
    }
    
    return -1;
}

// Function to calculate bonus points
int calculateBonusPoints(int score) {
    if (score < 0) {
        printf("Error: Score is negative\n");
        return -1;
    }
    
    // Simulate bonus calculation
    if (score >= 0) {
        printf("Calculating bonus points for score %d\n", score);
        return score * 1;
    }
    
    return -1;
}


int main() {
    printf("Starting ranking server...\n");
    
    // Receive network data
    char* networkData = receiveNetworkData();
    if (networkData == NULL) {
        printf("Failed to receive network data\n");
        return 1;
    }
    
    // Parse score from network data
    int score = parseScoreValue(networkData);
    
    // Validate score
    int validatedScore = validateScore(score);
    
    // Calculate bonus points
    int bonusPoints = calculateBonusPoints(validatedScore);
    
    // Create array with tainted value at position 0 and safe value at position 1
    int scores[2];
    scores[0] = validatedScore;  // Tainted value
    scores[1] = 50;              // Safe value
    
    int safeTotal = scores[1] + 100 + 1000;
    printf("Safe total points: %d\n", safeTotal);
    
    // SINK CWE 190
    int taintedTotal = scores[0] + 1000;
    printf("Tainted total points: %d\n", taintedTotal);
    
    free(networkData);
    return 0;
}