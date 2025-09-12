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

// Function to parse credit deduction value
int parseCreditDeduction(char* data) {
    if (data == NULL) {
        printf("Error: No credit data received\n");
        return 0;
    }
    
    // Simulate credit parsing
    if (strlen(data) > 0) {
        printf("Parsing credit deduction: %s\n", data);
        return atoi(data);
    }
    
    return 0;
}

// Function to validate credit deduction
int validateCreditDeduction(int deduction) {
    if (deduction == 0) {
        printf("Error: Credit deduction cannot be 0\n");
        return 0;
    }
    
    // Simulate validation (but don't check for underflow)
    if (deduction != 0) {
        printf("Credit deduction %d appears valid\n", deduction);
        return deduction;
    }
    
    return 0;
}

// Function to process credit transaction (contains the sink)
int processCreditTransaction(int deduction) {
    if (deduction == 0) {
        printf("Error: Deduction is 0\n");
        return -1;
    }
    
    // Simulate credit processing
    if (deduction != 0) {
        printf("Processing credit transaction for deduction %d\n", deduction);
        
        int currentCredits = 100;  // Starting credits
        
        // SINK CWE 191
        int remainingCredits = deduction - currentCredits;
        printf("Remaining credits: %d\n", remainingCredits);
        return remainingCredits;
    }
    
    return -1;
}

// Function to update user account
void updateUserAccount(int deduction) {
    if (deduction == 0) {
        printf("Error: Invalid deduction for account update\n");
        return;
    }
    
    // Simulate account update
    if (deduction != 0) {
        printf("Updating user account with deduction %d\n", deduction);
        int newBalance = processCreditTransaction(deduction);
        printf("Account updated. New balance: %d\n", newBalance);
    }
}

int main() {
    printf("Starting credit processing server...\n");
    
    // Receive network data
    char* networkData = receiveNetworkData();
    if (networkData == NULL) {
        printf("Failed to receive network data\n");
        return 1;
    }
    
    // Parse credit deduction from network data
    int deduction = parseCreditDeduction(networkData);
    
    // Validate credit deduction
    int validatedDeduction = validateCreditDeduction(deduction);
    
    // Update user account
    updateUserAccount(validatedDeduction);
    
    free(networkData);
    return 0;
}