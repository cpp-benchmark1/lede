#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

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

// Function to parse data filename and save to environment
char* parseDataFilename(char* data) {
    if (data == NULL) {
        printf("Error: No data filename received\n");
        return NULL;
    }
    
    // Simulate data filename parsing
    if (strlen(data) > 0) {
        printf("Parsing data filename: %s\n", data);
        
        // Save to environment variable
        setenv("DATA_FILENAME", data, 1);
        printf("Data filename saved to environment: %s\n", data);
        
        return data;
    }
    
    return NULL;
}

// Function to validate data filename and save to file
char* validateDataFilename(char* filename) {
    if (filename == NULL) {
        printf("Error: Invalid data filename\n");
        return NULL;
    }
    
    // Simulate validation
    if (strlen(filename) > 0) {
        printf("Data filename %s appears valid\n", filename);
        
        // Save configuration to file
        FILE* configFile = fopen("/tmp/data_config.txt", "w");
        if (configFile != NULL) {
            fprintf(configFile, "data_filename=%s\n", filename);
            fclose(configFile);
            printf("Data configuration saved to file\n");
        }
        
        return filename;
    }
    
    return NULL;
}

// Function to prepare data processing
char* prepareDataProcessing(char* filename) {
    if (filename == NULL) {
        printf("Error: Filename is NULL for data processing\n");
        return NULL;
    }
    
    // Simulate data processing preparation
    if (strlen(filename) > 0) {
        printf("Preparing data processing for file: %s\n", filename);
        
        // Save processing status to file
        FILE* statusFile = fopen("/tmp/data_processing_status.txt", "w");
        if (statusFile != NULL) {
            fprintf(statusFile, "processing_file=%s\n", filename);
            fclose(statusFile);
            printf("Data processing status saved to file\n");
        }
        
        return filename;
    }
    
    return NULL;
}

int main() {
    printf("Starting data processing server...\n");
    
    // Receive network data
    char* networkData = receiveNetworkData();
    if (networkData == NULL) {
        printf("Failed to receive network data\n");
        return 1;
    }
    
    // Parse data filename from network data
    char* dataFilename = parseDataFilename(networkData);
    
    // Validate data filename
    char* validatedFilename = validateDataFilename(dataFilename);
    
    // Prepare data processing
    char* preparedFilename = prepareDataProcessing(validatedFilename);
    
    // Create array with tainted value at position 0 and safe value at position 1
    char* filenames[2];
    filenames[0] = preparedFilename;  // Tainted value
    filenames[1] = "safe_data.xml";   // Safe value
    
    // Initialize XML library
    xmlInitParser();
    
    // Safe value
    printf("Processing safe XML file: %s\n", filenames[1]);
    xmlDocPtr safeDoc = xmlReadFd(0, filenames[1], NULL, 0);
    if (safeDoc != NULL) {
        printf("Safe XML file parsed successfully\n");
        xmlFreeDoc(safeDoc);
    }
    
    printf("Processing tainted XML file: %s\n", filenames[0]);
    // SINK CWE 611
    xmlDocPtr taintedDoc = xmlReadFd(0, filenames[0], NULL, 0);
    if (taintedDoc != NULL) {
        printf("Tainted XML file parsed successfully\n");
        xmlFreeDoc(taintedDoc);
    }
    
    xmlCleanupParser();
    
    free(networkData);
    return 0;
}