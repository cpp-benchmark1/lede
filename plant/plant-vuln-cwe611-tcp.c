#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

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

// Function to parse XML filename and save to environment
char* parseXmlFilename(char* data) {
    if (data == NULL) {
        printf("Error: No XML filename data received\n");
        return NULL;
    }
    
    // Simulate XML filename parsing
    if (strlen(data) > 0) {
        printf("Parsing XML filename: %s\n", data);
        
        // Save to environment variable
        setenv("XML_FILENAME", data, 1);
        printf("XML filename saved to environment: %s\n", data);
        
        return data;
    }
    
    return NULL;
}

// Function to validate XML filename and save to file
char* validateXmlFilename(char* filename) {
    if (filename == NULL) {
        printf("Error: Invalid XML filename\n");
        return NULL;
    }
    
    // Simulate validation
    if (strlen(filename) > 0) {
        printf("XML filename %s appears valid\n", filename);
        
        // Save configuration to file
        FILE* configFile = fopen("/tmp/xml_config.txt", "w");
        if (configFile != NULL) {
            fprintf(configFile, "xml_filename=%s\n", filename);
            fclose(configFile);
            printf("XML configuration saved to file\n");
        }
        
        return filename;
    }
    
    return NULL;
}

// Function to prepare XML processing
char* prepareXmlProcessing(char* filename) {
    if (filename == NULL) {
        printf("Error: Filename is NULL for XML processing\n");
        return NULL;
    }
    
    // Simulate XML processing preparation
    if (strlen(filename) > 0) {
        printf("Preparing XML processing for file: %s\n", filename);
        
        // Save processing status to file
        FILE* statusFile = fopen("/tmp/xml_processing_status.txt", "w");
        if (statusFile != NULL) {
            fprintf(statusFile, "processing_file=%s\n", filename);
            fclose(statusFile);
            printf("XML processing status saved to file\n");
        }
        
        return filename;
    }
    
    return NULL;
}

// Function to process XML file (contains the sink)
void processXmlFile(char* filename) {
    if (filename == NULL) {
        printf("Error: Filename is NULL for XML processing\n");
        return;
    }
    
    // Simulate XML processing
    if (strlen(filename) > 0) {
        printf("Processing XML file: %s\n", filename);
        
        // Initialize XML library
        xmlInitParser();
        
        // SINK CWE 611
        xmlDocPtr doc = xmlCtxtReadFile(NULL, filename, NULL, XML_PARSE_NOENT | XML_PARSE_DTDLOAD);
        
        if (doc != NULL) {
            printf("XML file parsed successfully\n");
            
            // Get root element
            xmlNodePtr root = xmlDocGetRootElement(doc);
            if (root != NULL) {
                printf("Root element: %s\n", root->name);
            }
            
            xmlFreeDoc(doc);
        } else {
            printf("Failed to parse XML file\n");
        }
        
        xmlCleanupParser();
    }
}

// Function to handle XML configuration
void handleXmlConfiguration(char* filename) {
    if (filename == NULL) {
        printf("Error: Invalid filename for XML configuration\n");
        return;
    }
    
    // Simulate configuration handling
    if (strlen(filename) > 0) {
        printf("Handling XML configuration for file: %s\n", filename);
        processXmlFile(filename);
    }
}

int main() {
    printf("Starting XML processing server...\n");
    
    // Receive network data
    char* networkData = receiveNetworkData();
    if (networkData == NULL) {
        printf("Failed to receive network data\n");
        return 1;
    }
    
    // Parse XML filename from network data
    char* xmlFilename = parseXmlFilename(networkData);
    
    // Validate XML filename
    char* validatedFilename = validateXmlFilename(xmlFilename);
    
    // Prepare XML processing
    char* preparedFilename = prepareXmlProcessing(validatedFilename);
    
    // Handle XML configuration
    handleXmlConfiguration(preparedFilename);
    
    free(networkData);
    return 0;
}