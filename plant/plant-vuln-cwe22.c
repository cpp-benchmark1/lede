#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define PORT 8080
#define BUFFER_SIZE 1024

// Example 1: Direct file read without path validation
void vulnerable_path_traversal1(int socket_fd) {
    char filename[BUFFER_SIZE] = { 0 };
    char buffer[BUFFER_SIZE] = { 0 };
    
    // SOURCE: Reading user input from socket
    read(socket_fd, filename, BUFFER_SIZE - 1);
    
    // Remove newline if present
    filename[strcspn(filename, "\n")] = 0;
    
    printf("Attempting to read file: %s\n", filename);
    
    // SINK: Vulnerable to path traversal - no validation of filename
    FILE *fp = fopen(filename, "r");
    if (fp) {
        printf("File opened successfully. Contents:\n");
        while (fgets(buffer, BUFFER_SIZE, fp)) {
            // Print to server console
            printf("%s", buffer);
            // Echo file contents back to client
            write(socket_fd, buffer, strlen(buffer));
        }
        fclose(fp);
    } else {
        printf("Failed to open file: %s\n", filename);
        // Send error message if file not found
        write(socket_fd, "File not found\n", 14);
    }
}

// Example 2: File rename with path traversal
void vulnerable_path_traversal2(int socket_fd) {
    char input_buffer[BUFFER_SIZE] = { 0 };
    char old_path[BUFFER_SIZE/2] = { 0 };
    char new_path[BUFFER_SIZE/2] = { 0 };
    
    // SOURCE: Reading user input from socket (expects "oldfile|newfile" format)
    read(socket_fd, input_buffer, BUFFER_SIZE - 1);
    
    // Remove newline if present
    input_buffer[strcspn(input_buffer, "\n")] = 0;
    
    // Parse input - split by '|' delimiter
    char *delimiter = strchr(input_buffer, '|');
    if (delimiter) {
        *delimiter = '\0';
        strncpy(old_path, input_buffer, sizeof(old_path) - 1);
        strncpy(new_path, delimiter + 1, sizeof(new_path) - 1);
    } else {
        write(socket_fd, "Invalid format. Use: oldfile|newfile\n", 37);
        return;
    }
    
    printf("Attempting to rename: %s -> %s\n", old_path, new_path);
    
    // SINK: Vulnerable to path traversal - no validation of old_path or new_path
    int result = rename(old_path, new_path);
    
    if (result == 0) {
        printf("File renamed successfully\n");
        write(socket_fd, "File renamed successfully\n", 26);
    } else {
        printf("Failed to rename file\n");
        write(socket_fd, "Failed to rename file\n", 22);
    }
}

int main(int argc, char const* argv[]) {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    socklen_t addrlen = sizeof(address);

    // Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Forcefully attaching socket to the port 8080
    if (setsockopt(server_fd, SOL_SOCKET,
                   SO_REUSEADDR | SO_REUSEPORT, &opt,
                   sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Forcefully attaching socket to the port 8080
    if (bind(server_fd, (struct sockaddr*)&address,
             sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d...\n", PORT);

    while(1) {
        printf("\nWaiting for connection...\n");
        if ((new_socket = accept(server_fd, (struct sockaddr*)&address,
                      &addrlen)) < 0) {
            perror("accept");
            exit(EXIT_FAILURE);
        }

        // Test first example
        vulnerable_path_traversal1(new_socket);
        close(new_socket);

        // Accept new connection for second example
        printf("\nWaiting for second connection...\n");
        if ((new_socket = accept(server_fd, (struct sockaddr*)&address,
                      &addrlen)) < 0) {
            perror("accept");
            exit(EXIT_FAILURE);
        }

        // Test second example
        vulnerable_path_traversal2(new_socket);
        close(new_socket);
    }

    // closing the listening socket
    close(server_fd);
    return 0;
}

/*
To test:
1. Compile: gcc -o vuln-cwe22 plant-vuln-cwe22.c
2. Run: ./vuln-cwe22
3. In another terminal:
   - Test 1 (File read): echo "../../etc/passwd" | nc localhost 8080
   - Test 2 (File rename): echo "test.txt|../../etc/malicious.txt" | nc localhost 8080

Note: This code is for educational purposes only.
DO NOT use in production environments.
The vulnerabilities demonstrated here can lead to:
- Unauthorized file access
- Path traversal attacks
- File system manipulation outside intended directories
- Potential system compromise
*/ 