#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define PORT 8080
#define BUFFER_SIZE 1024

// Example 1: Heap overflow using malloc and read
void vulnerable_heap_overflow1(int socket_fd) {
    char *buffer = malloc(10);  // Allocate only 10 bytes
    if (!buffer) {
        printf("Memory allocation failed\n");
        return;
    }
    
    printf("Buffer allocated at: %p\n", (void*)buffer);
    
    // SOURCE: Reading user input from socket
    // Vulnerable to heap overflow - reading more than allocated size
    read(socket_fd, buffer, 100);  // Reading 100 bytes into 10-byte buffer
    
    printf("Received data: %s\n", buffer);
    
    // SINK: Using the overflowed buffer
    char *destination = malloc(10);
    if (destination) {
        strcpy(destination, buffer);  // Vulnerable to heap overflow
        free(destination);
    }
    
    free(buffer);
}

// Example 2: Heap overflow using realloc
void vulnerable_heap_overflow2(int socket_fd) {
    char *buffer = malloc(10);  // Initial allocation of 10 bytes
    if (!buffer) {
        printf("Memory allocation failed\n");
        return;
    }
    
    printf("Initial buffer allocated at: %p\n", (void*)buffer);
    
    // SOURCE: Reading user input from socket
    // Vulnerable to heap overflow - reading more than allocated size
    read(socket_fd, buffer, 100);  // Reading 100 bytes into 10-byte buffer
    
    printf("Received data: %s\n", buffer);
    
    // SINK: Vulnerable realloc operation
    // Reducing buffer size after overflow has occurred
    buffer = realloc(buffer, 5);  // Vulnerable to heap overflow
    if (buffer) {
        printf("Buffer reallocated at: %p\n", (void*)buffer);
        free(buffer);
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
        vulnerable_heap_overflow1(new_socket);
        close(new_socket);

        // Accept new connection for second example
        printf("\nWaiting for second connection...\n");
        if ((new_socket = accept(server_fd, (struct sockaddr*)&address,
                      &addrlen)) < 0) {
            perror("accept");
            exit(EXIT_FAILURE);
        }

        // Test second example
        vulnerable_heap_overflow2(new_socket);
        close(new_socket);
    }

    // closing the listening socket
    close(server_fd);
    return 0;
}

/*
To test:
1. Create a Dockerfile in the same directory with the following content:
   FROM ubuntu:latest
   RUN apt update && apt install -y \
       build-essential \
       netcat-openbsd \
       vim \
       && rm -rf /var/lib/apt/lists/*
   WORKDIR /app
   COPY . /app
   CMD ["/bin/bash"]

2. Build the Docker image:
   docker build -t cwe122-test .

3. Start the container and mount your code:
   docker run -it --name cwe122-container -v "$PWD":/app cwe122-test

4. Inside the container, compile the code:
   gcc -o vuln-cwe122 plant-vuln-cwe122.c

5. Run the server (in first terminal):
   ./vuln-cwe122

6. Open a second terminal and access the container:
   docker exec -it cwe122-container /bin/bash

7. Test the vulnerabilities:
   - Test 1 (Heap overflow with malloc): python3 -c "print('A'*100)" | nc localhost 8080
   - Test 2 (Heap overflow with realloc): python3 -c "print('B'*200)" | nc localhost 8080

Note: This code is for educational purposes only.
DO NOT use in production environments.
The vulnerabilities demonstrated here can lead to:
- Heap corruption
- Memory leaks
- Potential system compromise
*/ 