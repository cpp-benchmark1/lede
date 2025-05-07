#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define PORT 8080
#define BUFFER_SIZE 1024

// Example 1: Array index out of bounds with visible corruption
void vulnerable_buffer_bounds1(int socket_fd) {
    char buffer[10] = { 0 };  // Fixed size buffer
    char canary1[10] = "CANARY1";  // First buffer to detect corruption
    char canary2[10] = "CANARY2";  // Second buffer to detect corruption
    int index;
    
    printf("Initial state:\n");
    printf("Buffer:    [%s]\n", buffer);
    printf("Canary1:   [%s]\n", canary1);
    printf("Canary2:   [%s]\n", canary2);
    
    // SOURCE: Reading user input from socket
    read(socket_fd, &index, sizeof(index));
    
    printf("\nReceived index: %d\n", index);
    
    // SINK: Vulnerable to out-of-bounds write - no bounds checking
    strcpy(&buffer[index], "OVERFLOW_ATTACK");  // Vulnerable to out-of-bounds write
    
    printf("\nAfter overflow:\n");
    printf("Buffer:    [%s]\n", buffer);
    printf("Canary1:   [%s]\n", canary1);
    printf("Canary2:   [%s]\n", canary2);
}

// Example 2: memcpy with user-controlled size
void vulnerable_buffer_bounds2(int socket_fd) {
    char buffer[10] = { 0 };  // Fixed size buffer
    int size;
    
    // SOURCE: Reading user input from socket
    read(socket_fd, &size, sizeof(size));
    
    printf("Received size: %d\n", size);
    
    // SINK: Vulnerable to out-of-bounds write - no size validation
    memcpy(buffer, "AAAAAAAAAA", size);  // Vulnerable to out-of-bounds write
    
    printf("Buffer content: %s\n", buffer);
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
        vulnerable_buffer_bounds1(new_socket);
        close(new_socket);

        // Accept new connection for second example
        printf("\nWaiting for second connection...\n");
        if ((new_socket = accept(server_fd, (struct sockaddr*)&address,
                      &addrlen)) < 0) {
            perror("accept");
            exit(EXIT_FAILURE);
        }

        // Test second example
        vulnerable_buffer_bounds2(new_socket);
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
   docker build -t cwe787-test .

3. Start the container and mount your code:
   docker run -it --name cwe787-container -v "$PWD":/app cwe787-test

4. Inside the container, compile the code:
   gcc -o vuln-cwe787 plant-vuln-cwe787.c

5. Run the server (in first terminal):
   ./vuln-cwe787

6. Open a second terminal and access the container:
   docker exec -it cwe787-container /bin/bash

7. Test the vulnerabilities:
   - Test 1 (Array index out of bounds): echo -e "\x0f\x00\x00\x00" | nc localhost 8080
   - Test 2 (memcpy out of bounds): echo -e "\x14\x00\x00\x00" | nc localhost 8080

Note: This code is for educational purposes only.
DO NOT use in production environments.
The vulnerabilities demonstrated here can lead to:
- Buffer overflow
- Memory corruption
- Potential system compromise
*/ 