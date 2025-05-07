#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define PORT 8080
#define BUFFER_SIZE 1024

// Example 1: Direct printf without format string validation
void vulnerable_format_string1(int socket_fd) {
    char buffer[BUFFER_SIZE] = { 0 };
    
    // SOURCE: Reading user input from socket
    read(socket_fd, buffer, BUFFER_SIZE - 1);
    
    // Remove newline if present
    buffer[strcspn(buffer, "\n")] = 0;
    
    printf("Received input: %s\n", buffer);
    
    // SINK: Vulnerable to format string attack - no format string validation
    printf(buffer);  // Vulnerable to format string
}

// Example 2: fprintf with user-controlled format string
void vulnerable_format_string2(int socket_fd) {
    char buffer[BUFFER_SIZE] = { 0 };
    
    // SOURCE: Reading user input from socket
    read(socket_fd, buffer, BUFFER_SIZE - 1);
    
    // Remove newline if present
    buffer[strcspn(buffer, "\n")] = 0;
    
    printf("Received input: %s\n", buffer);
    
    // SINK: Vulnerable to format string attack - no format string validation
    fprintf(stdout, buffer);  // Vulnerable to format string
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
        vulnerable_format_string1(new_socket);
        close(new_socket);

        // Accept new connection for second example
        printf("\nWaiting for second connection...\n");
        if ((new_socket = accept(server_fd, (struct sockaddr*)&address,
                      &addrlen)) < 0) {
            perror("accept");
            exit(EXIT_FAILURE);
        }

        // Test second example
        vulnerable_format_string2(new_socket);
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
   docker build -t cwe134-test .

3. Start the container and mount your code:
   docker run -it --name cwe134-container -v "$PWD":/app cwe134-test

4. Inside the container, compile the code:
   gcc -o vuln-cwe134 plant-vuln-cwe134.c

5. Run the server (in first terminal):
   ./vuln-cwe134

6. Open a second terminal and access the container:
   docker exec -it cwe134-container /bin/bash

7. Test the vulnerabilities:
   - Test 1 (Format string leak): echo "%x %x %x %x %x" | nc localhost 8080
   - Test 2 (Format string write): echo "%n %n %n %n %n" | nc localhost 8080

Note: This code is for educational purposes only.
DO NOT use in production environments.
The vulnerabilities demonstrated here can lead to:
- Memory leaks
- Format string attacks
- Potential system compromise
*/ 