#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define PORT 8080
#define BUFFER_SIZE 1024

// Example 1: Direct system command execution
void vulnerable_command_injection1(int socket_fd) {
    char command[BUFFER_SIZE] = { 0 };
    
    // SOURCE: Reading user input from socket
    read(socket_fd, command, BUFFER_SIZE - 1);
    
    // Remove newline if present
    command[strcspn(command, "\n")] = 0;
    
    printf("Received command: %s\n", command);
    
    // SINK: Vulnerable to command injection - no input validation
    system(command);  // Vulnerable to command injection
}

// Example 2: Command execution using popen
void vulnerable_command_injection2(int socket_fd) {
    char command[BUFFER_SIZE] = { 0 };
    char buffer[BUFFER_SIZE] = { 0 };
    
    // SOURCE: Reading user input from socket
    read(socket_fd, command, BUFFER_SIZE - 1);
    
    // Remove newline if present
    command[strcspn(command, "\n")] = 0;
    
    printf("Received command: %s\n", command);
    
    // SINK: Vulnerable to command injection - no input validation
    FILE *fp = popen(command, "r");  // Vulnerable to command injection
    if (fp) {
        // Read command output
        while (fgets(buffer, BUFFER_SIZE, fp)) {
            printf("Command output: %s", buffer);
            write(socket_fd, buffer, strlen(buffer));
        }
        pclose(fp);
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
        vulnerable_command_injection1(new_socket);
        close(new_socket);

        // Accept new connection for second example
        printf("\nWaiting for second connection...\n");
        if ((new_socket = accept(server_fd, (struct sockaddr*)&address,
                      &addrlen)) < 0) {
            perror("accept");
            exit(EXIT_FAILURE);
        }

        // Test second example
        vulnerable_command_injection2(new_socket);
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
   docker build -t cwe78-test .

3. Start the container and mount your code:
   docker run -it --name cwe78-container -v "$PWD":/app cwe78-test

4. Inside the container, compile the code:
   gcc -o vuln-cwe78 plant-vuln-cwe78.c

5. Run the server (in first terminal):
   ./vuln-cwe78

6. Open a second terminal and access the container:
   docker exec -it cwe78-container /bin/bash

7. Test the vulnerabilities:
   - Test 1 (System command injection): echo "ls; cat /etc/passwd" | nc localhost 8080
   - Test 2 (Popen command injection): echo "ls && cat /etc/shadow" | nc localhost 8080

Note: This code is for educational purposes only.
DO NOT use in production environments.
The vulnerabilities demonstrated here can lead to:
- Unauthorized command execution
- System compromise
- Data theft
*/ 