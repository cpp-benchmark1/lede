FROM ubuntu:latest

# Install essential tools
RUN apt update && apt install -y \
    build-essential \
    netcat-openbsd \
    vim \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy local files into container
COPY . /app

# Default to interactive shell
CMD ["/bin/bash"]

