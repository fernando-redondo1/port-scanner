FROM python:3.11-slim

# Install tcpdump to provide necessary libraries for Scapy packet crafting
RUN apt-get update && \
    apt-get install -y tcpdump && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the project files into the container
COPY . .

# Install the Python package and its dependencies
RUN pip install --no-cache-dir .

# Run the command directly
ENTRYPOINT ["infoscann"]
