# Image source is located at https://github.com/nzyuko/fox3-docker/blob/main/Dockerfile
# Image repository is at https://hub.docker.com/r/ne0nd0g/fox3-base
FROM ne0nd0g/fox3-base:v1.5.0

# Build the Docker image first
#  > sudo docker build -t fox3-server .

# To start the Fox3 Server and interact with it, run:
#  > sudo docker run -p 50051:50051 -p 443:443 -v ~/fox3:/opt/fox3/data fox3-server:latest

# Port 50051 is the gRPC port for the Fox3 CLI to connect to
# Port 443 is the port where a Fox3 listener will bind to
# Run the docker image with extra '-p' arguments to expose more ports for Fox3 listeners to bind to

WORKDIR /opt/fox3

ENTRYPOINT ["./fox3Server-Linux-x64", "-addr", "0.0.0.0:50051"]
