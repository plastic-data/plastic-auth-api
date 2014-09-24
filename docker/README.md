# What is Plastic-Auth-API?

Plastic-Auth is an authentication service for [Plastic-Data](https://github.com/plastic-data).

[Plastic-Auth-API](https://github.com/plastic-data/plastic-auth-api) is the Git repository of the web API of Plastic-Auth.

This Docker image contains a working Plastic-Auth-API web service.

# How to use this image

## Start a MongoDB Docker

```
docker pull mongo:latest
docker run --name plastic-mongo -d mongo:latest
```

## Start Plastic-Auth-API

```
docker run -d --link plastic-mongo:mongo --name plastic-auth-api -p 2040:2040 plastic_data/plastic-auth-api:latest
```
