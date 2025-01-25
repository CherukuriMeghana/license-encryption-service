#Secure License Encryption Service

A Go-based application that generates license keys, uses AES encryption for file protection, and provides a secure link with an expiry time to access the decrypted file.


## Installation

1. Install Go (If not installed already) [Go Installation Guide](https://golang.org/doc/install)

2. Navigate to project directory

3. Install project dependencies
    ```bash
    go get
    ```
4. Generate Swagger documentation
    ```bash
    swag init
    ```
4. Once dependencies are installed, build and run the application:
    ```bash
    go build
    go run .
    ```
5. The server will be running on http://localhost:3000.

You can access the Swagger UI at `[http://localhost:3000/swagger/index.html](http://localhost:3000/swagger/index.html)` to view the API documentation and interact with the endpoints.

## Running UT

To run the unit tests for the project, use the following command:
 ```bash
    go test
```
