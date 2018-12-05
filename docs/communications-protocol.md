# Client-Server Communication protocol

Client-Server communication protocol contains only 1 request.

Sample:

Client Request:
```json
{
    "type": "hello",
    "rsa-key": "xxxx",
    "fileName": "xyz.txt"
}
```

Successful Response:
```json
{
    "type": "hello",
    "status": "OK",
    "content": "%encrypted_file%",
    "encrypted_key": "bla-bla"
}
```

File not found response
```json
{
    "type": "hello",
    "status": "FAIL",
    "failureReason": "File not found"
}
```