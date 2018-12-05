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

Response:
```json
{
    "type": "hello",
    "content": "%encrypted_file%",
    "encrypted_key": "bla-bla"
}
```
