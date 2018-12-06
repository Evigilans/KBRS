# Client-Server Communication protocol

Client-Server communication protocol contains only 1 request.


## Request 1

Request:
```json
{
  "type": "auth",
  "user": "user1",
  "password": "ffff",
  "rsa-key": "xxxx"
}
```

Successful Response:
```json
{
  "type": "auth",
  "status": "OK",
  "encryption_key": "yyyy""zzzz"
}
```
"encryption_key" is a session key encrypted with rsa public key
 
Fail Response:
```json
{
  "type": "auth",
  "status": "FAIL",
  "failureReason": "user or password is not valid"
}
```
### Request 2:

get the file

Client Request:
```json
{
    "type": "getFile",
    "fileName": "xyz.txt",
    "sessionId": "zzzz"
}
```
sessionId is a first 16 characters of rsa-encrypted encryption key

Successful Response:
```json
{
    "type": "getFile",
    "status": "OK",
    "content": "%encrypted_file%"
}
```
"content" is encrypted using AES session key.

File not found response
```json
{
    "type": "getFile",
    "status": "FAIL",
    "failureReason": "File not found"
}
```
