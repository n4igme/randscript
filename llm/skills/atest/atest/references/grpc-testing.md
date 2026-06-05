# gRPC Testing Reference

## Discovery & Enumeration

### Server Reflection
```bash
# List all services
grpcurl -plaintext $HOST:$PORT list
# Describe a service (shows all methods)
grpcurl -plaintext $HOST:$PORT describe <package.ServiceName>
# Describe a message type
grpcurl -plaintext $HOST:$PORT describe <package.MessageType>
# Full proto file reconstruction
grpcurl -plaintext $HOST:$PORT describe | grep -E "^(service|message|rpc)"
```

### Without Reflection
```bash
# If reflection is disabled, need .proto files
# Check for proto files in: source code, documentation, client SDKs
# Compile proto: protoc --descriptor_set_out=desc.pb *.proto
grpcurl -protoset desc.pb $HOST:$PORT list
```

### Port Discovery
```bash
# Common gRPC ports
nmap -p 50051,50052,9090,8443,443 $HOST
# gRPC over TLS
grpcurl $HOST:$PORT list  # (without -plaintext for TLS)
# gRPC-Web (HTTP/1.1 compatible)
curl -s -X POST "https://$HOST/package.Service/Method" \
  -H "Content-Type: application/grpc-web+proto"
```

## Authentication Testing

### No Authentication
```bash
# Call methods without any auth
grpcurl -plaintext -d '{}' $HOST:$PORT package.Service/GetUsers
# If returns data → no auth required
```

### Token-Based Auth
```bash
# Bearer token in metadata
grpcurl -plaintext -H "Authorization: Bearer $TOKEN" -d '{}' $HOST:$PORT package.Service/GetUsers
# API key in metadata
grpcurl -plaintext -H "x-api-key: $KEY" -d '{}' $HOST:$PORT package.Service/GetUsers
# Test with expired/invalid/empty token
grpcurl -plaintext -H "Authorization: Bearer invalid" -d '{}' $HOST:$PORT package.Service/GetUsers
```

### mTLS
```bash
# If mTLS required
grpcurl -cert client.crt -key client.key -cacert ca.crt $HOST:$PORT list
# Test without client cert (should fail)
grpcurl -cacert ca.crt $HOST:$PORT list
```

## Authorization Testing (BOLA/IDOR)

```bash
# Access other users' resources
grpcurl -plaintext -H "Authorization: Bearer $TOKEN_A" \
  -d '{"user_id": "USER_B_ID"}' $HOST:$PORT package.UserService/GetProfile

# Enumerate IDs
for id in $(seq 1 100); do
  grpcurl -plaintext -H "Authorization: Bearer $TOKEN" \
    -d "{\"id\": \"$id\"}" $HOST:$PORT package.Service/GetResource 2>&1 | grep -v "NotFound"
done

# Admin methods with regular user token
grpcurl -plaintext -H "Authorization: Bearer $USER_TOKEN" \
  -d '{}' $HOST:$PORT package.AdminService/ListAllUsers
```

## Input Validation & Injection

### Type Confusion
```bash
# Send wrong types (string where int expected)
grpcurl -plaintext -d '{"id": "not_a_number"}' $HOST:$PORT package.Service/Get
# Negative values
grpcurl -plaintext -d '{"amount": -1000}' $HOST:$PORT package.Service/Transfer
# Overflow values
grpcurl -plaintext -d '{"quantity": 2147483647}' $HOST:$PORT package.Service/Order
```

### SQL/NoSQL Injection
```bash
# In string fields
grpcurl -plaintext -d '{"name": "admin\" OR 1=1--"}' $HOST:$PORT package.Service/Search
grpcurl -plaintext -d '{"filter": "{\"$gt\": \"\"}"}' $HOST:$PORT package.Service/Find
```

### Large Message DoS
```bash
# Oversized message
python3 -c "print('{\"data\": \"' + 'A'*10000000 + '\"}')" | \
  grpcurl -plaintext -d @ $HOST:$PORT package.Service/Process
# Check for: message size limits, timeout behavior, memory exhaustion
```

### Streaming Abuse
```bash
# Client streaming — send unlimited messages
grpcurl -plaintext -d @ $HOST:$PORT package.Service/StreamUpload <<EOF
{"chunk": "data1"}
{"chunk": "data2"}
... (repeat thousands of times)
EOF
# Server streaming — request unbounded response
grpcurl -plaintext -d '{"limit": 999999999}' $HOST:$PORT package.Service/StreamData
```

## Information Disclosure

### Error Messages
```bash
# Trigger errors to extract info
grpcurl -plaintext -d '{"id": "nonexistent"}' $HOST:$PORT package.Service/Get
# Look for: stack traces, internal paths, database errors, service names
```

### Health Check
```bash
# Standard health check (often unauthenticated)
grpcurl -plaintext $HOST:$PORT grpc.health.v1.Health/Check
grpcurl -plaintext -d '{"service": ""}' $HOST:$PORT grpc.health.v1.Health/Check
```

### Metadata Leakage
```bash
# Response headers/trailers may leak info
grpcurl -plaintext -v -d '{}' $HOST:$PORT package.Service/Get 2>&1 | grep -i "trailer\|header"
# Look for: server version, internal routing, trace IDs
```

## gRPC-Web Testing

```bash
# gRPC-Web uses HTTP/1.1 — testable with curl/Burp
# Content-Type: application/grpc-web+proto (binary)
# Content-Type: application/grpc-web-text+proto (base64)

# Base64 encoded request
echo -n "AAAAAAV..." | base64 -d > request.bin
curl -s -X POST "https://$HOST/package.Service/Method" \
  -H "Content-Type: application/grpc-web+proto" \
  -H "X-Grpc-Web: 1" \
  --data-binary @request.bin

# Use grpcwebproxy or Envoy to convert between gRPC and gRPC-Web for testing
```

## Tools

| Tool | Purpose |
|------|---------|
| grpcurl | CLI for gRPC (like curl for REST) |
| grpcui | Web UI for gRPC exploration |
| protobuf-inspector | Decode raw protobuf without .proto |
| mitmproxy | Intercept gRPC traffic |
| Postman | gRPC client with GUI |
| BloomRPC | gRPC GUI client |
| buf | Proto linting and breaking change detection |

## Severity Matrix

| Finding | Severity | Condition |
|---------|----------|-----------|
| Reflection enabled (prod) | Low | Information disclosure |
| Unauthenticated method access | High-Critical | Depends on method sensitivity |
| BOLA via user_id parameter | High | Cross-user data access |
| No message size limit | Medium | DoS potential |
| Streaming without limits | Medium | Resource exhaustion |
| SQL injection in fields | Critical | Data breach |
| Missing mTLS (internal service) | Medium | Lateral movement enabler |
