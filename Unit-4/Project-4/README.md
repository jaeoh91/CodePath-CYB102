# Slowloris DoS Attack & Nginx Mitigation
A hands-on lab demonstrating a real-world application-layer denial-of-service attack and implementing effective server-side defenses.

## Overview
This project implements and tests a Slowloris attack against a local nginx web server, then designs and validates mitigation rules to protect against it. Unlike volumetric DoS attacks that flood with raw traffic, Slowloris exhausts server resources by holding connections open with deliberately slow, incomplete HTTP requests — a technique that requires application-layer understanding to defend against.

## Key Findings
### Unprotected Server
- Slowloris easily accumulates ~500 held connections
- Connections plateau and sustain for the duration of the attack
- Server resource exhaustion prevents legitimate traffic from being served
- Very low bandwidth footprint (attacker sends minimal data)

### Protected Server (with nginx rules)
- Connection count repeatedly spikes and drops (sawtooth pattern) every ~5 seconds
- No sustained plateau — connections are forcibly closed before they accumulate
- Attacker forced into constant reconnects and header retransmits
- Network traffic increases slightly due to protocol churn, but resources remain bounded
- Legitimate traffic can still be served

## Mitigation Rules Implemented
Nginx configuration file: /etc/nginx/conf.d/default.conf

```nginx
limit_conn_zone $binary_remote_addr zone=addr:10m;
limit_req_zone  $binary_remote_addr zone=req:10m rate=30r/m;

server {
    listen 80 default_server;
    
    # Timeout aggressively against slow clients
    client_header_timeout 5s;
    client_body_timeout   5s;
    keepalive_timeout     5s;
    send_timeout         10s;
    
    # Connection and request rate limiting
    limit_conn addr 10;          # Max 10 concurrent connections per IP
    limit_req  zone=req burst=20 nodelay;  # Max 30 req/min, allow 20-req bursts
    
    # Block known attack tool user agents
    map $http_user_agent $bad_ua {
        default 0;
        ~*(curl|wget|python|libwww|nikto) 1;
    }
    if ($bad_ua) { return 403; }
}
```

## Why Each Rule Matters
| Rule | Defense Against |
| --- | --- |
| client_header_timeout 5s | Slowloris sends partial headers slowly; killed after 5s |
| client_body_timeout 5s | Attack relies on slow/incomplete request bodies |
| keepalive_timeout 5s | Limits idle connection persistence |
| limit_conn addr 10 | Caps total connections per attacker IP to 10 |
| limit_req burst=20 | Prevents rapid-fire request floods |

## Attack Vector
Slowloris opens many connections and sends HTTP request headers one byte at a time, keeping each connection alive with minimal bandwidth. The server allocates a worker process to each connection, quickly exhausting the worker_connections limit and making the server unavailable to legitimate clients.

Why it's hard to defend against at the network layer:

- Each individual packet looks like valid HTTP traffic
- No volumetric signature (low bandwidth = invisible to bandwidth-based DoS filters)
- Requires understanding HTTP protocol semantics (incomplete headers, slow sends)

## Technical Details
- Attack tool: Slowloris (500 concurrent sockets)
- Target: Local nginx server on 127.0.0.1:80
- Monitoring: Netdata dashboard (TCP connections + network traffic graphs)
- Server: nginx/1.18+ on Linux
- Test duration: 30+ seconds per attack