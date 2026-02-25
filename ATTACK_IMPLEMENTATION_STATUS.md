# CICIDS2018 Attack Implementation - Status and Required Changes

## Current State vs. Required Specification

### ✅ CORRECT
- SO_RCVBUF = 8192 (recently fixed)
- TCP_NODELAY = 1 (correct)
- Fwd Seg Size Min = 32 (with timestamps)
- DoS/DDoS attack types are identified

### ❌ NEEDS FIXING

#### 1. HULK Attack
**Issue:** Missing throttle delays between new connections
**Spec:** 2.0-3.0 second delay between NEW connections
**Current:** Likely too fast / no delay
**Fix:** Add `time.sleep(random.uniform(2.0, 3.0))` after each connection closes

#### 2. Slowloris Attack  
**Issue:** Sending COMPLETE headers (ends with \r\n\r\n)
**Spec:** NEVER send final \r\n\r\n - keep headers incomplete to hold server connection
**Current:** Missing the incomplete header concept
**Fix:** 
- Send initial headers WITHOUT the final blank line
- Every 10-15 seconds, send additional header like: `X-a-{random}: {random}\r\n` 
- Never finalize the request with empty line

#### 3. GoldenEye
**Issue:** Request method distribution unclear
**Spec:** 60% GET, 40% POST, NEW connection per request, 2-3 sec throttle
**Fix:** Ensure proper GET/POST ratio and throttle

#### 4. SlowHTTPTest
**Issue:** May not drip body data slowly enough
**Spec:** 
- Keep-alive, announce huge Content-Length (100k-500k)
- Drip 1-10 random bytes per chunk
- Wait 1-3 seconds between chunks
- Maintain 50 open sockets
**Fix:** Implement proper slow drip mechanism

#### 5. LOIC-HTTP
**Issue:** Requests per connection may be too high
**Spec:** 1-5 requests per keep-alive connection (NOT 20-200)
**Current:** May have too many requests per connection
**Fix:** Limit kept-alive requests to 1-5 per connection

#### 6. LOIC-UDP
**Issue:** Payload sizes may not vary correctly
**Spec:** 512, 1024, or 1400 bytes randomly selected per packet
**Fix:** Ensure proper payload variation

---

## Implementation Priority

1. **CRITICAL:** Fix Slowloris - incomplete headers are essential
2. **HIGH:** Add throttle delays to HULK/GoldenEye (2-3 sec between connections)
3. **HIGH:** Fix LOIC-HTTP request distribution (1-5 per connection)
4. **MEDIUM:** Implement SlowHTTPTest slow drip properly
5. **MEDIUM:** Verify LOIC-UDP payload selection
6. **LOW:** Fine-tune timing parameters

---

## Key Insight

The 2-3 second throttle delay is CRITICAL for CICIDS2018 attacks because:
- Without delays, attacks generate too many packets per second
- This causes network stack buffering effects
- Buffering changes TCP window behavior and packet timings
- With delays, attacks match the original HULK/GoldenEye tool behavior
- This is why your Init Fwd Win Byts was 18910 (buffering happened)
- With proper throttle, it should be ~8192

The Slowloris incomplete headers are critical because:
- They force the server to keep connections open waiting for completion
- This generates the characteristic "long flow duration" signature
- Complete headers would cause immediate response/close cycle
