# CyberTwin ML API Guide

This guide is only for ML model inference integration.

## 1) Run the ML API locally

Install dependencies:

```bash
pip install -r requirements.txt
```

Start server:

```bash
python3 api.py
```

Default base URL:

```text
http://localhost:8000
```

If port 8000 is busy, the API auto-selects the next available port.

## 2) ML Endpoints Only

- `GET /health` -> API health + loaded model info
- `GET /metadata` -> model schema (`required_fields`, `input_schema`)
- `POST /predict` -> score one telemetry record
- `POST /predict/batch` -> score multiple telemetry records

## 3) Frontend Base Config

```js
const API_BASE_URL = "http://localhost:8000";
```

## 4) Frontend Call Examples

### A) Single prediction

```js
async function predictOne(record) {
  const res = await fetch(`${API_BASE_URL}/predict`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ record })
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Predict failed: ${res.status}`);
  }

  return res.json();
}
```

### B) Batch prediction

```js
async function predictBatch(records) {
  const res = await fetch(`${API_BASE_URL}/predict/batch`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ records })
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Batch predict failed: ${res.status}`);
  }

  return res.json();
}
```

## 5) Required Input Fields

Get required model input fields from:

`GET /metadata`

Use `required_fields` and `input_schema` to build request payloads.

Single request body:

```json
{
  "record": {
    "dur": 0.1,
    "proto": "tcp"
  }
}
```

Batch request body:

```json
{
  "records": [
    {"dur": 0.1, "proto": "tcp"},
    {"dur": 0.2, "proto": "udp"}
  ]
}
```

Note: each record must contain all fields listed in `required_fields`.

## 6) Prediction Fields to Render

Read these fields from each prediction result:

- `is_malicious`
- `predicted_attack`
- `malicious_probability`
- `attack_confidence`
- `anomaly_probability`
- `risk_score`
- `risk_band`
- `recommended_action`

## 7) Error Handling

- `200` success
- `400` invalid payload / missing required fields
- `500` model load/runtime issue

Error body:

```json
{
  "detail": "..."
}
```

## 8) Quick Checks

```bash
curl http://localhost:8000/health
curl http://localhost:8000/metadata
curl -X POST http://localhost:8000/predict \
  -H "Content-Type: application/json" \
  -d '{"record":{}}'
```
