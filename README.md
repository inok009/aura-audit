# Aura-Audit

**Semantic IAM Policy Auditor** — identifies Functional Over-privilege by comparing
raw AWS IAM policies against the Semantic Intent of a role using a local SLM.

> Local-only. Zero external API calls. Runs entirely on your machine via Ollama.

## Architecture
```
CLI → Provider ABC → Ingestion (Boto3)
           ↓
    Tier 1: Heuristics Filter   (static, ~0ms)
    Tier 2: Context Engine      (semantic intent extraction)
    Tier 3: Inference Bridge    (async Ollama / Qwen 2.5 1.5B)
           ↓
    Findings Aggregator → JSON Formatter (ASFF schema)
```

## Requirements

- Python 3.11+
- [Ollama](https://ollama.ai) running locally
- AWS credentials (profile or environment variables)

## Setup
```bash
# 1. Pull the model
ollama pull qwen2.5:1.5b

# 2. Install aura-audit
pip install -e ".[dev]"

# 3. Verify connectivity
aura-audit health --profile your-profile --region us-east-1
```

## Usage
```bash
# Full semantic audit (all principal types)
aura-audit scan --profile prod --region us-east-1

# Fast mode — static checks only, no AI inference
aura-audit scan --profile prod --fast

# Audit a single role
aura-audit scan \
  --profile prod \
  --principal-arn arn:aws:iam::123456789012:role/ReadOnly-Billing

# Write to file, high severity only
aura-audit scan \
  --profile prod \
  --output findings.json \
  --min-severity HIGH

# Pipe to jq for quick CRITICAL triage
aura-audit scan --profile prod \
  | jq '.findings[] | select(.severity == "CRITICAL") | {title, resource: .resource.name}'
```

## Output Schema

All output follows an ASFF-inspired JSON schema:
```json
{
  "schema": "aura-audit/v1",
  "total_findings": 1,
  "findings": [
    {
      "id": "...",
      "severity": "HIGH",
      "finding_type": "SEMANTIC_MISMATCH",
      "title": "...",
      "description": "...",
      "resource": { "type": "AwsIamRole", "id": "...", "name": "..." },
      "ai_reasoning": "...",
      "remediation": { "recommendation": "..." },
      "confidence": 0.92,
      "tier": 3
    }
  ]
}
```

## Running Tests
```bash
pytest -v
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `AURA_OLLAMA_URL` | `http://localhost:11434` | Ollama endpoint |
| `AURA_OLLAMA_MODEL` | `qwen2.5:1.5b` | Model name |
| `AURA_OLLAMA_CONCURRENCY` | `4` | Parallel inference workers |
| `AWS_PROFILE` | `default` | AWS credentials profile |
| `AWS_DEFAULT_REGION` | `us-east-1` | Target region |