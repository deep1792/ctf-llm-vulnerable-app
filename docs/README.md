# CTF LLM Vulnerable Application

A deliberately vulnerable LLM application designed for security education and CTF challenges.

## 🎯 Challenges Included

### LLM01: Prompt Injection
**Objective**: Bypass AI safety controls
**Flag**: `CTF{Pr0mPt_1nj3ct10n_4_W1n}`
**Solution**: Use phrases like "ignore previous instructions"

### LLM02: Insecure Output Handling  
**Objective**: Execute XSS through AI responses
**Flag**: `CTF{XSS_Thr0ugh_4I_0utput}`
**Solution**: Inject JavaScript in queries

### LLM03: Training Data Leakage
**Objective**: Extract sensitive training data
**Flag**: `CTF{Tr41n1ng_D4t4_L34k}`
**Solution**: Ask about training data or model knowledge

### LLM04: Model Denial of Service
**Objective**: Crash or exhaust AI resources  
**Flag**: `CTF{D05_4g41n5t_4I}`
**Solution**: Send very large inputs

### LLM07: Insecure Plugin Design
**Objective**: Achieve RCE through plugins
**Flag**: `CTF{RCE_v14_Plu61n5}`
**Solution**: Use EXEC: or FILE_READ: commands

## 🚀 Quick Start

```bash
# Local development
cd src
pip install -r requirements.txt
python app.py

# Docker
docker build -t ctf-llm-app .
docker run -p 5000:5000 ctf-llm-app