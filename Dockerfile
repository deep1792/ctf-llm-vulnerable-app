FROM python:3.9-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    sqlite3 \
    iputils-ping \
    netcat-traditional \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements and install Python dependencies
COPY src/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ .

# Create flag file for LLM07 challenge
RUN echo "CTF{RCE_v14_Plu61n5}" > /flag.txt
RUN chmod 644 /flag.txt

# Initialize database
RUN sqlite3 ctf.db "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, email TEXT, api_key TEXT, is_admin INTEGER DEFAULT 0, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);" \
    && sqlite3 ctf.db "INSERT OR IGNORE INTO users (username, password, email, api_key, is_admin) VALUES ('admin', 'admin_ctf_2024_secret!!', 'admin@ctf-llm.com', 'sk-ctf-admin-key-1234567890', 1);" \
    && sqlite3 ctf.db "INSERT OR IGNORE INTO users (username, password, email, api_key, is_admin) VALUES ('user', 'user_password_123', 'user@ctf-llm.com', 'sk-user-key-0987654321', 0);"

EXPOSE 5000

CMD ["python", "app.py"]