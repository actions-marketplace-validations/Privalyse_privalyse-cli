import os
import openai
import requests

# SCENARIO: A typical AI integration with multiple leaks

def process_user_request(user_email, query):
    # LEAK 1: Sending PII (email) directly to OpenAI (AI_PII_LEAK)
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": f"User {user_email} asked: {query}"}
        ]
    )
    return response

def backup_data(data):
    # LEAK 2: Sending data to a US server (POLICY_VIOLATION_COUNTRY if configured)
    # This simulates a hardcoded US endpoint
    requests.post("https://us-east-1.storage.aws.amazon.com/backup", json=data)

def safe_process(user_email):
    # SAFE: Sanitized data
    import hashlib
    hashed_email = hashlib.sha256(user_email.encode()).hexdigest()
    
    openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
        messages=[{"role": "user", "content": hashed_email}]
    )
