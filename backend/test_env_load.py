#!/usr/bin/env python3
"""Test if environment variables load correctly"""
import os
from dotenv import load_dotenv

print("=" * 50)
print("Testing .env loading")
print("=" * 50)

# Load environment
load_dotenv()

api_key = os.getenv('GEMINI_API_KEY')

if api_key:
    print(f"✓ API Key loaded: {api_key[:20]}...{api_key[-10:]}")
    print(f"✓ Full length: {len(api_key)} characters")
    
    # Test with Gemini
    try:
        from google import genai
        client = genai.Client(api_key=api_key)
        print("✓ Gemini client initialized successfully")
        
        # Try a simple request
        response = client.models.generate_content(
            model='gemini-2.0-flash-exp',
            contents='Say "Hello"'
        )
        print(f"✓ API request successful! Response: {response.text[:50]}")
    except Exception as e:
        print(f"✗ API request failed: {e}")
else:
    print("✗ API Key not found!")
