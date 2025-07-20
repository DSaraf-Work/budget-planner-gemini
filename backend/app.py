from flask import Flask, jsonify, request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
import os
import re
import json

app = Flask(__name__)

# If modifying these scopes, delete the file token.json.
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

transactions = []

# In-memory storage for tokens (will not persist across serverless invocations)
token_cache = {}

def get_gmail_service():
    creds = None
    user_id = 'default_user' # In a real app, this would be dynamic per user

    # Try to get credentials from cache
    if user_id in token_cache:
        creds = Credentials.from_authorized_user_info(token_cache[user_id], SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            # For Vercel, credentials.json content comes from environment variables
            client_config = {
                "web": {
                    "client_id": os.environ.get("GOOGLE_CLIENT_ID"),
                    "project_id": os.environ.get("GOOGLE_PROJECT_ID"),
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
                    "client_secret": os.environ.get("GOOGLE_CLIENT_SECRET"),
                    "redirect_uris": ["http://localhost:8080/"], # Still needed for local auth flow
                    "javascript_origins": ["http://localhost:3000"]
                }
            }
            flow = InstalledAppFlow.from_client_config(client_config, SCOPES)
            creds = flow.run_local_server(port=0)
        
        # Store updated credentials in cache
        token_cache[user_id] = {
            'token': creds.token,
            'refresh_token': creds.refresh_token,
            'token_uri': creds.token_uri,
            'client_id': creds.client_id,
            'client_secret': creds.client_secret,
            'scopes': creds.scopes
        }

    return build('gmail', 'v1', credentials=creds)

def parse_email_body(message_id, body):
    # Credit Card Transaction
    cc_match = re.search(r'Rs (\d+\.\d{2}) at (.+?) on (\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2})', body)
    if cc_match:
        return {
            'messageId': message_id,
            'amount': float(cc_match.group(1)),
            'merchant': cc_match.group(2).strip(),
            'time': cc_match.group(3),
            'paymentMethod': 'Credit Card'
        }

    # UPI Transaction
    upi_match = re.search(r'Rs\.(\d+\.\d{2}) has been debited from account \d+ to VPA (.+?) on (\d{2}-\d{2}-\d{2})', body)
    if upi_match:
        return {
            'messageId': message_id,
            'amount': float(upi_match.group(1)),
            'merchant': upi_match.group(2).strip(),
            'time': upi_match.group(3),
            'paymentMethod': 'UPI'
        }
    return None

@app.route('/api/fetch_emails', methods=['GET'])
def fetch_emails():
    global transactions
    transactions = [] # Clear previous transactions
    try:
        service = get_gmail_service()
        results = service.users().messages().list(userId='me', q='from:alerts@hdfcbank.net').execute()
        messages = results.get('messages', [])

        if not messages:
            return jsonify({"message": "No messages found from alerts@hdfcbank.net"}), 200
        
        for message in messages:
            msg = service.users().messages().get(userId='me', id=message['id'], format='full').execute()
            payload = msg['payload']
            headers = payload['headers']
            
            # Get the message ID from headers
            message_id = next((header['value'] for header in headers if header['name'] == 'Message-ID'), None)

            # Get the email body
            parts = payload.get('parts', [])
            body_data = ''
            if parts:
                for part in parts:
                    if part['mimeType'] == 'text/plain':
                        body_data = part['body']['data']
                        break
            else:
                body_data = payload['body']['data']

            if body_data:
                import base64
                decoded_body = base64.urlsafe_b64decode(body_data).decode('utf-8')
                parsed_transaction = parse_email_body(message_id, decoded_body)
                if parsed_transaction:
                    transactions.append(parsed_transaction)

        return jsonify(transactions), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/transactions', methods=['GET'])
def get_transactions():
    return jsonify(transactions), 200

if __name__ == '__main__':
    app.run(debug=True)