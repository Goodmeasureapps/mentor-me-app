import os
from twilio.rest import Client

TWILIO_ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN")
TWILIO_PHONE_NUMBER = os.environ.get("TWILIO_PHONE_NUMBER")

def send_temp_password_sms(phone_number: str, temp_password: str) -> bool:
    """Send temporary password via SMS using Twilio"""
    # Check if Twilio credentials are available
    if not all([TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_PHONE_NUMBER]):
        # SMS service not configured - would send SMS in production
        return False
    
    try:
        client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
        
        message_body = f"Your MentorMe temporary password is: {temp_password}. This code expires in 15 minutes. Use it to log in and create a new password."
        
        message = client.messages.create(
            body=message_body,
            from_=TWILIO_PHONE_NUMBER,
            to=phone_number
        )
        
        return True
        
    except Exception as e:
        # Log error in production - could use proper logging here
        return False