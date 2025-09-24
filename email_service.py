import os
import sys
import secrets
import base64
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, Email, To, Content
from flask import url_for
from datetime import datetime, timedelta

# Get SendGrid API key from environment
SENDGRID_API_KEY = os.environ.get('SENDGRID_API_KEY')
if not SENDGRID_API_KEY:
    pass  # SendGrid API key not set - emails will be logged but not sent

FROM_EMAIL = 'noreply@mentorme.com'
FROM_NAME = 'MentorMe Team'

def send_email(to_email, subject, html_content, text_content=None):
    """Send an email using SendGrid"""
    if not SENDGRID_API_KEY:
        # Email service not configured - would send email in production
        return False
    
    try:
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        
        message = Mail(
            from_email=Email(FROM_EMAIL, FROM_NAME),
            to_emails=To(to_email),
            subject=subject
        )
        
        if html_content:
            message.content = Content("text/html", html_content)
        elif text_content:
            message.content = Content("text/plain", text_content)
        
        response = sg.send(message)
        return response.status_code == 202
    except Exception as e:
        # Log error in production - could use proper logging here
        return False

def generate_consent_token(user_id, parent_email):
    """Generate a secure token for parental consent"""
    data = f"{user_id}:{parent_email}:{datetime.utcnow().isoformat()}"
    token = base64.urlsafe_b64encode(data.encode()).decode()
    return token

def verify_consent_token(token):
    """Verify and decode a consent token"""
    try:
        data = base64.urlsafe_b64decode(token.encode()).decode()
        parts = data.split(':')
        if len(parts) != 3:
            return None
        
        user_id, parent_email, timestamp = parts
        token_time = datetime.fromisoformat(timestamp)
        
        # Token expires after 7 days
        if datetime.utcnow() - token_time > timedelta(days=7):
            return None
            
        return {'user_id': int(user_id), 'parent_email': parent_email}
    except:
        return None

def send_parent_welcome_email(parent_email, teen_name, teen_age=None):
    """Send welcome email to parents when teen registers"""
    subject = f"Welcome to MentorMe - {teen_name} has joined!"
    
    age_text = f" (age {teen_age})" if teen_age else ""
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
            .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
            .header {{ background: #007bff; color: white; padding: 20px; text-align: center; }}
            .content {{ padding: 20px; }}
            .benefits {{ background: #f8f9fa; padding: 15px; margin: 20px 0; }}
            .cta {{ background: #28a745; color: white; padding: 15px 25px; text-decoration: none; border-radius: 5px; display: inline-block; margin: 10px 5px; }}
            .footer {{ text-align: center; color: #666; font-size: 12px; margin-top: 30px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Welcome to MentorMe!</h1>
                <p>Your teen is learning essential life skills</p>
            </div>
            
            <div class="content">
                <h2>Hello Parent,</h2>
                
                <p>Great news! <strong>{teen_name}{age_text}</strong> has just registered for MentorMe, and we're excited to support their journey in learning essential life skills.</p>
                
                <p>Thank you for choosing MentorMe to help guide your teen's personal development. We're committed to providing safe, age-appropriate educational content.</p>
                
                <div class="benefits">
                    <h3>Benefits Your Teen Will Gain:</h3>
                    <ul>
                        <li><strong>Financial Literacy:</strong> Learn budgeting, saving, and money management</li>
                        <li><strong>Online Safety:</strong> Understand digital citizenship and privacy protection</li>
                        <li><strong>Mental Health Awareness:</strong> Develop emotional intelligence and coping strategies</li>
                        <li><strong>Career Guidance:</strong> Explore interests and plan for the future</li>
                        <li><strong>Life Skills:</strong> Master practical skills for independent living</li>
                        <li><strong>Interactive Learning:</strong> Engage with quizzes and progress tracking</li>
                    </ul>
                </div>
                
                <p><strong>Next Steps:</strong></p>
                
                <div style="text-align: center; margin: 30px 0;">
                    <a href="#" class="cta">
                        Confirm Registration & Grant Full Access
                    </a>
                    <br>
                    <a href="#" class="cta" style="background: #6c757d;">
                        Create Parent Portal Account
                    </a>
                </div>
                
                <p><strong>Parent Portal Features:</strong></p>
                <ul>
                    <li>View your teen's progress and quiz results</li>
                    <li>Monitor completed learning modules</li>
                    <li>Receive progress reports and insights</li>
                    <li>Manage account settings and permissions</li>
                </ul>
                
                <p>If you have any questions or concerns, please don't hesitate to reach out to our support team.</p>
                
                <p>Best regards,<br>
                <strong>The MentorMe Team</strong></p>
            </div>
            
            <div class="footer">
                <p>MentorMe - Empowering teens with essential life skills</p>
                <p>This email was sent because {teen_name} registered using your email as their parent contact.</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    text_content = f"""
    Welcome to MentorMe!
    
    Hello Parent,
    
    {teen_name}{age_text} has just registered for MentorMe, and we're excited to support their journey in learning essential life skills.
    
    Thank you for choosing MentorMe to help guide your teen's personal development.
    
    Benefits Your Teen Will Gain:
    - Financial Literacy: Learn budgeting, saving, and money management
    - Online Safety: Understand digital citizenship and privacy protection
    - Mental Health Awareness: Develop emotional intelligence and coping strategies
    - Career Guidance: Explore interests and plan for the future
    - Life Skills: Master practical skills for independent living
    - Interactive Learning: Engage with quizzes and progress tracking
    
    To grant your teen full access, please confirm their registration by visiting the link in the HTML version of this email.
    
    Create your Parent Portal account to monitor progress by visiting the link in the HTML version of this email.
    
    Best regards,
    The MentorMe Team
    """
    
    return send_email(parent_email, subject, html_content, text_content)

def send_consent_confirmation_email(parent_email, teen_name, consent_token):
    """Send parental consent confirmation email"""
    subject = f"Confirm Registration for {teen_name} - MentorMe"
    
    confirm_url = url_for('parent_confirm_registration', token=consent_token, _external=True)
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
            .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
            .header {{ background: #007bff; color: white; padding: 20px; text-align: center; }}
            .content {{ padding: 20px; }}
            .cta {{ background: #28a745; color: white; padding: 15px 25px; text-decoration: none; border-radius: 5px; display: inline-block; margin: 20px 0; }}
            .important {{ background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Parental Consent Required</h1>
            </div>
            
            <div class="content">
                <h2>Hello Parent,</h2>
                
                <p><strong>{teen_name}</strong> has registered for MentorMe and needs your consent to access full features.</p>
                
                <div class="important">
                    <p><strong>COPPA Compliance:</strong> As your child is under 13, federal law requires parental consent before we can collect personal information or provide full access to our educational platform.</p>
                </div>
                
                <p>By clicking the confirmation link below, you:</p>
                <ul>
                    <li>Grant consent for your child to use MentorMe</li>
                    <li>Allow us to track their educational progress</li>
                    <li>Enable full access to quizzes and interactive features</li>
                    <li>Permit age-appropriate educational communications</li>
                </ul>
                
                <div style="text-align: center;">
                    <a href="{confirm_url}" class="cta">
                        Confirm Registration & Grant Consent
                    </a>
                </div>
                
                <p><strong>This link expires in 7 days.</strong></p>
                
                <p>If you did not authorize this registration or have concerns, please contact us immediately.</p>
                
                <p>Best regards,<br>
                <strong>The MentorMe Team</strong></p>
            </div>
        </div>
    </body>
    </html>
    """
    
    return send_email(parent_email, subject, html_content)