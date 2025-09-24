# MentorMe Deployment Configuration

## Required Production Environment Variables

To successfully deploy MentorMe, you need to configure the following environment variables in your deployment platform:

### Essential Variables

1. **SESSION_SECRET** (Required)
   - Purpose: Flask session encryption and security
   - Example: `your-very-long-random-secret-key-here`
   - Generate with: `python -c "import secrets; print(secrets.token_hex(32))"`

2. **DATABASE_URL** (Required for Production)
   - Purpose: PostgreSQL database connection
   - Format: `postgresql://username:password@host:port/database`
   - Example: `postgresql://user:pass@localhost:5432/mentorme_prod`

### Optional Variables

3. **STRIPE_PUBLISHABLE_KEY** (If using payment features)
   - Purpose: Stripe payment processing (public key)
   - Get from: Stripe Dashboard

4. **STRIPE_SECRET_KEY** (If using payment features)
   - Purpose: Stripe payment processing (private key)
   - Get from: Stripe Dashboard

5. **SENDGRID_API_KEY** (If using email features)
   - Purpose: Email notifications via SendGrid
   - Get from: SendGrid Dashboard

6. **TWILIO_ACCOUNT_SID** (If using SMS features)
   - Purpose: SMS notifications via Twilio
   - Get from: Twilio Console

7. **TWILIO_AUTH_TOKEN** (If using SMS features)
   - Purpose: SMS authentication
   - Get from: Twilio Console

8. **TWILIO_PHONE_NUMBER** (If using SMS features)
   - Purpose: SMS sender number
   - Format: `+1234567890`

### Environment Configuration

For production deployment, also set:
- **FLASK_ENV**: `production`

## Deployment Steps

1. Set all required environment variables in your deployment platform
2. Ensure your PostgreSQL database is accessible from your deployment environment
3. Deploy the application using the provided `main.py` entry point
4. The application will automatically create database tables on first run

## Security Notes

- Never commit secrets to version control
- Use strong, randomly generated values for SESSION_SECRET
- Ensure DATABASE_URL uses SSL in production
- Keep all API keys and tokens secure

## Troubleshooting

- If you see "could not translate host name" errors, verify your DATABASE_URL format
- If sessions don't work, check that SESSION_SECRET is set
- Enable debug logging by setting log level to DEBUG if needed