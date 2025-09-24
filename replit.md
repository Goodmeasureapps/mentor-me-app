# MentorMe

## Overview

MentorMe is a comprehensive web-based educational platform designed to transform the minds and hearts of teenagers by teaching essential life principles. The application addresses young teens (male and female) with practical education on making better choices, budgeting money, being responsible, and understanding life from a perspective that prepares them for independence. The platform features a role-based system supporting teens, parents, and administrators, with detailed educational content covering 16 core life skills topics across categories like Life Principles, Character Development, Money Management, Safety Awareness, Critical Thinking, Goals & Dreams, and Health.

### Recent Major Enhancement (August 2025)
Transformed MentorMe into a comprehensive life skills development platform with 10 major categories, prioritized by importance:

**Faith & Values** - Core character development foundation (prominently featured):
- Character Building principles
- Respect & Relationships
- Spiritual Growth
- Service & Giving

**Sports & Athletics** - Complete pathways for 7 major sports (Football, Basketball, Soccer, Baseball, Tennis, Track, Golf) with city-specific resources, age targeting (13-19), and local opportunity integration.

**Career Paths** - Enhanced career exploration for 9+ professions (Doctor, Lawyer, Engineer, Teacher, Business Owner, Police Officer, Nurse, Architect, Military) following the same successful sports model with city selection, age-appropriate timelines, and local professional resources.

**Personal Development** - New comprehensive category including:
- Confidence & Self-Esteem building
- Goal Setting & Time Management
- Public Speaking & Communication
- Leadership Skills development

**Technology & Innovation** - Modern tech career exploration covering:
- Coding & App Development
- Robotics and automation
- Digital Media & Graphic Design
- Gaming & eSports Careers

**Education & Academics** - Academic success pathways including:
- Study Skills & Tutoring strategies
- STEM (Science, Tech, Engineering, Math) exploration
- Writing & Creative Arts development
- College Prep & Scholarships guidance

**Creativity & Hobbies** - Artistic and creative development including:
- Music & Instruments
- Art & Design
- Dance & Theater
- Photography & Videography

**Community & Volunteering** - Service and leadership opportunities:
- Charity & Outreach programs
- Environmental Projects
- Leadership in the Community
- Peer Mentoring development

**Life Skills** - Essential practical skills:
- Cooking & Meal Prep
- Car & Home Basics (maintenance, repairs)
- Job Interview Skills
- Resume & Portfolio Building

**Money & Budgeting** - Complete financial literacy education:
- Money Mindset & Values (biblical foundation for money management)
- Budgeting Basics (50/30/20 rule and expense tracking)
- Banking & Digital Money (accounts, cards, digital payments safety)
- Debt & Credit Awareness (credit scores, avoiding debt traps)
- Saving & Goal Setting (emergency funds, delayed gratification)
- Investing Early (compound interest, stocks, ETFs)
- Work, Side Hustles & Income (earning money, taxes basics)
- Generosity & Responsibility (tithing, charitable giving)
- Avoiding Money Traps (scams, get-rich-quick schemes)
- Planning for the Future (college costs, long-term financial planning)

Each category includes comprehensive 10-question quizzes with perfect score entries for bi-weekly gift card drawings ($5-$15 with free shipping). All pathways provide step-by-step learning, practical benefits, and actionable next steps designed for teens aged 8-17.

### Recent Deployment Improvements (August 2025)
Enhanced the application for production deployment with comprehensive error handling and configuration management:

**Production Deployment Configuration**:
- Added environment variable validation with detailed error logging
- Improved database connection error handling with specific error messages
- Created comprehensive deployment guide with all required environment variables
- Added fallback configurations for development vs production environments
- Enhanced security headers and session configuration for production

**Environment Variables Management**:
- SESSION_SECRET: Flask session encryption (with development fallback)
- DATABASE_URL: PostgreSQL connection string (with SQLite fallback)
- STRIPE_PUBLISHABLE_KEY & STRIPE_SECRET_KEY: Payment processing (optional)
- SENDGRID_API_KEY: Email notifications (optional)
- TWILIO credentials: SMS notifications (optional)

**Error Handling Enhancements**:
- Graceful handling of database connection failures
- Specific error messages for common deployment issues
- Production vs development environment detection
- Comprehensive logging for troubleshooting deployment problems

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture
- **Template Engine**: Jinja2 templates with Flask
- **UI Framework**: Bootstrap 5 with dark theme support
- **Progressive Web App**: Includes service worker and manifest for offline capabilities
- **Responsive Design**: Mobile-first approach with responsive grid layouts

### Backend Architecture
- **Web Framework**: Flask with modular structure separating routes, models, and configuration
- **Authentication**: Flask-Login for session management with role-based access control (teen, parent, admin)
- **Password Security**: Passlib with bcrypt hashing for secure password storage
- **Database ORM**: SQLAlchemy with declarative base model structure
- **File Organization**: Separated concerns with dedicated files for models, routes, and app configuration

### Data Storage Solutions
- **Primary Database**: SQLite for development with PostgreSQL support via environment configuration
- **Connection Pooling**: Configured with pool recycling and pre-ping health checks
- **Schema Design**: Relational model with foreign key relationships for user hierarchies and content associations

### Authentication and Authorization
- **Multi-Role System**: Supports teen, parent, and admin user types with dedicated portals
- **Parental Controls**: Complete parent-child relationship modeling with automatic linking
- **COPPA Compliance**: Age-based consent requirements with email-based verification for users under 8
- **Session Security**: Configurable secure cookies with proxy fix for deployment environments
- **Parent Portal**: Comprehensive dashboard for monitoring teen progress, quiz results, and activity tracking

### Content Management
- **Comprehensive Topics**: 16 detailed educational topics covering life principles, character development, money management, safety, and health
- **Rich Educational Format**: Each topic includes definitions, real teen examples, good vs bad practice comparisons, practical advice, and action checklists
- **Interactive Quizzes**: JSON-based question storage with automatic quiz generation
- **Progress Tracking**: User-specific checklist completion and quiz results
- **Data Export**: CSV export functionality for administrative reporting
- **Teen-Focused Communication**: Simple, engaging language with relatable examples and encouraging guidance

### Career Exploration System
- **Sports Pathways**: Complete roadmaps for 7 major sports showing progression from Jr High through professional levels
- **Professional Careers**: Detailed guidance for 9+ career paths including education requirements and success strategies
- **Health Education**: Comprehensive health awareness covering leading causes of death and prevention strategies
- **Support Resources**: Biblical guidance and practical advice for 50+ common teen issues
- **Academic Support**: Homework help resources with links to educational websites organized by subject
- **Employment Guidance**: Age-appropriate job opportunities with application tips and money management advice
- **Summer Programming**: Activity finder with camps, enrichment programs, and volunteer opportunities

## External Dependencies

### Email Services
- **SendGrid Integration**: Complete email notification system for parent communications
- **Parental Consent System**: COPPA-compliant consent workflow with secure token-based verification
- **Welcome Emails**: Automated parent notifications with app benefits and portal access links

### Payment Processing
- **Stripe Integration**: Test keys configured for subscription management (requires production implementation)

### Core Libraries
- **Flask**: Web application framework
- **SQLAlchemy**: Database ORM and connection management
- **Flask-Login**: User session and authentication management
- **Passlib**: Password hashing and verification
- **Werkzeug**: WSGI utilities and proxy fix middleware

### Frontend Dependencies
- **Bootstrap 5**: UI components and responsive design system
- **Bootstrap Agent Dark Theme**: Replit-specific dark theme styling

### Development Tools
- **Environment Configuration**: Support for environment variables for sensitive configuration
- **Logging**: Built-in Python logging with debug level configuration
- **Database Migration**: SQLAlchemy create_all for schema initialization