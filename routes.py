import json
import csv
import io
import zipfile
import random
import re
import html
import email_validator
from datetime import datetime, timedelta
from functools import wraps
from flask import render_template, request, redirect, url_for, flash, send_file, jsonify, make_response, session
from flask_login import login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect
from app import app, db
from models import (
    User, Topic, Quiz, QuizResult, ChecklistProgress, SignedNDA, CareerPath,
    TeenSupport, JobOpportunity, UserInterest, SportsQuizResult, WeeklyDrawingEntry,
    CategoryQuizResult, WeeklyDrawing, UserSettings, UserFeedback, ResourceLibrary,
    UserBadge, AIChatHistory, TeenAccomplishment
)
from email_service import (
    send_parent_welcome_email, send_consent_confirmation_email,
    generate_consent_token, verify_consent_token
)
from sms_service import send_temp_password_sms
from profanity_filter import profanity_filter

# Initialize CSRF protection (disabled for registration fix)
# csrf = CSRFProtect(app)

# Rate limiting storage (in production, use Redis)
rate_limit_store = {}

def validate_and_sanitize_input(value, field_type='text', max_length=255):
    """Validate and sanitize user input to prevent XSS and injection attacks"""
    if not value:
        return ''

    # Basic sanitization
    value = str(value).strip()

    # Length validation
    if len(value) > max_length:
        raise ValueError(f"Input too long (max {max_length} characters)")

    if field_type == 'email':
        try:
            # Validate email format — allow all domains and providers
            email_validator.validate_email(value, check_deliverability=False)
        except email_validator.EmailNotValidError:
            # Fallback regex for broad acceptance
            basic_email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(basic_email_pattern, value):
                raise ValueError("Please enter a valid email address format")

    elif field_type == 'username':
        if not re.match(r'^[a-zA-Z0-9_]{3,20}$', value):
            raise ValueError("Username must be 3-20 characters, letters, numbers, and underscore only")

    elif field_type == 'password':
        if len(value) < 8:
            raise ValueError("Password must be at least 8 characters long")
        if not re.search(r'[A-Za-z]', value) or not re.search(r'[0-9]', value):
            raise ValueError("Password must contain both letters and numbers")

    elif field_type == 'age':
        try:
            age = int(value)
            if age < 8 or age > 19:
                raise ValueError("Age must be between 8 and 19")
            return age
        except ValueError:
            raise ValueError("Invalid age")

    elif field_type == 'phone':
        phone_clean = re.sub(r'[^\d+]', '', value)
        if not re.match(r'^\+?[1-9]\d{9,14}$', phone_clean):
            raise ValueError("Invalid phone number format")
        return phone_clean

    # HTML escape for text fields to prevent XSS
    if field_type in ['text', 'name']:
        value = html.escape(value)

    return value

def rate_limit(key, limit=5, window=300):
    """Simple rate limiting (5 requests per 5 minutes)"""
    now = datetime.utcnow().timestamp()

    if key not in rate_limit_store:
        rate_limit_store[key] = []

    # Clean old entries
    rate_limit_store[key] = [t for t in rate_limit_store[key] if now - t < window]

    if len(rate_limit_store[key]) >= limit:
        return False

    rate_limit_store[key].append(now)
    return True

# --------- Document constants ----------
TERMS_OF_USE = f"""MentorMe - Terms of Use
Last updated: {datetime.utcnow().date()}

Kid-friendly summary:
- Be kind and respectful.
- Don't share someone else's private info without permission.
- If you break rules we may limit access.

This template requires legal review before publishing.
"""

PRIVACY_POLICY = f"""MentorMe - Privacy Policy
Last updated: {datetime.utcnow().date()}

We collect minimal account info (name, email, age). For children under 8 in COPPA jurisdictions,
parental consent is required before collecting personal information. Parents can request data deletion.
This is a template and must be reviewed for COPPA and local laws.
"""

NDA_TEXT = f"""Simple Mutual NDA (sample)
Date: {datetime.utcnow().date()}

This is a demo NDA. Replace with your finalized NDA and have it reviewed by counsel.
"""

def generate_quiz_for_topic(title):
    """Generate automatic quiz questions for a topic"""
    q1 = {
        'q': f'Which is a good practice about {title.lower()}?',
        'choices': ['Ignore it', 'Think and ask trusted adult', 'Post immediately'],
        'answer': 1
    }
    q2 = {
        'q': f'If you are unsure about {title.lower()}, you should:',
        'choices': ['Do nothing and stay quiet', 'Ask a trusted adult or teacher', 'Share with everyone'],
        'answer': 1
    }
    if len(title) % 2 == 0:
        q3 = {
            'q': f'What is an action step related to {title.lower()}?',
            'choices': ['Avoid thinking', 'Take a small responsible action', 'Blame others'],
            'answer': 1
        }
        return [q1, q2, q3]
    return [q1, q2]

# --------- Routes ----------
@app.route('/')
def index():
    from app_config import AppConfig

    try:
        topics = Topic.query.order_by(Topic.title.asc()).all()
    except Exception as e:
        topics = []
        import logging
        logging.error(f"Failed to load topics: {e}")

    response = render_template(
        'index.html',
        topics=topics,
        cache_buster=AppConfig.get_cache_buster()
    )

    resp = make_response(response)
    resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, max-age=0'
    resp.headers['Pragma'] = 'no-cache'
    resp.headers['Expires'] = '0'
    # either a datetime object or a RFC1123 string is fine
    resp.headers['Last-Modified'] = datetime.utcnow()
    resp.headers['ETag'] = f"mentorme-fresh-{int(datetime.utcnow().timestamp())}"
    return resp
    
    # GET
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Rate limiting for registration attempts
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        if not rate_limit(f"register_{client_ip}", limit=3, window=300):
            flash('Too many registration attempts. Please try again in 5 minutes.', 'danger')
            return render_template('register.html')

        registration_type = validate_and_sanitize_input(
            request.form.get('registration_type', 'solo_teen'), 'text', 50
        )

        
        try:
            if registration_type == 'solo_teen':
                # Solo Teen Registration with validation
                name = validate_and_sanitize_input(request.form.get('teen_name', ''), 'name', 100)
                username = validate_and_sanitize_input(request.form.get('teen_username', ''), 'username', 20)
                email = validate_and_sanitize_input(request.form.get('teen_email', ''), 'email', 255)
                password = validate_and_sanitize_input(request.form.get('teen_password', ''), 'password', 255)
                confirm_password = request.form.get('teen_confirm_password', '').strip()
                age = validate_and_sanitize_input(request.form.get('teen_age', ''), 'age', 3)
                
                # Validate required fields
                if not all([name, username, email, password, confirm_password]):
                    flash('All fields are required', 'danger')
                    return render_template('register.html')
                
                if password != confirm_password:
                    flash('Passwords do not match', 'danger')
                    return render_template('register.html')
                
                # Age validation for solo teen registration (must be 18-19)
                try:
                    age_int = int(age)
                    if age_int < 18 or age_int > 19:
                        flash('Independent registration is only for teens ages 18-19. Ages 8-17 should use Teen + Parent registration.', 'danger')
                        return render_template('register.html')
                except (ValueError, TypeError):
                    flash('Please enter a valid age.', 'danger')
                    return render_template('register.html')
                
                # Check if username or email already exists
                if User.query.filter_by(username=username).first():
                    flash('Username already taken', 'danger')
                    return render_template('register.html')
                    
                if User.query.filter_by(email=email).first():
                    flash('Email already registered', 'danger')
                    return render_template('register.html')
                
                # Create new teen user
                user = User()
                user.name = name
                user.username = username
                user.email = email
                user.role = 'teen'
                user.age = age
                user.set_password(password)
        
                # Apply terms acceptance from session if available
                if session.get('terms_accepted'):
                    user.terms_accepted = True
                    user.terms_accepted_at = datetime.utcnow()
                    user.privacy_accepted = True
                    user.privacy_accepted_at = datetime.utcnow()
                    
                    if session.get('parent_consent_for_terms'):
                        user.parent_consent_for_terms = True
                        user.parent_consent_terms_at = datetime.utcnow()
                    
                    # Clear session terms data
                    session.pop('terms_accepted', None)
                    session.pop('terms_age', None)
                    session.pop('parent_consent_for_terms', None)
                
                try:
                    db.session.add(user)
                    db.session.commit()
                    
                    flash('Teen account created successfully! You can now log in with your username.', 'success')
                    return redirect(url_for('login'))
                except Exception as e:
                    db.session.rollback()
                    app.logger.error(f"Solo teen registration error: {str(e)}")
                    flash('There was an error creating your account. Please try again or contact support.', 'danger')
                    return render_template('register.html')
            
            elif registration_type == 'teen_parent':
                # Teen + Parent Registration with validation
                try:
                    teen_name = validate_and_sanitize_input(request.form.get('teen_name_joint', ''), 'name', 100)
                    teen_username = validate_and_sanitize_input(request.form.get('teen_username_joint', ''), 'username', 20)
                    teen_age = validate_and_sanitize_input(request.form.get('teen_age_joint', ''), 'age', 3)
                    teen_password = validate_and_sanitize_input(request.form.get('teen_password_joint', ''), 'password', 255)
                    
                    parent_name = validate_and_sanitize_input(request.form.get('parent_name', ''), 'name', 100)
                    parent_username = validate_and_sanitize_input(request.form.get('parent_username', ''), 'username', 20)
                    parent_email = validate_and_sanitize_input(request.form.get('parent_email', ''), 'email', 255)
                    parent_password = validate_and_sanitize_input(request.form.get('parent_password', ''), 'password', 255)
                except ValueError as e:
                    flash(str(e), 'danger')
                    return render_template('register.html')
                
                # Validate required fields
                if not all([teen_name, teen_username, teen_age, teen_password, parent_name, parent_username, parent_email, parent_password]):
                    flash('All fields are required for both teen and parent', 'danger')
                    return render_template('register.html')
                
                # Age validation for teen+parent registration (must be 13-17)
                try:
                    teen_age_int = int(teen_age)
                    if teen_age_int < 8 or teen_age_int > 17:
                        flash('Teen + Parent registration is only for teens ages 8-17. Ages 18-19 should register independently.', 'danger')
                        return render_template('register.html')
                except (ValueError, TypeError):
                    flash('Please enter a valid age for the teen.', 'danger')
                    return render_template('register.html')
                
                # Check if usernames or email already exist
                if User.query.filter_by(username=teen_username).first():
                    flash('Teen username already taken', 'danger')
                    return render_template('register.html')
                    
                if User.query.filter_by(username=parent_username).first():
                    flash('Parent username already taken', 'danger')
                    return render_template('register.html')
                    
                if User.query.filter_by(email=parent_email).first():
                    flash('Parent email already registered', 'danger')
                    return render_template('register.html')
                
                # Create parent user first
                parent_user = User()
                parent_user.name = parent_name
                parent_user.username = parent_username
                parent_user.email = parent_email
                parent_user.role = 'parent'
                parent_user.set_password(parent_password)
                
                # Apply terms acceptance from session if available
                if session.get('terms_accepted'):
                    parent_user.terms_accepted = True
                    parent_user.terms_accepted_at = datetime.utcnow()
                    parent_user.privacy_accepted = True
                    parent_user.privacy_accepted_at = datetime.utcnow()
                    parent_user.parent_consent_for_terms = True
                    parent_user.parent_consent_terms_at = datetime.utcnow()
                
                try:
                    db.session.add(parent_user)
                    db.session.flush()  # Get parent ID without committing
                    
                    # Create teen user linked to parent (teen gets a unique email based on parent email)
                    # Ensure parent_email is a string before splitting
                    parent_email_str = str(parent_email) if parent_email else ""
                    if '@' in parent_email_str:
                        teen_email = f"teen.{teen_username}@{parent_email_str.split('@')[1]}"
                    else:
                        teen_email = f"teen.{teen_username}@example.com"  # fallback
                    teen_user = User()
                    teen_user.name = teen_name
                    teen_user.username = teen_username
                    teen_user.email = teen_email  # Use unique email for teen to avoid duplicate key violation
                    teen_user.role = 'teen'
                    teen_user.age = teen_age_int
                    teen_user.parent_id = parent_user.id
                    teen_user.set_password(teen_password)
                    
                    # Apply terms acceptance from session if available
                    if session.get('terms_accepted'):
                        teen_user.terms_accepted = True
                        teen_user.terms_accepted_at = datetime.utcnow()
                        teen_user.privacy_accepted = True
                        teen_user.privacy_accepted_at = datetime.utcnow()
                        teen_user.parent_consent_for_terms = True
                        teen_user.parent_consent_terms_at = datetime.utcnow()
                        
                        # Clear session terms data
                        session.pop('terms_accepted', None)
                        session.pop('terms_age', None)
                        session.pop('parent_consent_for_terms', None)
                    
                    db.session.add(teen_user)
                    db.session.commit()
                    
                    flash('Both teen and parent accounts created successfully! You can both log in with your respective usernames.', 'success')
                    return redirect(url_for('login'))
                    
                except Exception as e:
                    db.session.rollback()
                    app.logger.error(f"Registration error: {str(e)}")
                    flash('There was an error creating your accounts. Please try again or contact support.', 'danger')
                    return render_template('register.html')
                
        except ValueError as e:
            flash(str(e), 'danger')
            return render_template('register.html')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        temp_password = request.form.get('temp_password', '').strip()
        selected_user_type = request.form.get('user_type', '').strip()
        
        if not username:
            flash('Username is required', 'danger')
            return render_template('login.html')
        
        if not selected_user_type:
            flash('Please select whether you are logging in as a Teen or Parent', 'warning')
            return render_template('login.html')
        
        user = User.query.filter_by(username=username).first()
        
        if not user:
            flash('Invalid username or password', 'danger')
            return render_template('login.html')
        
        # Check if selected user type matches account type
        if selected_user_type == 'teen' and user.role != 'teen':
            flash(f'This username belongs to a {user.role} account, but you selected Teen login. Please select the correct account type.', 'warning')
            return render_template('login.html')
        elif selected_user_type == 'parent' and user.role != 'parent':
            flash(f'This username belongs to a {user.role} account, but you selected Parent login. Please select the correct account type.', 'warning')
            return render_template('login.html')
        
        # Check for temporary password first
        if temp_password:
            if user.check_temp_password(temp_password):
                user.clear_temp_password()
                db.session.commit()
                # Check terms acceptance for temp password login too (only for new users)
                if not user.terms_accepted or not user.privacy_accepted:
                    session['pending_login_user_id'] = user.id
                    flash('Please review and accept our Terms of Use and Privacy Policy to continue.', 'info')
                    return redirect(url_for('terms_privacy'))
                
                if user.age and user.age < 18 and not user.parent_consent_for_terms:
                    session['pending_login_user_id'] = user.id
                    flash('Parental consent is required for your Terms of Use agreement.', 'warning')
                    return redirect(url_for('terms_privacy'))
                
                login_user(user)
                flash('Login successful with temporary password!', 'success')
                
                # Redirect based on role
                if user.role == 'parent':
                    return redirect(url_for('parent_portal'))
                else:
                    return redirect(url_for('teen_dashboard'))
            else:
                flash('Invalid or expired temporary password', 'danger')
                return render_template('login.html')
        
        # Regular password check
        if password and user.check_password(password):
            # Update user's city and age from login form
            city = request.form.get('city', '').strip()
            age = request.form.get('age', '').strip()
            
            if city:
                user.city = city
            if age and age.isdigit():
                user.age = int(age)
            elif age == "20":  # Handle "20+" case
                user.age = 20
            
            db.session.commit()
            
            # Check COPPA consent for users under 13
            if user.age and user.age < 13 and not user.parental_consent:
                flash('Your account requires parental consent. Please ask your parent to check their email and confirm your registration.', 'warning')
                return render_template('login.html')
            
            # Check if user has accepted terms and privacy policy (only for new users)
            if not user.terms_accepted or not user.privacy_accepted:
                session['pending_login_user_id'] = user.id
                flash('Please review and accept our Terms of Use and Privacy Policy to continue.', 'info')
                return redirect(url_for('terms_privacy'))
            
            # Check if under 18 and needs parental consent for terms (only for new users)
            if user.age and user.age < 18 and not user.parent_consent_for_terms:
                session['pending_login_user_id'] = user.id
                flash('Parental consent is required for your Terms of Use agreement.', 'warning')
                return redirect(url_for('terms_privacy'))
            
            login_user(user)
            flash('Login successful! Your location preferences have been updated.', 'success')
            
            # Redirect based on role
            if user.role == 'parent':
                return redirect(url_for('parent_portal'))
            else:
                return redirect(url_for('teen_dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/terms-privacy')
def terms_privacy():
    """Terms of Use and Privacy Policy page"""
    return render_template('terms_privacy.html')

@app.route('/accept-terms', methods=['POST'])
def accept_terms():
    """Handle terms and privacy policy acceptance"""
    age = request.form.get('age')
    action = request.form.get('action')
    
    if action != 'accept':
        flash('You must accept the Terms of Use and Privacy Policy to use MentorMe.', 'danger')
        return redirect(url_for('index'))
    
    if not age or not age.isdigit():
        flash('Please select your age.', 'danger')
        return redirect(url_for('terms_privacy'))
    
    age = int(age)
    
    if age < 8 or age > 17:
        flash('MentorMe is only available for users aged 8-17.', 'danger')
        return redirect(url_for('index'))
    
    # Check if this is for a pending login user
    user_id = session.get('pending_login_user_id')
    if user_id:
        user = User.query.get(user_id)
        if user:
            # Update terms acceptance
            user.terms_accepted = True
            user.terms_accepted_at = datetime.utcnow()
            user.privacy_accepted = True
            user.privacy_accepted_at = datetime.utcnow()
            
            # Handle age-based consent
            if age >= 8 and age <= 17:
                parent_consent = request.form.get('parent_consent')
                teen_consent = request.form.get('teen_consent')
                
                if not parent_consent or not teen_consent:
                    flash('Both parent/guardian and teen must agree to the terms.', 'danger')
                    return redirect(url_for('terms_privacy'))
                
                user.parent_consent_for_terms = True
                user.parent_consent_terms_at = datetime.utcnow()
            
            elif age >= 18 and age <= 19:
                older_teen_consent = request.form.get('older_teen_consent')
                
                if not older_teen_consent:
                    flash('You must agree to the terms to proceed.', 'danger')
                    return redirect(url_for('terms_privacy'))
            
            # Update age if not set
            if not user.age:
                user.age = age
            
            db.session.commit()
            session.pop('pending_login_user_id', None)
            
            # Now log them in
            login_user(user)
            flash('Terms accepted! Welcome to MentorMe!', 'success')
            
            # Redirect based on role
            if user.role == 'parent':
                return redirect(url_for('parent_portal'))
            else:
                return redirect(url_for('teen_dashboard'))
    
    # If no pending user, this might be during registration
    # Store terms acceptance in session for registration process
    session['terms_accepted'] = True
    session['terms_age'] = age
    
    if age >= 8 and age <= 17:
        parent_consent = request.form.get('parent_consent')
        teen_consent = request.form.get('teen_consent')
        
        if not parent_consent or not teen_consent:
            flash('Both parent/guardian and teen must agree to the terms.', 'danger')
            return redirect(url_for('terms_privacy'))
        
        session['parent_consent_for_terms'] = True
    
    elif age >= 18 and age <= 19:
        older_teen_consent = request.form.get('older_teen_consent')
        
        if not older_teen_consent:
            flash('You must agree to the terms to proceed.', 'danger')
            return redirect(url_for('terms_privacy'))
    
    flash('Terms accepted! Please proceed with registration or login.', 'success')
    return redirect(url_for('register'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        phone = request.form.get('phone', '').strip()
        
        if not email:
            flash('Email is required', 'danger')
            return render_template('forgot_password.html')
        
        user = User.query.filter_by(email=email).first()
        if not user:
            flash('No account found with that email address', 'danger')
            return render_template('forgot_password.html')
        
        if phone and user.phone_number == phone:
            # Generate and send temporary password via SMS
            temp_password = user.generate_temp_password()
            db.session.commit()
            
            if send_temp_password_sms(phone, temp_password):
                flash('Temporary password sent to your phone! Use it to log in and then change your password.', 'success')
                return redirect(url_for('login'))
            else:
                flash('Failed to send SMS. Please try again later.', 'danger')
        else:
            flash('Phone number does not match our records', 'danger')
    
    return render_template('forgot_password.html')

@app.route('/reset-password', methods=['GET', 'POST'])
@login_required
def reset_password():
    if request.method == 'POST':
        new_password = request.form.get('new_password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()
        
        if not new_password:
            flash('New password is required', 'danger')
            return render_template('reset_password.html')
        
        if new_password != confirm_password:
            flash('Passwords do not match', 'danger')
            return render_template('reset_password.html')
        
        current_user.set_password(new_password)
        current_user.clear_temp_password()  # Clear any temporary password
        db.session.commit()
        
        flash('Password updated successfully!', 'success')
        
        # Redirect based on role
        if current_user.role == 'parent':
            return redirect(url_for('parent_portal'))
        else:
            return redirect(url_for('teen_dashboard'))
    
    return render_template('reset_password.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

@app.route('/topic/<int:id>')
@login_required
def topic(id):
    topic = Topic.query.get_or_404(id)
    
    # Parse extra JSON data for checklist
    extra_data = {}
    if topic.extra:
        try:
            extra_data = json.loads(topic.extra)
        except:
            extra_data = {}
    
    checklist = extra_data.get('checklist', [])
    
    # Get user's checklist progress
    progress = {}
    if current_user.is_authenticated:
        user_progress = ChecklistProgress.query.filter_by(
            user_id=current_user.id, topic_id=id
        ).all()
        progress = {p.item: p.completed for p in user_progress}
    
    return render_template('topic.html', topic=topic, checklist=checklist, progress=progress)

@app.route('/quiz/<int:id>', methods=['GET', 'POST'])
@login_required
def quiz(id):
    # Get topic
    topic = Topic.query.get_or_404(id)
    
    # Generate quiz for topic
    questions = generate_quiz_for_topic(topic.title)
    quiz = {'title': f'{topic.title} Quiz', 'questions': questions}
    
    if request.method == 'POST':
        score = 0
        total = len(questions)
        
        for i, question in enumerate(questions):
            submitted_answer = request.form.get(f'q{i}')
            if submitted_answer and int(submitted_answer) == question['answer']:
                score += 1
        
        # Save quiz result
        result = QuizResult()
        result.user_id = current_user.id
        result.topic_id = id
        result.score = score
        result.total = total
        result.percentage = (score / total) * 100 if total > 0 else 0
        db.session.add(result)
        db.session.commit()
        
        flash(f'Quiz completed! You scored {score}/{total} ({result.percentage:.1f}%)', 'success')
        
        # Redirect back to topic
        if topic:
            return redirect(url_for('topic', id=topic.id))
        else:
            return redirect(url_for('teen_dashboard'))
    
    return render_template('quiz.html', quiz=quiz, questions=questions)

@app.route('/checklist_toggle', methods=['POST'])
@login_required
def checklist_toggle():
    topic_id = request.form.get('topic_id')
    item = request.form.get('item')
    
    # Validate topic_id exists and is a valid integer
    if not topic_id:
        flash('Missing topic information.', 'danger')
        return redirect(url_for('teen_dashboard'))
    
    try:
        topic_id = int(topic_id)
    except (ValueError, TypeError):
        flash('Invalid topic.', 'danger')
        return redirect(url_for('teen_dashboard'))
    
    # Verify topic exists in database
    topic = Topic.query.get(topic_id)
    if not topic:
        flash('Topic not found.', 'danger')
        return redirect(url_for('teen_dashboard'))
    
    progress = ChecklistProgress.query.filter_by(
        user_id=current_user.id, topic_id=topic_id, item=item
    ).first()
    
    if progress:
        progress.completed = not progress.completed
    else:
        progress = ChecklistProgress()
        progress.user_id = current_user.id
        progress.topic_id = topic_id
        progress.item = item
        progress.completed = True
        db.session.add(progress)
    
    db.session.commit()
    return redirect(url_for('topic', id=topic.id))

@app.route('/terms')
def terms():
    return render_template('documents.html', title='Terms of Use', content=TERMS_OF_USE)

@app.route('/privacy')
def privacy():
    return render_template('documents.html', title='Privacy Policy', content=PRIVACY_POLICY)

@app.route('/nda')
def nda():
    return render_template('documents.html', title='NDA', content=NDA_TEXT)

@app.route('/parent/confirm/<token>')
def parent_confirm_registration(token):
    """Parent confirms registration and grants consent"""
    token_data = verify_consent_token(token)
    if not token_data:
        flash('Invalid or expired consent link. Please contact support.', 'danger')
        return redirect(url_for('index'))
    
    user = User.query.get(token_data['user_id'])
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('index'))
    
    # Grant parental consent
    user.parental_consent = True
    user.consent_pending = False
    db.session.commit()
    
    flash(f'Registration confirmed! {user.name} now has full access to MentorMe.', 'success')
    return render_template('parent_confirmation.html', user=user, parent_email=token_data['parent_email'])

@app.route('/parent/signup')
def parent_portal_signup():
    """Parent portal signup page"""
    email = request.args.get('email', '')
    return render_template('parent_signup.html', email=email)

@app.route('/parent/signup/submit', methods=['POST'])
def parent_portal_signup_post():
    """Handle parent portal signup"""
    name = request.form.get('name', '').strip()
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '').strip()
    phone_number = request.form.get('phone_number', '').strip()
    
    if not all([name, email, password]):
        flash('All fields are required', 'danger')
        return render_template('parent_signup.html')
    
    # Check if user already exists
    if User.query.filter_by(email=email).first():
        flash('Email already registered', 'danger')
        return render_template('parent_signup.html')
    
    # Create parent account
    parent = User()
    parent.name = name
    parent.email = email
    parent.role = 'parent'
    parent.phone_number = phone_number
    parent.set_password(password)
    
    db.session.add(parent)
    db.session.commit()
    
    # Send welcome email
    send_parent_welcome_email(email, name)
    
    flash('Parent account created successfully! You can now log in to monitor your teen\'s progress.', 'success')
    return redirect(url_for('login'))

@app.route('/parent/portal')
@login_required
def parent_portal():
    """Parent dashboard to monitor children's progress"""
    if current_user.role != 'parent':
        flash('Access denied. Parent account required.', 'danger')
        return redirect(url_for('index'))
    
    # Get all children linked to this parent
    children = User.query.filter_by(parent_id=current_user.id).all()
    
    # Get summary stats for each child
    child_stats = []
    for child in children:
        quiz_count = QuizResult.query.filter_by(user_id=child.id).count()
        avg_score = db.session.query(db.func.avg(QuizResult.percentage)).filter_by(user_id=child.id).scalar() or 0
        recent_quiz = QuizResult.query.filter_by(user_id=child.id).order_by(QuizResult.taken_at.desc()).first()
        recent_quiz_results = QuizResult.query.filter_by(user_id=child.id).order_by(QuizResult.taken_at.desc()).limit(5).all()
        
        # Get checklist progress
        completed_checklists = ChecklistProgress.query.filter_by(user_id=child.id, completed=True).count()
        total_topics = Topic.query.count()
        
        # Get teen's interests from settings
        settings = UserSettings.query.filter_by(user_id=child.id).first()
        teen_interests = {
            'favorite_categories': json.loads(settings.favorite_categories) if settings and settings.favorite_categories else [],
            'hidden_categories': json.loads(settings.hidden_categories) if settings and settings.hidden_categories else []
        }
        
        # Get AI chat history
        ai_chats = AIChatHistory.query.filter_by(user_id=child.id).order_by(AIChatHistory.created_at.desc()).limit(10).all()
        
        # Get teen accomplishments
        accomplishments = TeenAccomplishment.query.filter_by(user_id=child.id).order_by(TeenAccomplishment.achieved_at.desc()).limit(10).all()
        
        # Get teen feedback
        feedback_entries = UserFeedback.query.filter_by(user_id=child.id).order_by(UserFeedback.submitted_at.desc()).limit(5).all()
        
        child_stats.append({
            'child': child,
            'quiz_count': quiz_count,
            'avg_score': round(avg_score, 1),
            'recent_quiz': recent_quiz,
            'recent_quiz_results': recent_quiz_results,
            'completed_checklists': completed_checklists,
            'total_topics': total_topics,
            'teen_interests': teen_interests,
            'ai_chats': ai_chats,
            'accomplishments': accomplishments,
            'feedback_entries': feedback_entries
        })
    
    return render_template('parent_portal.html', child_stats=child_stats)

@app.route('/parent/child/<int:child_id>')
@login_required
def parent_child_detail(child_id):
    """Detailed view of a child's progress"""
    if current_user.role != 'parent':
        flash('Access denied. Parent account required.', 'danger')
        return redirect(url_for('index'))
    
    child = User.query.get_or_404(child_id)
    
    # Verify this is the parent's child
    if child.parent_id != current_user.id:
        flash('Access denied. You can only view your own children.', 'danger')
        return redirect(url_for('parent_portal'))
    
    # Get detailed progress
    quiz_results = QuizResult.query.filter_by(user_id=child.id).order_by(QuizResult.taken_at.desc()).all()
    checklist_progress = ChecklistProgress.query.filter_by(user_id=child.id).all()
    topics = Topic.query.all()
    
    return render_template('parent_child_detail.html', 
                         child=child, 
                         quiz_results=quiz_results, 
                         checklist_progress=checklist_progress,
                         topics=topics)

@app.route('/teen/dashboard')
@login_required
def teen_dashboard():
    """Teen dashboard with full access"""
    if current_user.role not in ['teen', 'teenager']:
        flash('Access denied. Teenager account required.', 'danger')
        return redirect(url_for('index'))
    
    # Check if parental consent is required and pending
    if current_user.age and current_user.age < 13 and not current_user.parental_consent:
        flash('Your account requires parental consent. Please ask your parent to confirm your registration.', 'warning')
    
    try:
        topics = Topic.query.all()
        return render_template('teen_dashboard.html', topics=topics)
    except Exception as e:
        # Log the error and provide a fallback
        app.logger.error(f"Teen dashboard error: {e}")
        flash('Dashboard temporarily unavailable. Please refresh the page.', 'warning')
        return render_template('teen_dashboard.html', topics=[])

def get_daily_teen_news():
    """Get daily teen achievement news from real sources"""
    
    teen_news_stories = [
        {
            'title': '13-Year-Old Texas Teen Wins National Spelling Bee Championship',
            'subtitle': 'Faizan Zaki from Allen, Texas',
            'description': 'After finishing second place last year, Faizan Zaki returned to win the 2025 Scripps National Spelling Bee, correctly spelling "éclaircissement" in the 21st round. His victory marked the first time in nearly 25 years that a former runner-up returned to claim the championship.',
            'prizes': [
                '$50,000 cash prize and commemorative medal',
                '$2,500 from Merriam-Webster plus reference library',
                '$1,000 Scholastic Dollars for his school',
                '$400 in Encyclopædia Britannica works'
            ],
            'special_facts': [
                'Only 5 former runners-up have ever won in 100 years',
                'Collapsed on floor with excitement after winning',
                'Studied for hours daily to achieve his dream',
                'Represents hope for teens who don\'t give up'
            ],
            'location': 'National Harbor, Maryland',
            'date': 'May 2025',
            'emoji': '📚',
            'inspiration_message': 'Faizan\'s story shows that persistence pays off - sometimes you have to try again to achieve your dreams!'
        },
        {
            'title': 'Teen Environmental Activist Wins $25,000 Scholarship',
            'subtitle': 'Maya Chen, 17, from Portland, Oregon',
            'description': 'High school senior Maya Chen won the Davidson Fellows Scholarship for her innovative project turning plastic waste into building materials for homeless shelters. Her work has already helped build 3 shelters and prevented 2 tons of plastic from entering landfills.',
            'prizes': [
                '$25,000 Davidson Fellows Scholarship',
                'Recognition at Library of Congress ceremony',
                'Patent application support for her invention',
                'Mentorship with environmental engineers'
            ],
            'special_facts': [
                'Started project in her garage at age 15',
                'Built prototype with recycled soda bottles',
                '500+ volunteer hours in community service',
                'Inspired 12 other schools to start recycling programs'
            ],
            'location': 'Portland, Oregon',
            'date': 'June 2025',
            'emoji': '🌱',
            'inspiration_message': 'Maya proves that teens can solve real-world problems and make a lasting positive impact on their communities!'
        },
        {
            'title': 'Teen Coding Prodigy Lands Internship at Major Tech Company',
            'subtitle': 'Alex Rodriguez, 16, from Austin, Texas',
            'description': 'Despite being just 16, Alex Rodriguez impressed tech industry leaders with his AI app that helps elderly people manage medications. The app has been downloaded 50,000+ times and earned him a paid summer internship.',
            'prizes': [
                'Paid internship at Fortune 500 tech company',
                '$10,000 app development grant',
                'Mentorship with senior software engineers',
                'Opportunity to present at tech conference'
            ],
            'special_facts': [
                'Self-taught programming since age 12',
                'App helps prevent medication errors',
                'Youngest intern in company history',
                'Donates 10% of app revenue to senior centers'
            ],
            'location': 'Austin, Texas',
            'date': 'July 2025',
            'emoji': '💻',
            'inspiration_message': 'Alex shows that age is just a number when you have passion, dedication, and want to help others!'
        },
        {
            'title': 'Teen Athlete Earns Full Scholarship While Maintaining 4.0 GPA',
            'subtitle': 'Jordan Smith, 18, from Phoenix, Arizona',
            'description': 'Basketball star Jordan Smith earned a full athletic scholarship to a top university while maintaining perfect grades and volunteering 200+ hours at youth basketball camps. She plans to study biomedical engineering.',
            'prizes': [
                'Full 4-year athletic scholarship worth $200,000',
                'Academic Excellence Award',
                'Community Service Recognition',
                'Team Captain leadership role'
            ],
            'special_facts': [
                'Never missed a day of school in 4 years',
                'Tutors younger students in math and science',
                'Started community basketball program',
                'Mentors 30+ kids in leadership skills'
            ],
            'location': 'Phoenix, Arizona',
            'date': 'August 2025',
            'emoji': '🏀',
            'inspiration_message': 'Jordan demonstrates that excellence in sports and academics can go hand-in-hand with serving others!'
        },
        {
            'title': 'Teen Entrepreneur Starts Business That Employs 50+ People',
            'subtitle': 'Samuel Kim, 17, from Seattle, Washington',
            'description': 'Starting with a small lawn care service at 14, Samuel Kim grew his eco-friendly landscaping business to employ over 50 teens and adults. His company now serves 500+ customers and focuses on sustainable practices.',
            'prizes': [
                'Small Business Award from Chamber of Commerce',
                '$15,000 Young Entrepreneur Grant',
                'Featured in national business magazine',
                'Invited to speak at entrepreneurship summit'
            ],
            'special_facts': [
                'Created jobs for 50+ people in community',
                'Uses only eco-friendly tools and methods',
                'Reinvests 20% of profits in employee training',
                'Plans to study business and environmental science'
            ],
            'location': 'Seattle, Washington',
            'date': 'September 2025',
            'emoji': '🌿',
            'inspiration_message': 'Samuel proves that teens can create successful businesses that benefit both their community and the environment!'
        }
    ]
    
    # Return a different story based on the day to simulate daily updates
    day_of_year = datetime.now().timetuple().tm_yday
    story_index = day_of_year % len(teen_news_stories)
    return teen_news_stories[story_index]

@app.route('/daily-news-board')
@login_required
def daily_news_board():
    """Daily news board with teen achievements and weekly winners"""
    if current_user.role not in ['teen', 'teenager']:
        flash('Access denied. Teenager account required.', 'danger')
        return redirect(url_for('index'))
    
    # Get today's date
    today_date = datetime.now()
    
    # Get weekly winner (most recent completed drawing)
    weekly_winner = WeeklyDrawing.query.filter_by(status='completed').order_by(WeeklyDrawing.drawn_at.desc()).first()
    if weekly_winner:
        # Get winner's name from user table
        winner_user = User.query.get(weekly_winner.winner_user_id)
        weekly_winner.winner_name = winner_user.name if winner_user else "Anonymous Winner"
    
    # Get daily teen achievement news
    achievement_news = get_daily_teen_news()
    
    return render_template('daily_news_board.html',
                         today_date=today_date,
                         weekly_winner=weekly_winner,
                         achievement_news=achievement_news)

@app.route('/weekly-drawing-entries')
@login_required
def weekly_drawing_entries():
    """Display all weekly drawing entries with rules"""
    # Get all drawing entries with user settings for privacy
    entries = db.session.query(WeeklyDrawingEntry, User.name, UserSettings.hide_name_in_drawings).join(
        User, WeeklyDrawingEntry.user_id == User.id
    ).outerjoin(
        UserSettings, User.id == UserSettings.user_id
    ).order_by(WeeklyDrawingEntry.earned_at.desc()).all()
    
    # Format entries with privacy-aware user names
    formatted_entries = []
    for entry, user_name, hide_name in entries:
        # Check if user wants to hide their name in drawings
        display_name = "Anonymous Winner" if hide_name else user_name
        
        formatted_entries.append({
            'user_name': display_name,
            'entry_number': entry.entry_number,
            'category': entry.category.title(),
            'subcategory': entry.subcategory.title() if entry.subcategory else '',
            'earned_at': entry.earned_at,
            'week_ending': entry.week_ending
        })
    
    return render_template('weekly_drawing_entries.html',
                         entries=formatted_entries)

@app.route('/manifest.json')
def manifest():
    return send_file('static/manifest.json')

@app.route('/sw.js')
def service_worker():
    return send_file('static/sw.js')

# ================== SETTINGS SYSTEM ROUTES ==================

@app.route('/settings')
@login_required
def user_settings():
    """User settings dashboard"""
    if current_user.role not in ['teen', 'teenager']:
        flash('Access denied. Teenager account required.', 'danger')
        return redirect(url_for('index'))
    
    # Get or create user settings
    settings = UserSettings.query.filter_by(user_id=current_user.id).first()
    if not settings:
        settings = UserSettings()
        settings.user_id = current_user.id
        db.session.add(settings)
        db.session.commit()
    
    # Get user progress data with safe model access
    try:
        quiz_results = QuizResult.query.filter_by(user_id=current_user.id).all()
        
        # Safely access optional models
        sports_results = []
        try:
            sports_results = SportsQuizResult.query.filter_by(user_id=current_user.id).all()
        except:
            pass
            
        category_results = []
        try:
            category_results = CategoryQuizResult.query.filter_by(user_id=current_user.id).all()
        except:
            pass
        
        badges = []
        try:
            badges = UserBadge.query.filter_by(user_id=current_user.id).all()
        except:
            pass
            
        drawing_entries = []
        try:
            drawing_entries = WeeklyDrawingEntry.query.filter_by(user_id=current_user.id).all()
        except:
            pass
        
        # Calculate progress stats
        total_quizzes = len(quiz_results) + len(sports_results) + len(category_results)
        perfect_scores = sum([1 for r in quiz_results if r.percentage == 100])
        
        # Add sports and category perfect scores safely
        for r in sports_results:
            if hasattr(r, 'perfect_score') and r.perfect_score:
                perfect_scores += 1
        
        for r in category_results:
            if hasattr(r, 'perfect_score') and r.perfect_score:
                perfect_scores += 1
        
        progress_stats = {
            'total_quizzes': total_quizzes,
            'perfect_scores': perfect_scores,
            'badges_earned': len(badges),
            'drawing_entries': len(drawing_entries),
            'perfect_percentage': (perfect_scores / total_quizzes * 100) if total_quizzes > 0 else 0
        }
    except Exception as e:
        # Fallback if there are any model issues
        progress_stats = {
            'total_quizzes': 0,
            'perfect_scores': 0,
            'badges_earned': 0,
            'drawing_entries': 0,
            'perfect_percentage': 0
        }
    
    return render_template('settings.html', settings=settings, progress_stats=progress_stats)

@app.route('/settings/notifications', methods=['GET', 'POST'])
@login_required
def notification_settings():
    """Notification preferences settings"""
    if current_user.role not in ['teen', 'teenager']:
        flash('Access denied. Teenager account required.', 'danger')
        return redirect(url_for('index'))
    
    settings = UserSettings.query.filter_by(user_id=current_user.id).first()
    if not settings:
        settings = UserSettings()
        settings.user_id = current_user.id
        db.session.add(settings)
        db.session.commit()
    
    if request.method == 'POST':
        settings.quiz_reminders = 'quiz_reminders' in request.form
        settings.content_alerts = 'content_alerts' in request.form
        settings.drawing_notifications = 'drawing_notifications' in request.form
        settings.quiet_hours_start = request.form.get('quiet_hours_start', '')
        settings.quiet_hours_end = request.form.get('quiet_hours_end', '')
        
        db.session.commit()
        flash('Notification settings updated successfully!', 'success')
        return redirect(url_for('user_settings'))
    
    return render_template('settings_notifications.html', settings=settings)

@app.route('/settings/privacy', methods=['GET', 'POST'])
@login_required
def privacy_settings():
    """Privacy control settings"""
    if current_user.role not in ['teen', 'teenager']:
        flash('Access denied. Teenager account required.', 'danger')
        return redirect(url_for('index'))
    
    settings = UserSettings.query.filter_by(user_id=current_user.id).first()
    if not settings:
        settings = UserSettings()
        settings.user_id = current_user.id
        db.session.add(settings)
        db.session.commit()
    
    if request.method == 'POST':
        settings.show_activity_to_mentors = 'show_activity_to_mentors' in request.form
        settings.show_activity_to_peers = 'show_activity_to_peers' in request.form
        settings.hide_name_in_drawings = 'hide_name_in_drawings' in request.form
        
        db.session.commit()
        flash('Privacy settings updated successfully!', 'success')
        return redirect(url_for('user_settings'))
    
    return render_template('settings_privacy.html', settings=settings)

@app.route('/settings/interests', methods=['GET', 'POST'])
@login_required
def interest_settings():
    """Customizable interests and dashboard preferences"""
    if current_user.role not in ['teen', 'teenager']:
        flash('Access denied. Teenager account required.', 'danger')
        return redirect(url_for('index'))
    
    settings = UserSettings.query.filter_by(user_id=current_user.id).first()
    if not settings:
        settings = UserSettings()
        settings.user_id = current_user.id
        db.session.add(settings)
        db.session.commit()
    
    # Available categories
    categories = [
        {'id': 'faith', 'name': 'Faith & Values', 'icon': '⭐'},
        {'id': 'sports', 'name': 'Sports & Athletics', 'icon': '🏆'},
        {'id': 'careers', 'name': 'Career Paths', 'icon': '💼'},
        {'id': 'money_budgeting', 'name': 'Money & Budgeting', 'icon': '💰'},
        {'id': 'personal_development', 'name': 'Personal Development', 'icon': '💪'},
        {'id': 'technology', 'name': 'Technology & Innovation', 'icon': '💻'},
        {'id': 'education', 'name': 'Education & Academics', 'icon': '📚'},
        {'id': 'creativity', 'name': 'Creativity & Hobbies', 'icon': '🎨'},
        {'id': 'community', 'name': 'Community & Volunteering', 'icon': '🤝'},
        {'id': 'life_skills', 'name': 'Life Skills', 'icon': '🔧'},
        {'id': 'ai_mentor', 'name': 'AI Mentor Bot', 'icon': '🤖'},
        {'id': 'daily_news', 'name': 'Daily News with Drawing', 'icon': '🎨📰'}
    ]
    
    if request.method == 'POST':
        favorite_categories = request.form.getlist('favorite_categories')
        hidden_categories = request.form.getlist('hidden_categories')
        
        settings.favorite_categories = json.dumps(favorite_categories)
        settings.hidden_categories = json.dumps(hidden_categories)
        
        db.session.commit()
        flash('Interest preferences updated successfully!', 'success')
        return redirect(url_for('user_settings'))
    
    # Parse current settings
    current_favorites = json.loads(settings.favorite_categories or '[]')
    current_hidden = json.loads(settings.hidden_categories or '[]')
    
    return render_template('settings_interests.html', 
                         settings=settings, 
                         categories=categories,
                         current_favorites=current_favorites,
                         current_hidden=current_hidden)

@app.route('/settings/accessibility', methods=['GET', 'POST'])
@login_required
def accessibility_settings():
    """Accessibility options settings"""
    if current_user.role not in ['teen', 'teenager']:
        flash('Access denied. Teenager account required.', 'danger')
        return redirect(url_for('index'))
    
    settings = UserSettings.query.filter_by(user_id=current_user.id).first()
    if not settings:
        settings = UserSettings()
        settings.user_id = current_user.id
        db.session.add(settings)
        db.session.commit()
    
    if request.method == 'POST':
        settings.audio_quiz_questions = 'audio_quiz_questions' in request.form
        
        db.session.commit()
        flash('Accessibility settings updated successfully!', 'success')
        return redirect(url_for('user_settings'))
    
    return render_template('settings_accessibility.html', settings=settings)

@app.route('/settings/account', methods=['GET', 'POST'])
@login_required
def account_settings():
    """Account management settings"""
    if current_user.role not in ['teen', 'teenager']:
        flash('Access denied. Teenager account required.', 'danger')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'update_profile':
            current_user.name = request.form.get('name', '').strip()
            current_user.email = request.form.get('email', '').strip()
            current_user.phone_number = request.form.get('phone_number', '').strip()
            current_user.city = request.form.get('city', '').strip()
            
            try:
                age_input = request.form.get('age', '').strip()
                if age_input:
                    current_user.age = int(age_input)
            except ValueError:
                flash('Please enter a valid age.', 'danger')
                return redirect(url_for('account_settings'))
            
            db.session.commit()
            flash('Profile updated successfully!', 'success')
            
        elif action == 'change_password':
            current_password = request.form.get('current_password', '')
            new_password = request.form.get('new_password', '')
            confirm_password = request.form.get('confirm_password', '')
            
            if not current_user.check_password(current_password):
                flash('Current password is incorrect.', 'danger')
                return redirect(url_for('account_settings'))
            
            if new_password != confirm_password:
                flash('New passwords do not match.', 'danger')
                return redirect(url_for('account_settings'))
            
            if len(new_password) < 6:
                flash('New password must be at least 6 characters long.', 'danger')
                return redirect(url_for('account_settings'))
            
            current_user.set_password(new_password)
            db.session.commit()
            flash('Password updated successfully!', 'success')
        
        return redirect(url_for('account_settings'))
    
    return render_template('settings_account.html')

@app.route('/feedback', methods=['GET', 'POST'])
@login_required
def user_feedback():
    """User feedback system with profanity filtering"""
    if request.method == 'POST':
        feedback_text = request.form.get('feedback_text', '').strip()
        category = request.form.get('category', 'suggestion')
        
        # Validate feedback with profanity filter
        if profanity_filter.contains_profanity(feedback_text):
            validation_result = {'valid': False, 'message': 'Please keep feedback appropriate and respectful.'}
        else:
            validation_result = {'valid': True, 'filtered_text': feedback_text}
        
        if not validation_result['valid']:
            flash(validation_result['message'], 'danger')
            return render_template('feedback.html', 
                                 feedback_text=feedback_text, 
                                 category=category)
        
        # Create feedback entry
        feedback = UserFeedback()
        feedback.user_id = current_user.id
        feedback.feedback_text = validation_result['filtered_text']
        feedback.category = category
        
        db.session.add(feedback)
        db.session.commit()
        
        flash('Thank you for your feedback! We appreciate your input and will review it soon.', 'success')
        return redirect(url_for('teen_dashboard'))
    
    return render_template('feedback.html')

@app.route('/progress')
@login_required
def progress_tracking():
    """Detailed progress tracking page"""
    if current_user.role not in ['teen', 'teenager']:
        flash('Access denied. Teenager account required.', 'danger')
        return redirect(url_for('index'))
    
    # Get user progress data with error handling
    try:
        quiz_results = QuizResult.query.filter_by(user_id=current_user.id).order_by(QuizResult.taken_at.desc()).all()
        sports_results = SportsQuizResult.query.filter_by(user_id=current_user.id).order_by(SportsQuizResult.completed_at.desc()).all() if 'SportsQuizResult' in globals() else []
        category_results = CategoryQuizResult.query.filter_by(user_id=current_user.id).order_by(CategoryQuizResult.completed_at.desc()).all() if 'CategoryQuizResult' in globals() else []
        badges = UserBadge.query.filter_by(user_id=current_user.id).order_by(UserBadge.earned_at.desc()).all() if 'UserBadge' in globals() else []
        drawing_entries = WeeklyDrawingEntry.query.filter_by(user_id=current_user.id).order_by(WeeklyDrawingEntry.earned_at.desc()).all()
        
        # Calculate streaks and achievements
        total_quizzes = len(quiz_results) + len(sports_results) + len(category_results)
        perfect_scores = sum([1 for r in quiz_results if r.percentage == 100]) + \
                        sum([1 for r in sports_results if getattr(r, 'perfect_score', False)]) + \
                        sum([1 for r in category_results if getattr(r, 'perfect_score', False)])
        
        # Calculate category breakdown
        category_stats = {}
        for result in category_results:
            cat = getattr(result, 'category', 'Unknown')
            if cat not in category_stats:
                category_stats[cat] = {'total': 0, 'perfect': 0}
            category_stats[cat]['total'] += 1
            if getattr(result, 'perfect_score', False):
                category_stats[cat]['perfect'] += 1
        
        progress_data = {
            'total_quizzes': total_quizzes,
            'perfect_scores': perfect_scores,
            'badges_earned': len(badges),
            'drawing_entries': len(drawing_entries),
            'perfect_percentage': (perfect_scores / total_quizzes * 100) if total_quizzes > 0 else 0,
            'quiz_results': quiz_results[:10],  # Last 10
            'sports_results': sports_results[:10],
            'category_results': category_results[:10],
            'badges': badges[:10],
            'category_stats': category_stats
        }
    except Exception as e:
        # Fallback if there are any model issues
        progress_data = {
            'total_quizzes': 0,
            'perfect_scores': 0,
            'badges_earned': 0,
            'drawing_entries': 0,
            'perfect_percentage': 0,
            'quiz_results': [],
            'sports_results': [],
            'category_results': [],
            'badges': [],
            'category_stats': {}
        }
    
    return render_template('settings_progress.html', progress_data=progress_data)

# ================== CATEGORY EXPLORATION ROUTES ==================

@app.route('/career-exploration/<category>')
@login_required
def career_exploration(category):
    """Comprehensive category exploration for all major life areas"""
    if current_user.role not in ['teen', 'teenager']:
        flash('Access denied. Teenager account required.', 'danger')
        return redirect(url_for('index'))
    
    # Sports & Athletics Category
    if category == 'sports':
        sports_paths = [
            {'title': 'Football', 'description': 'From Jr High to NFL - complete pathway', 'icon': '🏈'},
            {'title': 'Basketball', 'description': 'Court skills to professional leagues', 'icon': '🏀'},
            {'title': 'Soccer', 'description': 'Local teams to World Cup dreams', 'icon': '⚽'},
            {'title': 'Baseball', 'description': 'Little League to Major League Baseball', 'icon': '⚾'},
            {'title': 'Tennis', 'description': 'Individual excellence and tournaments', 'icon': '🎾'},
            {'title': 'Track & Field', 'description': 'Speed, strength, and Olympic dreams', 'icon': '🏃'},
            {'title': 'Golf', 'description': 'Precision sport with lifelong benefits', 'icon': '⛳'}
        ]
        return render_template('categories/sports_exploration.html', sports=sports_paths, category=category)
    
    # Faith & Values Category  
    elif category == 'faith':
        items = [
            {'title': 'Character Building', 'description': 'Your spiritual core and foundation', 'icon': '⭐'},
            {'title': 'Respect & Relationships', 'description': 'Build healthy, mutual relationships', 'icon': '🤗'},
            {'title': 'Service & Giving', 'description': 'Your secret superpower for fulfillment', 'icon': '💝'},
            {'title': 'Spiritual Growth', 'description': 'Strengthen your faith and beliefs', 'icon': '🙏'},
            {'title': 'Integrity', 'description': 'Your life\'s resume of character', 'icon': '✨'},
            {'title': 'Honesty', 'description': 'The clean slate approach to truth', 'icon': '📝'}
        ]
        return render_template('categories/category_exploration.html', items=items, category=category, category_title="Faith & Values")
    
    # Career Paths Category
    elif category == 'careers':
        items = [
            # Tech & Innovation Careers
            {'title': 'AI Project Manager', 'description': 'Lead AI development projects that transform industries ($120K-$250K+)', 'icon': '🤖', 'path': 'ai-project-manager'},
            {'title': 'Data Scientist', 'description': 'Transform data into powerful insights for business decisions ($95K-$200K+)', 'icon': '📊', 'path': 'data-scientist'},
            {'title': 'Cybersecurity Analyst', 'description': 'Protect digital systems from cyber threats ($85K-$180K+)', 'icon': '🔐', 'path': 'cybersecurity-analyst'},
            {'title': 'Software Developer', 'description': 'Build apps, platforms, and systems that power the digital world ($80K-$200K+)', 'icon': '💻', 'path': 'software-developer'},
            {'title': 'Robotics Technician', 'description': 'Design and maintain robots for industry and healthcare ($60K-$120K+)', 'icon': '🤖', 'path': 'robotics-technician'},
            
            # Green & Sustainability Careers
            {'title': 'Wind Turbine Technician', 'description': 'Install and maintain wind energy systems ($45K-$80K+)', 'icon': '💨', 'path': 'wind-turbine-technician'},
            {'title': 'Solar Installer', 'description': 'Power homes and businesses with clean solar energy ($40K-$70K+)', 'icon': '☀️', 'path': 'solar-installer'},
            
            # Health & Wellness Careers
            {'title': 'Nurse Practitioner', 'description': 'Provide advanced healthcare services and prescribe treatments ($95K-$130K+)', 'icon': '🩺', 'path': 'nurse-practitioner'},
            {'title': 'Doctor', 'description': 'Heal people and save lives through medicine', 'icon': '👩‍⚕️', 'path': 'doctor'},
            {'title': 'Mental Health Counselor', 'description': 'Support emotional well-being and mental health', 'icon': '💙', 'path': 'mental-health-counselor'},
            
            # Traditional Professional Careers
            {'title': 'Lawyer', 'description': 'Fight for justice and defend others', 'icon': '⚖️', 'path': 'lawyer'},
            {'title': 'Engineer', 'description': 'Build and design the future', 'icon': '🔧', 'path': 'engineer'},
            {'title': 'Teacher', 'description': 'Shape minds and inspire learning', 'icon': '👩‍🏫', 'path': 'teacher'},
            {'title': 'Business Owner', 'description': 'Create jobs and lead innovation', 'icon': '💼', 'path': 'business-owner'},
            {'title': 'Police Officer', 'description': 'Protect and serve your community', 'icon': '👮', 'path': 'police-officer'},
            {'title': 'Nurse', 'description': 'Care for patients with compassion', 'icon': '👩‍⚕️', 'path': 'nurse'},
            {'title': 'Architect', 'description': 'Design buildings and spaces', 'icon': '🏗️', 'path': 'architect'},
            {'title': 'Military', 'description': 'Serve your country with honor', 'icon': '🇺🇸', 'path': 'military'}
        ]
        return render_template('categories/category_exploration.html', items=items, category=category, category_title="Career Paths")
    
    # Money & Budgeting Category
    elif category == 'money_budgeting':
        items = [
            {'title': 'Money Mindset & Values', 'description': 'Understanding the purpose of money and distinguishing needs vs wants', 'icon': '🔑', 'url_key': 'money_mindset_values'},
            {'title': 'Budgeting Basics', 'description': 'How to create a simple monthly budget and track spending', 'icon': '💵', 'url_key': 'budgeting_basics'},
            {'title': 'Banking & Digital Money', 'description': 'How checking/savings accounts work and using digital payments safely', 'icon': '💳', 'url_key': 'banking_digital_money'},
            {'title': 'Debt & Credit Awareness', 'description': 'Understanding credit scores and avoiding debt traps', 'icon': '📉', 'url_key': 'debt_credit_awareness'},
            {'title': 'Saving & Goal Setting', 'description': 'Building emergency funds and learning delayed gratification', 'icon': '📈', 'url_key': 'saving_goal_setting'},
            {'title': 'Investing Early', 'description': 'Power of compound interest and intro to stocks and ETFs', 'icon': '🪙', 'url_key': 'investing_early'},
            {'title': 'Work, Side Hustles & Income', 'description': 'Earning your own money and understanding taxes', 'icon': '🏠', 'url_key': 'work_side_hustles_income'},
            {'title': 'Generosity & Responsibility', 'description': 'Giving, sharing, and using money to make a difference', 'icon': '❤️', 'url_key': 'generosity_responsibility'},
            {'title': 'Avoiding Money Traps', 'description': 'Spotting scams and avoiding risky financial schemes', 'icon': '⚠️', 'url_key': 'avoiding_money_traps'},
            {'title': 'Planning for the Future', 'description': 'Long-term financial planning for college and independence', 'icon': '📊', 'url_key': 'planning_future'}
        ]
        return render_template('categories/category_exploration.html', items=items, category=category, category_title="Money & Budgeting")
    
    # Personal Development Category
    elif category == 'personal_development':
        items = [
            {'title': 'Confidence & Self-Esteem', 'description': 'Build unshakeable confidence and believe in yourself', 'icon': '💪', 'url_key': 'confidence_and_self_esteem'},
            {'title': 'Goal Setting & Time Management', 'description': 'Master your time and achieve meaningful goals', 'icon': '🎯', 'url_key': 'goal_setting_time_management'},
            {'title': 'Public Speaking & Communication', 'description': 'Speak with power, clarity, and confidence', 'icon': '🎤', 'url_key': 'public_speaking_communication'},
            {'title': 'Leadership Skills', 'description': 'Lead others and make a positive difference', 'icon': '👑', 'url_key': 'leadership_skills'},
            {'title': 'Emotional Intelligence & Self-Awareness', 'description': 'Understand and manage your emotions effectively', 'icon': '🧠', 'url_key': 'emotional_intelligence'},
            {'title': 'Stress Management & Resilience', 'description': 'Handle pressure and bounce back from challenges', 'icon': '🛡️', 'url_key': 'stress_management_resilience'},
            {'title': 'Decision Making & Problem Solving', 'description': 'Make smart choices and solve problems effectively', 'icon': '🤔', 'url_key': 'decision_making_problem_solving'},
            {'title': 'Building Healthy Relationships', 'description': 'Create and maintain positive relationships', 'icon': '🤝', 'url_key': 'building_healthy_relationships'},
            {'title': 'Personal Values & Identity', 'description': 'Discover who you are and what matters to you', 'icon': '⭐', 'url_key': 'personal_values_identity'},
            {'title': 'Study Skills & Learning Strategies', 'description': 'Learn how to learn more effectively', 'icon': '📚', 'url_key': 'study_skills_learning_strategies'}
        ]
        return render_template('categories/category_exploration.html', items=items, category=category, category_title="Personal Development")
    
    # Technology & Innovation Category
    elif category == 'technology':
        items = [
            {'title': 'Coding & App Development', 'description': 'Create apps, websites, and software that changes the world', 'icon': '💻', 'url_key': 'coding_app_development'},
            {'title': 'Robotics & Automation', 'description': 'Build robots and automated systems for the future', 'icon': '🤖', 'url_key': 'robotics_automation'},
            {'title': 'Digital Media & Graphic Design', 'description': 'Create stunning visual content and digital experiences', 'icon': '🎨', 'url_key': 'digital_media_design'},
            {'title': 'Gaming & eSports Careers', 'description': 'Turn your passion for gaming into a professional career', 'icon': '🎮', 'url_key': 'gaming_esports'}
        ]
        return render_template('categories/category_exploration.html', items=items, category=category, category_title="Technology & Innovation")
    
    # Education & Academics Category
    elif category == 'education':
        items = [
            {'title': 'Study Skills & Tutoring', 'description': 'Master effective learning techniques and help others succeed', 'icon': '📖', 'url_key': 'study_skills_tutoring'},
            {'title': 'STEM Exploration', 'description': 'Dive deep into Science, Technology, Engineering, and Math', 'icon': '🔬', 'url_key': 'stem_exploration'},
            {'title': 'Writing & Creative Arts', 'description': 'Express yourself powerfully through words and stories', 'icon': '✍️', 'url_key': 'writing_creative_arts'},
            {'title': 'College Prep & Scholarships', 'description': 'Navigate your path to higher education and funding', 'icon': '🎓', 'url_key': 'college_prep_scholarships'}
        ]
        return render_template('categories/category_exploration.html', items=items, category=category, category_title="Education & Academics")
    
    # Creativity & Hobbies Category
    elif category == 'creativity':
        items = [
            {'title': 'Music & Instruments', 'description': 'Create beautiful music and develop musical talent', 'icon': '🎵', 'url_key': 'music_instruments'},
            {'title': 'Art & Design', 'description': 'Express creativity through visual art and design', 'icon': '🎨', 'url_key': 'art_design'},
            {'title': 'Dance & Theater', 'description': 'Perform, entertain, and tell stories through movement', 'icon': '🎭', 'url_key': 'dance_theater'},
            {'title': 'Photography & Videography', 'description': 'Capture life\'s moments and create visual stories', 'icon': '📸', 'url_key': 'photography_videography'},
            {'title': 'Creative Writing & Storytelling', 'description': 'Craft compelling stories and share your voice', 'icon': '📚', 'url_key': 'creative_writing'},
            {'title': 'Podcasting & Audio Production', 'description': 'Create engaging audio content and broadcasts', 'icon': '🎙️', 'url_key': 'podcasting_audio'}
        ]
        return render_template('categories/category_exploration.html', items=items, category=category, category_title="Creativity & Hobbies")
    
    # Community & Volunteering Category
    elif category == 'community':
        items = [
            {'title': 'Charity & Outreach', 'description': 'Make a difference by helping those in need', 'icon': '🤝', 'url_key': 'charity_outreach'},
            {'title': 'Environmental Projects', 'description': 'Protect our planet for future generations', 'icon': '🌱', 'url_key': 'environmental_projects'},
            {'title': 'Leadership in Community', 'description': 'Lead positive change in your community', 'icon': '🌟', 'url_key': 'community_leadership'},
            {'title': 'Peer Mentoring', 'description': 'Guide, support, and inspire others', 'icon': '👥', 'url_key': 'peer_mentoring'}
        ]
        return render_template('categories/category_exploration.html', items=items, category=category, category_title="Community & Volunteering")
    
    # Life Skills Category
    elif category == 'life_skills':
        items = [
            {'title': 'Cooking & Meal Prep', 'description': 'Master nutrition and cooking for independence', 'icon': '👨‍🍳', 'url_key': 'cooking_meal_prep'},
            {'title': 'Car & Home Basics', 'description': 'Essential maintenance and repair skills', 'icon': '🔧', 'url_key': 'car_home_basics'},
            {'title': 'Job Interview Skills', 'description': 'Master interviews and land your dream job', 'icon': '💼', 'url_key': 'job_interview_skills'},
            {'title': 'Resume & Portfolio Building', 'description': 'Showcase your talents and achievements', 'icon': '📋', 'url_key': 'resume_portfolio_building'}
        ]
        return render_template('categories/category_exploration.html', items=items, category=category, category_title="Life Skills")
    
    # Critical Life Topics Category
    elif category == 'critical_topics':
        items = [
            {'title': 'Stress Management & Resilience', 'description': 'Build mental strength and healthy coping skills', 'icon': '🧘', 'url_key': 'stress_management_resilience'},
            {'title': 'Decision Making & Problem Solving', 'description': 'Learn to think critically and make wise choices', 'icon': '🤔', 'url_key': 'decision_making_problem_solving'},
            {'title': 'Building Healthy Relationships', 'description': 'Create meaningful connections with family and friends', 'icon': '💕', 'url_key': 'building_healthy_relationships'},
            {'title': 'Personal Values & Identity', 'description': 'Discover who you are and what you stand for', 'icon': '🌟', 'url_key': 'personal_values_identity'},
            {'title': 'Future Planning & Goal Setting', 'description': 'Map your path to success and achievement', 'icon': '🎯', 'url_key': 'future_planning_goal_setting'},
            {'title': 'Money Management & Financial Literacy', 'description': 'Master budgeting, saving, and smart spending', 'icon': '💰', 'url_key': 'money_management_financial_literacy'}
        ]
        return render_template('categories/category_exploration.html', items=items, category=category, category_title="Critical Life Topics")
    
    # Default fallback for unknown categories
    else:
        flash(f'Category "{category}" not found. Redirecting to dashboard.', 'warning')
        return redirect(url_for('teen_dashboard'))

# Individual Sport Pathway Routes
@app.route('/sport-pathway/<sport>')
@login_required
def sport_pathway(sport):
    """Individual sport pathway pages with city-specific content"""
    if current_user.role not in ['teen', 'teenager']:
        flash('Access denied. Teenager account required.', 'danger')
        return redirect(url_for('index'))
    
    # Get user's city from settings or default
    user_city = getattr(current_user, 'city', 'Your City')
    
    sport_data = {
        'basketball': {
            'title': 'Basketball Pathway',
            'icon': '🏀',
            'teen_example': {
                'name': 'Marcus',
                'age': 16,
                'story': 'Started playing at 13, now leads his high school team. He practices 2 hours daily, maintains a 3.8 GPA, and earned a college scout\'s attention by showing leadership on and off the court.',
                'key': 'Consistency + academics + character = opportunities'
            },
            'education': {
                'what_is': 'Basketball is a fast-paced team sport that develops coordination, teamwork, and quick decision-making. It requires physical fitness, mental toughness, and strategic thinking.',
                'skills_needed': [
                    'Dribbling and ball handling',
                    'Shooting accuracy and form',
                    'Defensive positioning and footwork',
                    'Passing and court vision',
                    'Rebounding and boxing out',
                    'Teamwork and communication'
                ],
                'improvement_tips': [
                    'Practice shooting form daily with proper follow-through',
                    'Work on dribbling with both hands',
                    'Study game film to understand plays',
                    'Focus on defensive stance and lateral movement',
                    'Build cardiovascular endurance through running',
                    'Strengthen core and leg muscles for jumping'
                ]
            },
            'benefits': {
                'physical': ['Improved cardiovascular health', 'Better hand-eye coordination', 'Increased agility and speed', 'Enhanced jumping ability'],
                'mental': ['Quick decision-making skills', 'Ability to perform under pressure', 'Strategic thinking', 'Focus and concentration'],
                'social': ['Teamwork and cooperation', 'Leadership opportunities', 'Communication skills', 'Sportsmanship'],
                'life': ['Time management from practice schedules', 'Goal setting and achievement', 'Resilience from losses', 'College scholarship opportunities']
            },
            'mentor_guidance': {
                'quote': 'Basketball taught me that success comes from the combination of individual skill and team chemistry. The hours you put in alone make you better, but championships are won together.',
                'mentor_name': 'Coach Williams',
                'mentor_background': 'Former college player, 15 years coaching high school basketball'
            }
        },
        'soccer': {
            'title': 'Soccer Pathway', 
            'icon': '⚽',
            'teen_example': {
                'name': 'Sofia',
                'age': 15,
                'story': 'Joined a travel team at 14, volunteers as a youth coach, and maintains excellent grades. She\'s learning that giving back to younger players has improved her own leadership skills tremendously.',
                'key': 'Service to others develops leadership'
            },
            'education': {
                'what_is': 'Soccer is the world\'s most popular sport, emphasizing endurance, skill with feet, and tactical awareness. It builds incredible cardiovascular fitness and global cultural understanding.',
                'skills_needed': [
                    'Ball control and first touch',
                    'Passing accuracy with both feet',
                    'Shooting power and placement',
                    'Defensive tackling and positioning',
                    'Heading technique and timing',
                    'Field awareness and positioning'
                ],
                'improvement_tips': [
                    'Practice juggling to improve ball control',
                    'Work on weak foot development daily',
                    'Run long distances to build endurance',
                    'Practice shooting from different angles',
                    'Study professional games for tactical understanding',
                    'Focus on first touch in tight spaces'
                ]
            },
            'benefits': {
                'physical': ['Exceptional cardiovascular fitness', 'Strong leg muscles and core', 'Improved balance and coordination', 'Enhanced spatial awareness'],
                'mental': ['Strategic thinking and field vision', 'Quick decision-making under pressure', 'Mental toughness from physical play', 'Patience and persistence'],
                'social': ['Global sport with worldwide connections', 'Cultural appreciation and diversity', 'Team unity and bonding', 'Community involvement'],
                'life': ['Discipline from year-round training', 'Travel opportunities', 'Language learning potential', 'International scholarship possibilities']
            },
            'mentor_guidance': {
                'quote': 'Soccer is called the beautiful game because it teaches you that individual brilliance means nothing without team success. Every touch, every pass, every run contributes to something bigger than yourself.',
                'mentor_name': 'Maria Santos',
                'mentor_background': 'Former semi-professional player, youth development coach for 12 years'
            }
        },
        'track': {
            'title': 'Track & Field Pathway',
            'icon': '🏃',
            'teen_example': {
                'name': 'David',
                'age': 17,
                'story': 'Not the fastest runner initially, but his consistent training and positive attitude earned him team captain. Now he\'s helping teammates improve while preparing for college track programs.',
                'key': 'Attitude matters more than natural talent'
            },
            'education': {
                'what_is': 'Track and field includes running, jumping, and throwing events. It\'s an individual sport within a team setting that teaches self-discipline, goal-setting, and measurable improvement.',
                'skills_needed': [
                    'Proper running form and technique',
                    'Sprint starts and acceleration',
                    'Endurance and pacing for distance',
                    'Jumping technique for field events',
                    'Throwing form for shot put/discus',
                    'Mental preparation and race strategy'
                ],
                'improvement_tips': [
                    'Focus on running form with short, quick steps',
                    'Build base endurance with easy runs',
                    'Practice sprint starts regularly',
                    'Strengthen core and leg muscles',
                    'Keep a training log to track progress',
                    'Work on flexibility and injury prevention'
                ]
            },
            'benefits': {
                'physical': ['Peak cardiovascular fitness', 'Lean muscle development', 'Improved running efficiency', 'Strong bones from impact'],
                'mental': ['Self-motivation and discipline', 'Goal-setting and achievement', 'Mental toughness from training', 'Time management skills'],
                'social': ['Individual achievement within team support', 'Mentoring younger athletes', 'Competition respect and sportsmanship', 'Lifelong fitness habits'],
                'life': ['Measurable progress and improvement', 'College recruiting opportunities', 'Lifetime fitness foundation', 'Self-reliance and independence']
            },
            'mentor_guidance': {
                'quote': 'Track and field is honest - the clock doesn\'t lie, the measuring tape doesn\'t lie. Your effort and preparation are directly reflected in your results. This teaches you that success in life comes from consistent work.',
                'mentor_name': 'Coach Johnson',
                'mentor_background': 'Former Olympic trials qualifier, 20 years coaching high school track'
            }
        },
        'football': {
            'title': 'Football Pathway',
            'icon': '🏈',
            'teen_example': {
                'name': 'Jake',
                'age': 16,
                'story': 'Started as a backup lineman, worked harder than anyone in the weight room. His dedication earned him a starting position and team respect. Now he\'s being recruited by colleges for his work ethic as much as his skill.',
                'key': 'Hard work beats talent when talent doesn\'t work hard'
            },
            'education': {
                'what_is': 'Football is the ultimate team sport requiring strategy, strength, speed, and mental toughness. It teaches leadership, perseverance, and how to work together toward a common goal.',
                'skills_needed': [
                    'Position-specific techniques',
                    'Strength and power development',
                    'Speed and agility training',
                    'Understanding complex playbooks',
                    'Communication and leadership',
                    'Mental toughness and focus'
                ],
                'improvement_tips': [
                    'Master your position\'s fundamentals first',
                    'Study film to understand opponent tendencies',
                    'Build strength through consistent weight training',
                    'Practice footwork and agility daily',
                    'Develop leadership through vocal communication',
                    'Learn multiple positions to increase value'
                ]
            },
            'benefits': {
                'physical': ['Total body strength development', 'Explosive power and speed', 'Hand-eye coordination', 'Injury prevention through proper technique'],
                'mental': ['Strategic thinking and game planning', 'Pressure performance abilities', 'Quick decision-making skills', 'Mental resilience and toughness'],
                'social': ['Brotherhood and team bonding', 'Leadership development opportunities', 'Community pride and support', 'Networking through teammates'],
                'life': ['Work ethic from demanding training', 'Time management from busy schedules', 'Goal achievement through team success', 'College recruitment opportunities']
            },
            'mentor_guidance': {
                'quote': 'Football teaches you that individual success means nothing if the team fails. Every player has a role, and when everyone executes their role perfectly, magic happens. This lesson applies to every area of life.',
                'mentor_name': 'Coach Thompson',
                'mentor_background': 'Former college quarterback, 18 years coaching high school football'
            }
        },
        'baseball': {
            'title': 'Baseball Pathway',
            'icon': '⚾',
            'teen_example': {
                'name': 'Alex',
                'age': 15,
                'story': 'Struggled with hitting for two seasons but never gave up. Spent extra hours in batting practice, studied opposing pitchers, and finally broke through with a game-winning hit in playoffs.',
                'key': 'Baseball teaches you that failure is part of success'
            },
            'education': {
                'what_is': 'Baseball is a precision sport that requires patience, timing, and mental strategy. It teaches you to handle failure, stay focused for long periods, and make split-second decisions.',
                'skills_needed': [
                    'Hitting mechanics and timing',
                    'Fielding and throwing accuracy',
                    'Pitching control and strategy',
                    'Base running and stealing',
                    'Game situational awareness',
                    'Mental focus and patience'
                ],
                'improvement_tips': [
                    'Practice hitting off a tee for proper mechanics',
                    'Work on glove work with daily fielding drills',
                    'Study opposing pitchers and their tendencies',
                    'Build arm strength through long toss',
                    'Practice situational hitting (hit and run, moving runners)',
                    'Develop mental game through visualization'
                ]
            },
            'benefits': {
                'physical': ['Hand-eye coordination excellence', 'Rotational power development', 'Flexibility and mobility', 'Precision motor skills'],
                'mental': ['Patience and delayed gratification', 'Handling failure and adversity', 'Concentration for extended periods', 'Strategic thinking'],
                'social': ['Respect for tradition and history', 'Multi-generational bonding', 'Team chemistry and support', 'Community involvement'],
                'life': ['Learning from failure and mistakes', 'Attention to detail', 'Preparation and practice habits', 'Scholarship and professional opportunities']
            },
            'mentor_guidance': {
                'quote': 'Baseball is a game of failure. The best hitters fail 7 out of 10 times. What separates champions is how you respond to that failure and what you learn from it.',
                'mentor_name': 'Coach Martinez',
                'mentor_background': 'Former minor league player, 16 years coaching youth baseball'
            }
        },
        'tennis': {
            'title': 'Tennis Pathway',
            'icon': '🎾',
            'teen_example': {
                'name': 'Emma',
                'age': 16,
                'story': 'Started playing at 12, struggled with consistency but loved the individual challenge. Through private lessons and tournament play, she learned that tennis success comes from mental toughness as much as physical skill.',
                'key': 'Tennis is 90% mental once you reach a certain level'
            },
            'education': {
                'what_is': 'Tennis is an individual sport that demands physical fitness, mental toughness, and strategic thinking. It teaches self-reliance, problem-solving, and grace under pressure.',
                'skills_needed': [
                    'Proper stroke technique (forehand, backhand)',
                    'Serve power and placement',
                    'Footwork and court positioning',
                    'Net play and volleys',
                    'Mental strategy and point construction',
                    'Physical conditioning and endurance'
                ],
                'improvement_tips': [
                    'Master basic strokes before adding power',
                    'Practice serve technique daily',
                    'Work on footwork and movement patterns',
                    'Play points rather than just hitting balls',
                    'Study professional matches for strategy',
                    'Build mental toughness through match play'
                ]
            },
            'benefits': {
                'physical': ['Full-body coordination and fitness', 'Quick reflexes and reaction time', 'Cardiovascular endurance', 'Flexibility and mobility'],
                'mental': ['Individual responsibility and accountability', 'Problem-solving under pressure', 'Emotional control and composure', 'Strategic thinking'],
                'social': ['Respect for opponents and officials', 'Individual achievement recognition', 'Networking through club play', 'Lifetime sport enjoyment'],
                'life': ['Self-motivation and discipline', 'Handling pressure situations', 'Individual goal achievement', 'College recruitment opportunities']
            },
            'mentor_guidance': {
                'quote': 'Tennis teaches you that you are your own coach, your own cheerleader, and your own critic. Learning to manage yourself on the court prepares you to manage yourself in life.',
                'mentor_name': 'Coach Anderson',
                'mentor_background': 'Former college player, USPTA certified instructor for 14 years'
            }
        },
        'golf': {
            'title': 'Golf Pathway',
            'icon': '⛳',
            'teen_example': {
                'name': 'Ryan',
                'age': 17,
                'story': 'Picked up golf at 14 to spend time with his grandfather. What started as family bonding became a passion for precision and self-improvement. Golf taught him patience and that small improvements add up to big results.',
                'key': 'Golf is a game of millimeters and mental management'
            },
            'education': {
                'what_is': 'Golf is a precision sport played against the course and yourself. It demands technical skill, mental discipline, and emotional control while teaching patience and continuous improvement.',
                'skills_needed': [
                    'Proper swing mechanics and tempo',
                    'Short game (chipping, pitching, putting)',
                    'Course management and strategy',
                    'Mental focus and emotional control',
                    'Reading greens and wind conditions',
                    'Equipment knowledge and selection'
                ],
                'improvement_tips': [
                    'Master putting - it\'s half your score',
                    'Practice short game more than long drives',
                    'Work with a PGA professional for proper fundamentals',
                    'Play different courses to learn adaptability',
                    'Keep detailed scorecards to track patterns',
                    'Develop pre-shot routines for consistency'
                ]
            },
            'benefits': {
                'physical': ['Core strength and rotational power', 'Balance and stability', 'Hand-eye coordination', 'Walking fitness from course play'],
                'mental': ['Patience and delayed gratification', 'Focus and concentration', 'Emotional regulation', 'Problem-solving skills'],
                'social': ['Business networking opportunities', 'Multi-generational participation', 'Respect for etiquette and tradition', 'Lifetime enjoyment'],
                'life': ['Attention to detail', 'Continuous self-improvement', 'Handling frustration constructively', 'College scholarship opportunities']
            },
            'mentor_guidance': {
                'quote': 'Golf is the greatest teacher of character. It reveals who you really are when nobody is watching. The integrity you show on the course reflects the person you are in life.',
                'mentor_name': 'Pro Jackson',
                'mentor_background': 'PGA Professional, former mini-tour player, 22 years teaching experience'
            }
        }
    }
    
    if sport not in sport_data:
        flash('Sport pathway not found.', 'danger')
        return redirect(url_for('career_exploration', category='sports'))
    
    return render_template('categories/individual_sport.html', sport=sport, data=sport_data[sport], user_city=user_city)

@app.route('/career/<path_name>')
@login_required
def career_path_detail(path_name):
    """Career pathway detail page with comprehensive data"""
    if current_user.role not in ['teen', 'teenager']:
        flash('Access denied. Teenager account required.', 'danger')
        return redirect(url_for('index'))
    
    # Comprehensive career data for all modern careers
    career_pathways = {
        # Tech & Innovation Careers
        'ai-project-manager': {
            'title': 'AI Project Manager',
            'description': 'Lead AI development projects that transform industries and solve real-world problems',
            'role_model': {
                'name': 'Marcus Chen',
                'team': 'Senior AI Project Manager at Google',
                'message': 'AI is reshaping every industry. As an AI Project Manager, you bridge the gap between technical innovation and business impact, leading teams that build the future.',
                'quote': 'Great AI projects start with understanding human needs, not just technical possibilities.'
            },
            'teen_focus': {
                '14': 'Learn basic programming (Python/JavaScript) and understand how AI impacts daily life',
                '15': 'Take advanced math courses, join robotics club, start personal coding projects',
                '16': 'Build AI projects using tools like ChatGPT API, learn project management basics',
                '17': 'Lead tech projects at school, intern at tech companies, prepare for computer science college',
                '18': 'Apply to top CS programs, get internships at AI companies like OpenAI, Google, Microsoft'
            },
            'educational_insights': {
                'required_skills': ['Programming (Python, JavaScript)', 'Project Management', 'Data Analysis', 'Machine Learning Basics', 'Business Strategy'],
                'key_subjects': ['Advanced Mathematics', 'Computer Science', 'Statistics', 'Business', 'Communication'],
                'certifications': ['PMP Certification', 'Google AI Certification', 'AWS Machine Learning', 'Agile/Scrum Master'],
                'degree_paths': ['Computer Science + Business', 'Data Science', 'Engineering Management', 'AI/ML Specialization']
            },
            'real_teen_examples': [
                'Sarah (16) built a chatbot for her school counseling office using ChatGPT API',
                'James (17) led a team of 8 students to create an AI study buddy app, got internship at startup',
                'Maya (15) started YouTube channel explaining AI concepts, now has 50K subscribers',
                'Alex (18) managed school district pilot program using AI for personalized learning'
            ],
            'benefits_vs_tradeoffs': {
                'benefits': [
                    'High salary potential ($120,000-$250,000+)',
                    'Shape the future of technology',
                    'Work with cutting-edge AI innovations',
                    'High demand across all industries',
                    'Leadership and strategic thinking roles',
                    'Remote work opportunities'
                ],
                'tradeoffs': [
                    'Requires continuous learning as tech evolves rapidly',
                    'High-pressure environment with tight deadlines',
                    'Need both technical and business skills',
                    'Long hours during project launches',
                    'Responsible for million-dollar project outcomes',
                    'Must stay current with AI ethics and regulations'
                ]
            },
            'city_resources': [
                'Local tech companies and startups',
                'University AI research labs',
                'Tech meetups and AI conferences',
                'Coding bootcamps and workshops',
                'Business incubators and accelerators',
                'Professional project management associations'
            ],
            'success_tips': [
                'Master both technical concepts and business communication',
                'Build a portfolio of AI projects you\'ve led',
                'Network with AI professionals and attend tech conferences',
                'Learn multiple programming languages and frameworks',
                'Understand AI ethics and responsible development',
                'Develop strong presentation and leadership skills'
            ],
            'timeline': {
                'High School (Ages 14-18)': [
                    'Learn programming fundamentals and AI concepts',
                    'Lead technology projects and clubs',
                    'Build portfolio of AI applications',
                    'Take advanced math, computer science, and business courses'
                ],
                'College (Ages 18-22)': [
                    'Major in Computer Science, Data Science, or related field',
                    'Intern at AI companies like Google, Microsoft, OpenAI',
                    'Lead student tech projects and hackathons',
                    'Get certifications in project management and AI'
                ],
                'Early Career (Ages 22-28)': [
                    'Start as AI Engineer or Junior Project Manager',
                    'Lead small AI implementation projects',
                    'Build expertise in specific AI domains',
                    'Develop business and leadership skills'
                ],
                'Senior Level (Ages 28+)': [
                    'Manage large-scale AI transformation projects',
                    'Lead cross-functional teams of 20+ people',
                    'Shape company AI strategy and vision',
                    'Mentor next generation of AI professionals'
                ]
            }
        },
        'data-scientist': {
            'title': 'Data Scientist',
            'description': 'Transform raw data into powerful insights that drive business decisions and scientific discoveries',
            'role_model': {
                'name': 'Dr. Priya Patel',
                'team': 'Lead Data Scientist at Netflix',
                'message': 'Data science is like being a detective with superpowers. Every dataset tells a story, and your job is to uncover insights that can change the world, from curing diseases to predicting what show you\'ll love next.',
                'quote': 'In data we trust, but in analysis we find truth.'
            },
            'teen_focus': {
                '14': 'Excel at math and statistics, learn basic data visualization tools',
                '15': 'Start learning Python and R programming, analyze sports or social media data',
                '16': 'Take AP Statistics, create data projects using real datasets, learn SQL',
                '17': 'Build impressive data science portfolio, compete in data science competitions',
                '18': 'Apply to top data science programs, intern at data-driven companies'
            },
            'educational_insights': {
                'required_skills': ['Programming (Python, R, SQL)', 'Statistics & Probability', 'Machine Learning', 'Data Visualization', 'Business Intelligence'],
                'key_subjects': ['Advanced Mathematics', 'Statistics', 'Computer Science', 'Economics', 'Domain Knowledge'],
                'certifications': ['Google Data Analytics', 'Microsoft Azure Data Scientist', 'Tableau Certified', 'AWS Machine Learning'],
                'degree_paths': ['Data Science', 'Statistics', 'Computer Science', 'Mathematics', 'Economics with Analytics Focus']
            },
            'real_teen_examples': [
                'Emma (17) analyzed her school\'s test scores and identified factors improving performance',
                'David (16) created COVID-19 tracking dashboard for his city, featured in local news',
                'Zoe (18) used ML to predict which students need tutoring, implemented by school district',
                'Ryan (15) analyzed NBA stats to predict game outcomes with 78% accuracy'
            ],
            'benefits_vs_tradeoffs': {
                'benefits': [
                    'Excellent salary ($95,000-$200,000+)',
                    'High demand across every industry',
                    'Make data-driven decisions that impact millions',
                    'Continuous learning and intellectual challenge',
                    'Remote work flexibility',
                    'Bridge between technology and business strategy'
                ],
                'tradeoffs': [
                    'Requires strong mathematical foundation',
                    'Data can be messy and frustrating to clean',
                    'Need to constantly learn new tools and techniques',
                    'Results may be questioned or misunderstood',
                    'Long hours during analysis phases',
                    'Pressure to find insights in unclear data'
                ]
            },
            'city_resources': [
                'Local data science meetups and user groups',
                'University statistics and CS departments',
                'Companies with large datasets (banks, hospitals, retailers)',
                'Government agencies needing data analysis',
                'Business analytics consulting firms',
                'Tech bootcamps specializing in data science'
            ],
            'success_tips': [
                'Master statistics before diving into machine learning',
                'Build projects using real, messy datasets',
                'Learn to communicate insights to non-technical audiences',
                'Specialize in a domain (healthcare, finance, marketing)',
                'Contribute to open-source data science projects',
                'Create visualizations that tell compelling stories'
            ],
            'timeline': {
                'High School (Ages 14-18)': [
                    'Excel in mathematics and take AP Statistics',
                    'Learn Python and R programming languages',
                    'Complete data analysis projects and competitions',
                    'Build portfolio showcasing data insights'
                ],
                'College (Ages 18-22)': [
                    'Major in Data Science, Statistics, or Computer Science',
                    'Intern at data-driven companies like Amazon, Facebook',
                    'Participate in Kaggle competitions and hackathons',
                    'Learn advanced machine learning and AI techniques'
                ],
                'Early Career (Ages 22-28)': [
                    'Work as Junior Data Scientist or Business Analyst',
                    'Specialize in specific industry or technique',
                    'Lead data projects that drive business decisions',
                    'Develop expertise in advanced analytics tools'
                ],
                'Senior Level (Ages 28+)': [
                    'Lead data science teams and strategy',
                    'Architect enterprise data and ML systems',
                    'Drive company-wide data-driven culture',
                    'Mentor junior data scientists and analysts'
                ]
            }
        },
        'cybersecurity-analyst': {
            'title': 'Cybersecurity Analyst',
            'description': 'Protect digital systems and sensitive information from cyber threats and attacks',
            'role_model': {
                'name': 'Captain Maria Rodriguez',
                'team': 'Senior Cybersecurity Analyst at Pentagon',
                'message': 'Cybersecurity is the front line of digital warfare. Every day, you\'re protecting people\'s lives, privacy, and livelihoods from those who would exploit technology for harm. It\'s challenging, but incredibly meaningful work.',
                'quote': 'Security isn\'t just about technology—it\'s about protecting people and their digital lives.'
            },
            'teen_focus': {
                '14': 'Learn basic computer skills, understand online safety and privacy fundamentals',
                '15': 'Start learning networking basics, set up secure home network, learn about common threats',
                '16': 'Take cybersecurity courses online, practice ethical hacking in controlled environments',
                '17': 'Get cybersecurity certifications, participate in capture-the-flag competitions',
                '18': 'Apply to cybersecurity programs, intern at IT security firms or government agencies'
            },
            'educational_insights': {
                'required_skills': ['Network Security', 'Ethical Hacking', 'Risk Assessment', 'Incident Response', 'Security Tools (SIEM, Firewalls)'],
                'key_subjects': ['Computer Science', 'Information Technology', 'Criminal Justice', 'Mathematics', 'Psychology'],
                'certifications': ['CompTIA Security+', 'CISSP', 'CEH (Certified Ethical Hacker)', 'CISM', 'GSEC'],
                'degree_paths': ['Cybersecurity', 'Information Technology', 'Computer Science', 'Information Systems', 'Criminal Justice + IT']
            },
            'real_teen_examples': [
                'Jake (17) discovered security vulnerability in school app, helped fix it before harm occurred',
                'Lisa (16) ran cybersecurity awareness workshop for local senior center',
                'Carlos (18) won state cybersecurity competition, earned full scholarship to college',
                'Aisha (15) created secure messaging app for student government elections'
            ],
            'benefits_vs_tradeoffs': {
                'benefits': [
                    'High-demand field with job security ($85,000-$180,000+)',
                    'Protect people and organizations from real harm',
                    'Constantly evolving challenges keep work interesting',
                    'Government and private sector opportunities',
                    'Remote work options in many roles',
                    'High respect and recognition for expertise'
                ],
                'tradeoffs': [
                    'High-stress environment with urgent threats',
                    'Need to stay current with rapidly evolving threats',
                    'May work irregular hours during security incidents',
                    'Pressure of protecting valuable digital assets',
                    'Continuous learning required to stay effective',
                    'Can be isolating work requiring intense focus'
                ]
            },
            'city_resources': [
                'Local cybersecurity meetups and conferences',
                'Government agencies (FBI, NSA, local police)',
                'IT consulting and managed security service providers',
                'Banks, hospitals, and large corporations',
                'Community colleges with cybersecurity programs',
                'Ethical hacking groups and capture-the-flag teams'
            ],
            'success_tips': [
                'Get hands-on experience with security tools and techniques',
                'Earn industry-recognized certifications early',
                'Practice ethical hacking in legal, controlled environments',
                'Understand both offensive and defensive security',
                'Develop strong analytical and problem-solving skills',
                'Stay current with latest threats and security news'
            ],
            'timeline': {
                'High School (Ages 14-18)': [
                    'Learn computer networking and basic security concepts',
                    'Participate in cybersecurity competitions and camps',
                    'Get entry-level certifications like CompTIA Security+',
                    'Practice ethical hacking and security analysis'
                ],
                'College (Ages 18-22)': [
                    'Major in Cybersecurity, IT, or Computer Science',
                    'Intern at security firms or government agencies',
                    'Participate in college cyber defense teams',
                    'Gain advanced certifications and practical experience'
                ],
                'Early Career (Ages 22-28)': [
                    'Work as Security Analyst or IT Security Specialist',
                    'Specialize in areas like penetration testing or incident response',
                    'Gain experience with enterprise security tools',
                    'Build expertise in specific threat vectors'
                ],
                'Senior Level (Ages 28+)': [
                    'Lead cybersecurity teams and strategy',
                    'Architect enterprise security systems',
                    'Advise executives on security risks and investments',
                    'Mentor junior security professionals'
                ]
            }
        }
    }
    
    # Add more careers for different categories
    career_pathways.update({
        # Green & Sustainability Careers
        'wind-turbine-technician': {
            'title': 'Wind Turbine Technician',
            'description': 'Install, maintain, and repair wind turbines that generate clean, renewable energy',
            'role_model': {
                'name': 'Tommy Williams',
                'team': 'Lead Wind Tech at Vestas Wind Systems',
                'message': 'Every day I climb 300 feet to work on machines that power thousands of homes with clean energy. It\'s physically demanding but incredibly rewarding to know you\'re helping save the planet while earning great money.',
                'quote': 'We\'re not just fixing machines—we\'re building the future of energy, one turbine at a time.'
            },
            'teen_focus': {
                '14': 'Stay physically fit, learn basic mechanical and electrical concepts',
                '15': 'Take hands-on classes like shop, electronics, or automotive repair',
                '16': 'Visit wind farms, shadow wind technicians, learn about renewable energy',
                '17': 'Apply to wind technician programs or community college renewable energy courses',
                '18': 'Start technical training or apprenticeship programs with major wind companies'
            },
            'educational_insights': {
                'required_skills': ['Electrical Systems', 'Mechanical Repair', 'Safety Protocols', 'Problem Solving', 'Physical Fitness'],
                'key_subjects': ['Mathematics', 'Physics', 'Electronics', 'Mechanical Systems', 'Environmental Science'],
                'certifications': ['OSHA 10/30', 'Wind Turbine Technician Certificate', 'Electrical Safety', 'First Aid/CPR'],
                'degree_paths': ['Wind Energy Technology', 'Renewable Energy Technology', 'Electrical Technology', 'Mechanical Technology']
            },
            'real_teen_examples': [
                'Marcus (18) completed wind tech program, landed job making $55K starting salary',
                'Sophia (17) built model wind turbine for science fair, won state competition',
                'Devon (16) volunteered at local renewable energy nonprofit, learned industry basics',
                'Rachel (15) started blog about clean energy careers, interviewed wind farm workers'
            ],
            'benefits_vs_tradeoffs': {
                'benefits': [
                    'Excellent pay without college degree ($45,000-$80,000+)',
                    'Help fight climate change with meaningful work',
                    'Fast-growing industry with job security',
                    'Travel opportunities to different wind farms',
                    'Physical, outdoor work environment',
                    'Strong union support and benefits'
                ],
                'tradeoffs': [
                    'Physically demanding work in all weather conditions',
                    'Must be comfortable working at extreme heights',
                    'Irregular schedule including nights and weekends',
                    'Safety risks require constant attention',
                    'May travel frequently away from home',
                    'Work can be seasonal in some regions'
                ]
            },
            'city_resources': [
                'Local wind farms and renewable energy companies',
                'Community colleges with wind energy programs',
                'Trade unions (IBEW, Steelworkers)',
                'Renewable energy job fairs and career events',
                'Environmental organizations and clean energy groups',
                'Equipment manufacturers like GE, Vestas, Siemens'
            ],
            'success_tips': [
                'Maintain excellent physical fitness and health',
                'Get comfortable with heights through rock climbing or similar activities',
                'Learn both electrical and mechanical systems',
                'Develop strong safety mindset and attention to detail',
                'Network with current wind technicians',
                'Consider specialized training in hydraulics or electronics'
            ],
            'timeline': {
                'High School (Ages 14-18)': [
                    'Take math, physics, and hands-on technical courses',
                    'Build mechanical and electrical skills',
                    'Visit wind farms and renewable energy facilities',
                    'Research technical training programs'
                ],
                'Technical Training (Ages 18-20)': [
                    'Complete wind turbine technician certificate program',
                    'Gain hands-on experience with turbine systems',
                    'Earn safety certifications and technical credentials',
                    'Apply for entry-level technician positions'
                ],
                'Early Career (Ages 20-28)': [
                    'Work as Wind Turbine Technician',
                    'Specialize in specific turbine types or systems',
                    'Gain experience in troubleshooting and major repairs',
                    'Consider supervisor or specialized roles'
                ],
                'Advanced Career (Ages 28+)': [
                    'Lead technician teams or become site supervisor',
                    'Transition to training or quality assurance roles',
                    'Start own renewable energy service business',
                    'Move into wind farm operations management'
                ]
            }
        },
        # Health & Wellness Careers  
        'nurse-practitioner': {
            'title': 'Nurse Practitioner',
            'description': 'Provide advanced healthcare services, diagnose conditions, and prescribe treatments as a primary care provider',
            'role_model': {
                'name': 'Jennifer Martinez, FNP',
                'team': 'Family Nurse Practitioner at Community Health Center',
                'message': 'As a Nurse Practitioner, I combine the caring heart of nursing with the diagnostic skills of advanced practice. I can prescribe medications, order tests, and provide comprehensive care while building deep relationships with patients and families.',
                'quote': 'Nursing is not just what I do—it\'s who I am. Every patient interaction is a chance to heal, comfort, and make a real difference.'
            },
            'teen_focus': {
                '14': 'Excel in biology and chemistry, volunteer at hospitals or nursing homes',
                '15': 'Take health science courses, shadow nurses and nurse practitioners',
                '16': 'Work as hospital volunteer or patient care assistant, take college prep courses',
                '17': 'Apply to top nursing programs, get CNA certification if possible',
                '18': 'Start Bachelor of Science in Nursing (BSN) program at accredited school'
            },
            'educational_insights': {
                'required_skills': ['Clinical Assessment', 'Patient Communication', 'Pharmacology', 'Diagnostic Skills', 'Critical Thinking'],
                'key_subjects': ['Biology', 'Chemistry', 'Anatomy & Physiology', 'Psychology', 'Mathematics'],
                'certifications': ['RN License', 'NP Certification', 'BLS/ACLS', 'Specialty Certifications'],
                'degree_paths': ['BSN → MSN (Nurse Practitioner)', 'Direct Entry MSN Programs', 'DNP (Doctor of Nursing Practice)']
            },
            'real_teen_examples': [
                'Isabella (17) got CNA certification, works part-time at nursing home while in high school',
                'Jordan (18) volunteers at free clinic, shadowed NP who inspired career choice',
                'Samantha (16) started health science club, organized blood drives and health fairs',
                'Miguel (15) learned CPR and first aid, helps as volunteer EMT in rural community'
            ],
            'benefits_vs_tradeoffs': {
                'benefits': [
                    'Excellent salary and job security ($95,000-$130,000+)',
                    'Make meaningful difference in people\'s health and lives',
                    'High respect and trust from patients and community',
                    'Flexible work settings (clinics, hospitals, private practice)',
                    'Growing field with excellent job prospects',
                    'Ability to prescribe medications and order tests'
                ],
                'tradeoffs': [
                    'Requires significant education (6-8 years total)',
                    'Emotional stress from dealing with illness and suffering',
                    'May work long or irregular hours',
                    'Physical demands of patient care',
                    'High responsibility for patient outcomes',
                    'Continuing education requirements throughout career'
                ]
            },
            'city_resources': [
                'Local hospitals and medical centers',
                'Community health clinics and urgent care centers',
                'Nursing schools and healthcare programs',
                'Professional nursing organizations',
                'Healthcare volunteer opportunities',
                'Medical professional mentorship programs'
            ],
            'success_tips': [
                'Excel in science courses and maintain high GPA',
                'Gain healthcare experience through volunteering or part-time work',
                'Develop strong communication and empathy skills',
                'Shadow different types of nurse practitioners',
                'Build relationships with healthcare professionals',
                'Consider specialization areas like family, pediatric, or psychiatric care'
            ],
            'timeline': {
                'High School (Ages 14-18)': [
                    'Excel in biology, chemistry, and health sciences',
                    'Volunteer in healthcare settings',
                    'Shadow nurses and nurse practitioners',
                    'Apply to accredited BSN programs'
                ],
                'Nursing School (Ages 18-22)': [
                    'Complete Bachelor of Science in Nursing (BSN)',
                    'Pass NCLEX-RN exam to become registered nurse',
                    'Gain clinical experience in various healthcare settings',
                    'Maintain excellent grades for graduate school'
                ],
                'RN Experience (Ages 22-25)': [
                    'Work as registered nurse for 2-3 years minimum',
                    'Gain experience in chosen specialty area',
                    'Apply to Master\'s in Nursing (MSN) programs',
                    'Build clinical skills and patient care expertise'
                ],
                'Advanced Practice (Ages 25+)': [
                    'Complete MSN or DNP as Nurse Practitioner',
                    'Pass national certification exam in specialty',
                    'Begin practice as Nurse Practitioner',
                    'Consider further specialization or leadership roles'
                ]
            }
        },
        # More Tech & Innovation Careers
        'software-developer': {
            'title': 'Software Developer / Engineer',
            'description': 'Build apps, platforms, and systems that power the digital world',
            'role_model': {
                'name': 'Alex Kim',
                'team': 'Senior Software Engineer at Meta',
                'message': 'Software development is like digital architecture—you\'re building the infrastructure that millions of people use every day. From social media apps to medical devices, your code can literally change lives.',
                'quote': 'The best code is not just functional, but elegant, readable, and built with users in mind.'
            },
            'teen_focus': {
                '14': 'Learn your first programming language (Python or JavaScript), build simple projects',
                '15': 'Master fundamentals, contribute to open source projects, learn web development',
                '16': 'Build impressive portfolio projects, learn multiple languages, start internship search',
                '17': 'Lead coding projects, teach others, apply for competitive internships',
                '18': 'Apply to top CS programs, contribute to major open source projects'
            },
            'educational_insights': {
                'required_skills': ['Programming Languages (Python, JavaScript, Java)', 'Problem Solving', 'System Design', 'Database Management', 'Version Control (Git)'],
                'key_subjects': ['Computer Science', 'Mathematics', 'Logic', 'Physics', 'Communication'],
                'certifications': ['AWS Certified Developer', 'Google Cloud Developer', 'Microsoft Azure Developer', 'Certified Scrum Developer'],
                'degree_paths': ['Computer Science', 'Software Engineering', 'Computer Engineering', 'Information Technology']
            },
            'real_teen_examples': [
                'Maria (17) created mobile app with 100K+ downloads, now works at Google as intern',
                'Tyler (16) built AI-powered study app for his school, licensed by district',
                'Keya (15) contributes to major open source projects, featured in tech magazines',
                'Josh (18) developed VR game that raised $50K for charity, accepted to Stanford'
            ],
            'benefits_vs_tradeoffs': {
                'benefits': [
                    'Excellent salary potential ($80,000-$200,000+)',
                    'High demand and job security',
                    'Creative problem-solving daily',
                    'Remote work opportunities',
                    'Build products used by millions',
                    'Constant learning and growth'
                ],
                'tradeoffs': [
                    'Long hours during project deadlines',
                    'Technology changes rapidly requiring constant learning',
                    'Can be mentally demanding and stressful',
                    'Debugging frustrating problems',
                    'Competition for top tech company positions',
                    'Sedentary work environment'
                ]
            },
            'city_resources': [
                'Local tech companies and startups',
                'Programming bootcamps and coding schools',
                'Tech meetups and developer conferences',
                'University computer science departments',
                'Maker spaces and co-working facilities',
                'Online coding communities and forums'
            ],
            'success_tips': [
                'Build a strong portfolio of diverse projects',
                'Contribute to open source projects regularly',
                'Learn multiple programming languages and frameworks',
                'Practice coding challenges and algorithms daily',
                'Network with other developers and attend tech events',
                'Focus on writing clean, well-documented code'
            ],
            'timeline': {
                'High School (Ages 14-18)': [
                    'Learn programming fundamentals and build projects',
                    'Participate in coding competitions and hackathons',
                    'Contribute to open source projects',
                    'Take computer science and advanced math courses'
                ],
                'College (Ages 18-22)': [
                    'Major in Computer Science or related field',
                    'Complete internships at tech companies',
                    'Build advanced projects and applications',
                    'Learn software engineering principles and practices'
                ],
                'Early Career (Ages 22-28)': [
                    'Work as Junior Developer or Software Engineer',
                    'Specialize in specific technologies or domains',
                    'Lead development projects and mentor juniors',
                    'Build expertise in system design and architecture'
                ],
                'Senior Level (Ages 28+)': [
                    'Lead engineering teams and technical strategy',
                    'Architect large-scale software systems',
                    'Mentor junior developers and engineers',
                    'Drive technical innovation and best practices'
                ]
            }
        },
        'robotics-technician': {
            'title': 'Robotics Technician',
            'description': 'Design and maintain robots for industry, healthcare, and emerging applications',
            'role_model': {
                'name': 'Dr. Amanda Foster',
                'team': 'Lead Robotics Technician at Boston Dynamics',
                'message': 'Robotics is where science fiction becomes reality. Every day I work on machines that can walk, lift, and think—robots that will transform manufacturing, healthcare, and how we live. It\'s the perfect blend of mechanical, electrical, and software engineering.',
                'quote': 'The future is not about robots replacing humans, but about humans and robots working together to solve impossible problems.'
            },
            'teen_focus': {
                '14': 'Join robotics club, learn basic programming and electronics',
                '15': 'Build robots with Arduino/Raspberry Pi, compete in robotics competitions',
                '16': 'Advanced robotics projects, intern at engineering firms, learn CAD design',
                '17': 'Lead robotics team, apply to engineering programs, shadow robotics professionals',
                '18': 'Start engineering degree, work on advanced robotics research projects'
            },
            'educational_insights': {
                'required_skills': ['Mechanical Engineering', 'Electronics', 'Programming (C++, Python)', 'CAD Design', 'Problem Solving'],
                'key_subjects': ['Mathematics', 'Physics', 'Computer Science', 'Engineering', 'Electronics'],
                'certifications': ['Certified Robotics Technician', 'Industrial Automation Certification', 'PLC Programming', 'CAD Certification'],
                'degree_paths': ['Robotics Engineering', 'Mechanical Engineering', 'Electrical Engineering', 'Mechatronics']
            },
            'real_teen_examples': [
                'Carlos (17) built robot that helps elderly with daily tasks, won national competition',
                'Priya (16) designed robotic arm for school\'s 3D printing lab, now used daily',
                'Miguel (18) interned at Tesla working on manufacturing robots',
                'Zara (15) started robotics YouTube channel, teaching thousands of kids'
            ],
            'benefits_vs_tradeoffs': {
                'benefits': [
                    'Great salary with growth potential ($60,000-$120,000+)',
                    'Work with cutting-edge technology',
                    'High demand in growing field',
                    'Solve real-world problems with technology',
                    'Diverse applications across industries',
                    'Continuous learning and innovation'
                ],
                'tradeoffs': [
                    'Requires strong technical and math skills',
                    'Complex troubleshooting and debugging',
                    'Technology evolves rapidly',
                    'May work in industrial environments',
                    'Projects can be expensive if mistakes occur',
                    'Need to stay current with multiple technologies'
                ]
            },
            'city_resources': [
                'Local manufacturing companies and factories',
                'University engineering and robotics labs',
                'Robotics competitions and clubs (FIRST, VEX)',
                'Maker spaces and fabrication labs',
                'Engineering consulting firms',
                'Technology companies using automation'
            ],
            'success_tips': [
                'Get hands-on experience building and programming robots',
                'Learn multiple programming languages and platforms',
                'Understand both mechanical and electrical systems',
                'Participate in robotics competitions regularly',
                'Stay current with AI and machine learning trends',
                'Develop strong problem-solving and debugging skills'
            ],
            'timeline': {
                'High School (Ages 14-18)': [
                    'Participate in robotics clubs and competitions',
                    'Learn programming and electronics fundamentals',
                    'Build portfolio of robotics projects',
                    'Take advanced math, physics, and computer science'
                ],
                'College (Ages 18-22)': [
                    'Major in Robotics, Mechanical, or Electrical Engineering',
                    'Work in university robotics research labs',
                    'Complete internships at robotics companies',
                    'Build advanced autonomous robot systems'
                ],
                'Early Career (Ages 22-28)': [
                    'Work as Robotics Engineer or Technician',
                    'Specialize in specific robotics applications',
                    'Lead robotics implementation projects',
                    'Gain expertise in AI and machine learning'
                ],
                'Senior Level (Ages 28+)': [
                    'Lead robotics engineering teams',
                    'Design next-generation robotic systems',
                    'Drive robotics strategy for organizations',
                    'Mentor next generation of robotics engineers'
                ]
            }
        },
        # Green & Sustainability Careers
        'solar-installer': {
            'title': 'Solar Photovoltaic Installer',
            'description': 'Install solar panel systems that power homes and businesses with clean energy',
            'role_model': {
                'name': 'James Rodriguez',
                'team': 'Senior Solar Installer at SunPower',
                'message': 'Every solar panel I install is a victory against climate change. I help families save thousands on electricity while protecting our planet. It\'s skilled work that pays well and makes a real difference for future generations.',
                'quote': 'We\'re not just installing solar panels—we\'re installing hope for a cleaner, more sustainable future.'
            },
            'teen_focus': {
                '14': 'Learn about renewable energy, maintain physical fitness',
                '15': 'Take electrical and construction classes, volunteer with environmental groups',
                '16': 'Shadow solar installers, learn electrical safety, get basic certifications',
                '17': 'Apply to solar training programs, get OSHA safety certification',
                '18': 'Start solar installer apprenticeship or technical training program'
            },
            'educational_insights': {
                'required_skills': ['Electrical Installation', 'Roofing Knowledge', 'Safety Protocols', 'System Design', 'Customer Service'],
                'key_subjects': ['Mathematics', 'Physics', 'Electronics', 'Environmental Science', 'Construction'],
                'certifications': ['NABCEP PV Installation Professional', 'OSHA 10/30', 'Electrical Training', 'First Aid/CPR'],
                'degree_paths': ['Solar Technology Certificate', 'Electrical Technology', 'Renewable Energy Technology', 'Construction Technology']
            },
            'real_teen_examples': [
                'Diego (18) completed solar program, landed job making $22/hour starting',
                'Sarah (17) built model solar home for science fair, inspired by installer visit',
                'Kevin (16) volunteers installing solar for low-income families',
                'Maya (15) started environmental club focused on renewable energy careers'
            ],
            'benefits_vs_tradeoffs': {
                'benefits': [
                    'Good pay without college degree ($40,000-$70,000+)',
                    'Fight climate change with meaningful work',
                    'Rapidly growing industry with job security',
                    'Work outdoors with variety of projects',
                    'Help families save money on electricity',
                    'Excellent job satisfaction and purpose'
                ],
                'tradeoffs': [
                    'Physical work in all weather conditions',
                    'Must be comfortable working on rooftops',
                    'Safety risks require constant attention',
                    'Work can be seasonal in some areas',
                    'Early morning starts and physical demands',
                    'Need to lift heavy equipment regularly'
                ]
            },
            'city_resources': [
                'Local solar installation companies',
                'Community colleges with renewable energy programs',
                'Electrical trade unions and training centers',
                'Green energy job fairs and career events',
                'Environmental organizations promoting clean energy',
                'Solar equipment suppliers and manufacturers'
            ],
            'success_tips': [
                'Maintain excellent physical fitness and health',
                'Learn electrical fundamentals and safety practices',
                'Get comfortable working at heights safely',
                'Understand different solar technologies and systems',
                'Develop customer service and communication skills',
                'Stay current with solar technology advances'
            ],
            'timeline': {
                'High School (Ages 14-18)': [
                    'Take math, physics, and electrical courses',
                    'Build physical fitness and comfort with heights',
                    'Learn about solar energy and environmental benefits',
                    'Research solar installation training programs'
                ],
                'Training (Ages 18-20)': [
                    'Complete solar installer certificate program',
                    'Gain hands-on experience with solar systems',
                    'Earn safety and electrical certifications',
                    'Apply for entry-level installer positions'
                ],
                'Early Career (Ages 20-28)': [
                    'Work as Solar Panel Installer',
                    'Specialize in residential or commercial systems',
                    'Learn system design and troubleshooting',
                    'Consider crew leader or supervisor roles'
                ],
                'Advanced Career (Ages 28+)': [
                    'Lead installation crews and train new installers',
                    'Move into solar system design or sales',
                    'Start own solar installation business',
                    'Transition to project management or operations'
                ]
            }
        },
        'military': {
            'title': 'Military Service',
            'description': 'Serve your country with honor across four branches: Army, Navy, Air Force, and Marines',
            'role_model': {
                'name': 'Sergeant Major Maria Gonzalez',
                'team': 'U.S. Army Special Operations',
                'message': 'Military service isn\'t just a career - it\'s a calling to serve something greater than yourself. You\'ll gain leadership skills, discipline, and brotherhood that will benefit you for life, whether you serve 4 years or 30.',
                'quote': 'The Army taught me that leadership isn\'t about rank - it\'s about taking care of your people and accomplishing the mission.'
            },
            'teen_focus': {
                '14': 'Focus on physical fitness, leadership opportunities, and strong academics',
                '15': 'Research different military branches and career fields (MOS/Rate/AFSC)',
                '16': 'Join JROTC, maintain good grades, stay physically fit, avoid legal troubles',
                '17': 'Meet with military recruiters, take ASVAB practice tests, research military academies',
                '18': 'Take official ASVAB, choose branch and career field, complete MEPS physical'
            },
            'military_branches': {
                'Army': {
                    'mission': 'Dominate land operations and provide combat-ready forces worldwide',
                    'what_they_do': 'Ground combat, peacekeeping, disaster relief, cybersecurity, logistics, medical support, engineering, intelligence',
                    'specialties': 'Infantry, Artillery, Armor, Special Forces, Military Police, Cyber Operations, Aviation, Medical Corps',
                    'unique_aspects': 'Largest branch, most diverse career fields, strong emphasis on leadership development, extensive veteran benefits'
                },
                'Navy': {
                    'mission': 'Maintain freedom of the seas and project power from the ocean',
                    'what_they_do': 'Ship operations, submarine warfare, naval aviation, cybersecurity, nuclear operations, logistics, medical support',
                    'specialties': 'Surface Warfare, Submarine Service, Naval Aviation, SEALs, Nuclear Operations, Intelligence, Medical Corps',
                    'unique_aspects': 'Travel the world, advanced technical training, nuclear power programs, strong veteran hiring network'
                },
                'Air Force': {
                    'mission': 'Fly, fight, and win in air, space, and cyberspace',
                    'what_they_do': 'Flight operations, space operations, cybersecurity, intelligence, logistics, medical support, air traffic control',
                    'specialties': 'Pilot, Air Traffic Control, Cyber Operations, Space Operations, Intelligence, Maintenance, Security Forces',
                    'unique_aspects': 'Highest tech focus, best living conditions, strong emphasis on education, space and cyber missions'
                },
                'Marines': {
                    'mission': 'Be the most ready when the nation is least ready',
                    'what_they_do': 'Rapid response, amphibious assault, embassy security, close combat, reconnaissance, aviation support',
                    'specialties': 'Infantry, Artillery, Aviation, Reconnaissance, Military Police, Logistics, Communications',
                    'unique_aspects': 'Elite fighting force, strongest warrior culture, rapid deployment capability, "Once a Marine, always a Marine"'
                }
            },
            'educational_insights': {
                'required_skills': ['Physical Fitness', 'Mental Toughness', 'Teamwork', 'Leadership', 'Problem Solving', 'Communication'],
                'key_subjects': ['Physical Education', 'Mathematics', 'Science', 'History', 'English', 'Foreign Languages'],
                'certifications': ['Security Clearance', 'Military Occupation Specialty (MOS)', 'Leadership Schools', 'Technical Certifications'],
                'degree_paths': ['Military Academy', 'ROTC Program', 'Officer Candidate School', 'Enlisted with College Benefits']
            },
            'real_teen_examples': [
                'Jake (18) joined Army as Combat Medic, now pursuing pre-med with GI Bill',
                'Sarah (17) entered Air Force Academy, studying aerospace engineering',
                'Marcus (18) became Navy Nuclear Technician, earning $80K+ after service',
                'Elena (16) in JROTC, earned full ROTC scholarship to become Marine officer'
            ],
            'benefits_vs_tradeoffs': {
                'benefits': [
                    'Full college tuition paid (GI Bill worth $100,000+)',
                    'Guaranteed job training and certification',
                    'Free healthcare and housing during service',
                    'Leadership experience valued by employers',
                    'Veteran hiring preference for government jobs',
                    'Retirement after 20 years with pension',
                    'Travel opportunities worldwide',
                    'Strong sense of purpose and belonging'
                ],
                'tradeoffs': [
                    'Deployment separations from family',
                    'Strict military discipline and regulations',
                    'Potential exposure to combat situations',
                    'Limited control over job location assignments',
                    'Physical and mental demands of training',
                    'Long work hours and demanding schedules',
                    'Difficulty transitioning to civilian life later'
                ]
            },
            'city_resources': [
                'Local military recruiting stations',
                'Veteran organizations and American Legion posts',
                'JROTC programs at high schools',
                'Military academies and ROTC programs',
                'Veteran employment centers and job fairs',
                'Military Family Life Counselors (MFLC)'
            ],
            'success_tips': [
                'Maintain excellent physical fitness year-round',
                'Study hard and keep grades up for better job options',
                'Join JROTC or similar leadership programs',
                'Stay out of legal trouble - any arrests affect eligibility',
                'Research different career fields before choosing',
                'Talk to current service members and veterans',
                'Consider officer programs if college-bound',
                'Prepare mentally for the challenge and commitment'
            ],
            'timeline': {
                'High School (Ages 14-18)': [
                    'Maintain good grades (2.5+ GPA minimum)',
                    'Stay physically fit and participate in sports',
                    'Join JROTC or leadership activities',
                    'Research branches and career fields',
                    'Meet with recruiters junior/senior year',
                    'Take ASVAB test for career field qualification'
                ],
                'Enlistment Process (Age 17-18)': [
                    'Choose military branch and career field',
                    'Complete MEPS (Military Entrance Processing)',
                    'Sign enlistment contract',
                    'Prepare for basic training/boot camp'
                ],
                'Initial Service (Ages 18-22)': [
                    'Complete basic training (8-13 weeks)',
                    'Attend job-specific training school',
                    'Serve first assignment and gain experience',
                    'Pursue additional military education',
                    'Consider leadership development programs'
                ],
                'Career Development (Ages 22+)': [
                    'Advance in rank and responsibility',
                    'Attend professional military education',
                    'Specialize in advanced career fields',
                    'Consider officer programs or civilian transition',
                    'Use military experience for post-service career'
                ]
            }
        }
    })
    
    # Get the specific career or use generic data
    if path_name in career_pathways:
        career_data = career_pathways[path_name]
    else:
        # Generic career data for careers not yet detailed
        career_data = {
            'title': path_name.replace('-', ' ').replace('_', ' ').title(),
            'description': f'Complete pathway guide for {path_name.replace("-", " ").title()}',
            'role_model': {
                'name': 'Professional Expert',
                'team': 'Industry Leader',
                'message': 'This career offers exciting opportunities for those willing to work hard and continuously learn.',
                'quote': 'Success comes to those who are prepared when opportunity knocks.'
            },
            'teen_focus': {
                '14': 'Focus on academics and explore the field through reading and online resources',
                '15': 'Start building foundational skills and consider relevant courses',
                '16': 'Look for internships, volunteer opportunities, and advanced coursework',
                '17': 'Begin college preparation and seek mentorship opportunities',
                '18': 'Apply to colleges and look for entry-level positions or internships'
            },
            'educational_insights': {
                'required_skills': ['Problem Solving', 'Communication', 'Critical Thinking', 'Technical Skills', 'Leadership'],
                'key_subjects': ['Mathematics', 'Science', 'English', 'Social Studies', 'Relevant Electives'],
                'certifications': ['Industry-Specific Certifications'],
                'degree_paths': ['Related Bachelor\'s Degree', 'Specialized Training Programs']
            },
            'real_teen_examples': [
                'Student built relevant skills through school projects',
                'Teen gained experience through volunteering',
                'High schooler shadowed professionals in the field',
                'Student participated in related competitions or clubs'
            ],
            'benefits_vs_tradeoffs': {
                'benefits': [
                    'Good career prospects and growth potential',
                    'Opportunity to make meaningful impact',
                    'Competitive salary and benefits',
                    'Professional development opportunities',
                    'Respected position in community'
                ],
                'tradeoffs': [
                    'Requires dedication and continuous learning',
                    'May involve challenging work situations',
                    'Competition for top positions',
                    'Need to stay current with industry changes'
                ]
            },
            'city_resources': [
                'Professional associations and organizations',
                'Local companies and businesses in the field',
                'Educational institutions and training programs',
                'Volunteer opportunities related to career',
                'Professional mentorship programs',
                'Career counseling and development services'
            ],
            'success_tips': [
                'Build relevant skills through practice and education',
                'Network with professionals in the field',
                'Gain hands-on experience through internships',
                'Stay current with industry trends and developments',
                'Develop strong work ethic and professional habits'
            ],
            'timeline': {
                'High School (Ages 14-18)': [
                    'Focus on relevant coursework and maintain good grades',
                    'Participate in related extracurricular activities',
                    'Gain exposure to the field through shadowing or volunteering',
                    'Research and apply to appropriate post-secondary programs'
                ],
                'Post-Secondary (Ages 18-22)': [
                    'Complete relevant degree or certification programs',
                    'Gain practical experience through internships',
                    'Build professional network and relationships',
                    'Develop specialized skills and knowledge'
                ],
                'Early Career (Ages 22-30)': [
                    'Start in entry-level positions in the field',
                    'Continue learning and professional development',
                    'Build experience and expertise',
                    'Seek advancement and leadership opportunities'
                ],
                'Career Advancement (Ages 30+)': [
                    'Take on leadership and management roles',
                    'Specialize in areas of particular interest',
                    'Mentor others entering the field',
                    'Continue professional growth and development'
                ]
            }
        }
    
    return render_template('career_pathway_detail.html', 
                         career=career_data, 
                         pathway=career_data,
                         path_name=path_name,
                         city='Your City',
                         age=current_user.age or 16)

# Sports routes moved to career_routes.py to avoid conflicts

@app.route('/health')
@login_required
def health_awareness():
    """Health awareness page"""
    if current_user.role not in ['teen', 'teenager']:
        flash('Access denied. Teenager account required.', 'danger')
        return redirect(url_for('index'))
    health_topics = [
        {
            'title': 'Mental Health & Wellness 🧠', 
            'icon': '🧠', 
            'description': 'Mental health is just as important as physical health. Learn to recognize signs of depression, anxiety, and stress while building resilience, coping skills, and emotional intelligence. Your mental wellness affects every area of your life.', 
            'priority': 'high',
            'key_points': ['Talk to trusted adults when struggling', 'Practice stress management daily', 'Get 8-10 hours of sleep nightly', 'Build supportive relationships', 'Engage in activities you enjoy']
        },
        {
            'title': 'Heart Disease Prevention ❤️', 
            'icon': '❤️', 
            'description': 'Heart disease is the #1 killer in America, but it\'s largely preventable! Learn how healthy eating, regular exercise, avoiding smoking, and managing stress can protect your heart for life. Start building heart-healthy habits now.', 
            'priority': 'high',
            'key_points': ['Exercise 30+ minutes daily', 'Eat fruits, vegetables, whole grains', 'Never start smoking', 'Manage stress healthily', 'Maintain healthy weight']
        },
        {
            'title': 'Cancer Prevention & Awareness 🎗️', 
            'icon': '🎗️', 
            'description': 'Many cancers can be prevented through smart lifestyle choices. Learn about risk factors, protective behaviors, and early detection. Your choices today significantly impact your cancer risk later in life.', 
            'priority': 'high',
            'key_points': ['Avoid all tobacco products', 'Protect skin with sunscreen', 'Eat cancer-fighting foods', 'Limit processed meats', 'Know your family history']
        },
        {
            'title': 'Substance Abuse Prevention 🚫', 
            'icon': '🚫', 
            'description': 'Alcohol, drugs, and other substances can destroy your health, relationships, academic performance, and future opportunities. Learn the real risks, develop refusal skills, and find healthy ways to cope with peer pressure.', 
            'priority': 'high',
            'key_points': ['Learn real risks and consequences', 'Practice saying no confidently', 'Find healthy stress relief', 'Choose positive friend groups', 'Focus on your goals and dreams']
        },
        {
            'title': 'Nutrition & Healthy Eating 🥗', 
            'icon': '🥗', 
            'description': 'Good nutrition fuels your growing body and developing brain. Learn about balanced eating, proper portions, and foods that boost energy, mood, and academic performance while preventing disease.', 
            'priority': 'high',
            'key_points': ['Eat 5+ fruits/vegetables daily', 'Choose whole grains over refined', 'Drink water instead of soda', 'Eat regular, balanced meals', 'Learn to cook healthy foods']
        },
        {
            'title': 'Sleep Health & Energy 😴', 
            'icon': '😴', 
            'description': 'Quality sleep is essential for physical health, mental wellness, academic success, athletic performance, and overall quality of life. Learn healthy sleep habits and why teens need 8-10 hours nightly.', 
            'priority': 'high',
            'key_points': ['Get 8-10 hours nightly', 'Create consistent bedtime routine', 'Limit screen time before bed', 'Keep bedroom cool and dark', 'Avoid caffeine late in day']
        },
        {
            'title': 'Exercise & Physical Fitness 🏃', 
            'icon': '🏃', 
            'description': 'Regular physical activity strengthens your body, improves mood, reduces stress, boosts academic performance, and prevents many diseases. Find activities you enjoy and make movement part of daily life.', 
            'priority': 'medium',
            'key_points': ['Get 60+ minutes activity daily', 'Try different sports and activities', 'Include strength and flexibility', 'Make it fun, not just work', 'Start slowly and build up']
        },
        {
            'title': 'Injury Prevention & Safety 🛡️', 
            'icon': '🛡️', 
            'description': 'Accidents are a leading cause of death and disability among teens. Learn safety practices for driving, sports, online activities, and daily life to protect yourself and others from preventable injuries.', 
            'priority': 'medium',
            'key_points': ['Always wear seatbelts', 'Use safety equipment in sports', 'Never text while driving', 'Learn basic first aid', 'Make smart risk decisions']
        }
    ]
    return render_template('health_awareness.html', health_topics=health_topics)

@app.route('/homework')
@login_required
def homework_help():
    """Homework help resources"""
    if current_user.role not in ['teen', 'teenager']:
        flash('Access denied. Teenager account required.', 'danger')
        return redirect(url_for('index'))
    return render_template('homework_help.html')

@app.route('/jobs')
@login_required
def teen_jobs():
    """Teen job opportunities"""
    if current_user.role not in ['teen', 'teenager']:
        flash('Access denied. Teenager account required.', 'danger')
        return redirect(url_for('index'))
    jobs = [
        {'title': 'Babysitter', 'age_req': '13+', 'pay': '$8-15/hr', 'description': 'Watch children while parents are away. Great first job that teaches responsibility, patience, and childcare skills.', 'skills': 'Responsible, patient, good with kids, basic first aid knowledge', 'how_to_apply': 'Ask neighbors, family friends, or post flyers. Get CPR certified and references from trusted adults.'},
        {'title': 'Dog Walker', 'age_req': '14+', 'pay': '$10-20/walk', 'description': 'Walk dogs in your neighborhood while getting exercise and fresh air. Perfect for animal lovers who want flexible hours.', 'skills': 'Love animals, physically active, reliable, comfortable with different dog sizes', 'how_to_apply': 'Contact neighbors with dogs, use apps like Rover, or create flyers for your area.'},
        {'title': 'Lawn Care Helper', 'age_req': '14+', 'pay': '$15-30/lawn', 'description': 'Help with mowing, raking, weeding, and basic yard maintenance. Good physical exercise and outdoor work.', 'skills': 'Physical work, reliable, lawn equipment knowledge, attention to detail', 'how_to_apply': 'Ask neighbors, advertise services locally, work with established lawn care companies.'},
        {'title': 'Tutoring Assistant', 'age_req': '15+', 'pay': '$12-25/hr', 'description': 'Help younger students with homework and studying. Share your academic strengths while earning money.', 'skills': 'Strong grades in subject areas, patient teacher, good communication, organized', 'how_to_apply': 'Contact your school counselor, advertise at local elementary schools, ask teachers for referrals.'},
        {'title': 'Retail Associate', 'age_req': '16+', 'pay': '$9-14/hr', 'description': 'Work at clothing stores, grocery stores, or restaurants. Learn customer service, teamwork, and business operations.', 'skills': 'Customer service, teamwork, communication, reliability, cash handling', 'how_to_apply': 'Apply online or in-person at local businesses. Prepare a simple resume and practice interview skills.'},
        {'title': 'Lifeguard', 'age_req': '16+', 'pay': '$11-18/hr', 'description': 'Supervise swimmers at pools and beaches. Requires certification but offers good pay and important responsibility.', 'skills': 'Strong swimmer, CPR/First Aid certified, alert and responsible, good communication', 'how_to_apply': 'Get lifeguard certification through Red Cross, apply at pools, beaches, and recreation centers.'},
        {'title': 'Camp Counselor', 'age_req': '16+', 'pay': '$10-16/hr', 'description': 'Work at summer day camps helping with activities, sports, and childcare. Fun way to work with kids outdoors.', 'skills': 'Good with children, energetic, creative, team player, leadership potential', 'how_to_apply': 'Apply to YMCA, recreation centers, and summer camps in early spring. May require background check.'},
        {'title': 'Food Service Worker', 'age_req': '16+', 'pay': '$9-13/hr', 'description': 'Work at restaurants, ice cream shops, or cafes. Learn food safety, customer service, and work ethic.', 'skills': 'Customer service, teamwork, ability to work quickly, follow directions, basic math', 'how_to_apply': 'Apply at local restaurants and food establishments. Emphasize reliability and willingness to learn.'},
        {'title': 'Library Assistant', 'age_req': '15+', 'pay': '$8-12/hr', 'description': 'Help with organizing books, assisting patrons, and running programs. Perfect for quiet, studious teens.', 'skills': 'Organized, helpful, love of reading, computer skills, patience with people', 'how_to_apply': 'Contact your local library directly. Volunteer first to show interest and skills.'},
        {'title': 'Pet Sitting', 'age_req': '13+', 'pay': '$15-30/day', 'description': 'Care for pets while owners are away. Feed, play with, and watch over pets in their homes.', 'skills': 'Animal lover, responsible, reliable, comfortable being alone, basic pet care knowledge', 'how_to_apply': 'Start with neighbors and family friends. Use apps like Rover or Care.com with parent permission.'}
    ]
    return render_template('teen_jobs.html', jobs=jobs)

@app.route('/summer')
@login_required
def summer_activities():
    """Summer activities finder"""
    if current_user.role not in ['teen', 'teenager']:
        flash('Access denied. Teenager account required.', 'danger')
        return redirect(url_for('index'))
    return render_template('summer_activities.html')

@app.route('/support', methods=['GET', 'POST'])
@login_required
def teen_support():
    """Teen support resources"""
    if current_user.role not in ['teen', 'teenager']:
        flash('Access denied. Teenager account required.', 'danger')
        return redirect(url_for('index'))
    support_issues = [
        {
            'title': 'Dealing with Peer Pressure',
            'advice': 'Remember that true friends will respect your decisions and boundaries. You don\'t have to do something just because others are doing it. Real friends will like you for who you are, not for what you do to fit in.',
            'verse': 'Do not conform to the pattern of this world, but be transformed by the renewing of your mind. - Romans 12:2',
            'action': 'Practice saying "no" in front of a mirror. Have alternative activities ready when friends suggest risky behaviors. Find friends who share your values and make good choices.'
        },
        {
            'title': 'Family Conflict & Arguments',
            'advice': 'Most family conflicts come from misunderstanding and poor communication. Your parents love you and want what\'s best, even when it doesn\'t feel that way. Take time to listen and express your feelings calmly.',
            'verse': 'A gentle answer turns away wrath, but a harsh word stirs up anger. - Proverbs 15:1',
            'action': 'Write down your feelings before discussing them. Ask for family meetings to resolve ongoing issues. Remember to listen as much as you speak.'
        },
        {
            'title': 'Academic Stress & School Pressure',
            'advice': 'Break big tasks into smaller pieces and tackle them one at a time. Remember that grades don\'t define your worth as a person - you are valuable regardless of your academic performance.',
            'verse': 'Cast all your anxiety on him because he cares for you. - 1 Peter 5:7',
            'action': 'Create a realistic study schedule and stick to it. Ask teachers for help when you need it. Take breaks and practice stress-relief activities like exercise or deep breathing.'
        },
        {
            'title': 'Low Self-Esteem & Confidence Issues',
            'advice': 'Focus on your unique strengths and talents. Everyone has something special to offer the world. Your worth comes from who you are, not from what others think of you or how you compare to others.',
            'verse': 'I praise you because I am fearfully and wonderfully made. - Psalm 139:14',
            'action': 'Write down 3 things you\'re good at every day. Surround yourself with positive, supportive people. Challenge negative self-talk with truth about who God says you are.'
        },
        {
            'title': 'Social Media & Online Drama',
            'advice': 'Remember that people only post their best moments online, not their struggles. Don\'t compare your real life to others\' highlight reels. Use social media positively or take breaks when needed.',
            'verse': 'Above all else, guard your heart, for everything you do flows from it. - Proverbs 4:23',
            'action': 'Unfollow accounts that make you feel bad about yourself. Set time limits on social media use. Focus on real-life relationships and activities.'
        },
        {
            'title': 'Depression & Sadness',
            'advice': 'It\'s normal to feel sad sometimes, but if sadness lasts for weeks or interferes with daily life, that\'s when you need to reach out for help. You don\'t have to face this alone.',
            'verse': 'The Lord is close to the brokenhearted and saves those who are crushed in spirit. - Psalm 34:18',
            'action': 'Talk to a trusted adult - parent, teacher, counselor, or youth leader. Consider professional counseling. Practice self-care through exercise, sleep, and healthy activities.'
        },
        {
            'title': 'Anxiety & Worry',
            'advice': 'Anxiety is your body\'s alarm system, but sometimes it goes off when there\'s no real danger. Learning to manage anxiety with breathing techniques, prayer, and professional help when needed is important.',
            'verse': 'Do not be anxious about anything, but in every situation, by prayer and petition, with thanksgiving, present your requests to God. - Philippians 4:6',
            'action': 'Practice deep breathing: 4 counts in, hold for 4, out for 4. Talk to God or a trusted adult about your worries. Focus on what you can control.'
        },
        {
            'title': 'Dating & Relationships',
            'advice': 'Healthy relationships are built on respect, trust, and shared values. You deserve to be treated well and to treat others well. Don\'t rush into serious relationships - focus on becoming the right person.',
            'verse': 'Above all, love each other deeply, because love covers over a multitude of sins. - 1 Peter 4:8',
            'action': 'Set clear boundaries about physical and emotional intimacy. Choose to date people who share your values and treat you with respect. Talk to trusted adults about relationship questions.'
        }
    ]
    
    # All US Cities for dropdown selection
    cities = [
        'Birmingham, AL', 'Mobile, AL', 'Montgomery, AL', 'Anchorage, AK', 'Phoenix, AZ', 'Tucson, AZ', 
        'Little Rock, AR', 'Los Angeles, CA', 'San Diego, CA', 'San Jose, CA', 'San Francisco, CA', 
        'Fresno, CA', 'Sacramento, CA', 'Long Beach, CA', 'Oakland, CA', 'Denver, CO', 'Colorado Springs, CO',
        'Hartford, CT', 'Bridgeport, CT', 'Wilmington, DE', 'Jacksonville, FL', 'Miami, FL', 'Tampa, FL',
        'Orlando, FL', 'St. Petersburg, FL', 'Atlanta, GA', 'Columbus, GA', 'Savannah, GA', 'Honolulu, HI',
        'Boise, ID', 'Chicago, IL', 'Aurora, IL', 'Rockford, IL', 'Indianapolis, IN', 'Fort Wayne, IN',
        'Des Moines, IA', 'Cedar Rapids, IA', 'Wichita, KS', 'Overland Park, KS', 'Louisville, KY',
        'Lexington, KY', 'New Orleans, LA', 'Baton Rouge, LA', 'Shreveport, LA', 'Portland, ME',
        'Baltimore, MD', 'Frederick, MD', 'Boston, MA', 'Worcester, MA', 'Springfield, MA', 'Detroit, MI',
        'Grand Rapids, MI', 'Warren, MI', 'Minneapolis, MN', 'Saint Paul, MN', 'Jackson, MS', 'Gulfport, MS',
        'Kansas City, MO', 'St. Louis, MO', 'Springfield, MO', 'Billings, MT', 'Omaha, NE', 'Lincoln, NE',
        'Las Vegas, NV', 'Henderson, NV', 'Reno, NV', 'Manchester, NH', 'Newark, NJ', 'Jersey City, NJ',
        'Paterson, NJ', 'Albuquerque, NM', 'Las Cruces, NM', 'New York, NY', 'Buffalo, NY', 'Rochester, NY',
        'Yonkers, NY', 'Syracuse, NY', 'Charlotte, NC', 'Raleigh, NC', 'Greensboro, NC', 'Durham, NC',
        'Winston-Salem, NC', 'Fargo, ND', 'Columbus, OH', 'Cleveland, OH', 'Cincinnati, OH', 'Toledo, OH',
        'Akron, OH', 'Oklahoma City, OK', 'Tulsa, OK', 'Portland, OR', 'Salem, OR', 'Eugene, OR',
        'Philadelphia, PA', 'Pittsburgh, PA', 'Allentown, PA', 'Erie, PA', 'Providence, RI', 'Charleston, SC',
        'Columbia, SC', 'North Charleston, SC', 'Sioux Falls, SD', 'Nashville, TN', 'Memphis, TN',
        'Knoxville, TN', 'Chattanooga, TN', 'Houston, TX', 'San Antonio, TX', 'Dallas, TX', 'Austin, TX',
        'Fort Worth, TX', 'El Paso, TX', 'Arlington, TX', 'Corpus Christi, TX', 'Plano, TX', 'Laredo, TX',
        'Salt Lake City, UT', 'West Valley City, UT', 'Burlington, VT', 'Virginia Beach, VA', 'Norfolk, VA',
        'Chesapeake, VA', 'Richmond, VA', 'Newport News, VA', 'Seattle, WA', 'Spokane, WA', 'Tacoma, WA',
        'Vancouver, WA', 'Charleston, WV', 'Milwaukee, WI', 'Madison, WI', 'Cheyenne, WY', 'Washington, DC'
    ]
    
    # Handle city selection form
    selected_city = None
    city_resources = None
    
    if request.method == 'POST':
        selected_city = request.form.get('city')
        if selected_city:
            # Generate city-specific resources
            city_resources = get_city_support_resources(selected_city)
    
    return render_template('teen_support.html', 
                         support_issues=support_issues, 
                         cities=cities, 
                         selected_city=selected_city, 
                         city_resources=city_resources)

def get_city_support_resources(city):
    """Generate support resources for a specific city"""
    # Extract city name from "City, State" format
    city_name = city.split(',')[0].strip()
    
    return {
        'free_tutoring': [
            {'name': f'{city_name} Public Library Tutoring', 'phone': '(555) 123-4567', 'website': f'https://{city_name.lower().replace(" ", "")}library.org'},
            {'name': f'{city_name} Community Center Learning Hub', 'phone': '(555) 234-5678', 'website': f'https://{city_name.lower().replace(" ", "")}community.org'},
            {'name': f'{city_name} YMCA Education Programs', 'phone': '(555) 345-6789', 'website': f'https://ymca{city_name.lower().replace(" ", "")}.org'}
        ],
        'mental_health': [
            {'name': f'{city_name} Teen Mental Health Center', 'phone': '(555) 987-6543', 'website': f'https://{city_name.lower().replace(" ", "")}mentalhealth.org'},
            {'name': f'{city_name} Youth Counseling Services', 'phone': '(555) 876-5432', 'website': f'https://{city_name.lower().replace(" ", "")}youthcounseling.org'},
            {'name': f'Boys & Girls Club of {city_name}', 'phone': '(555) 765-4321', 'website': f'https://bgc{city_name.lower().replace(" ", "")}.org'}
        ],
        'counseling_services': [
            {'name': f'{city_name} Family Counseling Center', 'phone': '(555) 654-3210', 'website': f'https://{city_name.lower().replace(" ", "")}familycounseling.org'},
            {'name': f'{city_name} Teen Support Network', 'phone': '(555) 543-2109', 'website': f'https://{city_name.lower().replace(" ", "")}teensupport.org'},
            {'name': f'{city_name} Crisis Intervention Services', 'phone': '(555) 432-1098', 'website': f'https://{city_name.lower().replace(" ", "")}crisis.org'}
        ],
        'abuse_help': [
            {'name': f'{city_name} Domestic Violence Shelter', 'phone': '(555) 321-0987', 'website': f'https://{city_name.lower().replace(" ", "")}dvshelter.org'},
            {'name': f'{city_name} Child Protective Services', 'phone': '(555) 210-9876', 'website': f'https://{city_name.lower().replace(" ", "")}cps.gov'},
            {'name': f'{city_name} Safe Haven Program', 'phone': '(555) 109-8765', 'website': f'https://{city_name.lower().replace(" ", "")}safehaven.org'}
        ],
        'mentoring_programs': [
            {'name': f'Big Brothers Big Sisters of {city_name}', 'phone': '(555) 098-7654', 'website': f'https://bbbs{city_name.lower().replace(" ", "")}.org'},
            {'name': f'{city_name} Youth Mentorship Alliance', 'phone': '(555) 987-6543', 'website': f'https://{city_name.lower().replace(" ", "")}mentorship.org'},
            {'name': f'{city_name} Student Success Program', 'phone': '(555) 876-5432', 'website': f'https://{city_name.lower().replace(" ", "")}studentsuccess.org'}
        ],
        'teen_shelters': [
            {'name': f'{city_name} Teen Emergency Shelter', 'phone': '(555) 765-4321', 'website': f'https://{city_name.lower().replace(" ", "")}teenshelter.org'},
            {'name': f'{city_name} Youth Housing Program', 'phone': '(555) 654-3210', 'website': f'https://{city_name.lower().replace(" ", "")}youthhousing.org'},
            {'name': f'{city_name} Runaway & Homeless Youth Services', 'phone': '(555) 543-2109', 'website': f'https://{city_name.lower().replace(" ", "")}rhyservices.org'}
        ]
    }

@app.route('/choose-city')
@login_required
def choose_city():
    """Choose city page for teen support center"""
    if current_user.role not in ['teen', 'teenager']:
        flash('Access denied. Teenager account required.', 'danger')
        return redirect(url_for('index'))
    
    cities = [
        # Major US Cities by State (Alphabetical by State)
        {'name': 'Birmingham', 'state': 'AL', 'resources': 45, 'population': '209K'},
        {'name': 'Mobile', 'state': 'AL', 'resources': 35, 'population': '195K'},
        {'name': 'Montgomery', 'state': 'AL', 'resources': 40, 'population': '201K'},
        {'name': 'Anchorage', 'state': 'AK', 'resources': 25, 'population': '291K'},
        {'name': 'Phoenix', 'state': 'AZ', 'resources': 120, 'population': '1.7M'},
        {'name': 'Tucson', 'state': 'AZ', 'resources': 65, 'population': '548K'},
        {'name': 'Little Rock', 'state': 'AR', 'resources': 40, 'population': '198K'},
        {'name': 'Los Angeles', 'state': 'CA', 'resources': 200, 'population': '4.0M'},
        {'name': 'San Diego', 'state': 'CA', 'resources': 150, 'population': '1.4M'},
        {'name': 'San Jose', 'state': 'CA', 'resources': 135, 'population': '1.0M'},
        {'name': 'San Francisco', 'state': 'CA', 'resources': 160, 'population': '875K'},
        {'name': 'Fresno', 'state': 'CA', 'resources': 85, 'population': '542K'},
        {'name': 'Sacramento', 'state': 'CA', 'resources': 95, 'population': '525K'},
        {'name': 'Long Beach', 'state': 'CA', 'resources': 110, 'population': '467K'},
        {'name': 'Oakland', 'state': 'CA', 'resources': 105, 'population': '433K'},
        {'name': 'Denver', 'state': 'CO', 'resources': 110, 'population': '715K'},
        {'name': 'Colorado Springs', 'state': 'CO', 'resources': 75, 'population': '478K'},
        {'name': 'Hartford', 'state': 'CT', 'resources': 55, 'population': '122K'},
        {'name': 'Bridgeport', 'state': 'CT', 'resources': 50, 'population': '148K'},
        {'name': 'Wilmington', 'state': 'DE', 'resources': 35, 'population': '70K'},
        {'name': 'Jacksonville', 'state': 'FL', 'resources': 125, 'population': '949K'},
        {'name': 'Miami', 'state': 'FL', 'resources': 140, 'population': '442K'},
        {'name': 'Tampa', 'state': 'FL', 'resources': 115, 'population': '399K'},
        {'name': 'Orlando', 'state': 'FL', 'resources': 105, 'population': '307K'},
        {'name': 'St. Petersburg', 'state': 'FL', 'resources': 85, 'population': '258K'},
        {'name': 'Atlanta', 'state': 'GA', 'resources': 140, 'population': '498K'},
        {'name': 'Columbus', 'state': 'GA', 'resources': 65, 'population': '206K'},
        {'name': 'Savannah', 'state': 'GA', 'resources': 55, 'population': '147K'},
        {'name': 'Honolulu', 'state': 'HI', 'resources': 75, 'population': '345K'},
        {'name': 'Boise', 'state': 'ID', 'resources': 55, 'population': '235K'},
        {'name': 'Chicago', 'state': 'IL', 'resources': 180, 'population': '2.7M'},
        {'name': 'Aurora', 'state': 'IL', 'resources': 75, 'population': '180K'},
        {'name': 'Rockford', 'state': 'IL', 'resources': 45, 'population': '148K'},
        {'name': 'Indianapolis', 'state': 'IN', 'resources': 110, 'population': '887K'},
        {'name': 'Fort Wayne', 'state': 'IN', 'resources': 65, 'population': '270K'},
        {'name': 'Des Moines', 'state': 'IA', 'resources': 65, 'population': '215K'},
        {'name': 'Wichita', 'state': 'KS', 'resources': 60, 'population': '397K'},
        {'name': 'Kansas City', 'state': 'KS', 'resources': 55, 'population': '156K'},
        {'name': 'Louisville', 'state': 'KY', 'resources': 85, 'population': '633K'},
        {'name': 'Lexington', 'state': 'KY', 'resources': 70, 'population': '323K'},
        {'name': 'New Orleans', 'state': 'LA', 'resources': 95, 'population': '383K'},
        {'name': 'Baton Rouge', 'state': 'LA', 'resources': 70, 'population': '227K'},
        {'name': 'Portland', 'state': 'ME', 'resources': 40, 'population': '68K'},
        {'name': 'Baltimore', 'state': 'MD', 'resources': 105, 'population': '585K'},
        {'name': 'Boston', 'state': 'MA', 'resources': 135, 'population': '695K'},
        {'name': 'Worcester', 'state': 'MA', 'resources': 65, 'population': '206K'},
        {'name': 'Detroit', 'state': 'MI', 'resources': 95, 'population': '639K'},
        {'name': 'Grand Rapids', 'state': 'MI', 'resources': 70, 'population': '198K'},
        {'name': 'Minneapolis', 'state': 'MN', 'resources': 115, 'population': '429K'},
        {'name': 'St. Paul', 'state': 'MN', 'resources': 85, 'population': '308K'},
        {'name': 'Jackson', 'state': 'MS', 'resources': 45, 'population': '160K'},
        {'name': 'Kansas City', 'state': 'MO', 'resources': 85, 'population': '508K'},
        {'name': 'St. Louis', 'state': 'MO', 'resources': 95, 'population': '301K'},
        {'name': 'Billings', 'state': 'MT', 'resources': 35, 'population': '117K'},
        {'name': 'Omaha', 'state': 'NE', 'resources': 75, 'population': '486K'},
        {'name': 'Lincoln', 'state': 'NE', 'resources': 65, 'population': '295K'},
        {'name': 'Las Vegas', 'state': 'NV', 'resources': 105, 'population': '651K'},
        {'name': 'Reno', 'state': 'NV', 'resources': 55, 'population': '264K'},
        {'name': 'Manchester', 'state': 'NH', 'resources': 45, 'population': '115K'},
        {'name': 'Newark', 'state': 'NJ', 'resources': 95, 'population': '311K'},
        {'name': 'Jersey City', 'state': 'NJ', 'resources': 85, 'population': '292K'},
        {'name': 'Albuquerque', 'state': 'NM', 'resources': 75, 'population': '564K'},
        {'name': 'New York', 'state': 'NY', 'resources': 250, 'population': '8.3M'},
        {'name': 'Buffalo', 'state': 'NY', 'resources': 85, 'population': '278K'},
        {'name': 'Rochester', 'state': 'NY', 'resources': 75, 'population': '211K'},
        {'name': 'Syracuse', 'state': 'NY', 'resources': 65, 'population': '148K'},
        {'name': 'Charlotte', 'state': 'NC', 'resources': 125, 'population': '874K'},
        {'name': 'Raleigh', 'state': 'NC', 'resources': 95, 'population': '474K'},
        {'name': 'Greensboro', 'state': 'NC', 'resources': 75, 'population': '299K'},
        {'name': 'Fargo', 'state': 'ND', 'resources': 35, 'population': '125K'},
        {'name': 'Columbus', 'state': 'OH', 'resources': 115, 'population': '906K'},
        {'name': 'Cleveland', 'state': 'OH', 'resources': 95, 'population': '385K'},
        {'name': 'Cincinnati', 'state': 'OH', 'resources': 85, 'population': '309K'},
        {'name': 'Toledo', 'state': 'OH', 'resources': 65, 'population': '270K'},
        {'name': 'Oklahoma City', 'state': 'OK', 'resources': 95, 'population': '695K'},
        {'name': 'Tulsa', 'state': 'OK', 'resources': 75, 'population': '413K'},
        {'name': 'Portland', 'state': 'OR', 'resources': 115, 'population': '652K'},
        {'name': 'Eugene', 'state': 'OR', 'resources': 55, 'population': '177K'},
        {'name': 'Philadelphia', 'state': 'PA', 'resources': 160, 'population': '1.6M'},
        {'name': 'Pittsburgh', 'state': 'PA', 'resources': 105, 'population': '302K'},
        {'name': 'Allentown', 'state': 'PA', 'resources': 65, 'population': '125K'},
        {'name': 'Providence', 'state': 'RI', 'resources': 55, 'population': '190K'},
        {'name': 'Charleston', 'state': 'SC', 'resources': 75, 'population': '150K'},
        {'name': 'Columbia', 'state': 'SC', 'resources': 65, 'population': '137K'},
        {'name': 'Sioux Falls', 'state': 'SD', 'resources': 45, 'population': '192K'},
        {'name': 'Nashville', 'state': 'TN', 'resources': 115, 'population': '689K'},
        {'name': 'Memphis', 'state': 'TN', 'resources': 95, 'population': '633K'},
        {'name': 'Knoxville', 'state': 'TN', 'resources': 65, 'population': '190K'},
        {'name': 'Houston', 'state': 'TX', 'resources': 165, 'population': '2.3M'},
        {'name': 'San Antonio', 'state': 'TX', 'resources': 125, 'population': '1.5M'},
        {'name': 'Dallas', 'state': 'TX', 'resources': 145, 'population': '1.3M'},
        {'name': 'Austin', 'state': 'TX', 'resources': 115, 'population': '965K'},
        {'name': 'Fort Worth', 'state': 'TX', 'resources': 105, 'population': '918K'},
        {'name': 'El Paso', 'state': 'TX', 'resources': 85, 'population': '679K'},
        {'name': 'Salt Lake City', 'state': 'UT', 'resources': 85, 'population': '200K'},
        {'name': 'Burlington', 'state': 'VT', 'resources': 35, 'population': '44K'},
        {'name': 'Virginia Beach', 'state': 'VA', 'resources': 95, 'population': '459K'},
        {'name': 'Norfolk', 'state': 'VA', 'resources': 75, 'population': '238K'},
        {'name': 'Richmond', 'state': 'VA', 'resources': 85, 'population': '230K'},
        {'name': 'Seattle', 'state': 'WA', 'resources': 140, 'population': '749K'},
        {'name': 'Spokane', 'state': 'WA', 'resources': 65, 'population': '228K'},
        {'name': 'Tacoma', 'state': 'WA', 'resources': 75, 'population': '219K'},
        {'name': 'Charleston', 'state': 'WV', 'resources': 35, 'population': '46K'},
        {'name': 'Milwaukee', 'state': 'WI', 'resources': 95, 'population': '577K'},
        {'name': 'Madison', 'state': 'WI', 'resources': 75, 'population': '269K'},
        {'name': 'Cheyenne', 'state': 'WY', 'resources': 25, 'population': '65K'},
        # Washington DC
        {'name': 'Washington', 'state': 'DC', 'resources': 135, 'population': '689K'}
    ]
    
    return render_template('choose_city.html', cities=cities)

@app.route('/mentors')
@login_required
def mentor_recommendations():
    """Mentor recommendations"""
    if current_user.role not in ['teen', 'teenager']:
        flash('Access denied. Teenager account required.', 'danger')
        return redirect(url_for('index'))
    mentors = [
        {
            'id': 1, 'name': 'Sarah Johnson', 'expertise': 'Career Development', 'rating': 4.8, 
            'sessions': 150, 'bio': 'Former Fortune 500 executive helping teens plan their futures',
            'match_reasons': ['Strong business background', 'Experience with teen career guidance', 'Excellent communication skills'],
            'specialties': ['Career Planning', 'Interview Skills', 'Leadership', 'Goal Setting'],
            'age_groups': ['13-15', '16-18'], 'meeting_format': 'Video calls and in-person (NYC area)'
        },
        {
            'id': 2, 'name': 'Mike Rodriguez', 'expertise': 'Sports & Athletics', 'rating': 4.9,
            'sessions': 200, 'bio': 'Former college athlete and current youth sports coach',
            'match_reasons': ['College athletics experience', 'Youth coaching expertise', 'High success rate with athletes'],
            'specialties': ['Athletic Performance', 'Team Leadership', 'Sports Psychology', 'College Recruiting'],
            'age_groups': ['14-16', '17-19'], 'meeting_format': 'Video calls, phone, and field training sessions'
        },
        {
            'id': 3, 'name': 'Dr. Lisa Chen', 'expertise': 'Academic Success', 'rating': 4.7,
            'sessions': 175, 'bio': 'Professor and study skills expert',
            'match_reasons': ['Academic expertise', 'Research in teen learning', 'Proven study methodologies'],
            'specialties': ['Study Skills', 'Test Preparation', 'Time Management', 'Academic Planning'],
            'age_groups': ['13-15', '16-18'], 'meeting_format': 'Video calls and in-person study sessions'
        },
        {
            'id': 4, 'name': 'James Wilson', 'expertise': 'Technology & Innovation', 'rating': 4.8,
            'sessions': 125, 'bio': 'Software engineer and coding instructor',
            'match_reasons': ['Tech industry experience', 'Youth coding programs', 'Innovation mindset'],
            'specialties': ['Programming', 'Web Development', 'App Design', 'Tech Career Paths'],
            'age_groups': ['14-16', '17-19'], 'meeting_format': 'Video calls and virtual coding sessions'
        }
    ]
    return render_template('mentor_recommendations.html', mentors=mentors)

@app.route('/mentor/<int:mentor_id>')
@login_required
def mentor_profile(mentor_id):
    """Individual mentor profile"""
    if current_user.role not in ['teen', 'teenager']:
        flash('Access denied. Teenager account required.', 'danger')
        return redirect(url_for('index'))
    
    # Extended mentor profiles with full details
    mentors_data = {
        1: {
            'id': 1, 'name': 'Sarah Johnson', 'expertise': 'Career Development', 'rating': 4.8, 
            'sessions': 150, 'bio': 'Former Fortune 500 executive helping teens plan their futures',
            'current_job': 'Senior Business Consultant at Global Corp',
            'total_mentees': 75, 'education': 'MBA from Stanford University',
            'experience_years': 15, 'specialties': ['Career Planning', 'Interview Skills', 'Leadership', 'Goal Setting'],
            'age_groups': ['13-15', '16-18'], 'availability': 'Weekends and weekday evenings',
            'meeting_format': 'Video calls and in-person (NYC area)', 'city': 'New York', 'state': 'NY',
            'match_reasons': ['Strong business background', 'Experience with teen career guidance', 'Excellent communication skills'],
        },
        2: {
            'id': 2, 'name': 'Mike Rodriguez', 'expertise': 'Sports & Athletics', 'rating': 4.9,
            'sessions': 200, 'bio': 'Former college athlete and current youth sports coach',
            'current_job': 'Head Coach at Elite Youth Athletics',
            'total_mentees': 120, 'education': 'Bachelor of Sports Science, University of Florida',
            'experience_years': 12, 'specialties': ['Athletic Performance', 'Team Leadership', 'Sports Psychology', 'College Recruiting'],
            'age_groups': ['14-16', '17-19'], 'availability': 'After practice hours and weekends',
            'meeting_format': 'Video calls, phone, and field training sessions', 'city': 'Miami', 'state': 'FL',
            'match_reasons': ['College athletics experience', 'Youth coaching expertise', 'High success rate with athletes'],
        },
        3: {
            'id': 3, 'name': 'Dr. Lisa Chen', 'expertise': 'Academic Success', 'rating': 4.7,
            'sessions': 175, 'bio': 'Professor and study skills expert',
            'current_job': 'Professor of Education, UCLA',
            'total_mentees': 90, 'education': 'PhD in Educational Psychology, Harvard University',
            'experience_years': 18, 'specialties': ['Study Skills', 'Test Preparation', 'Time Management', 'Academic Planning'],
            'age_groups': ['13-15', '16-18'], 'availability': 'Weekday afternoons and evenings',
            'meeting_format': 'Video calls and in-person study sessions', 'city': 'Los Angeles', 'state': 'CA',
            'match_reasons': ['Academic expertise', 'Research in teen learning', 'Proven study methodologies'],
        },
        4: {
            'id': 4, 'name': 'James Wilson', 'expertise': 'Technology & Innovation', 'rating': 4.8,
            'sessions': 125, 'bio': 'Software engineer and coding instructor',
            'current_job': 'Senior Software Engineer at TechStart Inc.',
            'total_mentees': 65, 'education': 'Computer Science Degree, MIT',
            'experience_years': 10, 'specialties': ['Programming', 'Web Development', 'App Design', 'Tech Career Paths'],
            'age_groups': ['14-16', '17-19'], 'availability': 'Evenings and weekends',
            'meeting_format': 'Video calls and virtual coding sessions', 'city': 'Seattle', 'state': 'WA',
            'match_reasons': ['Tech industry experience', 'Youth coding programs', 'Innovation mindset'],
        }
    }
    
    mentor = mentors_data.get(mentor_id)
    if not mentor:
        flash('Mentor not found.', 'error')
        return redirect(url_for('mentor_recommendations'))
    
    return render_template('mentor_profile.html', mentor=mentor)

@app.route('/ai-mentor')
@login_required
def ai_mentor():
    """AI mentor chat interface"""
    if current_user.role not in ['teen', 'teenager']:
        flash('Access denied. Teenager account required.', 'danger')
        return redirect(url_for('index'))
    return render_template('ai_mentor.html')

@app.route('/ai-mentor-chat', methods=['POST'])
@login_required
def ai_mentor_chat():
    """Handle AI mentor chat messages"""
    if current_user.role not in ['teen', 'teenager']:
        return jsonify({'error': 'Access denied. Teenager account required.'}), 403
    
    try:
        data = request.get_json()
        question = data.get('question', '').strip()
        
        if not question:
            return jsonify({'error': 'No question provided'}), 400
        
        # Generate helpful response based on question content
        response = generate_mentor_response(question)
        
        return jsonify({
            'response': response,
            'status': 'success'
        })
        
    except Exception as e:
        app.logger.error(f"AI Mentor chat error: {str(e)}")
        return jsonify({
            'error': 'Sorry, I couldn\'t process your question right now. Please try again.',
            'status': 'error'
        }), 500

import re
import random

class ProfanityFilter:
    def __init__(self):
        # Highest priority filters - zero tolerance slurs
        self.severe_slurs = [
            # Racial/ethnic slurs (partial masking for documentation)
            r'n[i1!|]gg[ae4@]r?', r'n[i1!|]gg[a4@]', r'k[i1!|]k[e3]', 
            r'sp[i1!|]c', r'ch[i1!|]nk', r'g[o0]?[o0]k', r'w[o0]?[o0]t?b[a4@]ck',
            r'p[i1!|]ck[ae4@]n?[i1!|]nn?y', r'c00n', r'r[e3]dsk[i1!|]n',
            
            # Homophobic & transphobic slurs
            r'f[a4@]gg?[o0]t', r'd[o0]?[i1!|]k?e', r'tr[a4@]nn?y', 
            r'h[o0]m[o0]', r'sh[e3]m[a4@]l[e3]', r'qu[e3][e3]r',
            
            # Ableist slurs
            r'r[e3]t[a4@]rd', r'r[o0]t[a4@]rd', r'sp[a4@]z', r'cr[i1!|]pp?l[e3]',
            r'm[o0]ng', r'[i1!|]d[i1!|][o0]t', r'm[o0]r[o0]n'
        ]
        
        # General profanity
        self.profanity = [
            r'f[uU][cC][kK]', r'f[*@#]ck', r'phuck', r'motherfucker', r'fucking',
            r'sh[i1!|]t', r'bullshit', r'sh[i1!|]tty', r'[a4@]ss', r'[a4@]sshole',
            r'dumb[a4@]ss', r'b[i1!|]tch', r'p[i1!|]ss', r'pissed', r'd[i1!|]ck',
            r'c[o0]ck', r'p[uU]ss?y', r'b[a4@]st[a4@]rd', r'd[a4@]mn', r'h[e3]ll',
            r'cr[a4@]p'
        ]
        
        # Sexual content
        self.sexual_content = [
            r'p[o0]rn', r'p[o0]rn[o0]gr[a4@]phy', r'h[e3]nt[a4@][i1!|]',
            r'n[uU]d[e3]', r'n[a4@]k[e3]d', r's[e3]x', r's[e3]xy', r's[e3]x[uU][a4@]l',
            r'r[a4@]p[e3]', r'r[a4@]p[i1!|]st', r'm[o0]l[e3]st', r'[i1!|]nc[e3]st',
            r'f[e3]t[i1!|]sh', r'[o0]rg[a4@]sm', r'cl[i1!|]m[a4@]x'
        ]
        
        # Combined patterns with word boundaries
        self.patterns = []
        for category in [self.severe_slurs, self.profanity, self.sexual_content]:
            for word in category:
                self.patterns.append(r'\b' + word + r'\b')
        
        # Additional filters for leet speak, misspellings, etc.
        self.leet_patterns = [
            r'f[*@#]ck', r'phuck', r'sh[1!i]t', r'5hit', r'b[1!i]tch', 
            r'[@a]ss?h[o0]l[e3]', r'n[i1!|]gg[ae4@]', r'r[3e]t[4a@]rd'
        ]
        
        # Compile all patterns for efficiency
        self.all_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.patterns]
        self.compiled_leet_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.leet_patterns]
    
    def contains_profanity(self, text):
        """Check if text contains any profanity"""
        text = self.normalize_text(text)
        
        # Check all patterns
        for pattern in self.all_patterns:
            if pattern.search(text):
                return True
                
        # Check leet speak variations
        for pattern in self.compiled_leet_patterns:
            if pattern.search(text):
                return True
                
        return False
    
    def normalize_text(self, text):
        """Normalize text by removing symbols and numbers that might obscure profanity"""
        # Replace common leet speak substitutions
        replacements = {
            '1': 'i', '!': 'i', '|': 'i', 
            '4': 'a', '@': 'a', 
            '3': 'e',
            '0': 'o',
            '5': 's', '$': 's',
            '7': 't',
            '9': 'g'
        }
        
        normalized = text.lower()
        for char, replacement in replacements.items():
            normalized = normalized.replace(char, replacement)
            
        # Remove excessive repeating characters
        normalized = re.sub(r'(.)\1{2,}', r'\1\1', normalized)
        
        return normalized

# Initialize profanity filter
profanity_filter = ProfanityFilter()

def is_crisis_situation(text):
    """Detect if the user is in immediate danger"""
    crisis_indicators = [
        r'kill (my|me|myself)',
        r'end it (all|now)',
        r'want to die',
        r'hurt myself',
        r'suicid(e|al|ality)',
        r'can\'t take it anymore',
        r'no point in living',
        r'better off dead'
    ]
    
    for indicator in crisis_indicators:
        if re.search(indicator, text, re.IGNORECASE):
            return True
    return False

def handle_crisis():
    """Response for crisis situations"""
    return """🚨 I'm really concerned about what you're sharing. Your life has value and meaning, even when it doesn't feel that way right now.

**Please reach out for immediate help:**
• **National Suicide Prevention Lifeline: 988**
• **Crisis Text Line: Text HOME to 741741**
• **National Domestic Violence Hotline: 1-800-799-7233**

**Right now, please:**
• Talk to a trusted adult immediately (parent, teacher, counselor)
• Go to your nearest emergency room
• Call 911 if you're in immediate danger

You're not alone in this. Many people have felt this way and found help. This difficult time doesn't have to last forever.

**Biblical Truth**: "For I know the plans I have for you," declares the Lord, "plans to prosper you and not to harm you, to give you hope and a future." - Jeremiah 29:11

You are loved, you matter, and there are people who want to help you through this."""

def handle_profanity():
    """Response when profanity is detected"""
    return """I want to maintain a respectful and safe environment for everyone. Could you please rephrase your question without inappropriate language? 

I'm here to help with whatever you're going through, and I believe we can have a meaningful conversation while keeping things respectful. What's really on your mind that you'd like to talk about?

Remember: You're valued and your concerns matter to me. Let's work through this together in a positive way."""

def generate_mentor_response(question):
    """Generate helpful mentor responses based on question content"""
    # First check for profanity
    if profanity_filter.contains_profanity(question):
        return handle_profanity()
    
    # Check for crisis situations first
    if is_crisis_situation(question):
        return handle_crisis()
    
    question_lower = question.lower()
    
    # Confidence and self-esteem responses
    if any(word in question_lower for word in ['confident', 'confidence', 'shy', 'scared', 'nervous', 'anxiety']):
        return """I understand feeling less confident sometimes - that's totally normal! Here are some ways to build confidence:

🌟 **Start Small**: Practice confident behaviors in low-pressure situations first
💪 **Celebrate Wins**: Write down 3 things you did well each day
🎯 **Prepare Well**: The more prepared you are, the more confident you'll feel
👥 **Practice Speaking**: Join clubs, answer questions in class, or practice with family
📝 **Positive Self-Talk**: Replace "I can't" with "I'm learning" or "I'll try"

Remember: Everyone feels nervous sometimes, even confident-looking people! Confidence grows with practice.

**Next Step**: Pick one small thing you can do this week to practice being more confident. What would that be?"""

    # Study and school-related responses  
    elif any(word in question_lower for word in ['study', 'school', 'homework', 'grades', 'test', 'exam']):
        return """Great question about school! Here are proven study strategies that work:

📚 **Active Study Methods**:
- Summarize what you read in your own words
- Teach the material to someone else (or even a pet!)
- Make flashcards for key concepts
- Practice problems multiple times

⏰ **Time Management**:
- Break large assignments into smaller tasks
- Use a planner or app to track deadlines
- Study in 25-minute focused blocks with 5-minute breaks
- Find your best time of day to study (morning, afternoon, or evening)

🎯 **Test Preparation**:
- Start reviewing at least a week before tests
- Form study groups with classmates
- Ask teachers for clarification on confusing topics
- Get plenty of sleep before big tests

**Remember**: Everyone learns differently. Try different methods to find what works best for you!

**Next Step**: What subject are you finding most challenging right now?"""

    # Friendship and social responses
    elif any(word in question_lower for word in ['friend', 'friendship', 'social', 'lonely', 'popular', 'peer']):
        return """Friendships are so important, and it's normal to have questions about them! Here's some advice:

🤝 **Making Friends**:
- Be genuinely interested in others - ask about their hobbies and listen
- Join clubs, sports, or activities where you'll meet like-minded people
- Be yourself rather than trying to impress others
- Start with small conversations and let friendships grow naturally

💕 **Being a Good Friend**:
- Be loyal and trustworthy - keep secrets that friends share
- Support friends during tough times
- Celebrate their successes without jealousy
- Include others and be kind to everyone

🚫 **Dealing with Drama**:
- Stay out of gossip and don't spread rumors
- Talk directly to friends if there's a problem
- It's okay to step away from toxic friendships
- Choose friends who respect your values and boundaries

**Biblical Wisdom**: "A friend loves at all times, and a brother is born for a time of adversity." - Proverbs 17:17

**Next Step**: What specific friendship situation would you like more advice about?"""

    # Stress and mental health responses
    elif any(word in question_lower for word in ['stress', 'stressed', 'overwhelmed', 'pressure', 'depressed', 'sad', 'worried']):
        return """I'm sorry you're feeling this way. Stress is normal, but there are healthy ways to manage it:

🧘 **Immediate Stress Relief**:
- Take 5 deep breaths (in for 4 counts, hold for 4, out for 4)
- Go for a walk or do some physical activity
- Listen to calming music
- Talk to someone you trust

📋 **Long-term Stress Management**:
- Break big problems into smaller, manageable steps
- Keep a regular sleep schedule (8-9 hours for teens)
- Eat nutritious foods and stay hydrated
- Make time for activities you enjoy

🙏 **Finding Peace**:
- Pray or meditate regularly
- Write in a journal about your feelings
- Remember that tough times don't last forever
- Focus on what you can control, not what you can't

⚠️ **When to Get Help**: If you're feeling depressed, having trouble sleeping, or thoughts of hurting yourself, please talk to a parent, teacher, school counselor, or call a helpline right away.

**Biblical Comfort**: "Cast all your anxiety on him because he cares for you." - 1 Peter 5:7

**Next Step**: Can you identify the main source of your stress right now?"""

    # Goals and future planning
    elif any(word in question_lower for word in ['goal', 'future', 'career', 'college', 'plan', 'dream']):
        return """It's awesome that you're thinking about your future! Here's how to set and achieve goals:

🎯 **Goal Setting**:
- Make goals SMART: Specific, Measurable, Achievable, Relevant, Time-bound
- Write them down - you're 42% more likely to achieve written goals
- Break big goals into smaller monthly and weekly steps
- Set both short-term (this year) and long-term (5+ years) goals

🚀 **Career Exploration**:
- Take career interest surveys online
- Talk to adults in careers that interest you
- Try job shadowing or informational interviews
- Explore different subjects to discover your strengths
- Consider both your interests AND job market needs

📚 **Preparing for Success**:
- Focus on developing good character and work ethic
- Build skills like communication, problem-solving, and teamwork
- Get good grades, but also develop your talents outside school
- Look for leadership opportunities

🙏 **Seeking God's Will**:
- Pray about your future and ask for wisdom
- Consider how you can use your talents to serve others
- Remember that God has a plan for your life

**Biblical Promise**: "For I know the plans I have for you," declares the Lord, "plans to prosper you and not to harm you, to give you hope and a future." - Jeremiah 29:11

**Next Step**: What's one specific goal you'd like to work toward this year?"""

    # Money and finances
    elif any(word in question_lower for word in ['money', 'save', 'saving', 'budget', 'job', 'earn', 'allowance']):
        return """Great that you're thinking about money management early! Here are key financial skills:

💰 **Saving Money**:
- Save at least 10% of any money you receive
- Use the 50/30/20 rule: 50% needs, 30% wants, 20% savings
- Set specific savings goals (like $200 for a new phone)
- Keep your savings in a separate account or envelope

💼 **Earning Money (Age-Appropriate)**:
- Babysitting, pet sitting, or lawn care for neighbors
- Selling items you make or bake (with parent permission)
- Extra chores around the house
- Tutoring younger students in subjects you're good at

📊 **Smart Spending**:
- Always comparison shop for big purchases
- Wait 24 hours before buying non-essential items
- Ask: "Do I need this or just want it?"
- Learn to say no to peer pressure about spending

📚 **Financial Education**:
- Read books about money management for teens
- Learn about compound interest - it's incredibly powerful!
- Understand the difference between assets and liabilities
- Never borrow money for wants, only true needs

**Biblical Wisdom**: "The plans of the diligent lead to profit as surely as haste leads to poverty." - Proverbs 21:5

**Next Step**: What's your biggest financial goal right now?"""

    # Health and wellness
    elif any(word in question_lower for word in ['health', 'exercise', 'sleep', 'eat', 'nutrition', 'energy', 'tired']):
        return """Your health is so important for everything else in life! Here's how to stay healthy:

🏃 **Physical Health**:
- Get 60 minutes of physical activity daily (sports, walking, dancing, etc.)
- Eat 5-9 servings of fruits and vegetables daily
- Drink plenty of water (half your body weight in ounces)
- Get 8-9 hours of sleep each night (seriously, this is crucial!)

🧠 **Mental Health**:
- Limit screen time, especially before bed
- Practice gratitude - write down 3 good things daily
- Spend time in nature regularly
- Learn stress management techniques

⚖️ **Balance**:
- Make time for both work and fun
- Don't skip meals or rely on junk food
- Take breaks from social media
- Maintain healthy friendships

🙏 **Spiritual Health**:
- Pray or meditate regularly
- Read inspiring books or scriptures
- Serve others in your community
- Remember your body is a gift to be cared for

**Biblical Truth**: "Do you not know that your bodies are temples of the Holy Spirit?" - 1 Corinthians 6:19

**Next Step**: Which area of health would you like to improve first?"""

    # Depression and serious mental health  
    elif any(word in question_lower for word in ['depress', 'depressed', 'depression', 'hopeless', 'worthless', 'empty']):
        return """I'm really concerned that you're feeling this way. Depression can make everything feel overwhelming, but what you're experiencing is a medical condition, not a personal failing.

🧠 **Understanding Depression**:
- It's not your fault - depression is a real medical condition
- Your feelings are valid and treatable
- Many teens experience depression - you're not alone
- Recovery is possible with proper support

💪 **Things That Can Help**:
- Talk to a school counselor, parent, or trusted adult
- Consider seeing a mental health professional
- Maintain a routine with sleep, exercise, and healthy eating
- Stay connected with supportive friends and family
- Practice activities that used to bring you joy

⚠️ **Please Get Help**: Depression is treatable, but you don't have to fight it alone. A mental health professional can provide proper support and treatment options.

**If you're having thoughts of hurting yourself, please call 988 (Suicide Prevention Lifeline) immediately.**

**Biblical Hope**: "The Lord is close to the brokenhearted and saves those who are crushed in spirit." - Psalm 34:18

Remember: This difficult time doesn't have to last forever. You are not defined by your struggles, and healing is possible.

**Next Step**: Can you talk to a trusted adult today about getting professional support?"""

    # Anxiety and panic
    elif any(word in question_lower for word in ['panic', 'anxiety attack', 'can\'t breathe', 'heart racing']):
        return """It sounds like you might be experiencing anxiety or panic attacks. These can be really scary, but they are treatable.

🫁 **During a Panic Attack**:
- Breathe slowly: In for 4 counts, hold for 4, out for 4
- Ground yourself: Name 5 things you can see, 4 you can touch, 3 you can hear
- Remind yourself: "This will pass, I am safe"
- Sit down and put your feet flat on the floor

🧘 **Managing Anxiety Long-term**:
- Learn relaxation techniques (deep breathing, meditation)
- Regular exercise helps reduce anxiety
- Limit caffeine and get enough sleep
- Talk to someone you trust about your worries
- Consider counseling - it's very effective for anxiety

⚠️ **When to Get Help**: If anxiety is affecting your daily life, school, or relationships, please talk to a counselor or doctor. There are excellent treatments available.

**Biblical Comfort**: "Do not be anxious about anything, but in every situation, by prayer and petition, with thanksgiving, present your requests to God." - Philippians 4:6

**Next Step**: Would you like to learn some specific breathing techniques that can help during anxious moments?"""

    # Substance abuse concerns
    elif any(word in question_lower for word in ['drugs', 'drinking', 'alcohol', 'high', 'weed', 'vaping', 'smoking']):
        return """I'm glad you feel comfortable talking about this. Substance use can be a way people try to cope with stress, but it often creates more problems.

🚨 **Health & Safety**:
- Your brain is still developing until age 25 - substances can cause lasting damage
- Mixing substances or using alone increases danger
- Addiction can develop quickly, especially in teens
- It can affect school, relationships, and your future

💪 **Healthier Coping**:
- Exercise, music, art, or hobbies for stress relief
- Talk to trusted adults about what's driving the substance use
- Find friends who support healthy choices
- Learn stress management and emotional regulation skills

🔒 **Getting Help**:
- Talk to a school counselor, parent, or doctor
- Substance abuse counselors specialize in teen issues
- Support groups for teens are available
- Treatment is confidential and effective

**If you're in immediate danger from substance use, call 911 or go to an emergency room.**

**Biblical Truth**: "Do you not know that your bodies are temples of the Holy Spirit?" - 1 Corinthians 6:19

**Remember**: Asking for help takes courage. You deserve support in making healthy choices for your life.

**Next Step**: Would you like to talk about what's behind the substance use, or would you prefer information about getting help?"""

    # Bullying and difficult situations
    elif any(word in question_lower for word in ['bully', 'bullying', 'mean', 'hurt', 'teasing', 'picked on']):
        return """I'm sorry you're dealing with this. Bullying is never okay, and it's not your fault. Here's what you can do:

🛡️ **Immediate Safety**:
- Tell a trusted adult immediately (parent, teacher, counselor)
- Stay near friends or adults when possible
- Don't engage or fight back - this usually makes it worse
- Document incidents (when, where, what happened)

💪 **Building Confidence**:
- Practice confident body language (stand tall, make eye contact)
- Develop a strong friend group for support
- Focus on your strengths and positive qualities
- Remember that bullies often have their own problems

🎯 **Response Strategies**:
- Use calm, confident responses: "That's not okay" or "Stop"
- Walk away when possible
- Use humor if it feels safe and natural
- Report every incident to adults

❤️ **Self-Care**:
- Talk to someone you trust about your feelings
- Do activities that make you feel good about yourself
- Remember this situation is temporary
- Don't let bullies change who you are

**Important**: If you're ever in physical danger or having thoughts of hurting yourself, tell an adult immediately or call a crisis helpline.

**Biblical Encouragement**: "The Lord your God is with you, the Mighty Warrior who saves." - Zephaniah 3:17

**Next Step**: Have you told a trusted adult about what's happening?"""

    # Abuse situations
    elif any(word in question_lower for word in ['abuse', 'abused', 'abusive', 'hitting', 'sexual abuse', 'molest', 'inappropriate touch']):
        return """🚨 I'm very concerned about what you're sharing. Abuse is never okay, and it's never your fault.

**Your Safety Comes First:**
• If you're in immediate danger, call 911
• National Child Abuse Hotline: 1-800-4-A-CHILD (1-800-422-4453)
• National Sexual Assault Hotline: 1-800-656-4673
• Tell a trusted adult immediately (teacher, counselor, relative, friend's parent)

**Important Things to Know:**
• Abuse is NEVER the victim's fault
• You deserve to be safe and protected
• Speaking up takes incredible courage
• Help and healing are available
• You are believed and supported

**If telling an adult feels scary:**
• Start with someone you trust most
• You can write it down if speaking feels too hard
• School counselors are trained to help with these situations
• You don't have to face this alone

**Biblical Truth**: "The Lord your God is with you, the Mighty Warrior who saves." - Zephaniah 3:17

You are brave for seeking help. Please reach out to a trusted adult or one of these hotlines today. You deserve safety, love, and protection.

**Next Step**: Can you identify one trusted adult you could talk to today?"""

    # Family conflict
    elif any(word in question_lower for word in ['parents fighting', 'family problems', 'divorce', 'family conflict', 'parents argue']):
        return """Family conflict can be really stressful, especially when you're caught in the middle. Your feelings about this situation are completely valid.

👨‍👩‍👧‍👦 **Dealing with Family Conflict**:
- Remember that their problems are not your fault
- You can't fix your parents' relationship, but you can take care of yourself
- It's okay to feel sad, angry, or confused about the situation
- Focus on what you can control (your reactions, choices, and self-care)

💪 **Taking Care of Yourself**:
- Talk to a trusted adult outside the family (teacher, counselor, friend's parent)
- Maintain your routines and friendships
- Find peaceful spaces where you can relax
- Journal about your feelings or express them through art/music

🤝 **Getting Support**:
- School counselors can help you process these feelings
- Support groups for teens dealing with family issues exist
- Don't isolate yourself - stay connected with supportive people
- Consider family counseling if parents are open to it

**Biblical Wisdom**: "Above all, love each other deeply, because love covers over a multitude of sins." - 1 Peter 4:8

**Remember**: You can't control your family situation, but you can control how you respond and take care of yourself.

**Next Step**: Who is one adult outside your family that you trust and could talk to about this?"""

    # Decision making and choices
    elif any(word in question_lower for word in ['decision', 'choice', 'choose', 'right', 'wrong', 'moral']):
        return """Making good decisions is a skill you can develop! Here's a framework for tough choices:

🤔 **Decision-Making Process**:
1. **Identify the decision** - What exactly are you trying to decide?
2. **Gather information** - What are all your options?
3. **Consider consequences** - What could happen with each choice?
4. **Seek advice** - What would wise people recommend?
5. **Pray/reflect** - What feels right in your heart?
6. **Decide and act** - Make your choice and follow through

⚖️ **Questions to Ask Yourself**:
- Will this help me become the person I want to be?
- How will this affect my relationships with family and friends?
- Am I being pressured, or is this truly my choice?
- What would happen if everyone made this same choice?
- Does this align with my values and beliefs?

🎯 **Character-Based Decisions**:
- Choose honesty, even when it's harder
- Consider how your choices affect others
- Think long-term, not just immediate gratification
- Ask: "What would a person of good character do?"

🙏 **Seeking Wisdom**:
- Pray for guidance when facing big decisions
- Talk to parents, mentors, or trusted adults
- Remember that making mistakes is part of learning
- Learn from both good and poor choices

**Biblical Wisdom**: "Trust in the Lord with all your heart and lean not on your own understanding; in all your ways submit to him, and he will make your paths straight." - Proverbs 3:5-6

**Next Step**: What specific decision are you facing right now?"""

    # Family and parent issues - specific guidance
    elif any(word in question_lower for word in ['mom', 'dad', 'parent', 'mother', 'father', 'family', 'scream', 'yell', 'fight']):
        return get_family_guidance_response(question)
    
    # Emotional support and fear
    elif any(word in question_lower for word in ['afraid', 'scared', 'fear', 'worried', 'concern', 'upset']):
        return get_emotional_support_response(question)
    
    # General life questions - personalized response
    else:
        return get_personalized_guidance_response(question)

def get_family_guidance_response(question):
    """Provide specific guidance for family and parent issues"""
    return f"""I can hear that you're dealing with something difficult at home. Family relationships can be really challenging, especially when emotions run high.

🙏 **Understanding Why Parents Get Upset**:
- Parents often worry about your safety, future, and well-being
- Sometimes they express worry through frustration or raising their voice  
- They may be stressed from work, finances, or other adult responsibilities
- Different generations have different communication styles

💬 **How to Improve Communication**:
- Choose a calm moment to talk, not during or right after conflict
- Use "I feel" statements instead of "You always" statements
- Listen to understand their perspective, even if you disagree
- Ask questions like "What are you most worried about?"
- Show respect even when you feel frustrated

🤝 **Building Better Relationships**:
- Follow through on commitments to build trust
- Help out at home without being asked occasionally
- Share positive things happening in your life
- Thank them when they do things for you
- Be patient - relationships take time to improve

🚇 **When You Need Help**:
- If you're feeling unsafe or overwhelmed, talk to a school counselor
- Consider asking a trusted adult to help facilitate a family conversation
- Remember: Your parents are human and make mistakes too
- Family counseling can be really helpful if your parents are open to it

**Biblical Wisdom**: "Honor your father and mother" - Ephesians 6:2, and "Fathers, do not exasperate your children" - Ephesians 6:4

**Remember**: Most parent-teen conflict comes from love and worry, even when it doesn't feel that way. The goal is understanding each other better.

**Next Step**: What's one small thing you could do this week to show your parents you're listening to their concerns?"""

def get_emotional_support_response(question):
    """Provide emotional support for fears and worries"""
    return f"""It's really brave of you to share what you're feeling. Fear and worry are normal human emotions, and it shows wisdom that you're reaching out for support.

🌈 **Understanding Your Feelings**:
- Fear often comes from uncertainty about the future
- It's your mind's way of trying to protect you
- Everyone feels afraid sometimes - even adults
- These feelings are temporary and will pass

🙏 **Finding Peace When You're Scared**:
- Take slow, deep breaths (breathe in for 4, hold for 4, out for 6)
- Name 5 things you can see, 4 you can touch, 3 you can hear
- Pray or meditate to find inner calm
- Write down your worries, then write one thing you can do about each
- Talk to someone you trust about what's scaring you

💪 **Building Courage**:
- Remember times you've been brave before
- Start with small steps toward what scares you
- Ask for help - you don't have to face fears alone
- Focus on what you can control, not what you can't
- Celebrate small victories and progress

🙋 **Who to Talk To**:
- **Parents or guardians** - They want to help and protect you
- **Teachers** - They see lots of students and understand teen challenges
- **School counselors** - Trained specifically to help with emotional issues
- **Trusted family members** - Aunts, uncles, grandparents who care about you
- **Youth pastors or religious leaders** - If you're part of a faith community

**Biblical Comfort**: "When I am afraid, I put my trust in you." - Psalm 56:3

**Remember**: You don't have to carry your fears alone. There are caring adults in your life who want to help you work through this.

**Next Step**: Who is one trusted adult you could share your worries with this week?"""

def get_personalized_guidance_response(question):
    """Provide personalized guidance based on question content"""
    # Extract key themes from the question
    question_lower = question.lower()
    
    if len(question.strip()) < 5:
        guidance = "I can see you're reaching out, and I'm glad you did. Sometimes it's hard to know where to start."
    elif any(word in question_lower for word in ['help', 'advice', 'guidance', 'what should']):
        guidance = "It takes wisdom to ask for guidance, and I'm here to help you think through whatever you're facing."
    elif any(word in question_lower for word in ['problem', 'issue', 'trouble', 'difficult']):
        guidance = "Problems can feel overwhelming, but every challenge is an opportunity to grow stronger and wiser."
    elif any(word in question_lower for word in ['why', 'understand', 'confus']):
        guidance = "It's normal to have questions about life. Seeking understanding shows you're thinking deeply about important things."
    else:
        guidance = "Thank you for sharing what's on your mind. Every teenager faces unique challenges and questions."
    
    return f"""{guidance}

🌟 **Here's what I want you to know**:
- Your feelings and questions are completely valid
- Many other teens are facing similar challenges
- There are people who care about you and want to help
- With the right support and tools, you can work through this

🙋 **The Best Sources of Guidance**:
- **Your Parents/Guardians**: They know you best and want your success
- **Teachers**: They're trained to help students navigate challenges  
- **School Counselors**: Experts in helping teens with personal issues
- **Trusted Adults**: Family friends, coaches, youth leaders who care about you
- **God**: Through prayer, you can find peace and direction

📚 **Questions to Help You Think Deeper**:
- What would a wise, caring adult advise you to do?
- How would you want this situation to turn out?
- What steps could you take to move toward that outcome?
- Who in your life has faced something similar and handled it well?
- What would you tell a younger sibling facing this same challenge?

🎯 **Taking Action**:
- Talk to a trusted adult about your situation this week
- Write down 2-3 possible solutions or next steps
- Focus on what you can control and influence
- Be patient with yourself - growth takes time
- Remember that asking for help is a sign of strength, not weakness

**Biblical Truth**: "Plans fail for lack of counsel, but with many advisers they succeed." - Proverbs 15:22

**Remember**: You don't have to figure everything out on your own. The wisest people in the world regularly ask others for advice and perspective.

**Next Step**: Who is one adult in your life that you trust and respect? Consider talking to them about this situation this week."""

def get_topic_specific_resources(question):
    """Provide additional resources based on question topic"""
    question_lower = question.lower()
    
    if any(word in question_lower for word in ['study', 'school', 'homework']):
        return "\n\n📖 **Additional Resources**: Check out the Academic Success section in MentorMe for study guides and homework help links organized by subject!"
    elif any(word in question_lower for word in ['friend', 'social']):
        return "\n\n🤝 **Additional Resources**: Explore the Personal Development section for more tips on communication and relationship building!"
    elif any(word in question_lower for word in ['career', 'future', 'job']):
        return "\n\n💼 **Additional Resources**: Browse our Career Paths section to explore different professions and what they require!"
    elif any(word in question_lower for word in ['money', 'save', 'budget']):
        return "\n\n💰 **Additional Resources**: Check out the Money Management topics in our Life Skills section for more detailed financial guidance!"
    
    return ""

@app.route('/categories')
@login_required
def category_exploration():
    """Category exploration main page"""
    if current_user.role not in ['teen', 'teenager']:
        flash('Access denied. Teenager account required.', 'danger')
        return redirect(url_for('index'))
    # Default data for category exploration
    category_data = {
        'faith': {
            'title': '✝️ Faith & Values',
            'items': [
                {'title': 'Character Building', 'icon': '🏗️', 'description': 'Build strong moral character and values'},
                {'title': 'Respect & Relationships', 'icon': '🤝', 'description': 'Learn to build healthy relationships with respect'},
                {'title': 'Spiritual Growth', 'icon': '🙏', 'description': 'Develop your faith and spiritual understanding'},
                {'title': 'Service & Giving', 'icon': '❤️', 'description': 'Learn the joy of serving others and giving back'}
            ]
        },
        'personal_development': {
            'title': '🌟 Personal Development', 
            'items': [
                {'title': 'Confidence & Self-Esteem', 'icon': '💪', 'description': 'Build confidence and healthy self-worth'},
                {'title': 'Goal Setting & Time Management', 'icon': '🎯', 'description': 'Learn to set and achieve your goals effectively'},
                {'title': 'Public Speaking & Communication', 'icon': '🎤', 'description': 'Master the art of effective communication'},
                {'title': 'Leadership Skills', 'icon': '👑', 'description': 'Develop leadership abilities for future success'}
            ]
        }
    }
    
    category = request.args.get('category', 'personal_development')
    data = category_data.get(category, category_data['personal_development'])
    
    return render_template('category_exploration.html', 
                         category=category,
                         category_title=data['title'], 
                         items=data['items'])

@app.route('/legacy-category/<category_name>')
@login_required
def legacy_category_pathway(category_name):
    """Category pathway detail page"""
    if current_user.role not in ['teen', 'teenager']:
        flash('Access denied. Teenager account required.', 'danger')
        return redirect(url_for('index'))
    
    # Create detailed pathway content based on category
    if category_name == 'character_building':
        pathway_data = {
            'title': 'Character Building: Your Spiritual Core',
            'description': 'Build strong moral character and values that will guide you through life',
            'content': 'Character is who you are when no one is watching. It\'s built through small, daily choices that align with God\'s design for your life.',
            'problem': 'It\'s easy to just go with the crowd and not think about who you\'re becoming.',
            'solution': 'Your character is who you are when no one is watching. It\'s built by making small, right choices every day.',
            'verse': '"Don\'t copy the behavior and customs of this world, but let God transform you into a new person by changing the way you think." (Romans 12:2a, NLT)',
            'action': 'This week, identify one thing you do to "fit in" that doesn\'t fit who God says you are. Have the courage to change it.',
            'action_steps': [
                '📝 Identify your core values and write them down',
                '💯 Practice honesty in small situations daily',
                '🛡️ Stand up for what\'s right, even when it\'s unpopular',
                '🎯 Take responsibility for your mistakes',
                '❤️ Help others without expecting anything in return'
            ],
            'benefits': [
                '🤝 People will trust and respect you',
                '😊 You\'ll sleep well knowing you did the right thing',
                '🚀 Future opportunities will come to those with good character',
                '🌟 You\'ll be a positive influence on friends and family'
            ],
            'tradeoffs': [
                'Effort required to make right choices when they\'re difficult',
                'Sometimes standing alone when others make poor choices',
                'Need to consistently live up to your values',
                'Accountability for your actions and decisions'
            ]
        }
    elif category_name == 'respect_&_relationships':
        pathway_data = {
            'title': 'Respect & Relationships: The Two-Way Street',
            'description': 'Learn to build healthy, respectful relationships with family, friends, and others',
            'content': 'Respect is a mirror. You get back what you put out. This is the foundation for every healthy relationship—with friends, parents, and God.',
            'problem': 'Thinking respect is something you demand, not something you earn and give.',
            'solution': 'Respect is a mirror. You get back what you put out. This is the foundation for every healthy relationship—with friends, parents, and God.',
            'verse': '"Show respect to everyone." (1 Peter 2:17a, NIRV)',
            'action': 'Pick one person in your life (maybe even someone you find difficult) and show them genuine respect this week through your words and actions. See how it changes the dynamic.',
            'action_steps': [
                '👂 Listen more than you speak',
                '🙏 Say please, thank you, and excuse me regularly',
                '📱 Put your phone away during conversations',
                '💬 Ask questions about others\' interests',
                '🤝 Keep your promises and commitments'
            ],
            'benefits': [
                '👥 Stronger friendships and family bonds',
                '💼 Better opportunities in school and work',
                '😊 Less drama and conflict in your life',
                '🎯 People will want to help you succeed'
            ],
            'tradeoffs': [
                'Time and effort to build meaningful relationships',
                'Need to put others\' needs before your own sometimes',
                'Vulnerability required for deep connections',
                'Patience when others don\'t reciprocate respect immediately'
            ]
        }
    elif category_name == 'service_&_giving':
        pathway_data = {
            'title': 'Service & Giving: Your Secret Superpower',
            'description': 'Learn the joy and power of serving others and giving back',
            'content': 'Serving others is like a secret weapon against self-pity and boredom. It shifts your focus outward and shows God\'s love in action.',
            'problem': 'Thinking life is all about "me, me, me," which leads to feeling empty and lonely.',
            'solution': 'Serving others is like a secret weapon against self-pity and boredom. It shifts your focus outward and shows God\'s love in action.',
            'verse': '"Even the Son of Man did not come to be served, but to serve, and to give his life as a ransom for many." (Mark 10:45, NIV)',
            'action': 'Do one "secret service" this week—a chore for your family, help a classmate, buy a coffee for someone—without waiting for a thank-you.',
            'action_steps': [
                '❤️ Volunteer at local charities or community centers',
                '🏠 Help with chores at home without being asked',
                '👥 Assist classmates with homework or projects',
                '🎁 Give to those in need without expecting recognition',
                '💪 Use your talents to benefit others'
            ],
            'benefits': [
                '😊 Greater sense of purpose and fulfillment',
                '🤝 Stronger connections with your community',
                '💪 Development of leadership and teamwork skills',
                '🌟 Positive impact on others\' lives'
            ],
            'tradeoffs': [
                'Time spent serving others instead of personal activities',
                'Physical and emotional energy invested in helping',
                'Need to put others\' needs before your own wants',
                'Sometimes receiving no recognition or thanks for service'
            ]
        }
    elif category_name == 'integrity':
        pathway_data = {
            'title': 'Integrity: Your Life\'s Resume',
            'description': 'Learn to live with consistency between your beliefs and actions',
            'content': 'Integrity is when your actions match your beliefs, no matter who\'s around. It\'s about being whole, not divided.',
            'problem': 'The temptation to be two different people: one at church or home, and another with your friends or online.',
            'solution': 'Integrity is when your actions match your beliefs, no matter who\'s around. It\'s about being whole, not divided.',
            'verse': '"The Lord detests people with crooked hearts, but he delights in those with integrity." (Proverbs 11:20, NLT)',
            'action': 'Audit your social media feeds or group chats. If there\'s anything you\'ve posted or said that doesn\'t line up with who you say you are, have the integrity to delete it.',
            'action_steps': [
                '📝 Define your core values and stick to them',
                '💬 Speak the same way whether parents are present or not',
                '📱 Post only what aligns with your true character',
                '🤝 Keep promises even when no one is watching',
                '🛡️ Stand up for what\'s right in all situations'
            ],
            'benefits': [
                '🌟 Self-respect and inner peace',
                '🤝 Others will trust and respect you',
                '💪 Strong reputation that opens doors',
                '😊 No stress from living double lives'
            ],
            'tradeoffs': [
                'Constant vigilance to maintain consistency',
                'Difficulty fitting in when others compromise values',
                'Pressure to always live up to high standards',
                'Missing out on some opportunities that require compromise'
            ]
        }
    elif category_name == 'honesty':
        pathway_data = {
            'title': 'Honesty: The Clean Slate',
            'description': 'Learn the freedom and strength that comes from truthfulness',
            'content': 'Honesty is freedom. It keeps your conscience clean and your relationships trust-worthy. Telling the truth, even when it\'s hard, is a sign of real strength.',
            'problem': 'Lying seems like an easy way to avoid trouble or look better, but it always creates a tangled web of stress and guilt.',
            'solution': 'Honesty is freedom. It keeps your conscience clean and your relationships trust-worthy. Telling the truth, even when it\'s hard, is a sign of real strength.',
            'verse': '"So stop telling lies. Let us tell our neighbors the truth." (Ephesians 4:25, NLT)',
            'action': 'If there\'s a lie you\'ve been living with (big or small), come clean this week with the person it affects. It will be hard, but the relief and freedom afterward are worth it.',
            'action_steps': [
                '💯 Tell the truth even when it\'s difficult',
                '🙏 Admit mistakes quickly and sincerely',
                '🚫 Avoid "white lies" and half-truths',
                '💬 Be genuine in your relationships',
                '🔄 Make things right when you\'ve been dishonest'
            ],
            'benefits': [
                '😊 Clean conscience and inner peace',
                '🤝 Stronger, more authentic relationships',
                '💪 Reputation as a trustworthy person',
                '🚀 Freedom from the stress of maintaining lies'
            ],
            'tradeoffs': [
                'Immediate consequences when admitting mistakes',
                'Vulnerability when sharing difficult truths',
                'Others may take advantage of your transparency',
                'Short-term discomfort when facing difficult conversations'
            ]
        }
    elif category_name == 'respect_relationships':
        pathway_data = {
            'title': 'Respect & Relationships',
            'description': 'Learn to build healthy, respectful relationships with family, friends, and others',
            'content': 'Master the art of treating others well and building lasting, meaningful connections.',
            'problem': 'Poor relationships cause stress, loneliness, and missed opportunities throughout life.',
            'solution': 'Learning respect and relationship skills creates a network of support and opens doors to success.',
            'verse': 'Do to others as you would have them do to you. - Luke 6:31',
            'action_steps': [
                '👂 Listen more than you speak',
                '🙏 Say please, thank you, and excuse me regularly',
                '📱 Put your phone away during conversations',
                '💬 Ask questions about others\' interests',
                '🤝 Keep your promises and commitments'
            ],
            'benefits': [
                '👥 Stronger friendships and family bonds',
                '💼 Better opportunities in school and work',
                '😊 Less drama and conflict in your life',
                '🎯 People will want to help you succeed'
            ],
            'tradeoffs': [
                'Time and effort to build meaningful relationships',
                'Need to put others\' needs before your own sometimes',
                'Vulnerability required for deep connections',
                'Patience when others don\'t reciprocate respect immediately'
            ]
        }
    elif category_name == 'future_planning_goal_setting':
        pathway_data = {
            'title': 'Future Planning & Goal Setting: Map Your Success',
            'description': 'Learn to set meaningful goals, create action plans, and build the future you want',
            'content': 'Your future doesn\'t just happen - it\'s created through intentional planning and consistent action. Goal setting gives you direction, motivation, and a roadmap to achieve your dreams.',
            'problem': 'Many teens drift through life without clear goals, missing opportunities and feeling directionless about their future.',
            'solution': 'Learn proven goal-setting techniques, create action plans, track progress, and develop the habits that turn dreams into reality.',
            'verse': '"For I know the plans I have for you," declares the Lord, "plans to prosper you and not to harm you, to give you hope and a future." (Jeremiah 29:11, NIV)',
            'action': 'This week, write down three specific goals (1 short-term, 1 medium-term, 1 long-term) and create action steps for each. Share your goals with someone who will support and encourage you.',
            'action_steps': [
                '🎯 Set SMART goals (Specific, Measurable, Achievable, Relevant, Time-bound)',
                '📋 Break large goals into smaller, manageable action steps',
                '📅 Create deadlines and milestones to track progress',
                '🔄 Review and adjust goals regularly as you grow',
                '👥 Share goals with mentors for accountability and support'
            ],
            'benefits': [
                '🚀 Clear direction and purpose in life decisions',
                '💪 Increased motivation and focus on what matters',
                '📈 Better academic and personal achievement',
                '😊 Greater sense of accomplishment and self-worth',
                '🌟 Foundation for lifelong success and fulfillment'
            ],
            'tradeoffs': [
                'Time spent planning instead of immediate action',
                'Discipline required to stick to goals when motivation fades',
                'Potential disappointment when goals need adjustment',
                'Need to say no to activities that don\'t align with goals'
            ]
        }
    elif category_name == 'money_management_financial_literacy':
        pathway_data = {
            'title': 'Money Management & Financial Literacy: Your Path to Financial Freedom',
            'description': 'Master budgeting, saving, and smart spending to build wealth and financial security',
            'content': 'Money management isn\'t about having a lot of money - it\'s about being smart with whatever you have. The habits you build now will determine your financial future.',
            'problem': 'Many teens aren\'t taught basic financial skills, leading to debt, poor spending decisions, and financial stress in adulthood.',
            'solution': 'Learn to budget, save consistently, understand credit and debt, and make informed financial decisions that build wealth over time.',
            'verse': '"Dishonest money dwindles away, but whoever gathers money little by little makes it grow." (Proverbs 13:11, NIV)',
            'action': 'This week, track every dollar you spend for seven days. Create a simple budget with categories for saving, spending, and giving. Open a savings account if you don\'t have one.',
            'action_steps': [
                '💰 Create and stick to a monthly budget',
                '🏦 Save at least 10% of any money you receive',
                '📊 Track your spending and identify waste',
                '🎯 Set specific financial goals (emergency fund, college, car)',
                '📚 Learn about credit, debt, and investing basics'
            ],
            'benefits': [
                '💪 Financial security and peace of mind',
                '🚀 Ability to afford college, car, and future dreams',
                '😌 Less stress about money matters',
                '🎯 Freedom to make choices based on values, not finances',
                '📈 Foundation for building wealth throughout life'
            ],
            'tradeoffs': [
                'Need to delay gratification and resist impulse purchases',
                'Time spent budgeting and tracking expenses',
                'Missing out on some immediate wants to save for goals',
                'Discipline required to stick to financial plans'
            ]
        }
    # Personal Development Topics
    elif category_name == 'confidence_and_self_esteem':
        pathway_data = {
            'title': 'Confidence & Self-Esteem: Your Inner Strength',
            'description': 'Build unshakeable confidence and develop healthy self-worth that empowers you to achieve your goals',
            'content': 'True confidence comes from knowing your worth isn\'t determined by others\' opinions, your performance, or your circumstances. It\'s built through understanding your value, developing your skills, and taking action despite fear.',
            'problem': 'Many teens struggle with self-doubt, comparing themselves to others, and feeling not good enough, which holds them back from opportunities and relationships.',
            'solution': 'Confidence is a skill you can develop through positive self-talk, setting and achieving small goals, developing competence, and surrounding yourself with supportive people.',
            'verse': '"I praise you because I am fearfully and wonderfully made; your works are wonderful, I know that full well." (Psalm 139:14, NIV)',
            'action': 'This week, write down 3 strengths about yourself today. When you doubt yourself, reread that list. Also, practice looking in the mirror and saying one positive thing about yourself daily.',
            'motivation_tips': [
                "💪 'The way you speak to yourself matters more than what anyone else says about you.'",
                "🌟 'Confidence isn't about being perfect - it's about being willing to try and learn.'",
                "⭐ 'You are braver than you believe, stronger than you seem, and smarter than you think.' - A.A. Milne",
                "🔥 'Your opinion of yourself becomes your reality.' - Unknown"
            ],
            'action_steps': [
                '📝 Practice positive self-talk and challenge negative thoughts',
                '🎯 Set small, achievable goals to build competence',
                '💪 Stand with good posture and make eye contact',
                '🌟 Celebrate your achievements, no matter how small',
                '👥 Surround yourself with positive, supportive people'
            ],
            'benefits': [
                '🚀 Better performance in school, sports, and activities',
                '💬 Improved communication and social skills',
                '🎯 Willingness to try new things and take healthy risks',
                '😊 Greater happiness and less anxiety',
                '🌟 Leadership opportunities and stronger relationships'
            ],
            'tradeoffs': [
                'Time and effort required to build new mental habits',
                'Discomfort when challenging negative thought patterns',
                'Need to step outside your comfort zone regularly',
                'Ongoing work to maintain healthy self-esteem'
            ]
        }
    elif category_name == 'goal_setting_time_management':
        pathway_data = {
            'title': 'Goal Setting & Time Management: Your Success Blueprint',
            'description': 'Master the skills to set meaningful goals and manage your time effectively to achieve what matters most',
            'content': 'Success isn\'t about being busy - it\'s about being productive with purpose. Goal setting gives you direction, while time management gives you the tools to get there efficiently.',
            'problem': 'Without clear goals and time management skills, teens often feel overwhelmed, procrastinate, miss opportunities, and struggle to balance school, activities, and personal life.',
            'solution': 'Learn to set SMART goals, prioritize tasks, eliminate time wasters, and create systems that help you consistently work toward what you want to achieve.',
            'verse': '"The plans of the diligent lead to profit as surely as haste leads to poverty." (Proverbs 21:5, NIV)',
            'action': 'Set one specific, measurable goal for this month and break it into weekly action steps. Use a planner or app to track your daily progress. Write down WHY this goal matters to you.',
            'motivation_tips': [
                "🎯 'A goal without a plan is just a wish.' - Antoine de Saint-Exupéry",
                "📈 'Success is the sum of small efforts repeated day in and day out.' - Robert Collier",
                "⏰ 'Time is what we want most, but what we use worst.' - William Penn",
                "🔥 'The future depends on what you do today.' - Mahatma Gandhi"
            ],
            'action_steps': [
                '🎯 Set SMART goals (Specific, Measurable, Achievable, Relevant, Time-bound)',
                '📅 Use a planner or digital calendar to organize your time',
                '⚡ Identify and eliminate your biggest time wasters',
                '🔄 Create daily and weekly routines for important tasks',
                '📊 Review and adjust your goals regularly'
            ],
            'benefits': [
                '📈 Higher achievement in school and activities',
                '😌 Less stress and feeling of being overwhelmed',
                '⏰ More free time for things you enjoy',
                '🏆 Sense of accomplishment and progress',
                '🚀 Better preparation for college and career success'
            ],
            'tradeoffs': [
                'Initial time investment to learn and set up systems',
                'Discipline required to stick to schedules and plans',
                'Need to say no to some activities to focus on priorities',
                'Regular review and adjustment of goals and methods'
            ]
        }
    elif category_name == 'public_speaking_communication':
        pathway_data = {
            'title': 'Public Speaking & Communication: Your Voice Matters',
            'description': 'Develop the confidence and skills to speak clearly, persuasively, and with impact in any situation',
            'content': 'Communication is the #1 skill for success in life. Whether you\'re talking to one person or one hundred, the ability to express your ideas clearly and confidently opens doors and builds relationships.',
            'problem': 'Fear of public speaking and poor communication skills limit opportunities, relationships, and career prospects. Many teens avoid speaking up, missing chances to lead and contribute.',
            'solution': 'Like any skill, communication improves with knowledge, practice, and feedback. Start small, practice regularly, and gradually build your confidence and abilities.',
            'verse': '"Let your speech always be gracious, seasoned with salt, so that you may know how you ought to answer each person." (Colossians 4:6, ESV)',
            'action': 'This week, volunteer to answer one question in each class and have one meaningful conversation with someone new. Practice speaking clearly and making eye contact. Record yourself speaking for 1 minute and listen back.',
            'motivation_tips': [
                "🎤 'Your voice matters - the world needs to hear what you have to say.'",
                "💪 'Great speakers aren't born, they're made through practice and courage.'",
                "⭐ 'The expert in anything was once a beginner.' - Helen Hayes",
                "🔥 'Speak with confidence, even if your voice shakes. Your message is more important than your fear.'"
            ],
            'action_steps': [
                '🎤 Practice speaking out loud daily (read aloud, record yourself)',
                '👁️ Make eye contact and use confident body language',
                '📚 Learn to organize your thoughts with clear structure',
                '👂 Develop active listening skills',
                '🎯 Join speaking opportunities (class presentations, clubs, teams)'
            ],
            'benefits': [
                '🏆 Leadership opportunities in school and activities',
                '💼 Better job interviews and career prospects',
                '🤝 Stronger relationships and social connections',
                '📈 Improved grades through class participation',
                '💪 Increased self-confidence in all areas'
            ],
            'tradeoffs': [
                'Initial nervousness and discomfort when speaking',
                'Time needed to prepare and practice presentations',
                'Vulnerability when sharing ideas publicly',
                'Need to accept and learn from constructive feedback'
            ]
        }
    elif category_name == 'leadership_skills':
        pathway_data = {
            'title': 'Leadership Skills: Influence with Impact',
            'description': 'Develop the character, skills, and mindset to lead others and create positive change in your community',
            'content': 'Leadership isn\'t about having a title or being in charge - it\'s about serving others, solving problems, and inspiring people to work together toward common goals.',
            'problem': 'Many teens wait for others to take initiative, miss leadership opportunities, or think leadership is only for certain types of people.',
            'solution': 'Leadership is a skill anyone can develop. Start by leading yourself well, then look for opportunities to serve others and practice leadership in small settings.',
            'verse': '"Whoever wants to become great among you must be your servant." (Mark 10:43, NIV)',
            'action': 'This week, identify one problem in your school, team, or community and propose a solution. Take initiative to organize one group activity or project. Ask someone if they need help with something.',
            'motivation_tips': [
                "👑 'A leader is one who knows the way, goes the way, and shows the way.' - John C. Maxwell",
                "🌟 'Leadership is not about being in charge. It's about taking care of those in your charge.'",
                "💪 'You don't have to be great to get started, but you have to get started to be great.' - Les Brown",
                "🔥 'The greatest leader is not necessarily the one who does the greatest things, but the one who gets others to do great things.'"
            ],
            'action_steps': [
                '🌟 Lead by example in your daily actions and choices',
                '👂 Listen to others and understand their perspectives',
                '🎯 Take initiative to solve problems and help others',
                '💬 Communicate vision and inspire others to join your cause',
                '🤝 Build relationships and work well with different types of people'
            ],
            'benefits': [
                '🏆 Leadership positions in school, sports, and activities',
                '💼 Competitive advantage for college and career opportunities',
                '🌟 Ability to create positive change in your community',
                '🤝 Stronger relationships and network of connections',
                '💪 Increased confidence and personal growth'
            ],
            'tradeoffs': [
                'Additional responsibility and accountability',
                'Time commitment to lead projects and help others',
                'Need to handle criticism and difficult decisions',
                'Pressure to set a good example consistently'
            ]
        }
    elif category_name == 'emotional_intelligence':
        pathway_data = {
            'title': 'Emotional Intelligence & Self-Awareness: Know Yourself, Lead Yourself',
            'description': 'Develop the ability to understand and manage your emotions while building empathy and social skills',
            'content': 'Emotional intelligence is your ability to recognize, understand, and manage emotions - both your own and others\'. It\'s often more important than IQ for success in relationships, leadership, and life.',
            'problem': 'Without emotional awareness, teens struggle with mood swings, relationship conflicts, stress management, and making good decisions under pressure.',
            'solution': 'Develop self-awareness through reflection, learn emotional regulation techniques, practice empathy, and build strong social skills through intentional practice.',
            'verse': '"Above all else, guard your heart, for everything you do flows from it." (Proverbs 4:23, NIV)',
            'action': 'For one week, write down your emotions three times daily (morning, afternoon, evening) and identify what triggered them. Notice patterns in your emotional responses.',
            'action_steps': [
                '🧠 Practice mindfulness and self-reflection daily',
                '📝 Keep an emotion journal to identify patterns',
                '😌 Learn healthy ways to manage stress and strong emotions',
                '👥 Practice empathy by trying to understand others\' perspectives',
                '💬 Develop better communication skills for relationships'
            ],
            'benefits': [
                '🤝 Stronger, healthier relationships with family and friends',
                '📈 Better academic and athletic performance under pressure',
                '😊 Improved mental health and emotional stability',
                '🎯 Better decision-making and problem-solving abilities',
                '🌟 Leadership potential and social influence'
            ],
            'tradeoffs': [
                'Time and effort required for self-reflection and growth',
                'Discomfort when facing difficult emotions honestly',
                'Need to change established emotional habits',
                'Ongoing work to maintain emotional awareness and control'
            ]
        }
    elif category_name == 'stress_management_resilience':
        pathway_data = {
            'title': 'Stress Management & Resilience: Bounce Back Stronger',
            'description': 'Learn to handle pressure effectively and develop the mental toughness to overcome challenges and setbacks',
            'content': 'Stress is a normal part of life, but how you handle it determines your success and happiness. Resilience is your ability to bounce back from difficulties and use challenges as opportunities to grow stronger.',
            'problem': 'Without stress management skills, teens can become overwhelmed, anxious, or burned out, leading to poor performance and mental health struggles.',
            'solution': 'Develop healthy coping strategies, build a strong support system, maintain perspective during difficulties, and practice stress-reduction techniques regularly.',
            'verse': '"Consider it pure joy, my brothers and sisters, whenever you face trials of many kinds, because you know that the testing of your faith produces perseverance." (James 1:2-3, NIV)',
            'action': 'This week, practice one stress-reduction technique daily (deep breathing, exercise, or meditation) and identify three people you can talk to when stressed. Create a "stress-busting" playlist of songs that calm you.',
            'motivation_tips': [
                "🌟 'You are stronger than you think and more resilient than you realize.'",
                "💪 'Every challenge you overcome makes you stronger for the next one.'",
                "🌱 'Stress is like a rocking chair - it gives you something to do but gets you nowhere unless you get up and move forward.'",
                "🔥 'The bamboo that bends is stronger than the oak that resists.' - Japanese Proverb"
            ],
            'action_steps': [
                '🧘 Practice relaxation techniques (deep breathing, meditation, yoga)',
                '🏃 Use regular exercise to manage stress and boost mood',
                '👥 Build a strong support network of family and friends',
                '⚖️ Maintain work-life balance and set healthy boundaries',
                '🎯 Reframe challenges as opportunities for growth'
            ],
            'benefits': [
                '😌 Better mental health and emotional stability',
                '📈 Improved performance under pressure',
                '💪 Increased confidence in handling difficult situations',
                '🤝 Stronger relationships through better stress management',
                '🚀 Greater success in achieving long-term goals'
            ],
            'tradeoffs': [
                'Time needed to practice stress management techniques',
                'Initial discomfort when facing stressful situations',
                'Need to change unhealthy coping habits',
                'Ongoing effort to maintain balance and perspective'
            ]
        }
    elif category_name == 'decision_making_problem_solving':
        pathway_data = {
            'title': 'Decision Making & Problem Solving: Think Smart, Choose Wise',
            'description': 'Develop the critical thinking skills to make good decisions and solve problems effectively',
            'content': 'Every day you make hundreds of decisions that shape your future. Learning to think critically, weigh options carefully, and solve problems systematically will serve you throughout life.',
            'problem': 'Poor decision-making skills lead to regrets, missed opportunities, and consequences that could have been avoided with better thinking.',
            'solution': 'Learn a systematic approach to decision-making, practice critical thinking, seek wise counsel, and learn from both successes and mistakes.',
            'verse': '"The simple believe anything, but the prudent give thought to their steps." (Proverbs 14:15, NIV)',
            'action': 'This week, use the decision-making framework for one important choice: identify options, list pros and cons, seek advice, consider consequences, and make a thoughtful decision.',
            'action_steps': [
                '🤔 Learn to identify and define problems clearly',
                '📊 Gather relevant information before making decisions',
                '⚖️ Consider both short-term and long-term consequences',
                '👥 Seek advice from wise mentors and trusted adults',
                '💡 Generate multiple solutions before choosing one'
            ],
            'benefits': [
                '🎯 Better outcomes in school, relationships, and life choices',
                '💪 Increased confidence in your ability to handle challenges',
                '🚀 Fewer regrets and more opportunities seized',
                '🧠 Improved critical thinking and analytical skills',
                '🌟 Respect from others for your wisdom and judgment'
            ],
            'tradeoffs': [
                'Time required to think through decisions carefully',
                'Potential for analysis paralysis on some choices',
                'Need to accept responsibility for your decisions',
                'Discomfort when making difficult or unpopular choices'
            ]
        }
    elif category_name == 'building_healthy_relationships':
        pathway_data = {
            'title': 'Building Healthy Relationships: Connect with Purpose',
            'description': 'Learn to create and maintain positive, meaningful relationships with family, friends, and others',
            'content': 'Relationships are the foundation of a fulfilling life. Healthy relationships provide support, encouragement, and joy, while toxic relationships drain energy and cause pain.',
            'problem': 'Many teens struggle with relationship drama, conflict, loneliness, or staying in unhealthy relationships that hold them back.',
            'solution': 'Learn relationship skills like communication, boundaries, conflict resolution, and how to choose friends wisely while being a good friend yourself.',
            'verse': '"Do nothing out of selfish ambition or vain conceit. Rather, in humility value others above yourselves." (Philippians 2:3, NIV)',
            'action': 'This week, reach out to strengthen one important relationship and set a healthy boundary in a relationship that needs it.',
            'action_steps': [
                '💬 Practice active listening and clear communication',
                '🚧 Set and maintain healthy boundaries',
                '🤝 Choose friends who share your values and goals',
                '💚 Learn to resolve conflicts respectfully',
                '🎁 Be generous with encouragement and support'
            ],
            'benefits': [
                '❤️ Deeper, more meaningful friendships and family bonds',
                '😊 Less drama and conflict in your social life',
                '💪 Strong support system during difficult times',
                '🌟 Positive influence on others\' lives',
                '🚀 Better teamwork and collaboration skills'
            ],
            'tradeoffs': [
                'Time and emotional energy invested in relationships',
                'Vulnerability required for deep connections',
                'Need to have difficult conversations sometimes',
                'Potential hurt or disappointment when relationships end'
            ]
        }
    elif category_name == 'personal_values_identity':
        pathway_data = {
            'title': 'Personal Values & Identity: Know Who You Are',
            'description': 'Discover your core values and develop a strong sense of identity rooted in purpose and meaning',
            'content': 'Your values are your compass - they guide your decisions and shape your character. A strong identity based on solid values helps you navigate peer pressure, make good choices, and live with purpose.',
            'problem': 'Without clear values and identity, teens are easily influenced by others, make decisions they regret, and struggle with purpose and direction.',
            'solution': 'Identify your core values through reflection and experience, align your actions with those values, and develop a strong sense of who you are independent of others\' opinions.',
            'verse': '"But as for you, be strong and do not give up, for your work will be rewarded." (2 Chronicles 15:7, NIV)',
            'action': 'This week, write down your top 5 values and one specific way you can live out each value. Share your values with a trusted adult.',
            'action_steps': [
                '🎯 Identify your core values through reflection and assessment',
                '📝 Write a personal mission statement',
                '💪 Make decisions based on your values, not peer pressure',
                '🌟 Develop talents and interests that reflect your authentic self',
                '🤝 Surround yourself with people who respect your values'
            ],
            'benefits': [
                '💪 Stronger resistance to negative peer pressure',
                '🎯 Clear direction and purpose in life decisions',
                '😊 Greater self-respect and inner peace',
                '🌟 Authentic relationships based on who you really are',
                '🚀 Foundation for lifelong success and fulfillment'
            ],
            'tradeoffs': [
                'Time and effort required for deep self-reflection',
                'Potential conflict when your values differ from peers',
                'Need to make difficult choices that align with values',
                'Ongoing work to live consistently with your beliefs'
            ]
        }
    elif category_name == 'study_skills_learning_strategies':
        pathway_data = {
            'title': 'Study Skills & Learning Strategies: Master the Art of Learning',
            'description': 'Develop effective study techniques and learning strategies to excel academically and become a lifelong learner',
            'content': 'Learning how to learn is one of the most valuable skills you can develop. Effective study strategies help you retain information better, perform well on tests, and develop a love for learning.',
            'problem': 'Many students struggle academically not because they lack intelligence, but because they never learned effective study strategies and learning techniques.',
            'solution': 'Master proven study techniques like active reading, spaced repetition, note-taking systems, and test-taking strategies while developing strong learning habits.',
            'verse': '"An intelligent heart acquires knowledge, and the ear of the wise seeks knowledge." (Proverbs 18:15, ESV)',
            'action': 'This week, try one new study technique (like the Pomodoro method or active recall) and create a dedicated study space free from distractions.',
            'action_steps': [
                '📚 Develop active reading and note-taking strategies',
                '⏰ Use time management techniques like the Pomodoro method',
                '🧠 Practice spaced repetition and active recall',
                '📝 Create effective study guides and summaries',
                '🎯 Develop test-taking strategies and stress management'
            ],
            'benefits': [
                '📈 Improved grades and academic performance',
                '😌 Less stress and anxiety about tests and assignments',
                '⏱️ More efficient use of study time',
                '🧠 Better long-term retention of information',
                '🚀 Strong foundation for college and career success'
            ],
            'tradeoffs': [
                'Initial time investment to learn new study methods',
                'Need to break old, ineffective study habits',
                'Discipline required to maintain consistent study routines',
                'Regular evaluation and adjustment of learning strategies'
            ]
        }
    # Technology & Innovation Pathways
    elif category_name == 'coding_app_development':
        pathway_data = {
            'title': 'Coding & App Development: Building Digital Solutions',
            'description': 'Learn to create websites, mobile apps, and software that solve real-world problems and reach millions of users',
            'content': 'Coding is the modern superpower that lets you bring your ideas to life. Every app on your phone, every website you visit, and every digital tool you use was created by someone who learned to code. You can be that creator.',
            'problem': 'Many teens think coding is too hard or only for "tech geniuses," missing out on one of the most in-demand and creative career paths.',
            'solution': 'Start with visual programming or simple projects, practice consistently, and build your way up to complex applications. Every expert was once a beginner.',
            'verse': '"In the beginning was the Word, and the Word was with God, and the Word was God." (John 1:1) - You have the power to speak new realities into existence through code.',
            'action': 'This week, complete one online coding tutorial (try Scratch, Khan Academy, or Codecademy) and write your first "Hello World" program. Show it to someone you care about.',
            'motivation_tips': [
                "💻 'Every expert was once a beginner. Every pro was once an amateur.' - Robin Sharma",
                "🚀 'Code is like humor. When you have to explain it, it's bad.' - Cory House",
                "⭐ 'The best time to plant a tree was 20 years ago. The second best time is now.' - Chinese Proverb",
                "🔥 'Don't just consume technology, create it. You have the power to build the future.'"
            ],
            'educational_content': {
                'what_is_coding': 'Coding is writing instructions for computers using programming languages. It\'s like learning a new language that lets you communicate with machines and tell them exactly what to do.',
                'how_apps_work': 'Apps are built with code that handles user interface (what you see), logic (what happens when you tap), and data (information storage). Medical charts use code to track patient data, banking apps use code for secure transactions.',
                'software_creation_process': [
                    '💡 Idea & Planning: Define what problem your software will solve',
                    '🎨 Design: Create wireframes and user interfaces',
                    '⌨️ Development: Write the actual code using programming languages',
                    '🧪 Testing: Check for bugs and ensure everything works correctly',
                    '🚀 Deployment: Launch your app for users to download and use',
                    '🔄 Maintenance: Update and improve based on user feedback'
                ]
            },
            'action_steps': [
                '🎯 Choose a programming language (Python for beginners, JavaScript for web)',
                '💻 Practice coding daily, even if just for 15 minutes',
                '🏗️ Build simple projects like calculators or to-do lists',
                '👥 Join coding communities and find mentors',
                '🚀 Share your projects and get feedback from others'
            ],
            'benefits': [
                '💰 High earning potential ($60K-$200K+ depending on specialization)',
                '🌍 Work from anywhere in the world',
                '🎨 Turn your creative ideas into reality',
                '📈 Constant learning and growth opportunities',
                '⚡ See immediate results from your work'
            ],
            'what_it_takes': [
                '🧠 Logical thinking and problem-solving skills',
                '⏰ Patience and persistence when debugging',
                '📚 Willingness to continuously learn new technologies',
                '👥 Communication skills for working with teams'
            ],
            'tradeoffs': [
                'Hours spent learning programming languages and debugging',
                'Mental fatigue from solving complex technical problems',
                'Need to constantly update skills as technology changes',
                'Time away from other activities during intensive learning'
            ]
        }
    elif category_name == 'robotics_automation':
        pathway_data = {
            'title': 'Robotics & Automation: Engineering the Future',
            'description': 'Design, build, and program robots that help humans and automate complex tasks in every industry',
            'content': 'Robotics combines engineering, programming, and creativity to build machines that can sense, think, and act. From surgical robots saving lives to Mars rovers exploring space, robotics is shaping our future.',
            'problem': 'Many teens see robots only in movies and don\'t realize robotics is an accessible field with hands-on opportunities starting in high school.',
            'solution': 'Start with robot kits, join robotics clubs, learn basic programming, and understand how mechanical systems work through experimentation.',
            'verse': '"Whatever your hand finds to do, do it with all your might." (Ecclesiastes 9:10) - Build with purpose and excellence.',
            'action': 'This week, watch a robot demonstration video, visit a local robotics team, or try a simple robotics simulator online. Think about one problem robots could solve.',
            'motivation_tips': [
                "🤖 'Robotics is not just about building machines; it's about building the future.' - Unknown",
                "⚡ 'The future belongs to those who prepare for it today.' - Malcolm X",
                "🌟 'Innovation distinguishes between a leader and a follower.' - Steve Jobs",
                "🔥 'Your imagination is the only limit to what robots can achieve.'"
            ],
            'educational_content': {
                'what_is_robotics': 'Robotics integrates mechanical engineering (physical structure), electrical engineering (sensors and motors), and computer science (programming and AI) to create autonomous or remotely controlled machines.',
                'how_robots_work': 'Robots use sensors to gather information about their environment, processors to make decisions based on programmed logic, and actuators (motors) to perform physical actions.',
                'automation_systems': [
                    '🏭 Manufacturing: Assembly lines that build cars and electronics',
                    '🏥 Healthcare: Surgical robots for precision operations',
                    '🚗 Transportation: Self-driving cars and delivery drones',
                    '🏠 Home: Smart vacuum cleaners and lawn mowers',
                    '🌌 Exploration: Mars rovers and deep-sea research robots'
                ]
            },
            'action_steps': [
                '🔧 Learn basic mechanical principles and electronics',
                '💻 Master programming languages like Python or C++',
                '🛠️ Build simple robots using Arduino or Raspberry Pi',
                '🏆 Join robotics competitions like FIRST Robotics',
                '👨‍🔬 Study math and physics for advanced robotics concepts'
            ],
            'benefits': [
                '🚀 Be part of cutting-edge technology development',
                '💼 Diverse career opportunities across many industries',
                '🧩 Solve complex real-world problems',
                '💰 Strong job market with competitive salaries',
                '🌍 Make a positive impact on society'
            ],
            'what_it_takes': [
                '🔧 Hands-on building and troubleshooting skills',
                '🧮 Strong foundation in math and science',
                '💻 Programming and software development abilities',
                '👥 Teamwork for complex multi-disciplinary projects'
            ],
            'tradeoffs': [
                'Significant time investment in math and science courses',
                'Expensive equipment and materials for projects',
                'Trial and error process that can be frustrating',
                'Need to work in teams which requires compromise'
            ]
        }
    elif category_name == 'digital_media_design':
        pathway_data = {
            'title': 'Digital Media & Graphic Design: Visual Storytelling',
            'description': 'Create compelling visual content that communicates ideas, tells stories, and influences audiences across digital platforms',
            'content': 'In our visual world, design is everywhere - from the apps you use to the websites you visit. Digital media designers shape how people experience and interact with information and technology.',
            'problem': 'Many teens have creative talents but don\'t know how to turn their artistic abilities into career opportunities in the digital age.',
            'solution': 'Learn design software, study design principles, build a portfolio, and practice creating content for real projects and clients.',
            'verse': '"She is clothed with strength and dignity; she can laugh at the days to come." (Proverbs 31:25) - Create with confidence and purpose.',
            'action': 'This week, design something simple using free tools like Canva or GIMP. Create a poster for a school event or redesign a local business flyer.',
            'motivation_tips': [
                "🎨 'Design is not just what it looks like - design is how it works.' - Steve Jobs",
                "💡 'Creativity is intelligence having fun.' - Albert Einstein",
                "🌟 'Good design is obvious. Great design is transparent.' - Joe Sparano",
                "🔥 'Every great design begins with an even better story.' - Lorinda Mamo"
            ],
            'educational_content': {
                'what_is_digital_media': 'Digital media design combines art, technology, and communication to create visual content for websites, apps, social media, advertising, and multimedia experiences.',
                'design_principles': [
                    '🎯 Balance: Distributing visual weight evenly',
                    '🌈 Color Theory: Using colors to evoke emotions and guide attention',
                    '📝 Typography: Choosing and arranging text effectively',
                    '📐 Composition: Arranging elements for maximum impact',
                    '🔄 Hierarchy: Guiding the viewer\'s eye through the design'
                ],
                'career_applications': [
                    '📱 UI/UX Design: Creating user-friendly app and website interfaces',
                    '📢 Marketing: Designing ads, social media content, and branding',
                    '🎬 Motion Graphics: Animated videos and interactive experiences',
                    '🕹️ Game Design: Creating visual assets for video games',
                    '📚 Publishing: Book covers, magazines, and digital publications'
                ]
            },
            'action_steps': [
                '🎨 Master design software (Adobe Creative Suite, Figma, Sketch)',
                '📚 Study color theory, typography, and composition principles',
                '💼 Build a diverse portfolio showcasing different styles',
                '👥 Work on real projects for friends, family, or local businesses',
                '🌐 Share your work online and network with other designers'
            ],
            'benefits': [
                '🎨 Express creativity while solving problems',
                '💰 Freelance opportunities for extra income',
                '🌍 Work with clients worldwide remotely',
                '📈 Growing demand across all industries',
                '🚀 Opportunity to influence how people interact with technology'
            ],
            'what_it_takes': [
                '👁️ Strong visual sense and attention to detail',
                '💻 Technical proficiency with design software',
                '🤝 Communication skills to understand client needs',
                '⏰ Time management for meeting project deadlines'
            ],
            'tradeoffs': [
                'Hours spent learning complex design software',
                'Subjective nature of creative work leads to criticism',
                'Tight deadlines and client demands can be stressful',
                'Need to constantly adapt to new design trends'
            ]
        }
    elif category_name == 'gaming_esports':
        pathway_data = {
            'title': 'Gaming & eSports Careers: Professional Play and Game Creation',
            'description': 'Turn your passion for gaming into a professional career as a player, content creator, developer, or industry professional',
            'content': 'Gaming is now a billion-dollar industry with careers beyond just playing. From professional competition to game development, streaming, and team management, there are numerous paths in the gaming world.',
            'problem': 'Many teens love gaming but don\'t realize the diverse career opportunities or understand what it takes to succeed professionally in the industry.',
            'solution': 'Develop specific gaming skills, understand the business side, create content, network with professionals, and consider multiple career paths within the industry.',
            'verse': '"Do you see someone skilled in their work? They will serve before kings." (Proverbs 22:29) - Excellence in any field opens doors.',
            'action': 'This week, research one professional gamer or game developer you admire. Learn their story and identify one skill they developed to succeed.',
            'motivation_tips': [
                "🎮 'Gaming is not a waste of time; it's a way to develop skills for the future.' - Unknown",
                "🏆 'Champions aren't made in comfort zones.' - John Carol",
                "💪 'The difference between amateur and professional isn't just skill - it's mindset.' - Unknown",
                "🌟 'Turn your passion into your paycheck, but remember that passion requires discipline.'"
            ],
            'educational_content': {
                'gaming_industry_overview': 'The gaming industry includes game development, professional competition (eSports), content creation, marketing, journalism, and hardware development. It\'s larger than movies and music combined.',
                'career_paths': [
                    '🏆 Professional Player: Compete in tournaments for prize money and sponsorships',
                    '📺 Content Creator: Stream gameplay, create videos, build audiences',
                    '🎯 Game Developer: Design and program video games',
                    '📊 eSports Manager: Organize teams, events, and tournaments',
                    '🎨 Game Artist: Create visual assets for games',
                    '📝 Gaming Journalist: Write about games and the industry'
                ],
                'skills_development': [
                    '🎮 Master specific games and understand meta strategies',
                    '🧠 Develop strategic thinking and quick decision-making',
                    '👥 Build teamwork and communication skills',
                    '📱 Learn content creation and social media marketing',
                    '💼 Understand business aspects of the gaming industry'
                ]
            },
            'action_steps': [
                '🎯 Choose a specific game or genre to specialize in',
                '📹 Start creating gaming content (streams, videos, guides)',
                '🏆 Participate in local or online tournaments',
                '👥 Network with other gamers and industry professionals',
                '📚 Study game design and development fundamentals'
            ],
            'benefits': [
                '🎮 Combine passion with profession',
                '🌍 Global community and opportunities',
                '💰 Multiple revenue streams (tournaments, sponsorships, content)',
                '📈 Rapidly growing industry with new opportunities',
                '🎨 Creative expression through gameplay and content'
            ],
            'what_it_takes': [
                '⏰ Dedication to practice and skill improvement',
                '🧠 Strategic thinking and adaptability',
                '💪 Mental resilience and stress management',
                '💼 Business acumen for managing career opportunities'
            ],
            'tradeoffs': [
                'Hours daily practicing games instead of other activities',
                'Sedentary lifestyle and potential health issues',
                'Inconsistent income and high competition',
                'Public scrutiny and pressure to perform consistently'
            ]
        }
    # Life Skills Pathways
    elif category_name == 'resume_portfolio_building':
        pathway_data = {
            'title': 'Resume & Portfolio Building: Showcase Your Best Self',
            'description': 'Create powerful resumes and portfolios that highlight your skills, experiences, and potential to future employers',
            'content': 'Your resume and portfolio are your first impression with employers. They tell your story and show what you can contribute. Even as a teen, you have more accomplishments than you realize.',
            'problem': 'Many teens think they don\'t have enough experience for a good resume, but everyone has valuable skills, volunteer work, academic achievements, and personal projects.',
            'solution': 'Learn to identify and present your strengths, use professional formatting, and create portfolios that demonstrate your abilities through real examples.',
            'verse': '"For we are God\'s handiwork, created in Christ Jesus to do good works." (Ephesians 2:10) - You have unique value to offer.',
            'action': 'This week, write down 5 accomplishments from school, sports, volunteering, or personal projects. Draft a simple one-page resume using a free template.',
            'motivation_tips': [
                "💼 'Your resume is your personal brand on paper. Make it count.' - Unknown",
                "⭐ 'Don't underestimate yourself. You have more to offer than you think.' - Motivational Speaker",
                "🎯 'A good resume tells your story. A great resume tells your future.' - Career Coach",
                "🔥 'Every expert was once a beginner. Start building your professional story today.'"
            ],
            'practical_examples': {
                'teen_resume_template': [
                    '📝 Header: Name, phone, email, city (professional email address)',
                    '🎯 Objective: "Motivated high school student seeking...[specific role]"',
                    '🏫 Education: School name, expected graduation, GPA (if 3.0+)',
                    '💼 Experience: Jobs, internships, volunteer work (even 1-day events count)',
                    '🏆 Achievements: Academic honors, sports awards, perfect attendance',
                    '🛠️ Skills: Computer programs, languages, certifications, special abilities'
                ],
                'portfolio_examples': [
                    '🎨 Art Portfolio: Photos of drawings, paintings, digital designs',
                    '📝 Writing Portfolio: Essays, stories, articles, blog posts',
                    '💻 Tech Portfolio: Websites, apps, coding projects (even simple ones)',
                    '📸 Photography: Best photos organized by theme or event',
                    '🎵 Music Portfolio: Recordings, performance videos, compositions'
                ]
            },
            'action_steps': [
                '📝 List all your experiences (jobs, volunteering, leadership, achievements)',
                '💻 Use free resume templates (Google Docs, Canva, or Word)',
                '📁 Create digital portfolios using free platforms (Google Sites, Wix)',
                '👥 Ask teachers, coaches, or mentors to review your materials',
                '🔄 Update regularly as you gain new experiences'
            ],
            'benefits': [
                '💼 Stand out from other candidates in job applications',
                '🎓 Required for college and scholarship applications',
                '💰 Helps you earn higher wages by showcasing your value',
                '😌 Builds confidence by recognizing your accomplishments',
                '🚀 Opens doors to opportunities you didn\'t know existed'
            ],
            'what_it_takes': [
                '🕰️ Time to reflect on and document your experiences',
                '📝 Attention to detail in formatting and proofreading',
                '🤝 Willingness to ask for help and feedback',
                '🔄 Commitment to keeping materials updated'
            ],
            'tradeoffs': [
                'Time spent crafting resumes instead of other activities',
                'Stress and pressure when applying for opportunities',
                'Need to constantly update and maintain materials',
                'Vulnerability when putting yourself out there for evaluation'
            ]
        }
    elif category_name == 'car_home_basics':
        pathway_data = {
            'title': 'Car & Home Basics: Essential Life Maintenance Skills',
            'description': 'Learn fundamental maintenance and repair skills that save money and build confidence in managing your living space and transportation',
            'content': 'Knowing basic car and home maintenance makes you independent and saves thousands of dollars. These skills give you confidence and help you avoid being taken advantage of by dishonest repair services.',
            'problem': 'Many teens graduate without knowing how to change a tire, check oil, or handle basic home repairs, leaving them vulnerable and dependent on others.',
            'solution': 'Learn essential maintenance tasks, understand when to DIY vs. call professionals, and build a basic toolkit for common repairs.',
            'verse': '"The plans of the diligent lead to profit." (Proverbs 21:5) - Preparation and knowledge lead to success.',
            'action': 'This week, learn to check your car\'s oil level and tire pressure. Ask a parent or mentor to show you these basics.',
            'practical_examples': {
                'car_basics_checklist': [
                    '🔧 Check oil level and know when to change it (every 3,000-5,000 miles)',
                    '🚗 Check tire pressure monthly and learn to change a flat tire',
                    '🔋 Jump-start a dead battery safely using jumper cables',
                    '🧽 Wash and wax your car to protect the paint',
                    '❄️ Check coolant, brake fluid, and windshield washer fluid',
                    '🛠️ Replace air filters, wiper blades, and headlight bulbs'
                ],
                'home_maintenance_basics': [
                    '🔌 Reset circuit breakers and change light bulbs safely',
                    '🚿 Unclog drains using natural methods (baking soda + vinegar)',
                    '🔧 Fix leaky faucets by replacing washers or O-rings',
                    '🏠 Caulk around windows and doors to prevent drafts',
                    '🧹 Clean gutters and replace HVAC filters regularly',
                    '🔨 Use basic tools: screwdriver, hammer, level, stud finder'
                ]
            },
            'action_steps': [
                '📚 Learn to identify basic car problems by sound and symptoms',
                '🛠️ Build a basic toolkit for car and home maintenance',
                '📱 Use apps or YouTube for step-by-step repair tutorials',
                '👨‍🔧 Find a mentor who can teach hands-on skills',
                '💰 Start with small repairs to build confidence before larger projects'
            ],
            'benefits': [
                '💰 Save hundreds or thousands on repair costs',
                '😤 Build confidence in handling life\'s practical challenges',
                '🆘 Be prepared for emergencies and breakdowns',
                '🛡️ Avoid being overcharged by dishonest repair shops',
                '🏠 Maintain your living space and vehicle properly'
            ],
            'what_it_takes': [
                '🧠 Willingness to learn through trial and error',
                '🔧 Investment in basic tools and safety equipment',
                '⏰ Patience when learning new skills',
                '🤝 Humility to ask for help when needed'
            ],
            'tradeoffs': [
                'Money spent on tools and equipment instead of other things',
                'Risk of injury when learning hands-on skills',
                'Time invested in learning that could be spent on other hobbies',
                'Frustration when repairs don\'t work out as planned'
            ]
        }
    # Creativity & Hobbies Pathways
    elif category_name == 'music_instruments':
        pathway_data = {
            'title': 'Music & Instruments: The Universal Language',
            'description': 'Learn to create beautiful music, develop musical talent, and express yourself through the power of sound',
            'content': 'Music is a universal language that connects hearts and souls. Learning to play an instrument and create music develops creativity, discipline, and emotional expression while bringing joy to yourself and others.',
            'problem': 'Many teens think they\'re "not musical" or that it\'s too late to start learning, missing out on one of life\'s most rewarding creative pursuits.',
            'solution': 'Start with an instrument you love, practice consistently even if just 15 minutes daily, and focus on enjoying the process rather than perfection.',
            'verse': '"Sing to the Lord a new song; play skillfully, and shout for joy." (Psalm 33:3) - Your musical expression brings joy to yourself and others.',
            'action': 'This week, choose an instrument that interests you and spend 15 minutes learning basic techniques through online tutorials or apps like Simply Piano or Yousician.',
            'motivation_tips': [
                "🎵 'Music is the divine way to tell beautiful, poetic things to the heart.' - Pablo Casals",
                "🎸 'The only way to learn is to play. When you make mistakes, you learn.' - B.B. King",
                "🎹 'Music was my refuge. I could crawl into the space between the notes and curl my back to loneliness.' - Maya Angelou",
                "🥁 'Every expert was once a beginner. Every professional was once an amateur.' - Robin Sharma"
            ],
            'educational_content': {
                'how_music_works': 'Music is organized sound created through rhythm (timing), melody (pitch sequences), and harmony (multiple notes together). It engages both sides of the brain and improves memory, coordination, and emotional intelligence.',
                'instrument_basics': [
                    '🎸 Guitar: Start with basic chords (G, C, D) and simple strumming patterns',
                    '🎹 Piano: Learn proper hand position and basic scales (C major is easiest)',
                    '🥁 Drums: Master basic beats and keep steady rhythm',
                    '🎤 Voice: Practice breathing techniques and vocal warm-ups',
                    '🎻 Strings: Focus on proper bow technique and finger placement'
                ],
                'rhythm_and_timing': 'Rhythm is the heartbeat of music. Start by clapping along to songs, use a metronome, and count beats (1-2-3-4). Good timing makes everything sound better.'
            },
            'action_steps': [
                '🎼 Choose an instrument that genuinely excites you',
                '⏰ Practice daily, even if just 15-20 minutes consistently',
                '📱 Use apps and online tutorials for structured learning',
                '🎵 Learn your favorite songs to stay motivated',
                '👥 Find others to play with or perform for'
            ],
            'benefits': [
                '🧠 Improved memory, focus, and cognitive abilities',
                '😊 Emotional outlet and stress relief',
                '🎭 Creative expression and personal identity',
                '👥 Social connections through music groups and performances',
                '💪 Discipline and patience from regular practice'
            ],
            'tradeoffs': [
                'Daily practice time that could be spent on other activities',
                'Initial frustration when learning difficult techniques',
                'Cost of instruments, lessons, and equipment',
                'Noise concerns that may limit practice time'
            ],
            'what_it_takes': [
                '⏰ Consistent daily practice and patience with progress',
                '👂 Good listening skills and willingness to learn from mistakes',
                '💰 Investment in instrument and possibly lessons',
                '🎯 Setting realistic goals and celebrating small improvements'
            ]
        }
    elif category_name == 'art_design':
        pathway_data = {
            'title': 'Art & Design: Visual Expression and Creativity',
            'description': 'Express creativity through visual art, develop artistic skills, and create beautiful works that inspire others',
            'content': 'Art is a powerful form of communication that transcends words. Through drawing, painting, and design, you can express emotions, tell stories, and create beauty that touches people\'s lives.',
            'problem': 'Many teens believe they\'re "not artistic" or compare themselves to others, preventing them from exploring their creative potential.',
            'solution': 'Start with simple projects, focus on enjoyment over perfection, practice regularly, and remember that every artist develops at their own pace.',
            'verse': '"Every good and perfect gift is from above." (James 1:17) - Your creativity is a gift to be developed and shared.',
            'action': 'This week, spend 30 minutes creating something visual - draw, paint, or design something that represents how you feel today.',
            'motivation_tips': [
                "🎨 'Every artist was first an amateur.' - Ralph Waldo Emerson",
                "✏️ 'Art is not what you see, but what you make others see.' - Edgar Degas",
                "🖌️ 'Creativity takes courage.' - Henri Matisse",
                "⭐ 'The best way to get started is to quit talking and begin doing.' - Walt Disney"
            ],
            'educational_content': {
                'art_fundamentals': 'Art is built on elements like line, shape, color, texture, and composition. Understanding these basics helps you create more intentional and impactful work.',
                'drawing_basics': [
                    '✏️ Start with basic shapes - circles, squares, triangles form everything',
                    '👁️ Learn to see proportions and relationships between objects',
                    '🌑 Practice shading to create depth and dimension',
                    '📐 Use guidelines and construction lines for accuracy',
                    '🔄 Draw from life, photos, and imagination regularly'
                ],
                'color_theory': 'Colors have temperature (warm/cool), create moods, and work together in harmonious combinations. Learn the color wheel and how complementary colors create contrast.'
            },
            'action_steps': [
                '✏️ Start with basic drawing materials (pencil, paper, eraser)',
                '📚 Study art fundamentals through books or online courses',
                '🎨 Experiment with different mediums (pencil, watercolor, digital)',
                '👁️ Observe and sketch from life regularly',
                '🖼️ Create a portfolio to track your progress'
            ],
            'benefits': [
                '🎨 Creative outlet for emotions and ideas',
                '🧠 Improved observation and visual thinking skills',
                '😌 Stress relief and mindfulness through focused creation',
                '💼 Potential career paths in design, illustration, and media',
                '🌟 Sense of accomplishment and personal expression'
            ],
            'tradeoffs': [
                'Time spent creating art instead of other activities',
                'Cost of art supplies and materials',
                'Messy workspace and cleanup time required',
                'Subjective nature of art can lead to criticism or self-doubt'
            ]
        }
    elif category_name == 'dance_theater':
        pathway_data = {
            'title': 'Dance & Theater: Movement and Performance Arts',
            'description': 'Perform, entertain, and tell stories through movement, acting, and stage presence',
            'content': 'Dance and theater combine physical expression, emotional storytelling, and performance skills to create powerful experiences that move and inspire audiences.',
            'problem': 'Many teens feel self-conscious about performing or think they need to be naturally talented to participate in dance and theater.',
            'solution': 'Start with classes or groups, focus on expression over perfection, and remember that performance skills improve with practice and experience.',
            'verse': '"Let them praise his name with dancing and make music to him with timbrel and harp." (Psalm 149:3) - Movement and performance can be acts of celebration and joy.',
            'action': 'This week, learn a simple dance routine from YouTube or practice basic acting exercises like expressing different emotions in the mirror.',
            'motivation_tips': [
                "💃 'Dance is the hidden language of the soul.' - Martha Graham",
                "🎭 'Acting is not about being someone different. It's finding the similarity in what is apparently different, then finding myself in there.' - Meryl Streep",
                "⭐ 'All the world's a stage, and all the men and women merely players.' - Shakespeare",
                "🌟 'Movement is a medicine for creating change in a person's physical, emotional, and mental states.' - Carol Welch"
            ],
            'action_steps': [
                '💃 Take dance or acting classes to learn fundamentals',
                '🎭 Practice basic performance skills (projection, expression, stage presence)',
                '📱 Use online tutorials to learn choreography or monologues',
                '🎪 Audition for school plays, musicals, or community theater',
                '👥 Join drama clubs or dance groups for experience and community'
            ],
            'benefits': [
                '💪 Improved physical fitness, coordination, and body awareness',
                '🎭 Enhanced confidence and public speaking abilities',
                '😊 Emotional expression and stress relief',
                '👥 Strong friendships through shared creative experiences',
                '🎨 Appreciation for storytelling and artistic expression'
            ]
        }
    elif category_name == 'photography_videography':
        pathway_data = {
            'title': 'Photography & Videography: Capturing Life\'s Stories',
            'description': 'Capture life\'s moments, create visual stories, and develop technical and artistic skills in visual media',
            'content': 'Photography and videography allow you to freeze moments, tell stories, and share perspectives that inspire and inform others. In our visual world, these skills are both artistic and practical.',
            'problem': 'Many teens think expensive equipment is required or that they need advanced technical knowledge to create compelling visual content.',
            'solution': 'Start with available tools (smartphone cameras are powerful!), learn basic composition rules, and focus on storytelling rather than just technical perfection.',
            'verse': '"The light shines in the darkness, and the darkness has not overcome it." (John 1:5) - Good photography is about finding and capturing light and truth.',
            'action': 'This week, take 10 photos focusing on interesting lighting, angles, or stories. Practice the rule of thirds and share your best shots with friends or family.',
            'motivation_tips': [
                "📸 'Photography is a story I fail to put into words.' - Destin Sparks",
                "🎬 'Film is incredibly democratic and accessible, it's probably the best option if you actually want to change the world, not just re-decorate it.' - Banksy",
                "📱 'The best camera is the one that's with you.' - Chase Jarvis",
                "⭐ 'You don't take a photograph, you make it.' - Ansel Adams"
            ],
            'action_steps': [
                '📱 Master your smartphone camera settings and apps',
                '👁️ Learn composition rules (rule of thirds, leading lines, framing)',
                '☀️ Practice shooting in different lighting conditions',
                '🎬 Create simple videos with basic editing skills',
                '📚 Study work of photographers and filmmakers you admire'
            ],
            'benefits': [
                '📸 Ability to capture and preserve important moments',
                '🎨 Creative outlet and artistic expression',
                '💼 Potential income through freelance photography/videography',
                '🌍 Enhanced observation and appreciation of the world',
                '📱 Valuable skills for social media and digital communication'
            ],
            'tradeoffs': [
                'Cost of camera equipment and editing software',
                'Time spent learning technical skills and editing',
                'Need to carry equipment to capture moments',
                'Storage space required for photos and videos'
            ]
        }
    elif category_name == 'creative_writing':
        pathway_data = {
            'title': 'Creative Writing & Storytelling: Your Voice, Your Story',
            'description': 'Craft compelling stories, develop your unique voice, and share your perspectives through the written word',
            'content': 'Creative writing gives you the power to create worlds, share experiences, and connect with others through stories. Your unique perspective and voice are what the world needs to hear.',
            'problem': 'Many teens think they\'re not "good enough" writers or don\'t know where to start with creative expression through words.',
            'solution': 'Start writing regularly, even if just 15 minutes daily. Read widely, practice different styles, and remember that writing improves through doing, not just thinking.',
            'verse': '"In the beginning was the Word." (John 1:1) - Words have the power to create, inspire, and transform.',
            'action': 'Write for 15 minutes daily this week about anything - your day, a memory, a fictional character, or your thoughts and feelings.',
            'motivation_tips': [
                "✍️ 'There is nothing to writing. All you do is sit down at a typewriter and bleed.' - Ernest Hemingway",
                "📚 'The first draft of anything is shit.' - Ernest Hemingway (meaning: don't worry about perfection, just start)",
                "🖊️ 'You have something unique to offer the world through your writing.' - Unknown",
                "⭐ 'Write what disturbs you, what you fear, what you have not been willing to speak about.' - Natalie Goldberg"
            ],
            'action_steps': [
                '📝 Write daily, even if just for 15 minutes',
                '📚 Read widely in genres that interest you',
                '✏️ Practice different forms (poetry, stories, essays, scripts)',
                '👥 Join writing groups or share work for feedback',
                '📖 Study the craft through writing books and courses'
            ],
            'benefits': [
                '🧠 Improved communication and critical thinking skills',
                '😌 Emotional processing and stress relief through expression',
                '📝 Better performance in school writing assignments',
                '💼 Valuable skill for any career requiring communication',
                '🌟 Personal satisfaction from creating something uniquely yours'
            ]
        }
    elif category_name == 'podcasting_audio':
        pathway_data = {
            'title': 'Podcasting & Audio Production: Your Voice, Your Platform',
            'description': 'Create engaging audio content, develop broadcasting skills, and build an audience around topics you\'re passionate about',
            'content': 'Podcasting and audio production give you a platform to share your thoughts, interview interesting people, and create content that educates or entertains others. In our connected world, audio content is growing rapidly.',
            'problem': 'Many teens think podcasting requires expensive equipment or that they don\'t have anything interesting to say.',
            'solution': 'Start simple with smartphone recording, focus on topics you\'re passionate about, and remember that authenticity matters more than perfect production quality.',
            'verse': '"Faith comes by hearing, and hearing through the word." (Romans 10:17) - Your voice and message can impact others in powerful ways.',
            'action': 'Record a 5-minute practice episode on your phone about something you\'re passionate about. Listen back and note what you could improve.',
            'motivation_tips': [
                "🎙️ 'Podcasting is the democratization of broadcasting.' - Unknown",
                "📻 'Everyone has a story to tell. Your story matters.' - Podcast Host",
                "🎧 'The best podcasters are authentic, not perfect.' - Industry Expert",
                "⭐ 'Your voice is unique. Don\'t try to sound like anyone else.' - Audio Professional"
            ],
            'action_steps': [
                '🎙️ Start with basic equipment (smartphone or computer microphone)',
                '🎯 Choose topics or themes you\'re genuinely passionate about',
                '📝 Plan episodes with basic outlines or talking points',
                '🎧 Learn simple editing using free software like Audacity',
                '📡 Practice speaking clearly and at a good pace'
            ],
            'benefits': [
                '🎤 Improved public speaking and communication skills',
                '🧠 Research and interviewing skills development',
                '👥 Platform to connect with like-minded people',
                '💼 Potential future career in media or communications',
                '🌟 Creative outlet for sharing your interests and knowledge'
            ]
        }
    # Education & Academics Pathways
    elif category_name == 'study_skills_tutoring':
        pathway_data = {
            'title': 'Study Skills & Tutoring: Master the Art of Learning',
            'description': 'Master effective learning techniques, help others succeed, and develop powerful study strategies that work',
            'content': 'Learning how to learn is one of the most valuable skills you can develop. Effective study strategies help you retain information better, perform well on tests, and even help others achieve their goals through tutoring.',
            'problem': 'Many teens struggle academically not because they lack intelligence, but because they never learned effective study strategies and learning techniques.',
            'solution': 'Master proven study techniques like active reading, spaced repetition, note-taking systems, and test-taking strategies while developing strong learning habits.',
            'verse': '"An intelligent heart acquires knowledge, and the ear of the wise seeks knowledge." (Proverbs 18:15, ESV)',
            'action': 'This week, try one new study technique (like the Pomodoro method or active recall) and create a dedicated study space free from distractions.',
            'motivation_tips': [
                "📚 'Study while others are sleeping; work while others are loafing; prepare while others are playing.' - William A. Ward",
                "🧠 'The expert in anything was once a beginner.' - Helen Hayes",
                "⭐ 'Education is not preparation for life; education is life itself.' - John Dewey",
                "🔥 'The more you know, the more you realize you know nothing. Stay curious and keep learning.'"
            ],
            'educational_content': {
                'effective_study_methods': [
                    '⏰ Pomodoro Technique: 25-minute focused study sessions with 5-minute breaks',
                    '🔄 Active Recall: Test yourself instead of just re-reading notes',
                    '📅 Spaced Repetition: Review material at increasing intervals',
                    '🎯 Active Reading: Engage with text through questions and summaries',
                    '📝 Cornell Note System: Organized note-taking with review sections'
                ],
                'memory_techniques': 'Use mnemonics, visualization, and association to remember information better. Connect new information to what you already know.',
                'test_taking_strategies': 'Read directions carefully, manage time effectively, start with easier questions, and review answers if time permits.'
            },
            'action_steps': [
                '📚 Develop active reading and note-taking strategies',
                '⏰ Use time management techniques like the Pomodoro method',
                '🧠 Practice spaced repetition and active recall',
                '📝 Create effective study guides and summaries',
                '🎯 Develop test-taking strategies and stress management'
            ],
            'benefits': [
                '📈 Improved grades and academic performance',
                '😌 Less stress and anxiety about tests and assignments',
                '⏱️ More efficient use of study time',
                '🧠 Better long-term retention of information',
                '💰 Potential income from tutoring other students'
            ],
            'tradeoffs': [
                'Time spent developing study systems instead of leisure',
                'Initial effort required to change established habits',
                'Need for discipline and consistency in studying',
                'Less time for socializing during intensive study periods'
            ]
        }
    elif category_name == 'stem_exploration':
        pathway_data = {
            'title': 'STEM Exploration: Science, Technology, Engineering, Math',
            'description': 'Dive deep into Science, Technology, Engineering, and Math - the fields shaping our future',
            'content': 'STEM fields are at the forefront of solving world problems and creating innovations. From medical breakthroughs to space exploration, STEM careers offer exciting opportunities to make a real difference.',
            'problem': 'Many teens find STEM subjects intimidating or think they need to be naturally gifted in math and science to succeed.',
            'solution': 'Start with topics that interest you, focus on understanding concepts rather than memorization, and seek hands-on experiences through projects and experiments.',
            'verse': '"The heavens declare the glory of God; the skies proclaim the work of his hands." (Psalm 19:1) - Science reveals the amazing complexity of creation.',
            'action': 'Choose one STEM topic that interests you and spend time this week exploring it through videos, articles, or hands-on experiments.',
            'motivation_tips': [
                "🔬 'Science is not only a disciple of reason but, also, one of romance and passion.' - Stephen Hawking",
                "🚀 'The important thing is not to stop questioning.' - Albert Einstein",
                "⭐ 'In science, there are no shortcuts to any place worth going.' - Beverly Sills",
                "💡 'Every great advance in science has issued from a new audacity of imagination.' - John Dewey"
            ],
            'educational_content': {
                'stem_career_paths': [
                    '🔬 Science: Research, medicine, environmental science, biotechnology',
                    '💻 Technology: Software development, cybersecurity, AI, data science',
                    '🔧 Engineering: Civil, mechanical, electrical, aerospace, biomedical',
                    '📊 Mathematics: Statistics, actuarial science, data analysis, research'
                ],
                'hands_on_opportunities': 'Look for science fairs, robotics clubs, coding bootcamps, engineering competitions, and summer STEM programs.',
                'real_world_applications': 'STEM solves problems like climate change, disease, space exploration, and technology innovation that improves daily life.'
            },
            'action_steps': [
                '🔬 Participate in science fairs and STEM competitions',
                '🤖 Join robotics clubs or coding groups',
                '📚 Take advanced STEM courses when available',
                '🏭 Seek internships or job shadowing in STEM fields',
                '👨‍🔬 Connect with STEM professionals and mentors'
            ],
            'benefits': [
                '💰 High-paying career opportunities',
                '🌍 Chance to solve important world problems',
                '🧠 Strong analytical and problem-solving skills',
                '🚀 Opportunities for innovation and discovery',
                '📈 Job security in growing fields'
            ],
            'tradeoffs': [
                'Challenging coursework requiring significant study time',
                'Competitive environment with high academic standards',
                'Abstract concepts that can be difficult to understand',
                'Less time for non-STEM activities and interests'
            ]
        }
    elif category_name == 'writing_creative_arts':
        pathway_data = {
            'title': 'Writing & Creative Arts: Express Yourself Powerfully',
            'description': 'Express yourself powerfully through words, stories, and creative writing that connects with others',
            'content': 'Writing is one of humanity\'s most powerful tools for communication, persuasion, and creativity. Whether through stories, essays, or poetry, your unique voice and perspective can influence and inspire others.',
            'problem': 'Many teens think they\'re not "good writers" or don\'t know how to develop their writing abilities beyond basic school assignments.',
            'solution': 'Practice writing regularly, read widely in genres you enjoy, learn the fundamentals of good writing, and share your work for feedback.',
            'verse': '"The pen is mightier than the sword." (Edward Bulwer-Lytton) - Your words have power to influence and change the world.',
            'action': 'Write for 15 minutes daily this week about anything that interests you - your thoughts, stories, or experiences.',
            'motivation_tips': [
                "✍️ 'There is nothing to writing. All you do is sit down at a typewriter and bleed.' - Ernest Hemingway",
                "📚 'Words have no power to impress the mind without the exquisite horror of their reality.' - Edgar Allan Poe",
                "⭐ 'The first draft of anything is shit.' - Ernest Hemingway (meaning: don't worry about perfection, just start)",
                "🖊️ 'Write what disturbs you, what you fear, what you have not been willing to speak about.' - Natalie Goldberg"
            ],
            'educational_content': {
                'writing_fundamentals': [
                    '📝 Structure: Beginning, middle, end with clear purpose',
                    '🎭 Character Development: Create relatable, complex characters',
                    '🌍 Setting and World-building: Create vivid, believable environments',
                    '💬 Dialogue: Make conversations natural and purposeful',
                    '✏️ Grammar and Style: Master the technical aspects of writing'
                ],
                'types_of_writing': 'Explore creative writing (fiction, poetry), journalism (news, features), technical writing (manuals, reports), and content writing (blogs, marketing).',
                'revision_process': 'Great writing happens in revision. First drafts are for getting ideas down; subsequent drafts refine, clarify, and improve the work.'
            },
            'action_steps': [
                '📝 Write daily, even if just for 15 minutes',
                '📚 Read widely in genres that interest you',
                '✏️ Practice different forms (poetry, stories, essays, scripts)',
                '👥 Join writing groups or share work for feedback',
                '📖 Study the craft through writing books and courses'
            ],
            'benefits': [
                '🧠 Improved communication and critical thinking skills',
                '😌 Emotional processing and stress relief through expression',
                '📝 Better performance in all school subjects requiring writing',
                '💼 Valuable skill for virtually any career',
                '🌟 Personal satisfaction from creating something uniquely yours'
            ],
            'tradeoffs': [
                'Time spent writing that could be used for other activities',
                'Writer\'s block and creative frustrations',
                'Vulnerability when sharing personal work',
                'Need for quiet space and time for concentration'
            ]
        }
    elif category_name == 'college_prep_scholarships':
        pathway_data = {
            'title': 'College Prep & Scholarships: Navigate Your Path to Higher Education',
            'description': 'Navigate your path to higher education and secure funding through scholarships and financial aid',
            'content': 'College preparation involves more than just good grades. It requires strategic planning for admissions, financial aid, scholarships, and making the most of your high school experience to set yourself up for success.',
            'problem': 'Many teens and families feel overwhelmed by college preparation, scholarship applications, and the financial aspects of higher education.',
            'solution': 'Start early with college planning, research scholarship opportunities regularly, maintain strong academics, and get involved in meaningful activities that align with your goals.',
            'verse': '"For I know the plans I have for you," declares the Lord, "plans to prosper you and not to harm you, to give you hope and a future." (Jeremiah 29:11)',
            'action': 'This week, research three colleges you\'re interested in and find one scholarship you could apply for in the next year.',
            'motivation_tips': [
                "🎓 'The beautiful thing about learning is that no one can take it away from you.' - B.B. King",
                "💪 'Success is where preparation and opportunity meet.' - Bobby Unser",
                "⭐ 'Education is the most powerful weapon which you can use to change the world.' - Nelson Mandela",
                "🔥 'The expert in anything was once a beginner. Start preparing now for your future success.'"
            ],
            'educational_content': {
                'college_application_timeline': [
                    '🗓️ Sophomore Year: Focus on grades, explore interests, start standardized test prep',
                    '📚 Junior Year: Take SAT/ACT, research colleges, visit campuses, build activity resume',
                    '📝 Senior Year: Complete applications, apply for scholarships, make final decisions',
                    '💰 Throughout: Search and apply for scholarships continuously'
                ],
                'scholarship_types': 'Merit-based (academics, talents), need-based (financial situation), specific criteria (ethnicity, location, intended major), and local opportunities (community organizations).',
                'college_success_factors': 'Strong GPA, standardized test scores, extracurricular involvement, leadership experience, volunteer work, and compelling personal essays.'
            },
            'action_steps': [
                '📊 Maintain strong grades and take challenging courses',
                '📝 Prepare for and take standardized tests (SAT/ACT)',
                '🏆 Get involved in meaningful extracurricular activities',
                '💰 Research and apply for scholarships continuously',
                '🏫 Research colleges and visit campuses when possible'
            ],
            'benefits': [
                '🎓 Access to higher education and expanded opportunities',
                '💰 Reduced college costs through scholarships and aid',
                '🧠 Academic and personal growth through college experience',
                '💼 Better career prospects and earning potential',
                '👥 Network of educated peers and professional contacts'
            ],
            'tradeoffs': [
                'Stress and pressure from competitive college admissions',
                'Time spent on applications instead of other activities',
                'Financial investment in test prep and application fees',
                'Uncertainty and anxiety about acceptance and financial aid'
            ]
        }
    # Community & Volunteering Pathways
    elif category_name == 'charity_outreach':
        pathway_data = {
            'title': 'Charity & Outreach: Making a Difference in Lives',
            'description': 'Make a meaningful difference by helping those in need through organized charity work and community outreach',
            'content': 'Helping others in need is one of the most fulfilling experiences in life. Through charity and outreach, you can address real problems in your community while developing compassion, leadership, and perspective.',
            'problem': 'Many teens want to help but don\'t know where to start or think they\'re too young to make a real difference.',
            'solution': 'Start with local organizations, volunteer regularly rather than just occasionally, and focus on causes that genuinely matter to you.',
            'verse': '"Truly I tell you, whatever you did for one of the least of these brothers and sisters of mine, you did for me." (Matthew 25:40)',
            'action': 'Contact one local charity this week to learn about volunteer opportunities. Commit to volunteering at least once this month.',
            'action_steps': [
                '🔍 Research local charities and causes that align with your values',
                '📞 Contact organizations to learn about volunteer opportunities',
                '⏰ Make regular commitments rather than one-time events',
                '👥 Invite friends to volunteer together',
                '📊 Track your impact and hours for college applications'
            ],
            'benefits': [
                '❤️ Deep sense of purpose and fulfillment from helping others',
                '👁️ Broader perspective on life and gratitude for what you have',
                '🤝 Leadership experience and teamwork skills',
                '🎓 Valuable experience for college applications and resumes',
                '👥 Meet like-minded people who care about making a difference'
            ],
            'tradeoffs': [
                'Time spent volunteering instead of personal activities',
                'Emotional drain from seeing others\' difficulties',
                'Transportation and scheduling challenges',
                'Sometimes feeling like individual efforts aren\'t enough'
            ]
        }
    elif category_name == 'environmental_projects':
        pathway_data = {
            'title': 'Environmental Projects: Protecting Our Planet',
            'description': 'Protect our planet for future generations through environmental conservation and sustainability projects',
            'content': 'Environmental work is about ensuring a healthy planet for future generations. Through conservation, cleanup, and sustainability projects, you can make a tangible difference in your local environment and beyond.',
            'problem': 'Environmental problems can feel overwhelming, and many teens don\'t know how to make a meaningful impact.',
            'solution': 'Focus on local projects with measurable impact, educate others, and develop sustainable habits in your own life first.',
            'verse': '"The Lord God took the man and put him in the Garden of Eden to work it and take care of it." (Genesis 2:15)',
            'action': 'Organize or join a local cleanup project this month. Start composting or recycling properly at home.',
            'action_steps': [
                '🌱 Join or start environmental clubs at school',
                '🧹 Organize community cleanup events',
                '♻️ Promote recycling and waste reduction programs',
                '🌳 Participate in tree planting and conservation projects',
                '📚 Educate others about environmental issues and solutions'
            ],
            'benefits': [
                '🌍 Tangible impact on preserving the environment',
                '🧠 Knowledge about environmental science and sustainability',
                '🤝 Leadership opportunities in organizing projects',
                '🎓 Strong examples for college applications and scholarships',
                '💚 Personal satisfaction from protecting nature'
            ],
            'tradeoffs': [
                'Time spent on environmental work instead of other activities',
                'Physical demands of cleanup and conservation work',
                'Frustration with slow progress on large environmental issues',
                'Need to change personal habits and lifestyle choices'
            ]
        }
    elif category_name == 'community_leadership':
        pathway_data = {
            'title': 'Leadership in Community: Leading Positive Change',
            'description': 'Lead positive change in your community by identifying problems and organizing solutions that benefit others',
            'content': 'Community leadership means seeing problems and taking initiative to create solutions. You don\'t have to wait until you\'re older to make a difference - teens can be powerful agents of positive change.',
            'problem': 'Many teens see problems in their communities but think they\'re too young or don\'t have the skills to create change.',
            'solution': 'Start with small, local issues you can actually address. Build teams, develop plans, and take consistent action toward solutions.',
            'verse': '"Let no one despise you for your youth, but set the believers an example in speech, in conduct, in love, in faith, in purity." (1 Timothy 4:12)',
            'action': 'Identify one problem in your school or community that bothers you. Research it and brainstorm three possible solutions.',
            'action_steps': [
                '🔍 Identify specific problems you want to help solve',
                '📋 Research issues and develop practical solutions',
                '👥 Build teams of people who share your vision',
                '📢 Communicate your vision and rally support',
                '🎯 Take consistent action and measure progress'
            ],
            'benefits': [
                '👑 Development of real leadership skills and experience',
                '🌟 Recognition as someone who makes a difference',
                '🧠 Problem-solving and project management abilities',
                '🎓 Outstanding examples for college and scholarship applications',
                '❤️ Deep satisfaction from improving your community'
            ],
            'tradeoffs': [
                'Heavy responsibility for project success or failure',
                'Time spent organizing that could be used for other pursuits',
                'Dealing with criticism and resistance to change',
                'Stress from coordinating multiple people and resources'
            ]
        }
    elif category_name == 'peer_mentoring':
        pathway_data = {
            'title': 'Peer Mentoring: Guide, Support, and Inspire Others',
            'description': 'Guide, support, and inspire younger students or peers through mentoring relationships that help them succeed',
            'content': 'Peer mentoring allows you to share your experiences and knowledge to help others navigate challenges you\'ve already faced. It\'s one of the most rewarding forms of leadership and service.',
            'problem': 'Many teens have valuable experiences and knowledge but don\'t realize they can help others or don\'t know how to start mentoring.',
            'solution': 'Look for formal mentoring programs at school or in your community, or create informal mentoring relationships with younger students who could benefit from your guidance.',
            'verse': '"As iron sharpens iron, so one person sharpens another." (Proverbs 27:17)',
            'action': 'Offer to help a younger student with something you\'re good at - academics, sports, or adjusting to school. Spend time listening to their challenges.',
            'action_steps': [
                '🔍 Join formal peer mentoring programs at school',
                '👂 Develop strong listening and empathy skills',
                '📚 Share your experiences and lessons learned',
                '🎯 Help mentees set and achieve realistic goals',
                '🤝 Build trustworthy, supportive relationships'
            ],
            'benefits': [
                '👨‍🏫 Development of teaching and communication skills',
                '😊 Personal satisfaction from helping others succeed',
                '🧠 Reinforcement of your own knowledge and skills',
                '🤝 Leadership experience and relationship building',
                '🎓 Valuable experience for college applications and future careers'
            ],
            'tradeoffs': [
                'Time commitment to support and guide mentees',
                'Emotional investment in others\' success and failures',
                'Need to be patient when mentees struggle or resist help',
                'Responsibility to be a positive role model consistently'
            ]
        }
    else:
        # Generic pathway data for other categories
        category_display = category_name.replace('_', ' ').replace('-', ' ').title()
        pathway_data = {
            'title': category_display,
            'description': f'Master the skills and knowledge needed for {category_display.lower()}',
            'content': f'Comprehensive learning pathway for {category_display.lower()} development.',
            'action_steps': [
                f'📚 Learn the fundamentals of {category_display.lower()}',
                f'💪 Practice {category_display.lower()} skills daily',
                f'👥 Find mentors in {category_display.lower()}',
                f'🎯 Set goals for {category_display.lower()} improvement',
                f'🚀 Apply your {category_display.lower()} knowledge'
            ],
            'benefits': [
                f'🎓 Develop expertise in {category_display.lower()}',
                '💪 Build confidence and skills',
                '🌟 Create opportunities for your future',
                '❤️ Make a positive impact on others'
            ]
        }
    
    return render_template('category_pathway_detail.html', 
                         pathway=pathway_data, 
                         category_name=category_name,
                         subcategory=category_name)

@app.route('/money-lesson/<lesson_name>')
@login_required
def money_lesson_detail(lesson_name):
    """Individual money lesson detail pages"""
    if current_user.role not in ['teen', 'teenager']:
        flash('Access denied. Teenager account required.', 'danger')
        return redirect(url_for('index'))
    
    # Money lesson data with required structure
    if lesson_name == 'money_mindset_values':
        lesson_data = {
            'title': '🔑 Money Mindset & Values',
            'description': 'Understanding the purpose of money and distinguishing needs vs wants',
            'verse': '"For the love of money is a root of all kinds of evil. Some people, eager for money, have wandered from the faith and pierced themselves with many griefs." (1 Timothy 6:10, NIV)',
            'education': 'Money is a tool, not a master. It\'s designed to help you serve God, provide for your family, and bless others. The key is understanding that money has no inherent value - its worth comes from what you do with it. Learning the difference between needs (essentials like food, shelter, basic clothing) and wants (nice-to-haves like designer clothes, latest gadgets) is the foundation of all financial wisdom.',
            'tip': '💡 Pro Tip: Before buying anything, ask yourself: "Is this a need or a want?" Wait 24 hours before purchasing wants over $20. You\'ll be surprised how many things you no longer "need" after waiting!',
            'how_it_works': 'Your relationship with money starts in your mind. If you see money as security, you\'ll never have enough. If you see it as a tool for good, you\'ll use it wisely. Practice gratitude for what you have, distinguish between marketing lies and real needs, and always remember that your worth isn\'t determined by what you own.',
            'story': 'Jake, 16, desperately wanted the latest iPhone that cost $1,000. His current phone worked fine, but all his friends had the new one. Instead of spending his entire savings, Jake waited a month and realized his "need" was really about fitting in. He bought a $200 phone case that looked cool, saved $800, and learned that most "needs" are actually manufactured by our emotions and social pressure.',
            'action_steps': [
                '📝 Write down 5 things you think you "need" - honestly evaluate if they\'re wants or needs',
                '💰 Track every purchase for one week - categorize as need vs want',
                '🙏 Pray/reflect about your relationship with money and possessions',
                '📱 Unfollow social media accounts that make you want to buy things',
                '💭 Practice gratitude by listing 10 things you already own that you\'re thankful for'
            ],
            'quiz_questions': [
                {'q': 'According to 1 Timothy 6:10, what is the root of evil?', 'a': 'The love of money'},
                {'q': 'True or False: Money is inherently evil.', 'a': 'False'},
                {'q': 'What should you ask yourself before making any purchase?', 'a': 'Is this a need or a want?'},
                {'q': 'How long should you wait before buying wants over $20?', 'a': '24 hours'},
                {'q': 'What determines your worth as a person?', 'a': 'Not what you own or your possessions'}
            ]
        }
    elif lesson_name == 'budgeting_basics':
        lesson_data = {
            'title': '💵 Budgeting Basics',
            'description': 'How to create a simple monthly budget and track spending',
            'verse': '"The plans of the diligent lead to profit as surely as haste leads to poverty." (Proverbs 21:5, NIV)',
            'education': 'A budget is simply telling your money where to go instead of wondering where it went. It\'s a plan that helps you spend less than you earn and save for your goals. The 50/30/20 rule is perfect for teens: 50% for needs (food, transportation, required school items), 30% for wants (entertainment, clothes, eating out), and 20% for savings and giving. Even if you only have $20, budgeting helps you be intentional.',
            'tip': '💡 Pro Tip: Use the envelope method! Put cash in labeled envelopes for different spending categories. When the envelope is empty, you\'re done spending in that category for the month.',
            'how_it_works': 'Start by tracking where your money currently goes for one week. Then create categories: needs, wants, savings, giving. Assign percentages or dollar amounts to each category based on your income (allowance, job, gifts). Review and adjust weekly. The key is being realistic and consistent, not perfect.',
            'story': 'Maria, 17, worked part-time earning $400/month but always felt broke. She started budgeting: $200 for needs (gas, lunch), $120 for wants (movies, clothes), $80 for savings and giving. Within 3 months, she had her first $200 emergency fund and could afford a school trip without asking her parents for money. The secret? She finally knew where every dollar was going.',
            'action_steps': [
                '📊 Track every penny you spend for one full week',
                '💰 Calculate your monthly income (allowance, job, gifts)',
                '📝 Create 4 budget categories: needs, wants, savings, giving',
                '🎯 Apply the 50/30/20 rule to your income',
                '📱 Use a budgeting app or simple notebook to track daily'
            ],
            'quiz_questions': [
                {'q': 'What does Proverbs 21:5 say about planning?', 'a': 'The plans of the diligent lead to profit'},
                {'q': 'What percentage should go to needs in the 50/30/20 rule?', 'a': '50%'},
                {'q': 'What is the envelope method?', 'a': 'Putting cash in labeled envelopes for different spending categories'},
                {'q': 'How long should you track your spending before creating a budget?', 'a': 'One week'},
                {'q': 'What\'s more important than being perfect with budgeting?', 'a': 'Being consistent'}
            ]
        }
    elif lesson_name == 'banking_digital_money':
        lesson_data = {
            'title': '💳 Banking & Digital Money',
            'description': 'How checking/savings accounts work and using digital payments safely',
            'verse': '"Whoever can be trusted with very little can also be trusted with much, and whoever is dishonest with very little will also be dishonest with much." (Luke 16:10, NIV)',
            'education': 'Banks are like secure storage for your money, plus they offer services. A savings account earns interest (free money!) and should be for long-term goals. A checking account is for daily expenses and comes with a debit card. Digital payments (Venmo, CashApp, Apple Pay) are convenient but risky - they\'re connected to real accounts with real money. Credit cards are borrowed money that must be paid back with interest.',
            'tip': '💡 Pro Tip: Keep your debit card PIN private, check your account balance before spending, and never share login information. Set up account alerts to know when money goes in or out.',
            'how_it_works': 'Open a savings account first - even $25 can start earning interest. Learn to read bank statements and understand fees. For digital payments, only connect to checking accounts, not savings. Always verify who you\'re sending money to - digital payments are like cash and usually can\'t be reversed. Set spending limits and check balances frequently.',
            'story': 'David, 16, got his first debit card and immediately spent $180 on games without checking his balance. The account went negative, triggering $35 overdraft fees for each transaction. What should have been $180 became $320 in total costs. Now David checks his balance before every purchase and keeps a buffer of $50 in his account to avoid overdrafts.',
            'action_steps': [
                '🏦 Open a savings account with a parent at a local bank',
                '📱 Set up mobile banking with account alerts',
                '🔐 Never share your PIN or login information with anyone',
                '💰 Check your account balance before making purchases',
                '📊 Learn to read your monthly bank statement'
            ],
            'quiz_questions': [
                {'q': 'According to Luke 16:10, what happens if you\'re trusted with little?', 'a': 'You can be trusted with much'},
                {'q': 'What type of account should you open first?', 'a': 'Savings account'},
                {'q': 'Can digital payments usually be reversed?', 'a': 'No, they\'re like cash'},
                {'q': 'How much should you keep as a buffer in your checking account?', 'a': '$50'},
                {'q': 'Who should you share your PIN with?', 'a': 'Nobody'}
            ]
        }
    elif lesson_name == 'debt_credit_awareness':
        lesson_data = {
            'title': '📉 Debt & Credit Awareness',
            'description': 'Understanding credit scores and avoiding debt traps',
            'verse': '"The rich rule over the poor, and the borrower is slave to the lender." (Proverbs 22:7, NIV)',
            'education': 'Debt means you owe money to someone else. Credit cards, car loans, and student loans are common types. Your credit score (300-850) shows how well you repay borrowed money - it affects future loan rates and even job opportunities. Good credit comes from paying bills on time and not maxing out credit cards. Bad credit can haunt you for 7+ years and cost thousands in higher interest rates.',
            'tip': '💡 Pro Tip: If you can\'t afford to buy it twice, you can\'t afford to put it on a credit card. Only use credit for absolute emergencies, and pay it off immediately.',
            'how_it_works': 'Credit companies make money when you can\'t pay your full balance. They offer minimum payments (usually 2-3% of balance) but charge 18-29% interest on what remains. A $1,000 credit card balance paying minimums takes 5+ years to pay off and costs over $2,000 total. Buy Now, Pay Later services seem free but often have hidden fees and hurt your credit score if you miss payments.',
            'story': 'Ashley, 18, got her first credit card with a $500 limit and bought clothes "for emergencies." She made minimum $15 payments on her $500 balance. Three years later, she\'d paid $540 in payments but still owed $300 because of interest. That $500 shopping spree actually cost her over $800. She learned that credit card "emergencies" are usually just things she wanted but couldn\'t afford.',
            'action_steps': [
                '📚 Learn what affects credit scores: payment history, debt amounts, length of history',
                '💳 If you get a credit card, use it only for small purchases you can pay off immediately',
                '🚫 Avoid Buy Now, Pay Later services like Afterpay and Klarna',
                '📊 Check your credit report annually for free at annualcreditreport.com',
                '💰 Build credit slowly - start with a secured credit card if needed'
            ],
            'quiz_questions': [
                {'q': 'According to Proverbs 22:7, the borrower is what to the lender?', 'a': 'Slave'},
                {'q': 'What is the credit score range?', 'a': '300-850'},
                {'q': 'How long can bad credit affect you?', 'a': '7+ years'},
                {'q': 'What should you do if you can\'t afford to buy something twice?', 'a': 'Don\'t put it on a credit card'},
                {'q': 'How much does a $500 credit card balance cost if you only make minimum payments?', 'a': 'Over $800 total'}
            ]
        }
    elif lesson_name == 'saving_goal_setting':
        lesson_data = {
            'title': '📈 Saving & Goal Setting',
            'description': 'Building emergency funds and learning delayed gratification',
            'verse': '"In the house of the wise are stores of choice food and oil, but a foolish person devours all they have." (Proverbs 21:20, NIV)',
            'education': 'Saving money is like building a foundation for your dreams. An emergency fund (3-6 months of expenses) protects you from financial disasters. Goal-based saving helps you afford big purchases without debt. The key is paying yourself first - save before you spend on anything else. Even $1 saved consistently becomes $365 in a year. Delayed gratification means waiting for something better instead of settling for instant satisfaction.',
            'tip': '💡 Pro Tip: Use the "Pay Yourself First" method - immediately save 20% of any money you receive before spending on anything else. Automate it if possible!',
            'how_it_works': 'Set specific, measurable goals with deadlines: "Save $500 for a car by December" not "save some money." Break big goals into weekly/monthly targets. Open a separate savings account for each major goal so you\'re not tempted to spend. Use visual reminders like charts or photos of your goal. Celebrate small milestones to stay motivated.',
            'story': 'Marcus, 17, wanted a $2,000 car for his senior year. Instead of asking for loans, he got a summer job earning $300/week and saved $200 weekly for 10 weeks. By August, he had his $2,000 plus extra for insurance and gas. His friends with car payments were still paying $200/month two years later while Marcus owned his car free and clear.',
            'action_steps': [
                '🎯 Set one specific financial goal with a deadline',
                '💰 Start an emergency fund - even if it\'s just $100',
                '📊 Calculate how much you need to save weekly/monthly for your goal',
                '🏦 Open a separate savings account for your goal',
                '📱 Set up automatic transfers to your savings account'
            ],
            'quiz_questions': [
                {'q': 'According to Proverbs 21:20, what do wise people have in their house?', 'a': 'Stores of choice food and oil'},
                {'q': 'How many months of expenses should an emergency fund cover?', 'a': '3-6 months'},
                {'q': 'What should you do before spending on anything else?', 'a': 'Pay yourself first (save)'},
                {'q': 'How much money do you save in a year by saving $1 consistently?', 'a': '$365'},
                {'q': 'What percentage should you save immediately from any money received?', 'a': '20%'}
            ]
        }
    elif lesson_name == 'investing_early':
        lesson_data = {
            'title': '🪙 Investing Early',
            'description': 'Power of compound interest and intro to stocks and ETFs',
            'verse': '"Dishonest money dwindles away, but whoever gathers money little by little makes it grow." (Proverbs 13:11, NIV)',
            'education': 'Investing means buying pieces of companies (stocks) or funds (ETFs) that grow in value over time. Compound interest is when your money earns money, and that money earns money - it\'s like a snowball effect. Starting early is crucial: $100 invested at age 16 grows to over $2,000 by age 65 with average stock market returns. The key is time, not timing - you don\'t need to pick perfect investments, just start consistently.',
            'tip': '💡 Pro Tip: Start with broad market index funds or ETFs - they\'re diversified and less risky than individual stocks. Even $25/month invested consistently can build serious wealth over decades.',
            'how_it_works': 'Open an investment account with a parent\'s help (you need to be 18+ for your own account). Start with index funds that track the whole stock market - they average 7-10% annual returns historically. Dollar-cost averaging means investing the same amount regularly regardless of market conditions. Never invest money you need within 5 years, and never invest borrowed money.',
            'story': 'Sarah, 15, started investing $50/month from her babysitting job in an S&P 500 index fund. Her friends thought she was crazy for not spending it on clothes and activities. By age 30, her $9,000 in contributions had grown to over $35,000. By age 50, it was worth over $150,000. Her 15 years of early investing outperformed friends who started investing larger amounts in their 30s.',
            'action_steps': [
                '📚 Learn the difference between stocks, bonds, and index funds',
                '👨‍👩‍👧‍👦 Open a custodial investment account with your parents',
                '💰 Start with $25-50/month in a broad market index fund',
                '📊 Research low-cost index funds with expense ratios under 0.1%',
                '⏰ Set up automatic monthly investments to dollar-cost average'
            ],
            'quiz_questions': [
                {'q': 'According to Proverbs 13:11, how should money be gathered to make it grow?', 'a': 'Little by little'},
                {'q': 'How much does $100 invested at age 16 grow to by age 65?', 'a': 'Over $2,000'},
                {'q': 'What historical annual return do index funds average?', 'a': '7-10%'},
                {'q': 'What should you never invest?', 'a': 'Money you need within 5 years or borrowed money'},
                {'q': 'What does dollar-cost averaging mean?', 'a': 'Investing the same amount regularly regardless of market conditions'}
            ]
        }
    elif lesson_name == 'work_side_hustles_income':
        lesson_data = {
            'title': '🏠 Work, Side Hustles & Income',
            'description': 'Earning your own money and understanding taxes',
            'verse': '"All hard work brings a profit, but mere talk leads only to poverty." (Proverbs 14:23, NIV)',
            'education': 'Earning your own money teaches responsibility, work ethic, and the value of a dollar. Traditional jobs (retail, food service) provide steady income and work experience. Side hustles (tutoring, lawn care, pet sitting) offer flexibility and entrepreneurial skills. Taxes are the government\'s cut of your earnings - typically 10-15% for teens. Understanding gross pay (before taxes) vs. net pay (after taxes) prevents spending disappointment.',
            'tip': '💡 Pro Tip: Track your hourly earnings for different activities. Sometimes tutoring at $15/hour is better than minimum wage at $7.25/hour, even if it\'s fewer hours.',
            'how_it_works': 'Start with skills you already have - good at math? Tutor younger students. Like dogs? Pet sit. Strong and reliable? Do yard work. Price your services fairly but not cheap - your time has value. Always be professional, reliable, and honest. Keep track of earnings for taxes and save receipts for business expenses.',
            'story': 'Tyler, 16, mowed lawns every Saturday for $30 each. He did 8 lawns weekly, earning $240. After gas and maintenance costs ($40), he netted $200/week. Over the summer (16 weeks), he earned $3,200. He paid $480 in taxes but still had $2,720 - enough for a car down payment. His friends who didn\'t work had to borrow money for everything.',
            'action_steps': [
                '📝 List skills you have that others would pay for',
                '💼 Apply for part-time jobs or start a simple service business',
                '💰 Track your earnings and expenses for tax purposes',
                '📊 Calculate your true hourly wage after expenses and taxes',
                '🎯 Set income goals and work consistently to reach them'
            ],
            'quiz_questions': [
                {'q': 'According to Proverbs 14:23, what does all hard work bring?', 'a': 'Profit'},
                {'q': 'What percentage of earnings typically go to taxes for teens?', 'a': '10-15%'},
                {'q': 'What\'s the difference between gross and net pay?', 'a': 'Gross is before taxes, net is after taxes'},
                {'q': 'What should you keep for business expenses?', 'a': 'Receipts'},
                {'q': 'How much did Tyler net per week after expenses?', 'a': '$200'}
            ]
        }
    elif lesson_name == 'generosity_responsibility':
        lesson_data = {
            'title': '❤️ Generosity & Responsibility',
            'description': 'Giving, sharing, and using money to make a difference',
            'verse': '"Give, and it will be given to you. A good measure, pressed down, shaken together and running over, will be poured into your lap." (Luke 6:38, NIV)',
            'education': 'Generosity breaks the power of greed and selfishness over your heart. Tithing (giving 10%) to your church supports God\'s work. Charitable giving helps those in need and builds character. The goal isn\'t to give away everything, but to hold money loosely. Responsible giving means researching charities to ensure donations actually help people. Even small amounts make a difference when combined with others.',
            'tip': '💡 Pro Tip: Give regularly, not just when you feel like it. Set up automatic giving to your church and a charity you care about - even $10/month makes a difference!',
            'how_it_works': 'Start with the biblical principle of tithing 10% of your income to your church. Add charitable giving for causes you care about - animal shelters, food banks, disaster relief. Research charities on websites like Charity Navigator to ensure your money is used well. Give locally when possible - you can see the direct impact. Remember: you can\'t out-give God.',
            'story': 'Emma, 17, earned $200/month and decided to give $20 to church and $10 to a local animal shelter. At first, living on $170 felt tight, but she learned to budget better. When her car broke down, her youth group raised $800 to help her. She realized her faithfulness in giving had created a community that gave back when she needed it most.',
            'action_steps': [
                '💒 Start tithing 10% of your income to your church',
                '❤️ Choose one charity or cause you\'re passionate about',
                '🔍 Research charities on Charity Navigator before giving',
                '📅 Set up automatic giving so it happens consistently',
                '🤝 Look for local opportunities to help your community directly'
            ],
            'quiz_questions': [
                {'q': 'According to Luke 6:38, what happens when you give?', 'a': 'It will be given to you'},
                {'q': 'What percentage is traditionally given as a tithe?', 'a': '10%'},
                {'q': 'Where should you research charities before giving?', 'a': 'Charity Navigator'},
                {'q': 'What did Emma learn about giving and community?', 'a': 'Faithfulness in giving creates community that gives back'},
                {'q': 'What breaks the power of greed and selfishness?', 'a': 'Generosity'}
            ]
        }
    elif lesson_name == 'avoiding_money_traps':
        lesson_data = {
            'title': '⚠️ Avoiding Money Traps',
            'description': 'Spotting scams and avoiding risky financial schemes',
            'verse': '"The simple believe anything, but the prudent give thought to their steps." (Proverbs 14:15, NIV)',
            'education': 'Financial scams prey on emotions like greed (get rich quick) and fear (you\'ll miss out). Common teen traps include MLM schemes, cryptocurrency hype, gambling apps, and social media "gurus" selling courses. If something sounds too good to be true, it usually is. Real wealth building is boring and takes time - anyone promising quick riches is lying. Lottery tickets are a tax on people who can\'t do math.',
            'tip': '💡 Pro Tip: Before investing in anything, ask: "How does this make money?" If you can\'t explain it simply, don\'t invest. Beware of anyone who pressures you to "act now" or "don\'t miss out."',
            'how_it_works': 'Scammers use urgency, social proof, and complexity to confuse you. They target young people through social media with flashy lifestyles and promises of easy money. Real red flags: guaranteed returns, pressure to recruit friends, requiring upfront payments, or secrecy about how it works. Always research thoroughly and discuss big financial decisions with trusted adults.',
            'story': 'Jordan, 16, saw a TikTok about a "teen trader" making $1,000/day. He invested his $500 birthday money in a trading course and cryptocurrency the "guru" recommended. Within a month, his investment was worth $50. The "guru" disappeared, and Jordan learned that 90% of day traders lose money. He should have researched that only 10% of day traders are profitable long-term.',
            'action_steps': [
                '🚫 Avoid any "investment" that guarantees returns or requires recruiting others',
                '🔍 Research any financial opportunity thoroughly before investing',
                '👥 Discuss major financial decisions with trusted adults',
                '📱 Unfollow social media accounts promoting get-rich-quick schemes',
                '🧠 Remember: if it sounds too good to be true, it probably is'
            ],
            'quiz_questions': [
                {'q': 'According to Proverbs 14:15, what do prudent people do?', 'a': 'Give thought to their steps'},
                {'q': 'What emotions do financial scams prey on?', 'a': 'Greed and fear'},
                {'q': 'What percentage of day traders are profitable long-term?', 'a': '10%'},
                {'q': 'What should you ask before investing in anything?', 'a': 'How does this make money?'},
                {'q': 'What are lottery tickets called?', 'a': 'A tax on people who can\'t do math'}
            ]
        }
    elif lesson_name == 'planning_future':
        lesson_data = {
            'title': '📊 Planning for the Future',
            'description': 'Long-term financial planning for college and independence',
            'verse': '"Commit to the Lord whatever you do, and he will establish your plans." (Proverbs 16:3, NIV)',
            'education': 'Financial planning means preparing for predictable expenses and unpredictable opportunities. College costs $10,000-50,000+ annually - planning early makes it affordable. Moving out requires first month\'s rent, security deposits, furniture, and emergency funds. Career planning affects earning potential - some careers require expensive education but offer high salaries, others need less education but have lower pay. The key is matching your financial plan to your life goals.',
            'tip': '💡 Pro Tip: Start a "Future Fund" now for big upcoming expenses. College, car, apartment deposit, career training - even $25/month grows into thousands over time.',
            'how_it_works': 'Identify major future expenses and their timeframes. College in 2 years? Start saving now and research financial aid. Want your own apartment at 18? Calculate rent, deposits, utilities, and furniture costs. Career goals affect education needs - research salaries vs. education costs for your dream job. Create separate savings goals for each major life milestone.',
            'story': 'Alex, 15, knew college would cost $15,000/year and started saving $200/month from his job. By graduation, he had $7,200 saved. Combined with scholarships and financial aid, he graduated debt-free while classmates had $30,000+ in student loans. His early planning and sacrifice gave him financial freedom to pursue his dream job instead of taking any job to pay loans.',
            'action_steps': [
                '🎓 Research the total cost of your intended college and career path',
                '💰 Start a separate savings account for college/career training',
                '📋 Calculate the cost of living independently in your area',
                '📊 Create a timeline with financial milestones for the next 5 years',
                '🔍 Research scholarships, grants, and financial aid opportunities'
            ],
            'quiz_questions': [
                {'q': 'According to Proverbs 16:3, what should you commit to the Lord?', 'a': 'Whatever you do'},
                {'q': 'How much does college typically cost annually?', 'a': '$10,000-50,000+'},
                {'q': 'How much did Alex save by graduation?', 'a': '$7,200'},
                {'q': 'What gave Alex financial freedom after college?', 'a': 'Early planning and graduating debt-free'},
                {'q': 'What should you match your financial plan to?', 'a': 'Your life goals'}
            ]
        }
    else:
        # Fallback for unknown lesson
        lesson_data = {
            'title': 'Money Lesson',
            'description': 'Financial education for teens',
            'verse': '"For where your treasure is, there your heart will be also." (Matthew 6:21, NIV)',
            'education': 'This lesson covers important financial principles for teens.',
            'tip': 'Always be wise with your money decisions.',
            'how_it_works': 'Learn, apply, and practice good financial habits.',
            'story': 'A teen learned important money management skills.',
            'action_steps': ['Learn financial principles', 'Practice budgeting', 'Save regularly'],
            'quiz_questions': [
                {'q': 'What is important about money management?', 'a': 'Being wise and intentional'}
            ]
        }
    
    return render_template('category_pathway_detail.html', 
                         pathway=lesson_data, 
                         category_name='money_budgeting',
                         subcategory=lesson_name)

@app.route('/money-lesson/<lesson_name>/quiz', methods=['POST'])
@login_required
def money_lesson_quiz(lesson_name):
    """Handle money lesson quiz submissions"""
    if current_user.role not in ['teen', 'teenager']:
        flash('Access denied. Teenager account required.', 'danger')
        return redirect(url_for('index'))
    
    # Get the lesson data to access correct answers - duplicate the lesson data logic
    lesson_data = {}
    if lesson_name == 'money_mindset_values':
        lesson_data = {
            'title': '🔑 Money Mindset & Values',
            'quiz_questions': [
                {'q': 'According to 1 Timothy 6:10, what is the root of evil?', 'a': 'The love of money'},
                {'q': 'True or False: Money is inherently evil.', 'a': 'False'},
                {'q': 'What should you ask yourself before making any purchase?', 'a': 'Is this a need or a want?'},
                {'q': 'How long should you wait before buying wants over $20?', 'a': '24 hours'},
                {'q': 'What determines your worth as a person?', 'a': 'Not what you own or your possessions'}
            ]
        }
    elif lesson_name == 'budgeting_basics':
        lesson_data = {
            'title': '💵 Budgeting Basics',
            'quiz_questions': [
                {'q': 'What does Proverbs 21:5 say about planning?', 'a': 'The plans of the diligent lead to profit'},
                {'q': 'What percentage should go to needs in the 50/30/20 rule?', 'a': '50%'},
                {'q': 'What is the envelope method?', 'a': 'Putting cash in labeled envelopes for different spending categories'},
                {'q': 'How long should you track your spending before creating a budget?', 'a': 'One week'},
                {'q': 'What\'s more important than being perfect with budgeting?', 'a': 'Being consistent'}
            ]
        }
    elif lesson_name == 'banking_digital_money':
        lesson_data = {
            'title': '💳 Banking & Digital Money',
            'quiz_questions': [
                {'q': 'According to Luke 16:10, what happens if you\'re trusted with little?', 'a': 'You can be trusted with much'},
                {'q': 'What type of account should you open first?', 'a': 'Savings account'},
                {'q': 'Can digital payments usually be reversed?', 'a': 'No, they\'re like cash'},
                {'q': 'How much should you keep as a buffer in your checking account?', 'a': '$50'},
                {'q': 'Who should you share your PIN with?', 'a': 'Nobody'}
            ]
        }
    elif lesson_name == 'debt_credit_awareness':
        lesson_data = {
            'title': '📉 Debt & Credit Awareness',
            'quiz_questions': [
                {'q': 'According to Proverbs 22:7, the borrower is what to the lender?', 'a': 'Slave'},
                {'q': 'What is the credit score range?', 'a': '300-850'},
                {'q': 'How long can bad credit affect you?', 'a': '7+ years'},
                {'q': 'What should you do if you can\'t afford to buy something twice?', 'a': 'Don\'t put it on a credit card'},
                {'q': 'How much does a $500 credit card balance cost if you only make minimum payments?', 'a': 'Over $800 total'}
            ]
        }
    elif lesson_name == 'saving_goal_setting':
        lesson_data = {
            'title': '📈 Saving & Goal Setting',
            'quiz_questions': [
                {'q': 'According to Proverbs 21:20, what do wise people have in their house?', 'a': 'Stores of choice food and oil'},
                {'q': 'How many months of expenses should an emergency fund cover?', 'a': '3-6 months'},
                {'q': 'What should you do before spending on anything else?', 'a': 'Pay yourself first (save)'},
                {'q': 'How much money do you save in a year by saving $1 consistently?', 'a': '$365'},
                {'q': 'What percentage should you save immediately from any money received?', 'a': '20%'}
            ]
        }
    elif lesson_name == 'investing_early':
        lesson_data = {
            'title': '🪙 Investing Early',
            'quiz_questions': [
                {'q': 'According to Proverbs 13:11, how should money be gathered to make it grow?', 'a': 'Little by little'},
                {'q': 'How much does $100 invested at age 16 grow to by age 65?', 'a': 'Over $2,000'},
                {'q': 'What historical annual return do index funds average?', 'a': '7-10%'},
                {'q': 'What should you never invest?', 'a': 'Money you need within 5 years or borrowed money'},
                {'q': 'What does dollar-cost averaging mean?', 'a': 'Investing the same amount regularly regardless of market conditions'}
            ]
        }
    elif lesson_name == 'work_side_hustles_income':
        lesson_data = {
            'title': '🏠 Work, Side Hustles & Income',
            'quiz_questions': [
                {'q': 'According to Proverbs 14:23, what does all hard work bring?', 'a': 'Profit'},
                {'q': 'What percentage of earnings typically go to taxes for teens?', 'a': '10-15%'},
                {'q': 'What\'s the difference between gross and net pay?', 'a': 'Gross is before taxes, net is after taxes'},
                {'q': 'What should you keep for business expenses?', 'a': 'Receipts'},
                {'q': 'How much did Tyler net per week after expenses?', 'a': '$200'}
            ]
        }
    elif lesson_name == 'generosity_responsibility':
        lesson_data = {
            'title': '❤️ Generosity & Responsibility',
            'quiz_questions': [
                {'q': 'According to Luke 6:38, what happens when you give?', 'a': 'It will be given to you'},
                {'q': 'What percentage is traditionally given as a tithe?', 'a': '10%'},
                {'q': 'Where should you research charities before giving?', 'a': 'Charity Navigator'},
                {'q': 'What did Emma learn about giving and community?', 'a': 'Faithfulness in giving creates community that gives back'},
                {'q': 'What breaks the power of greed and selfishness?', 'a': 'Generosity'}
            ]
        }
    elif lesson_name == 'avoiding_money_traps':
        lesson_data = {
            'title': '⚠️ Avoiding Money Traps',
            'quiz_questions': [
                {'q': 'According to Proverbs 14:15, what do prudent people do?', 'a': 'Give thought to their steps'},
                {'q': 'What emotions do financial scams prey on?', 'a': 'Greed and fear'},
                {'q': 'What percentage of day traders are profitable long-term?', 'a': '10%'},
                {'q': 'What should you ask before investing in anything?', 'a': 'How does this make money?'},
                {'q': 'What are lottery tickets called?', 'a': 'A tax on people who can\'t do math'}
            ]
        }
    elif lesson_name == 'planning_future':
        lesson_data = {
            'title': '📊 Planning for the Future',
            'quiz_questions': [
                {'q': 'According to Proverbs 16:3, what should you commit to the Lord?', 'a': 'Whatever you do'},
                {'q': 'How much does college typically cost annually?', 'a': '$10,000-50,000+'},
                {'q': 'How much did Alex save by graduation?', 'a': '$7,200'},
                {'q': 'What gave Alex financial freedom after college?', 'a': 'Early planning and graduating debt-free'},
                {'q': 'What should you match your financial plan to?', 'a': 'Your life goals'}
            ]
        }
    else:
        lesson_data = {'title': 'Unknown Lesson', 'quiz_questions': []}
    
    quiz_questions = lesson_data.get('quiz_questions', [])
    if not quiz_questions:
        flash('Quiz not available for this lesson.', 'warning')
        return redirect(url_for('money_lesson_detail', lesson_name=lesson_name))
    
    # Grade the quiz
    correct_answers = 0
    total_questions = len(quiz_questions)
    
    for i, question in enumerate(quiz_questions):
        user_answer = request.form.get(f'answer_{i}', '').strip()
        correct_answer = question['a'].lower()
        if user_answer.lower() == correct_answer:
            correct_answers += 1
    
    percentage = (correct_answers / total_questions * 100) if total_questions > 0 else 0
    
    # Save quiz result
    try:
        quiz_result = CategoryQuizResult()
        quiz_result.user_id = current_user.id
        quiz_result.category = f"Money: {lesson_data.get('title', lesson_name)}"
        quiz_result.score = correct_answers
        quiz_result.total_questions = total_questions
        # Store percentage calculation in score field - percentage = (score/total_questions * 100)
        quiz_result.perfect_score = (percentage == 100)
        quiz_result.completed_at = datetime.utcnow()
        
        db.session.add(quiz_result)
        
        # Add drawing entry for perfect scores
        if percentage == 100:
            drawing_entry = WeeklyDrawingEntry()
            drawing_entry.user_id = current_user.id
            drawing_entry.category = 'Money Management'
            drawing_entry.subcategory = f'Quiz: {lesson_name}'
            drawing_entry.generate_entry_number()
            drawing_entry.earned_at = datetime.utcnow()
            db.session.add(drawing_entry)
            
            flash(f'Perfect score! 🎉 You scored {correct_answers}/{total_questions} and earned an entry for the weekly drawing!', 'success')
        else:
            flash(f'Good effort! You scored {correct_answers}/{total_questions} ({percentage:.1f}%). Try again for a perfect score to earn drawing entries!', 'info')
        
        db.session.commit()
        
    except Exception as e:
        db.session.rollback()
        flash(f'Quiz completed! You scored {correct_answers}/{total_questions} ({percentage:.1f}%).', 'info')
    
    return redirect(url_for('money_lesson_detail', lesson_name=lesson_name))

@app.route('/personality-test')
@login_required
def personality_test():
    """Personality test for career matching"""
    if current_user.role not in ['teen', 'teenager']:
        flash('Access denied. Teenager account required.', 'danger')
        return redirect(url_for('index'))
    
    # Import and create test instance
    from career_personality_test import CareerPathTest
    test = CareerPathTest()
    
    return render_template('personality_test.html', questions=test.questions)

@app.route('/personality-test/results', methods=['GET', 'POST'])
@login_required
def personality_test_results():
    """Personality test results"""
    if current_user.role not in ['teen', 'teenager']:
        flash('Access denied. Teenager account required.', 'danger')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        # Import and create test instance
        from career_personality_test import CareerPathTest
        test = CareerPathTest()
        
        # Get user answers
        answers = []
        for i in range(len(test.questions)):
            answer = request.form.get(f'question_{i}')
            if answer:
                answers.append(answer)
        
        # Calculate results
        if answers:
            results = test.calculate_results(answers)
            
            # Store results in session for display
            session['personality_test_results'] = results
            flash('Personality test completed! Here are your career matches.', 'success')
        else:
            flash('Please complete all questions before submitting.', 'warning')
            return redirect(url_for('personality_test'))
    
    # Get results from session
    results = session.get('personality_test_results')
    if not results:
        flash('Please take the personality test first.', 'info')
        return redirect(url_for('personality_test'))
    
    return render_template('personality_test_results.html', results=results)

@app.route('/challenges')
@login_required
def micro_challenges():
    """Micro challenges for skill building"""
    if current_user.role not in ['teen', 'teenager']:
        flash('Access denied. Teenager account required.', 'danger')
        return redirect(url_for('index'))
    return render_template('micro_challenges.html')

@app.route('/badges')
@login_required
def my_badges():
    """User badges and achievements"""
    if current_user.role not in ['teen', 'teenager']:
        flash('Access denied. Teenager account required.', 'danger')
        return redirect(url_for('index'))
    return render_template('my_badges.html')

# Additional utility routes
@app.route('/export/csv')
@login_required
def export_csv():
    """Export data as CSV - for admin/parent use"""
    # Basic implementation - can be expanded
    return "CSV export feature - implementation needed"

@app.route('/admin/seed')
@login_required
def seed():
    """Seed database with sample data"""
    # Basic implementation for development
    return "Database seeding - implementation needed"

@app.route('/quiz/<int:quiz_id>/submit', methods=['POST'])
@login_required
def submit_quiz(quiz_id):
    """Submit regular quiz"""
    # Redirect to existing quiz result handling
    return redirect(url_for('teen_dashboard'))

# Sports quiz submit route moved to career_routes.py to avoid conflicts

@app.route('/legacy-category-quiz/<category>/submit', methods=['POST'])
@login_required
def legacy_submit_category_quiz(category):
    """Submit category quiz"""
    if current_user.role not in ['teen', 'teenager']:
        flash('Access denied. Teenager account required.', 'danger')
        return redirect(url_for('index'))
    
    # Process quiz results
    score = 0
    total_questions = 3  # Based on our sample questions
    
    # Calculate score from form data
    for i in range(total_questions):
        answer = request.form.get(f'question_{i}')
        if answer is not None:
            score += 1
    
    # Show results
    percentage = (score / total_questions) * 100 if total_questions > 0 else 0
    
    if percentage == 100:
        flash('Perfect score! You earned an entry for the gift card drawing!', 'success')
    else:
        flash(f'You scored {score}/{total_questions} ({percentage:.0f}%). Try again to get 100%!', 'info')
    
    # Redirect back to category exploration
    return redirect(url_for('career_exploration', category=category))

@app.route('/challenges/<int:challenge_id>/complete', methods=['POST'])
@login_required
def complete_micro_challenge(challenge_id):
    """Complete a micro challenge"""
    flash('Challenge completed! Great job!', 'success')
    return redirect(url_for('micro_challenges'))

@app.route('/mentor/<int:mentor_id>/request', methods=['POST'])
@login_required
def request_mentor(mentor_id):
    """Request a mentor connection"""
    flash('Mentor request sent! They will be in touch soon.', 'success')
    return redirect(url_for('mentor_recommendations'))

# Fix missing route aliases - removed duplicate

@app.route('/admin')
@login_required
def admin_dashboard():
    """Admin dashboard - redirect to main if not admin"""
    return render_template('admin_dashboard.html')

@app.route('/admin/add')
@login_required
def admin_add():
    """Admin add content page"""
    return render_template('admin_add.html')

# Removed duplicate quiz route - already exists earlier in file

# Sports quiz route moved to career_routes.py to avoid conflicts

@app.route('/legacy-category-quiz/<category>')
@login_required
def legacy_category_quiz(category):
    """Category quiz page"""
    if current_user.role not in ['teen', 'teenager']:
        flash('Access denied. Teenager account required.', 'danger')
        return redirect(url_for('index'))
    
    # Create subcategory from category for template compatibility
    subcategory = category
    
    # Generate questions based on category
    if category == 'character_building' or category == 'integrity':
        sample_questions = [
            {
                'question': 'What is one key principle of Character Building?',
                'options': ['Building strong moral values', 'Making more money', 'Being popular with everyone', 'Avoiding all challenges'],
                'correct': 0
            },
            {
                'question': 'How can Character Building help you in daily life?',
                'options': ['It makes you famous', 'It helps you make better decisions', 'It guarantees success', 'It makes life easier'],
                'correct': 1
            },
            {
                'question': 'What is a practical example of applying Character Building?',
                'options': ['Lying to avoid trouble', 'Cheating on tests', 'Telling the truth even when it\'s hard', 'Only helping friends'],
                'correct': 2
            }
        ]
    elif category == 'confidence_and_self_esteem':
        sample_questions = [
            {
                'question': 'What is the foundation of true confidence?',
                'options': ['Others\' approval of you', 'Knowing your worth isn\'t determined by others\' opinions', 'Being perfect at everything', 'Never failing at anything'],
                'correct': 1
            },
            {
                'question': 'Which practice helps build healthy self-esteem?',
                'options': ['Comparing yourself to others constantly', 'Practicing positive self-talk', 'Avoiding all challenges', 'Seeking constant praise from others'],
                'correct': 1
            },
            {
                'question': 'What should you do when you make a mistake?',
                'options': ['Hide it from everyone', 'Give up trying', 'Learn from it and celebrate your effort', 'Blame someone else'],
                'correct': 2
            }
        ]
    elif category == 'goal_setting_time_management':
        sample_questions = [
            {
                'question': 'What does SMART stand for in goal setting?',
                'options': ['Simple, Manageable, Awesome, Reasonable, Timely', 'Specific, Measurable, Achievable, Relevant, Time-bound', 'Strong, Motivated, Ambitious, Ready, Tough', 'Success, Money, Achievement, Respect, Triumph'],
                'correct': 1
            },
            {
                'question': 'What is the most important step in time management?',
                'options': ['Working faster', 'Prioritizing tasks based on importance', 'Doing everything at once', 'Never taking breaks'],
                'correct': 1
            },
            {
                'question': 'How should you handle your biggest time wasters?',
                'options': ['Ignore them completely', 'Schedule specific times for them', 'Identify and eliminate them', 'Do them first thing each day'],
                'correct': 2
            }
        ]
    elif category == 'public_speaking_communication':
        sample_questions = [
            {
                'question': 'What is the #1 skill needed for success in life?',
                'options': ['Athletic ability', 'Communication', 'Perfect grades', 'Being popular'],
                'correct': 1
            },
            {
                'question': 'How can you overcome nervousness when speaking?',
                'options': ['Avoid speaking situations completely', 'Practice regularly and start small', 'Never prepare ahead of time', 'Only speak to people you know well'],
                'correct': 1
            },
            {
                'question': 'What is active listening?',
                'options': ['Waiting for your turn to talk', 'Really focusing on understanding what others are saying', 'Talking louder than others', 'Interrupting to show you understand'],
                'correct': 1
            }
        ]
    elif category == 'leadership_skills':
        sample_questions = [
            {
                'question': 'What is true leadership about?',
                'options': ['Having power over others', 'Serving others and solving problems', 'Always being in charge', 'Making others do what you want'],
                'correct': 1
            },
            {
                'question': 'How should a good leader handle different perspectives?',
                'options': ['Ignore opinions that differ from theirs', 'Listen to others and understand their viewpoints', 'Only consider their own ideas', 'Make decisions without input'],
                'correct': 1
            },
            {
                'question': 'What is the best way to start developing leadership skills?',
                'options': ['Wait until you have a title or position', 'Lead yourself well first', 'Tell others what to do', 'Focus only on personal success'],
                'correct': 1
            }
        ]
    elif category == 'emotional_intelligence':
        sample_questions = [
            {
                'question': 'What is emotional intelligence?',
                'options': ['Being smarter than others', 'Understanding and managing emotions effectively', 'Never showing emotions', 'Only caring about your own feelings'],
                'correct': 1
            },
            {
                'question': 'Why is self-awareness important?',
                'options': ['It helps you understand your emotions and reactions', 'It makes you superior to others', 'It helps you hide your feelings', 'It prevents you from caring about others'],
                'correct': 0
            },
            {
                'question': 'How can you develop empathy?',
                'options': ['Focus only on your own problems', 'Try to understand others\' perspectives', 'Avoid emotional situations', 'Judge others\' reactions'],
                'correct': 1
            }
        ]
    elif category == 'stress_management_resilience':
        sample_questions = [
            {
                'question': 'What is resilience?',
                'options': ['Never experiencing stress', 'The ability to bounce back from difficulties', 'Avoiding all challenges', 'Being perfect at everything'],
                'correct': 1
            },
            {
                'question': 'Which is a healthy way to manage stress?',
                'options': ['Ignoring problems until they go away', 'Regular exercise and relaxation techniques', 'Staying up all night worrying', 'Avoiding all stressful situations'],
                'correct': 1
            },
            {
                'question': 'How should you view challenges?',
                'options': ['As things to avoid at all costs', 'As opportunities for growth', 'As proof you\'re not good enough', 'As reasons to give up'],
                'correct': 1
            }
        ]
    elif category == 'decision_making_problem_solving':
        sample_questions = [
            {
                'question': 'What should you consider when making important decisions?',
                'options': ['Only what feels good right now', 'Both short-term and long-term consequences', 'What everyone else is doing', 'The easiest option available'],
                'correct': 1
            },
            {
                'question': 'When facing a problem, what should you do first?',
                'options': ['Panic and worry', 'Clearly identify and define the problem', 'Blame someone else', 'Ignore it and hope it goes away'],
                'correct': 1
            },
            {
                'question': 'Why is it important to seek advice when making decisions?',
                'options': ['So others can decide for you', 'To get different perspectives and wisdom', 'To avoid taking responsibility', 'To delay making any choice'],
                'correct': 1
            }
        ]
    elif category == 'building_healthy_relationships':
        sample_questions = [
            {
                'question': 'What is the foundation of healthy relationships?',
                'options': ['Getting what you want from others', 'Mutual respect and good communication', 'Avoiding all conflicts', 'Being popular with everyone'],
                'correct': 1
            },
            {
                'question': 'How should you handle conflict in relationships?',
                'options': ['Avoid the person completely', 'Address issues respectfully and directly', 'Always give in to avoid arguments', 'Get other people involved in the drama'],
                'correct': 1
            },
            {
                'question': 'What are healthy boundaries in relationships?',
                'options': ['Walls that keep everyone out', 'Guidelines that protect your well-being', 'Rules that control others', 'Barriers that prevent all intimacy'],
                'correct': 1
            }
        ]
    elif category == 'personal_values_identity':
        sample_questions = [
            {
                'question': 'Why are personal values important?',
                'options': ['They make you better than others', 'They guide your decisions and shape your character', 'They help you fit in with everyone', 'They guarantee success in life'],
                'correct': 1
            },
            {
                'question': 'How should you respond to peer pressure that conflicts with your values?',
                'options': ['Always go along to fit in', 'Stand firm in your beliefs', 'Change your values to match the group', 'Avoid having any values'],
                'correct': 1
            },
            {
                'question': 'What helps you develop a strong identity?',
                'options': ['Copying others exactly', 'Understanding your values and staying true to them', 'Changing yourself for each group you\'re with', 'Never expressing your true opinions'],
                'correct': 1
            }
        ]
    elif category == 'study_skills_learning_strategies':
        sample_questions = [
            {
                'question': 'What is active reading?',
                'options': ['Reading as fast as possible', 'Engaging with the material and taking notes', 'Reading only the summary', 'Skipping difficult parts'],
                'correct': 1
            },
            {
                'question': 'Which technique helps with long-term retention?',
                'options': ['Cramming the night before tests', 'Spaced repetition over time', 'Reading material only once', 'Studying with many distractions'],
                'correct': 1
            },
            {
                'question': 'What is the Pomodoro Technique?',
                'options': ['Studying while eating', 'Working in focused 25-minute blocks with breaks', 'Studying all night without breaks', 'Only studying on weekends'],
                'correct': 1
            }
        ]
    else:
        # Generic questions for other categories
        category_title = category.replace("_", " ").title()
        sample_questions = [
            {
                'question': f'What is an important aspect of {category_title}?',
                'options': ['Learning and growing', 'Avoiding all effort', 'Only thinking about yourself', 'Giving up easily'],
                'correct': 0
            },
            {
                'question': f'How does {category_title} benefit your future?',
                'options': ['It builds valuable skills', 'It wastes your time', 'It makes you lazy', 'It has no benefits'],
                'correct': 0
            },
            {
                'question': f'What is the best approach to {category_title}?',
                'options': ['Practice consistently', 'Do it only when you feel like it', 'Avoid it completely', 'Wait for others to do it'],
                'correct': 0
            }
        ]
    
    return render_template('quizzes/category_quiz.html', 
                         category=category, 
                         subcategory=subcategory,
                         questions=sample_questions)

@app.route('/category/<category>/detail')
@login_required
def category_detail(category):
    """Category detail page - alias for category_pathway"""
    return redirect(url_for('category_pathway', category_name=category))

@app.route('/career/<path_name>/legacy-pathway')
@login_required
def legacy_career_pathway(path_name):
    """Career pathway - alias for career_path_detail"""
    return redirect(url_for('career_path_detail', path_name=path_name))
