from app import db
from flask_login import UserMixin
from passlib.hash import bcrypt
from sqlalchemy import Column, Integer, String, Text, Boolean, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from datetime import datetime, timedelta
import secrets
import string

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150))
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default='teen')  # teen | parent
    subscription_active = db.Column(db.Boolean, default=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    children = relationship('User', remote_side=[id])
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    age = db.Column(db.Integer, nullable=True)
    city = db.Column(db.String(100), nullable=True)
    consent_pending = db.Column(db.Boolean, default=False)
    parental_consent = db.Column(db.Boolean, default=False)
    parent_email_pending = db.Column(db.String(250), nullable=True)
    phone_number = db.Column(db.String(20), nullable=True)
    temp_password = db.Column(db.String(100), nullable=True)
    temp_password_expires = db.Column(db.DateTime, nullable=True)
    
    # Terms and Privacy Policy Acceptance
    terms_accepted = db.Column(db.Boolean, default=False)
    terms_accepted_at = db.Column(db.DateTime, nullable=True)
    privacy_accepted = db.Column(db.Boolean, default=False)
    privacy_accepted_at = db.Column(db.DateTime, nullable=True)
    parent_consent_for_terms = db.Column(db.Boolean, default=False)
    parent_consent_terms_at = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    settings = relationship('UserSettings', uselist=False, backref='user')
    feedback = relationship('UserFeedback', backref='user')

    def check_password(self, password):
        return bcrypt.verify(password, self.password_hash)

    def set_password(self, password):
        self.password_hash = bcrypt.hash(password)
    
    def generate_temp_password(self):
        """Generate a temporary 6-digit password"""
        temp_pass = ''.join(secrets.choice(string.digits) for _ in range(6))
        self.temp_password = temp_pass
        self.temp_password_expires = datetime.utcnow() + timedelta(minutes=15)
        return temp_pass
    
    def check_temp_password(self, password):
        """Check if temporary password is valid and not expired"""
        if not self.temp_password or not self.temp_password_expires:
            return False
        if datetime.utcnow() > self.temp_password_expires:
            return False
        return self.temp_password == password
    
    def clear_temp_password(self):
        """Clear temporary password after use"""
        self.temp_password = None
        self.temp_password_expires = None

class Topic(db.Model):
    __tablename__ = 'topics'
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(80))
    title = db.Column(db.String(250))
    slug = db.Column(db.String(250))
    body = db.Column(db.Text)
    examples = db.Column(db.Text)
    extra = db.Column(db.Text)  # JSON: checklist, verse, devotion, subtopics
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)

class Quiz(db.Model):
    __tablename__ = 'quizzes'
    id = db.Column(db.Integer, primary_key=True)
    topic_id = db.Column(db.Integer, db.ForeignKey('topics.id'))
    title = db.Column(db.String(200))
    questions_json = db.Column(db.Text)

class QuizResult(db.Model):
    __tablename__ = 'quiz_results'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    quiz_id = db.Column(db.Integer, db.ForeignKey('quizzes.id'))
    topic_id = db.Column(db.Integer, db.ForeignKey('topics.id'))
    score = db.Column(db.Integer)
    total = db.Column(db.Integer)
    percentage = db.Column(db.Float)
    taken_at = db.Column(db.DateTime, default=datetime.utcnow)

class ChecklistProgress(db.Model):
    __tablename__ = 'checklist_progress'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    topic_id = db.Column(db.Integer, db.ForeignKey('topics.id'))
    item = db.Column(db.String(400))
    completed = db.Column(db.Boolean, default=False)

class SignedNDA(db.Model):
    __tablename__ = 'signed_ndas'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    user_name = db.Column(db.String(150))
    user_email = db.Column(db.String(250))
    date_signed = db.Column(db.DateTime, default=datetime.utcnow)
    nda_text = db.Column(db.Text)

class CareerPath(db.Model):
    __tablename__ = 'career_paths'
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(100))  # Sports, Careers, Health, etc.
    title = db.Column(db.String(200))
    slug = db.Column(db.String(200))
    pathway_content = db.Column(db.Text)  # Detailed step-by-step guidance
    requirements = db.Column(db.Text)  # Education, skills needed
    timeline = db.Column(db.Text)  # Jr High → High School → College → Career
    success_tips = db.Column(db.Text)
    challenges = db.Column(db.Text)
    salary_info = db.Column(db.Text)
    icon = db.Column(db.String(50))  # Emoji or icon
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class TeenSupport(db.Model):
    __tablename__ = 'teen_support'
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(100))  # Emotional Support, Safety, Health
    issue_title = db.Column(db.String(300))
    description = db.Column(db.Text)
    advice = db.Column(db.Text)
    bible_verses = db.Column(db.Text)  # JSON array of verses
    resources = db.Column(db.Text)  # Links and contacts
    severity_level = db.Column(db.String(50))  # Low, Medium, High, Emergency

class JobOpportunity(db.Model):
    __tablename__ = 'job_opportunities'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    age_range = db.Column(db.String(50))  # 13-15, 16-18, etc.
    description = db.Column(db.Text)
    requirements = db.Column(db.Text)
    pay_range = db.Column(db.String(100))
    application_tips = db.Column(db.Text)
    common_locations = db.Column(db.Text)

class UserInterest(db.Model):
    __tablename__ = 'user_interests'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    category = db.Column(db.String(100))
    interest_item = db.Column(db.String(200))
    added_at = db.Column(db.DateTime, default=datetime.utcnow)

class Mentor(db.Model):
    __tablename__ = 'mentors'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    phone = db.Column(db.String(20))
    bio = db.Column(db.Text)
    specialties = db.Column(db.Text)  # JSON array of specialties
    experience_years = db.Column(db.Integer)
    education = db.Column(db.String(300))
    current_job = db.Column(db.String(200))
    age_groups = db.Column(db.String(100))  # "8-10,11-13,14-15,16-17"
    availability = db.Column(db.String(200))  # "weekends,evenings"
    meeting_format = db.Column(db.String(100))  # "in-person,virtual,both"
    city = db.Column(db.String(100))
    state = db.Column(db.String(50))
    profile_image = db.Column(db.String(300))
    is_verified = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    rating = db.Column(db.Float, default=0.0)
    total_mentees = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class MentorSpecialty(db.Model):
    __tablename__ = 'mentor_specialties'
    id = db.Column(db.Integer, primary_key=True)
    mentor_id = db.Column(db.Integer, db.ForeignKey('mentors.id'))
    category = db.Column(db.String(100))  # Sports, Career, Personal Development, etc.
    specialty = db.Column(db.String(200))  # Football, Engineering, Confidence Building, etc.
    proficiency_level = db.Column(db.String(50))  # Beginner, Intermediate, Expert

class MentorRecommendation(db.Model):
    __tablename__ = 'mentor_recommendations'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    mentor_id = db.Column(db.Integer, db.ForeignKey('mentors.id'))
    match_score = db.Column(db.Float)  # 0.0 to 1.0
    match_reasons = db.Column(db.Text)  # JSON array of reasons
    recommendation_date = db.Column(db.DateTime, default=datetime.utcnow)
    is_contacted = db.Column(db.Boolean, default=False)
    status = db.Column(db.String(50), default='recommended')  # recommended, contacted, matched, declined

class UserMentorMatch(db.Model):
    __tablename__ = 'user_mentor_matches'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    mentor_id = db.Column(db.Integer, db.ForeignKey('mentors.id'))
    match_date = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50), default='pending')  # pending, active, completed, cancelled
    meeting_frequency = db.Column(db.String(50))  # weekly, biweekly, monthly
    goals = db.Column(db.Text)  # Teen's goals for mentoring
    notes = db.Column(db.Text)  # Progress notes

class SportsQuizResult(db.Model):
    __tablename__ = 'sports_quiz_results'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    sport_name = db.Column(db.String(100))
    city = db.Column(db.String(100))
    age = db.Column(db.Integer)
    score = db.Column(db.Integer)
    total_questions = db.Column(db.Integer, default=10)
    completed_at = db.Column(db.DateTime, default=datetime.utcnow)
    perfect_score = db.Column(db.Boolean, default=False)

class WeeklyDrawingEntry(db.Model):
    __tablename__ = 'weekly_drawing_entries'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    entry_number = db.Column(db.String(20))  # Random number for drawing
    category = db.Column(db.String(100))  # sports, careers, personal_development, etc.
    subcategory = db.Column(db.String(100))  # football, doctor, confidence, etc.
    earned_at = db.Column(db.DateTime, default=datetime.utcnow)
    week_ending = db.Column(db.DateTime)  # Week this entry is valid for
    
    # Relationship to user for privacy settings
    user = relationship('User', backref='drawing_entries')
    
    def generate_entry_number(self):
        """Generate a random 6-digit entry number"""
        entry_num = ''.join(secrets.choice(string.digits) for _ in range(6))
        self.entry_number = entry_num
        return entry_num

class CategoryQuizResult(db.Model):
    __tablename__ = 'category_quiz_results'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    category = db.Column(db.String(100))  # personal_development, technology, etc.
    subcategory = db.Column(db.String(100))  # confidence, coding, etc.
    city = db.Column(db.String(100), nullable=True)  # For career paths
    age = db.Column(db.Integer, nullable=True)
    score = db.Column(db.Integer)
    total_questions = db.Column(db.Integer, default=10)
    completed_at = db.Column(db.DateTime, default=datetime.utcnow)
    perfect_score = db.Column(db.Boolean, default=False)

class AIChatHistory(db.Model):
    __tablename__ = 'ai_chat_history'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    question = db.Column(db.Text, nullable=False)
    answer = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class UserBadge(db.Model):
    __tablename__ = 'user_badges'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    badge_type = db.Column(db.String(100))  # quiz_perfect, micro_challenge, etc.
    badge_name = db.Column(db.String(200))  # "Football Quiz Master", "Study Champion", etc.
    pin_number = db.Column(db.String(20))  # 6-digit pin for weekly drawing
    category = db.Column(db.String(100))  # sports, career, personal_development, etc.
    subcategory = db.Column(db.String(100))  # football, doctor, confidence, etc.
    earned_at = db.Column(db.DateTime, default=datetime.utcnow)
    week_ending = db.Column(db.DateTime)  # Week this badge/pin is valid for drawing
    
    def generate_pin_number(self):
        """Generate a random 6-digit pin number"""
        pin = ''.join(secrets.choice(string.digits) for _ in range(6))
        self.pin_number = pin
        return pin

class WeeklyDrawing(db.Model):
    __tablename__ = 'weekly_drawings'
    id = db.Column(db.Integer, primary_key=True)
    week_ending = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(50), default='active')  # active, completed
    total_entries = db.Column(db.Integer, default=0)
    winner_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    winning_pin = db.Column(db.String(20), nullable=True)
    prize_amount = db.Column(db.String(50), nullable=True)  # "$25 Gift Card"
    drawn_at = db.Column(db.DateTime, nullable=True)

class MicroChallenge(db.Model):
    __tablename__ = 'micro_challenges'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    description = db.Column(db.Text)
    badge_name = db.Column(db.String(200))
    points_required = db.Column(db.Integer, default=1)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class UserMicroChallenge(db.Model):
    __tablename__ = 'user_micro_challenges'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    challenge_id = db.Column(db.Integer, db.ForeignKey('micro_challenges.id'))
    completed_at = db.Column(db.DateTime, default=datetime.utcnow)
    month_year = db.Column(db.String(7))  # "2025-08" format for monthly limit

class UserSettings(db.Model):
    __tablename__ = 'user_settings'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), unique=True)
    
    # Notification Preferences
    quiz_reminders = db.Column(db.Boolean, default=True)
    content_alerts = db.Column(db.Boolean, default=True)
    drawing_notifications = db.Column(db.Boolean, default=True)
    quiet_hours_start = db.Column(db.String(5))  # "22:00"
    quiet_hours_end = db.Column(db.String(5))    # "08:00"
    
    # Privacy Controls
    show_activity_to_mentors = db.Column(db.Boolean, default=True)
    show_activity_to_peers = db.Column(db.Boolean, default=False)
    hide_name_in_drawings = db.Column(db.Boolean, default=False)
    
    # Accessibility Options
    audio_quiz_questions = db.Column(db.Boolean, default=False)
    
    # Dashboard Preferences
    favorite_categories = db.Column(db.Text)  # JSON array of categories
    hidden_categories = db.Column(db.Text)   # JSON array to hide
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class UserFeedback(db.Model):
    __tablename__ = 'user_feedback'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    feedback_text = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(100))  # suggestion, bug_report, feature_request
    status = db.Column(db.String(50), default='pending')  # pending, reviewed, implemented
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
    reviewed_at = db.Column(db.DateTime)
    admin_response = db.Column(db.Text)

class ResourceLibrary(db.Model):
    __tablename__ = 'resource_library'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    category = db.Column(db.String(100))  # career, education, life_skills
    resource_type = db.Column(db.String(50))  # pdf, video, link
    file_path = db.Column(db.String(300))  # For downloadable files
    external_url = db.Column(db.String(300))  # For external links
    is_featured = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class ChatHistory(db.Model):
    __tablename__ = 'teen_chat_history'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    response = db.Column(db.Text, nullable=False)
    topic = db.Column(db.String(100), nullable=True)  # What topic was being discussed
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship
    user = relationship('User', backref='teen_chat_history')

class TeenInterest(db.Model):
    __tablename__ = 'teen_interests'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    category = db.Column(db.String(100), nullable=False)  # Sports, Career, Hobby, etc.
    interest = db.Column(db.String(200), nullable=False)  # Specific interest
    level = db.Column(db.String(50), nullable=True)  # Beginner, Intermediate, Advanced
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship
    user = relationship('User', backref='teen_interests')

class TeenAccomplishment(db.Model):
    __tablename__ = 'teen_accomplishments'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    category = db.Column(db.String(100), nullable=False)  # Quiz, Life Skill, Goal, etc.
    points_earned = db.Column(db.Integer, default=0)
    achieved_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship
    user = relationship('User', backref='teen_accomplishments')

class RelationshipVideo(db.Model):
    __tablename__ = 'relationship_videos'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    video_url = db.Column(db.String(500), nullable=False)
    thumbnail_url = db.Column(db.String(500), nullable=True)
    category = db.Column(db.String(100), nullable=False)  # Communication, Trust, Support, etc.
    target_age_group = db.Column(db.String(20), nullable=True)  # 8-10, 11-13, 14-15, 16-17
    duration_minutes = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
