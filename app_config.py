"""
MentorMe Application Configuration
Manages app branding and landing page content
"""
import json
import os
from datetime import datetime

class AppConfig:
    """Configuration manager for MentorMe app settings"""
    CONFIG_FILE = "mentorme_config.json"
    
    DEFAULT_CONFIG = {
        "app_name": "MentorMe",
        "app_tagline": "Learning life skills — money, choices, safety, health, careers",
        "welcome_message": "Welcome to MentorMe",
        "welcome_subtitle": "Sign up to personalize your learning experience.",
        "logo_filename": "logo_1756155752833.png",
        "theme": "dark",
        "version": "1.0.0",
        "last_updated": None
    }
    
    @classmethod
    def load_config(cls):
        """Load configuration from file or create default if not exists"""
        if os.path.exists(cls.CONFIG_FILE):
            try:
                with open(cls.CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                    # Ensure all default keys exist
                    for key, value in cls.DEFAULT_CONFIG.items():
                        if key not in config:
                            config[key] = value
                    return config
            except Exception:
                return cls.DEFAULT_CONFIG.copy()
        else:
            # Create default config file
            default_config = cls.DEFAULT_CONFIG.copy()
            default_config["last_updated"] = datetime.utcnow().isoformat()
            cls.save_config(default_config)
            return default_config
    
    @classmethod
    def save_config(cls, config):
        """Save configuration to file"""
        config["last_updated"] = datetime.utcnow().isoformat()
        with open(cls.CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=4)
    
    @classmethod
    def get_cache_buster(cls):
        """Get a unique cache buster value"""
        return int(datetime.utcnow().timestamp())
    
    @classmethod
    def update_branding(cls, **kwargs):
        """Update specific branding elements"""
        config = cls.load_config()
        for key, value in kwargs.items():
            if key in cls.DEFAULT_CONFIG:
                config[key] = value
        cls.save_config(config)
        return config