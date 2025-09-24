"""
MentorMe Profanity Filter System
Comprehensive filtering system for teen-focused educational platform
"""

import re
import json
from typing import List, Tuple, Dict, Any

class ProfanityFilter:
    """Advanced profanity filtering system with normalization and context awareness"""
    
    def __init__(self):
        self.blocked_words = self._get_blocked_words()
        self.bypass_patterns = self._get_bypass_patterns()
        
    def _get_blocked_words(self) -> List[str]:
        """Get comprehensive list of blocked words and phrases"""
        return [
            # Racial/Ethnic Slurs (heavily censored for safety)
            'n****r', 'n***a', 'k**e', 's**c', 'ch**k', 'g**k', 'sp**', 'w*tb**k',
            
            # Homophobic & Transphobic Slurs
            'f****t', 'd**e', 'f*g', 'tr**ny', 'h*mo', 'shem*le',
            
            # Ableist Slurs
            'r*t*rd', 'r*tard', 'sp*z', 'cr*pple', 'm*ng',
            
            # General Profanity
            'fuck', 'fucking', 'motherfucker', 'fucker', 'f**k', 'fck', 'phuck',
            'shit', 'bullshit', 'shitty', 'sh*t', 's**t', 'sh1t', '5hit',
            'asshole', 'dumbass', 'smartass', 'a**', 'a*s', '@ss', '@sshole',
            'bitch', 'b*tch', 'b1tch', 'biatch',
            'piss', 'pissed', 'p*ss',
            'dick', 'd*ck', 'dicc', 'd1ck',
            'cock', 'c*ck', 'kock',
            'pussy', 'p*ssy', 'pussey',
            'bastard', 'b*stard',
            'damn', 'd*mn',
            'hell', 'h*ll',
            'crap', 'cr*p',
            
            # Sexual Content
            'porn', 'pornography', 'p*rn',
            'nude', 'naked', 'n*ked',
            'sex', 'sexy', 'sexual', 's*x',
            'rape', 'rapist', 'r*pe',
            'molest', 'mol*st',
            'incest', 'inc*st',
            'fetish', 'f*tish',
            'orgasm', 'org*sm',
            'erotic', 'er*tic',
            'hentai', 'h*ntai',
            
            # Violent Language
            'kill', 'killer', 'killing', 'k*ll',
            'murder', 'murderer', 'm*rder',
            'die', 'death', 'dead', 'd*e',
            'suicide', 'kms', 'kill myself', 'su*cide',
            'shoot', 'shooting', 'sh**t',
            'stab', 'knife', 'st*b',
            'bomb', 'b*mb',
            'terror', 'terrorist', 'terr*r',
            
            # Bullying Terms
            'loser', 'l*ser',
            'hater', 'h*ter',
            'ugly', 'ugl*',
            'stupid', 'st*pid',
            'dumb', 'd*mb',
            'worthless', 'w*rthless',
            'useless', 'us*less',
            
            # Common Bypasses
            'fuk', 'fuq', 'sheeit', 'shiit', 'azz', 'biach'
        ]
    
    def _get_bypass_patterns(self) -> List[str]:
        """Get patterns commonly used to bypass filters"""
        return [
            r'f[\s\*\-_]*u[\s\*\-_]*c[\s\*\-_]*k',  # f u c k, f*u*c*k
            r's[\s\*\-_]*h[\s\*\-_]*i[\s\*\-_]*t',  # s h i t, s*h*i*t
            r'b[\s\*\-_]*i[\s\*\-_]*t[\s\*\-_]*c[\s\*\-_]*h',  # b i t c h
            r'a[\s\*\-_]*s[\s\*\-_]*s',  # a s s
            r'n[\s\*\-_]*i[\s\*\-_]*g[\s\*\-_]*g',  # n i g g patterns
        ]
    
    def normalize_text(self, text: str) -> str:
        """Normalize text by removing common bypass techniques"""
        if not text:
            return ""
            
        # Convert to lowercase
        normalized = text.lower()
        
        # Remove numbers commonly used as letter substitutes
        substitutions = {
            '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's',
            '7': 't', '8': 'b', '@': 'a', '$': 's'
        }
        
        for num, letter in substitutions.items():
            normalized = normalized.replace(num, letter)
        
        # Remove spaces, symbols, and repeated characters
        normalized = re.sub(r'[\s\*\-_\.,;:!?\'"]+', '', normalized)
        normalized = re.sub(r'(.)\1{2,}', r'\1', normalized)  # Remove repeated chars
        
        return normalized
    
    def contains_profanity(self, text: str) -> Tuple[bool, List[str]]:
        """
        Check if text contains profanity
        Returns: (has_profanity: bool, found_words: List[str])
        """
        if not text:
            return False, []
            
        found_words = []
        normalized = self.normalize_text(text)
        original_lower = text.lower()
        
        # Check exact matches in blocked words
        for word in self.blocked_words:
            clean_word = word.replace('*', '')
            if clean_word in normalized or clean_word in original_lower:
                found_words.append(word)
        
        # Check bypass patterns
        for pattern in self.bypass_patterns:
            if re.search(pattern, normalized, re.IGNORECASE):
                found_words.append(f"pattern_match: {pattern}")
        
        return bool(found_words), found_words
    
    def filter_text(self, text: str) -> str:
        """Filter profanity from text, replacing with appropriate message"""
        has_profanity, _ = self.contains_profanity(text)
        
        if has_profanity:
            return "[Content filtered - please use appropriate language]"
        
        return text
    
    def validate_feedback(self, feedback_text: str) -> Dict[str, Any]:
        """
        Validate feedback text for submission
        Returns validation result with status and message
        """
        if not feedback_text or not feedback_text.strip():
            return {
                'valid': False,
                'message': 'Feedback cannot be empty. Please share your thoughts!',
                'filtered_text': ''
            }
        
        has_profanity, found_words = self.contains_profanity(feedback_text)
        
        if has_profanity:
            return {
                'valid': False,
                'message': 'Whoops! It looks like your message contained words we don\'t allow to keep our community safe and positive. Please rephrase your feedback using appropriate language.',
                'filtered_text': '',
                'blocked_words': len(found_words)  # Don't reveal actual words
            }
        
        # Additional validation for minimum length
        if len(feedback_text.strip()) < 10:
            return {
                'valid': False,
                'message': 'Please provide more detailed feedback (at least 10 characters).',
                'filtered_text': feedback_text
            }
        
        return {
            'valid': True,
            'message': 'Feedback is ready for submission!',
            'filtered_text': feedback_text.strip()
        }

# Global instance for use in routes
profanity_filter = ProfanityFilter()