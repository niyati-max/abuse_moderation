import re
from datetime import datetime, timedelta
from typing import Dict
from sqlalchemy.orm import Session
from difflib import SequenceMatcher
import models

def calculate_similarity(text1: str, text2: str) -> float:
    """Calculate text similarity ratio between two texts"""
    return SequenceMatcher(None, text1.lower().strip(), text2.lower().strip()).ratio()

def is_promotional_content(text: str) -> bool:
    """Check if text contains promotional/spam keywords"""
    promotional_keywords = [
        'check out my', 'visit my', 'click here', 'buy now',
        'follow me', 'subscribe to', 'check my profile', 'dm me',
        'whatsapp', 'telegram', 'link in bio', 'follow for follow',
        'check this out', 'visit here', 'my website', 'my channel',
        'discount', 'limited offer', 'earn money', 'work from home'
    ]
    
    text_lower = text.lower()
    
    # Check for promotional keywords
    has_promotional = any(keyword in text_lower for keyword in promotional_keywords)
    
    # Check for URLs
    url_pattern = r'http[s]?://\S+|www\.\S+|\S+\.(com|net|org|io|co)\S*'
    has_url = bool(re.search(url_pattern, text_lower))
    
    return has_promotional or has_url

def detect_spam(text: str, user_id: int, post_id: int, db: Session) -> Dict:
    """
    Spam Detection Logic:
    1. Promotional: Allow 3 → Warning at 4 → Spam at 5 (HIDE ALL 5)
    2. Repetitive: Allow 5 → Warning at 6 → Spam at 7 (HIDE warning + spam only)
    
    Returns: dict with is_spam, reasons, confidence, action, message
    """
    
    text_clean = text.strip()
    
    # Get all comments by this user on THIS SPECIFIC POST
    user_comments_on_this_post = db.query(models.Comment).filter(
        models.Comment.user_id == user_id,
        models.Comment.post_id == post_id,
        models.Comment.status != "deleted"
    ).order_by(models.Comment.created_at.desc()).all()
    
    # Count exact and similar repetitions ON THIS POST ONLY
    exact_count = 0
    similar_count = 0
    similar_comment_ids = []  # Track IDs for hiding
    
    for comment in user_comments_on_this_post:
        similarity = calculate_similarity(text_clean, comment.text)
        if similarity == 1.0:
            exact_count += 1
            similar_comment_ids.append(comment.id)
        elif similarity >= 0.85:
            similar_count += 1
            similar_comment_ids.append(comment.id)
    
    # Check if content is promotional
    is_promotional = is_promotional_content(text_clean)
    
    total_repetitions = max(exact_count, similar_count)
    
    # CASE 1: Promotional spam at 5th repetition - HIDE ALL
    if is_promotional and total_repetitions >= 4:
        return {
            "is_spam": True,
            "reasons": ["promotional_repetition_same_post"],
            "confidence": 95,
            "action": "auto_hide",
            "hide_all": True,  # NEW: Flag to hide all similar comments
            "similar_comment_ids": similar_comment_ids,  # NEW: IDs to hide
            "message": f"🚫 Spam Detected! Promotional content repeated {total_repetitions + 1} times on this post. All promotional comments have been hidden."
        }
    
    # CASE 2: Repetitive spam at 7th repetition - HIDE warning + spam only
    if total_repetitions >= 6:
        return {
            "is_spam": True,
            "reasons": ["excessive_repetition_same_post"],
            "confidence": 100,
            "action": "auto_hide",
            "hide_all": False,  # NEW: Don't hide all, only recent ones
            "similar_comment_ids": [],  # No bulk hiding
            "message": f"🚫 Spam Detected! Comment repeated {total_repetitions + 1} times on this post. Recent repetitive comments have been hidden."
        }
    
    # Warning for promotional content (4th repetition)
    if is_promotional and total_repetitions >= 3:
        return {
            "is_spam": False,
            "reasons": ["promotional_warning"],
            "confidence": 50,
            "action": "warning",
            "message": f"⚠️ Warning: You've posted similar promotional content {total_repetitions + 1} times on this post. One more repetition will result in all promotional comments being hidden."
        }
    
    # Warning for repetitive content (6th repetition)
    if total_repetitions >= 5:
        return {
            "is_spam": False,
            "reasons": ["repetition_warning"],
            "confidence": 50,
            "action": "warning",
            "message": f"⚠️ Warning: You've posted similar comments {total_repetitions + 1} times on this post. Further repetition will result in spam detection."
        }
    
    # Not spam
    return {
        "is_spam": False,
        "reasons": [],
        "confidence": 0,
        "action": "allow",
        "message": "No spam detected"
    }