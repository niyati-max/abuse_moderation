from sqlalchemy import Column, Integer, String, ForeignKey, Text, DateTime, Boolean, Index
from sqlalchemy.orm import relationship
from datetime import datetime
from database import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True)
    
    # Authentication fields
    password_hash = Column(String, nullable=False)
    role = Column(String, default="user")  # "user", "moderator" or "admin"
    created_at = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True) 
    last_login = Column(DateTime, nullable=True) 

    # Suspension fields
    is_suspended = Column(Boolean, default=False, index=True)
    suspended_at = Column(DateTime, nullable=True)
    suspension_reason = Column(String, nullable=True)
    suspended_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    suspension_appeal_count = Column(Integer, default=0)
    
    # Email verification fields
    email_verified = Column(Boolean, default=False)
    email_verification_token = Column(String, nullable=True)
    
    # Warning system fields
    warning_count = Column(Integer, default=0)
    last_warning_sent = Column(DateTime, nullable=True)

    # Relationships
    posts = relationship("Post", back_populates="author", foreign_keys="Post.author_id")
    comments = relationship("Comment", back_populates="author", foreign_keys="Comment.user_id")
    suspended_users = relationship("User", foreign_keys=[suspended_by], remote_side=[id])

class Post(Base):
    __tablename__ = "posts"
    id = Column(Integer, primary_key=True, index=True)
    content = Column(Text, nullable=False)
    author_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    # Relationships
    comments = relationship("Comment", back_populates="post", cascade="all, delete-orphan")
    author = relationship("User", back_populates="posts", foreign_keys=[author_id])

class Comment(Base):
    __tablename__ = "comments"
    id = Column(Integer, primary_key=True, index=True)
    text = Column(Text, nullable=False)
    is_abusive = Column(Integer, default=0, index=True)  # 0=clean, 1=abusive

    is_spam = Column(Integer, default=0, index=True)  # 0=not spam, 1=spam
    spam_reasons = Column(String)  # Comma-separated spam reasons
    spam_confidence = Column(Integer, default=0)  # 0-100
    
    # Enhanced moderation fields
    status = Column(String, default="approved", index=True)  # "approved", "hidden", "pending_review"
    confidence_score = Column(Integer, default=0)
    flagged_words = Column(String)  # Comma-separated list
    
    # Auto-review fields
    auto_review_action = Column(String, index=True)  # "approve", "auto_approve", "keep_hidden", "human_review_needed"
    auto_review_reason = Column(String)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    moderated_at = Column(DateTime)
    
    # Foreign keys
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    post_id = Column(Integer, ForeignKey("posts.id"), nullable=False, index=True)
    moderated_by = Column(Integer, ForeignKey("users.id"))
    
    # Relationships
    author = relationship("User", back_populates="comments", foreign_keys=[user_id])
    post = relationship("Post", back_populates="comments", foreign_keys=[post_id])
    moderator = relationship("User", foreign_keys=[moderated_by])

class UserBlock(Base):
    __tablename__ = "user_blocks"
    
    id = Column(Integer, primary_key=True, index=True)
    blocker_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    blocked_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    reason = Column(String, nullable=True)  # "auto_abuse" or "manual"
    
    # Relationships
    blocker = relationship("User", foreign_keys=[blocker_id])
    blocked = relationship("User", foreign_keys=[blocked_id])
    
    # Ensure unique blocking relationships
    __table_args__ = (Index('idx_blocker_blocked', 'blocker_id', 'blocked_id', unique=True),)

class DeletedPost(Base):
    """Store deleted posts for user notifications"""
    __tablename__ = "deleted_posts"
    
    id = Column(Integer, primary_key=True, index=True)
    original_post_id = Column(Integer, nullable=False)
    content = Column(Text, nullable=False)
    author_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    deleted_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    deletion_reason = Column(String, nullable=False)
    deleted_at = Column(DateTime, default=datetime.utcnow)
    viewed = Column(Boolean, default=False)  # Track if user has seen the notification
    
    # Relationships
    author = relationship("User", foreign_keys=[author_id])
    deleter = relationship("User", foreign_keys=[deleted_by])