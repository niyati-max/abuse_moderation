from pydantic import BaseModel
from typing import Optional
from datetime import datetime

# User schemas
class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    role: Optional[str] = "user"

class UserLogin(BaseModel):
    username: str
    password: str

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    role: str
    created_at: datetime
    is_active: bool  
    
    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str
    user: UserResponse

class PostDeletionRequest(BaseModel):
    reason: str

class DeletedPostResponse(BaseModel):
    id: int
    original_post_id: int
    content: str
    deletion_reason: str
    deleted_at: datetime
    deleted_by_username: str
    viewed: bool
    
    class Config:
        from_attributes = True

# Post schemas
class PostCreate(BaseModel):
    content: str

class PostResponse(BaseModel):
    id: int
    content: str
    author_id: int
    created_at: datetime
    
    class Config:
        from_attributes = True

# Comment schemas
class CommentCreate(BaseModel):
    text: str
    post_id: int

class CommentResponse(BaseModel):
    id: int
    text: str
    is_abusive: int
    status: str
    confidence_score: int
    created_at: datetime
    user_id: int
    post_id: int
    
    class Config:
        from_attributes = True

# Moderation schema
class ModerationAction(BaseModel):
    action: str  # "approve", "hide", "delete" 
    reason: Optional[str] = "No reason provided"

