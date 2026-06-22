from typing import Optional
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from dotenv import load_dotenv
load_dotenv()
from email_config import email_service
import os
import uuid
from sqlalchemy import func
from schemas import PostDeletionRequest, DeletedPostResponse
from database import SessionLocal, engine, Base
import models, schemas
from filter import is_abusive_with_auto_review
from auth import (
    hash_password, 
    authenticate_user, 
    create_access_token,
    get_current_user,
    get_current_moderator,
    ACCESS_TOKEN_EXPIRE_MINUTES
)
from datetime import datetime, timedelta
import pytz
INDIA_TZ = pytz.timezone('Asia/Kolkata')

# Create tables
Base.metadata.create_all(bind=engine)
app = FastAPI(title="Abuse Moderation API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Database dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_india_time():
    """Get current time in India timezone"""
    return datetime.now(INDIA_TZ).replace(tzinfo=None)

# Authentication Endpoints
@app.post("/api/register", response_model=schemas.UserResponse)
async def register(user: schemas.UserCreate, db: Session = Depends(get_db)):
    """Register a new user with email verification"""
    # Check if username already exists
    if db.query(models.User).filter(models.User.username == user.username).first():
        raise HTTPException(status_code=400, detail="Username already registered")
    
    # Check if email already exists
    if db.query(models.User).filter(models.User.email == user.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    
    try:
        # Generate email verification token
        verification_token = str(uuid.uuid4())
        
        # Validate role - only allow 'user' and 'moderator' during registration
        valid_role = user.role if user.role in ["user", "moderator"] else "user"
        
        # Create user
        db_user = models.User(
            username=user.username,
            email=user.email,
            password_hash=hash_password(user.password),
            role=valid_role,
            email_verification_token=verification_token
        )
        
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        
        # Send welcome email asynchronously (registration doesnt fail if email fails)
        try:
            await email_service.send_welcome_email(
                user_email=user.email,
                username=user.username
            )
            print(f"✅ Welcome email sent successfully to {user.email}")
        except Exception as email_error:
            print(f"❌ Failed to send welcome email to {user.email}: {email_error}")
        
        return db_user
        
    except Exception as e:
        db.rollback()
        print(f"Registration error: {e}")
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")

@app.post("/api/login", response_model=schemas.Token)
async def login(user_credentials: schemas.UserLogin, db: Session = Depends(get_db)):
    """Login and get access token"""
    user = authenticate_user(db, user_credentials.username, user_credentials.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )
    
    user.last_login = datetime.utcnow()
    db.commit()
    
    # Check if user is suspended
    if user.is_suspended:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Account suspended: {user.suspension_reason or 'Policy violation'}. Contact support for appeals."
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(user.id)}, expires_delta=access_token_expires
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": user
    }

async def check_and_handle_user_abuse(user_id: int, db: Session):
    """Monitor user abuse rate and take action - RETURN suspension status"""
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        return False
    
    user_comments = db.query(models.Comment).filter(
        models.Comment.user_id == user_id
    ).all()
    
    # Group comments by post author to detect targeted abuse
    from collections import defaultdict
    abuse_by_author = defaultdict(int)
    
    for comment in user_comments:
        if comment.is_abusive == 1:
            post = db.query(models.Post).filter(models.Post.id == comment.post_id).first()
            if post:
                abuse_by_author[post.author_id] += 1
    
    # Check if user has 3+ abusive comments on any single author's posts
    for author_id, abuse_count in abuse_by_author.items():
        if abuse_count >= 3:
            # Check if blocking relationship already exists
            existing_block = db.query(models.UserBlock).filter(
                models.UserBlock.blocker_id == author_id,
                models.UserBlock.blocked_id == user_id
            ).first()
            
            if not existing_block:
                # Create blocking relationship
                block = models.UserBlock(
                    blocker_id=author_id,
                    blocked_id=user_id,
                    reason="auto_abuse",
                    created_at=datetime.utcnow()
                )
                db.add(block)
                db.commit()
                
                # Get blocker username
                blocker = db.query(models.User).filter(models.User.id == author_id).first()
                
                # Send blocking notification email
                try:
                    await email_service.send_blocking_notification(
                        user_email=user.email,
                        username=user.username,
                        blocked_by_username=blocker.username if blocker else "Unknown"
                    )
                except Exception as e:
                    print(f"Failed to send blocking notification: {e}")
    
    # Calculate abuse rate
    total_comments = db.query(models.Comment).filter(models.Comment.user_id == user_id).count()
    flagged_comments = db.query(models.Comment).filter(
        models.Comment.user_id == user_id,
        models.Comment.is_abusive == 1
    ).count()
    
    if total_comments < 5:
        return False
    
    abuse_rate = (flagged_comments / total_comments) * 100
    
    # Warning threshold (50% abuse rate)
    if abuse_rate >= 50 and abuse_rate < 70 and user.warning_count < 2:
        user.warning_count += 1
        user.last_warning_sent = datetime.utcnow()
        db.commit()
        
        try:
            await email_service.send_warning_email(
                user_email=user.email,
                username=user.username,
                abuse_rate=abuse_rate,
                threshold=70
            )
        except Exception as e:
            print(f"Failed to send warning email: {e}")
        
        return False
    
    # Suspension threshold (70% abuse rate)
    elif abuse_rate >= 70 and not user.is_suspended:
        user.is_suspended = True
        user.suspended_at = datetime.utcnow()
        user.suspension_reason = f"High abuse rate: {abuse_rate:.1f}% of comments flagged"
        db.commit()
        
        try:
            await email_service.send_suspension_email(
                user_email=user.email,
                username=user.username,
                reason=user.suspension_reason
            )
        except Exception as e:
            print(f"Failed to send suspension email: {e}")
        
        return True #User was suspended
    
    return False

# ==================== USER ENDPOINTS ====================

@app.get("/api/user/my-posts")
def get_my_posts(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """My Profile page - Shows 'My Posts' with all user's posts and approved comments only"""
    user_posts = db.query(models.Post).filter(
        models.Post.author_id == current_user.id
    ).order_by(models.Post.created_at.desc()).all()
    
    result = []
    for post in user_posts:
        approved_comments = []
        for c in post.comments:
            if c.status == "approved":
                approved_comments.append({
                    "id": c.id,
                    "text": c.text,
                    "author_username": c.author.username,
                    "created_at": c.created_at,
                    "box_color": "blue"
                })
        
        result.append({
            "id": post.id,
            "content": post.content,
            "created_at": post.created_at,
            "comments": approved_comments,
            "total_visible_comments": len(approved_comments),
            "can_view_comments": True
        })
    
    return {
        "page_title": "My Posts",
        "navigation": "my_profile",
        "user": {
            "id": current_user.id,
            "username": current_user.username
        },
        "posts": result,
        "can_create_post": True
    }

@app.get("/api/user/explore-feed")
def get_explore_feed(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Explore Feed page - Shows 'Discover Posts' from other users (EXCLUDING SUSPENDED)"""
    other_posts = db.query(models.Post).join(models.User).filter(
        models.Post.author_id != current_user.id,
        models.User.is_suspended == False  # NEW: Exclude suspended users
    ).order_by(models.Post.created_at.desc()).all()
    
    result = []
    for post in other_posts:
        # Show only approved comments from NON-SUSPENDED users
        approved_comments = []
        for c in post.comments:
            if c.status == "approved" and not c.author.is_suspended:  # NEW: Check author suspension
                approved_comments.append({
                    "id": c.id,
                    "text": c.text,
                    "author_username": c.author.username,
                    "created_at": c.created_at,
                    "box_color": "blue"
                })
        
        result.append({
            "id": post.id,
            "content": post.content,
            "author_username": post.author.username,
            "created_at": post.created_at,
            "comments": approved_comments,
            "total_comments": len(approved_comments),
            "can_comment": True
        })
    
    return {
        "page_title": "Discover Posts",
        "navigation": "explore_feed",
        "posts": result
    }

# ==================== POST ENDPOINTS ====================

@app.post("/api/posts/", response_model=schemas.PostResponse)
def create_post(post: schemas.PostCreate, 
               current_user: models.User = Depends(get_current_user),
               db: Session = Depends(get_db)):
    """Create a new post - For 'Create New Post' button"""
    if len(post.content.strip()) == 0:
        raise HTTPException(status_code=400, detail="Post content cannot be empty")
    if len(post.content) > 2000:
        raise HTTPException(status_code=400, detail="Post too long (max 2000 characters)")
    
    db_post = models.Post(
        content=post.content,
        author_id=current_user.id
    )
    db.add(db_post)
    db.commit()
    db.refresh(db_post)
    return db_post

# ==================== COMMENT ENDPOINTS ====================

@app.post("/api/comments/")
async def create_comment(comment: schemas.CommentCreate, 
                  current_user: models.User = Depends(get_current_user),
                  db: Session = Depends(get_db)):
    """Post a comment with ABUSE and spam monitoring + BLOCKING CHECK"""
    
    from spam_detection import detect_spam
    
    post = db.query(models.Post).filter(models.Post.id == comment.post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    
    is_blocked = db.query(models.UserBlock).filter(
        models.UserBlock.blocker_id == post.author_id,
        models.UserBlock.blocked_id == current_user.id
    ).first()
    
    if is_blocked:
        raise HTTPException(
            status_code=403, 
            detail="You are blocked from commenting on this user's posts."
        )
    # END OF BLOCKING CHECK
    
    if len(comment.text.strip()) == 0:
        raise HTTPException(status_code=400, detail="Comment cannot be empty")
    if len(comment.text) > 1000:
        raise HTTPException(status_code=400, detail="Comment too long (max 1000 characters)")
    
    # STEP 1: Check for ABUSE FIRST
    review_result = is_abusive_with_auto_review(comment.text)
    
    if review_result["is_abusive"] == 1:
        if review_result["auto_action"] in ["approve", "auto_approve"]:
            comment_status = "approved"
            visible_in_feed = True
        else:
            comment_status = "hidden" if review_result["auto_action"] == "keep_hidden" else "pending_review"
            visible_in_feed = False
        
        db_comment = models.Comment(
            text=comment.text,
            is_spam=0,
            is_abusive=review_result["is_abusive"],
            status=comment_status,
            confidence_score=int(review_result["confidence"] * 100),
            flagged_words=",".join(review_result["flagged_words"]) if review_result["flagged_words"] else None,
            auto_review_action=review_result["auto_action"],
            auto_review_reason=review_result["reason"],
            user_id=current_user.id,
            post_id=comment.post_id
        )
        
        db.add(db_comment)
        db.commit()
        db.refresh(db_comment)
        
        user_suspended = await check_and_handle_user_abuse(current_user.id, db)
        
        return {
            "message": "Comment flagged for abuse",
            "comment_id": db_comment.id,
            "visible_in_feed": visible_in_feed,
            "auto_processed": review_result["auto_action"] != "human_review_needed",
            "spam_detected": False,
            "abuse_detected": True,
            "user_suspended": user_suspended
        }
    
    # STEP 2: Check for SPAM
    spam_result = detect_spam(comment.text, current_user.id, comment.post_id, db)
    
    if spam_result["is_spam"]:
        if spam_result.get("hide_all") and spam_result.get("similar_comment_ids"):
            for comment_id in spam_result["similar_comment_ids"]:
                old_comment = db.query(models.Comment).filter(
                    models.Comment.id == comment_id
                ).first()
                if old_comment:
                    old_comment.status = "hidden"
                    old_comment.is_spam = 1
            db.commit()
        
        db_comment = models.Comment(
            text=comment.text,
            is_spam=1,
            is_abusive=0,
            status="hidden",
            spam_reasons=",".join(spam_result["reasons"]),
            spam_confidence=spam_result["confidence"],
            auto_review_action="auto_hide_spam",
            auto_review_reason=spam_result["message"],
            user_id=current_user.id,
            post_id=comment.post_id
        )
        db.add(db_comment)
        db.commit()
        db.refresh(db_comment)
        
        return {
            "message": "Comment detected as spam and hidden",
            "comment_id": db_comment.id,
            "visible_in_feed": False,
            "auto_processed": True,
            "spam_detected": True,
            "spam_reasons": spam_result["reasons"],
            "spam_message": spam_result["message"],
            "user_suspended": False
        }
    
    # Warning case
    if spam_result["action"] == "warning":
        db_comment = models.Comment(
            text=comment.text,
            is_spam=0,
            is_abusive=0,
            status="approved",
            spam_reasons=",".join(spam_result["reasons"]),
            spam_confidence=spam_result["confidence"],
            auto_review_action="warning_spam",
            auto_review_reason=spam_result["message"],
            user_id=current_user.id,
            post_id=comment.post_id
        )
        db.add(db_comment)
        db.commit()
        db.refresh(db_comment)
        
        return {
            "message": "Comment posted successfully",
            "comment_id": db_comment.id,
            "visible_in_feed": True,
            "auto_processed": True,
            "spam_detected": False,
            "warning": spam_result["message"],
            "user_suspended": False
        }
    
    # STEP 3: APPROVE clean comments
    db_comment = models.Comment(
        text=comment.text,
        is_spam=0,
        is_abusive=0,
        status="approved",
        confidence_score=0,
        auto_review_action="approve",
        auto_review_reason="clean_comment",
        user_id=current_user.id,
        post_id=comment.post_id
    )
    
    db.add(db_comment)
    db.commit()
    db.refresh(db_comment)
    
    return {
        "message": "Comment posted successfully",
        "comment_id": db_comment.id,
        "visible_in_feed": True,
        "auto_processed": True,
        "spam_detected": False,
        "user_suspended": False
    }

# ==================== POST DELETION ENDPOINTS ====================

@app.delete("/api/posts/{post_id}")
async def delete_own_post(
    post_id: int,
    deletion_data: PostDeletionRequest,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """User deletes their own post"""
    post = db.query(models.Post).filter(models.Post.id == post_id).first()
    
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    
    # Only allow author to delete their own post
    if post.author_id != current_user.id:
        raise HTTPException(status_code=403, detail="You can only delete your own posts")
    
    try:
        # Store deleted post info (for user's own records, no notification needed)
        deleted_post = models.DeletedPost(
            original_post_id=post.id,
            content=post.content,
            author_id=post.author_id,
            deleted_by=current_user.id,
            deletion_reason=deletion_data.reason,
            viewed=True  # Self-deletion, no notification needed
        )
        
        db.add(deleted_post)
        
        # Delete the post (cascade will delete comments)
        db.delete(post)
        db.commit()
        
        return {
            "message": "Post deleted successfully",
            "post_id": post_id
        }
        
    except Exception as e:
        db.rollback()
        print(f"Error deleting post: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete post")


@app.delete("/api/moderator/posts/{post_id}")
async def moderator_delete_post(
    post_id: int,
    deletion_data: PostDeletionRequest,
    moderator: models.User = Depends(get_current_moderator),
    db: Session = Depends(get_db)
):
    """Moderator deletes a post with reason - sends notification to author"""
    post = db.query(models.Post).filter(models.Post.id == post_id).first()
    
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    
    try:
        post_author = post.author
        post_content = post.content
        
        # Create deleted post notification for author
        deleted_post = models.DeletedPost(
            original_post_id=post.id,
            content=post_content,
            author_id=post.author_id,
            deleted_by=moderator.id,
            deletion_reason=deletion_data.reason,
            viewed=False  # User needs to see this
        )
        
        db.add(deleted_post)
        
        # Delete the post
        db.delete(post)
        db.commit()
        
        # Send email notification
        try:
            from email_config import email_service
            await email_service.send_email(
                to_email=post_author.email,
                subject="SafeSpace - Post Deleted by Moderator",
                html_body=f"""
                <div style="font-family: Arial, sans-serif; padding: 20px;">
                    <h2>Post Deletion Notice</h2>
                    <p>Dear {post_author.username},</p>
                    <p>One of your posts has been deleted by a moderator.</p>
                    <p><strong>Reason:</strong> {deletion_data.reason}</p>
                    <p>You can view the post content and details in your account notifications.</p>
                    <p>If you have questions, please contact support.</p>
                </div>
                """
            )
        except Exception as e:
            print(f"Failed to send deletion email: {e}")
        
        return {
            "message": f"Post deleted successfully. Notification sent to {post_author.username}",
            "post_id": post_id,
            "author_username": post_author.username
        }
        
    except Exception as e:
        db.rollback()
        print(f"Error deleting post: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete post")


@app.get("/api/user/deleted-posts", response_model=list[DeletedPostResponse])
def get_deleted_posts_notifications(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get user's deleted posts notifications"""
    deleted_posts = db.query(models.DeletedPost).filter(
        models.DeletedPost.author_id == current_user.id,
        models.DeletedPost.viewed == False  # Only unviewed notifications
    ).order_by(models.DeletedPost.deleted_at.desc()).all()
    
    result = []
    for dp in deleted_posts:
        deleter = db.query(models.User).filter(models.User.id == dp.deleted_by).first()
        result.append({
            "id": dp.id,
            "original_post_id": dp.original_post_id,
            "content": dp.content,
            "deletion_reason": dp.deletion_reason,
            "deleted_at": dp.deleted_at,
            "deleted_by_username": deleter.username if deleter else "Unknown",
            "viewed": dp.viewed
        })
    
    return result


@app.put("/api/user/deleted-posts/{deleted_post_id}/mark-viewed")
def mark_deleted_post_as_viewed(
    deleted_post_id: int,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Mark a deleted post notification as viewed"""
    deleted_post = db.query(models.DeletedPost).filter(
        models.DeletedPost.id == deleted_post_id,
        models.DeletedPost.author_id == current_user.id
    ).first()
    
    if not deleted_post:
        raise HTTPException(status_code=404, detail="Deleted post notification not found")
    
    deleted_post.viewed = True
    db.commit()
    
    return {"message": "Notification marked as viewed"}


@app.get("/api/user/deleted-posts-count")
def get_deleted_posts_count(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get count of unviewed deleted post notifications"""
    count = db.query(models.DeletedPost).filter(
        models.DeletedPost.author_id == current_user.id,
        models.DeletedPost.viewed == False
    ).count()
    
    return {"count": count}

# ==================== MODERATOR ENDPOINTS ====================

@app.get("/api/moderator/users")
def get_all_users_list(
    moderator: models.User = Depends(get_current_moderator),
    db: Session = Depends(get_db)
):
    """User List page - Exclude suspended users"""
    from datetime import datetime, timedelta
    
    # NEW: Filter out suspended users
    users = db.query(models.User).filter(
        models.User.is_suspended == False
    ).order_by(models.User.created_at.desc()).all()
    
    users_data = []
    for user in users:
        total_posts = db.query(models.Post).filter(models.Post.author_id == user.id).count()
        total_comments = db.query(models.Comment).filter(models.Comment.user_id == user.id).count()
        flagged_comments = db.query(models.Comment).filter(
            models.Comment.user_id == user.id,
            models.Comment.is_abusive == 1
        ).count()
        hidden_comments = db.query(models.Comment).filter(
            models.Comment.user_id == user.id,
            models.Comment.status == "hidden"
        ).count()
        approved_comments = db.query(models.Comment).filter(
            models.Comment.user_id == user.id,
            models.Comment.status == "approved"
        ).count()
        
        # Calculate last activity
        is_recently_active = False
        last_activity = "Never"
        
        if user.last_login is not None:
            time_since_login = datetime.utcnow() - user.last_login
            is_recently_active = time_since_login < timedelta(hours=24)
            
            total_seconds = time_since_login.total_seconds()
            
            if total_seconds < 60:
                last_activity = "Just now"
            elif total_seconds < 3600:
                minutes = int(total_seconds / 60)
                last_activity = f"{minutes} min ago"
            elif total_seconds < 86400:
                hours = int(total_seconds / 3600)
                last_activity = f"{hours} hour{'s' if hours > 1 else ''} ago"
            elif time_since_login.days < 7:
                days = time_since_login.days
                last_activity = f"{days} day{'s' if days > 1 else ''} ago"
            else:
                last_activity = user.last_login.strftime("%Y-%m-%d")

        users_data.append({
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "created_at": user.created_at,
            "is_active": user.is_active,
            "total_posts": total_posts,
            "total_comments": total_comments,
            "approved_comments": approved_comments,
            "flagged_comments": flagged_comments,
            "hidden_comments": hidden_comments,
            "join_date": user.created_at.strftime("%Y-%m-%d"),
            "status": "Active" if user.is_active else "Disabled",
            "is_recently_active": is_recently_active,
            "last_activity": last_activity
        })
    
    return {
        "page_title": "All Users List",
        "navigation": "user_list",
        "users": users_data,
        "total_users": len(users_data)
    }

@app.get("/api/moderator/users-dropdown")
def get_users_for_dropdown(
    moderator: models.User = Depends(get_current_moderator),
    db: Session = Depends(get_db)
):
    """Get simplified user list for dropdown - EXCLUDE SUSPENDED"""
    users = db.query(models.User).filter(
        models.User.role == "user",
        models.User.is_suspended == False  # ADD THIS
    ).order_by(models.User.username).all()
    
    return {
        "users": [
            {
                "id": user.id,
                "username": user.username,
                "role": user.role
            }
            for user in users
        ]
    }

@app.get("/api/moderator/all-posts")
def get_all_posts_moderation(
    user_id: Optional[int] = None,
    moderator: models.User = Depends(get_current_moderator),
    db: Session = Depends(get_db)
):
    """All Posts page - Exclude suspended users"""
    query = db.query(models.Post).join(models.User).filter(
        models.User.is_suspended == False  # ADD THIS
    )
    
    selected_user = None
    if user_id:
        selected_user = db.query(models.User).filter(models.User.id == user_id).first()
        if not selected_user:
            raise HTTPException(status_code=404, detail="User not found")
        query = query.filter(models.Post.author_id == user_id)
    
    posts = query.order_by(models.Post.created_at.desc()).all()
    result = []
    for post in posts:
        # Count different types of comments
        total_comments = len(post.comments)
        approved_comments = sum(1 for c in post.comments if c.status == "approved" and c.is_abusive == 0)
        pending_comments = sum(1 for c in post.comments if c.status == "pending_review" and c.auto_review_action == "human_review_needed")
        hidden_comments = sum(1 for c in post.comments if c.status == "hidden" and c.is_abusive == 1)
        
        result.append({
            "id": post.id,
            "content": post.content,
            "author_username": post.author.username,
            "author_id": post.author_id,
            "created_at": post.created_at,
            "total_comments": total_comments,
            "approved_comments": approved_comments,
            "pending_comments": pending_comments,
            "hidden_comments": hidden_comments,
            "has_comments_to_view": total_comments > 0
        })
    
    return {
        "page_title": "All Posts",
        "navigation": "all_posts",
        "selected_user": {
            "id": selected_user.id,
            "username": selected_user.username
        } if selected_user else None,
        "posts": result
    }

@app.get("/api/moderator/posts/{post_id}/view-comments")
def view_post_comments_moderation(
    post_id: int,
    moderator: models.User = Depends(get_current_moderator),
    db: Session = Depends(get_db)
):
    """View Comments - Show post with color-coded comments (blue=clean, yellow=review, red=hidden)"""
    post = db.query(models.Post).filter(models.Post.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    
    # Show ALL comments with color coding
    all_comments = []
    for c in post.comments:
        comment_data = {
            "id": c.id,
            "text": c.text,
            "author_username": c.author.username,
            "created_at": c.created_at,
            "status": c.status,
            "is_abusive": c.is_abusive,
            "flagged_words": c.flagged_words,
            "confidence_score": c.confidence_score,
            "auto_review_action": c.auto_review_action,
            "auto_review_reason": c.auto_review_reason
        }
        
        # Color coding based on actual status and abuse detection
        if c.status == "approved" and c.is_abusive == 0:
            comment_data["box_color"] = "blue"
            comment_data["label"] = "APPROVED"
        elif c.status == "pending_review" or c.auto_review_action == "human_review_needed":
            comment_data["box_color"] = "yellow"
            comment_data["label"] = "NEEDS REVIEW"
        elif c.status == "hidden" or c.is_abusive == 1:
            comment_data["box_color"] = "red"
            comment_data["label"] = "HIDDEN"
        else:
            comment_data["box_color"] = "gray"
            comment_data["label"] = "UNKNOWN"
        
        all_comments.append(comment_data)
    
    return {
        "post": {
            "id": post.id,
            "content": post.content,
            "author_username": post.author.username,
            "created_at": post.created_at
        },
        "comments": all_comments,
        "total_comments": len(all_comments)
    }

@app.get("/api/moderator/posts-for-review")
def get_posts_for_review(
    moderator: models.User = Depends(get_current_moderator),
    db: Session = Depends(get_db)
):
    """Review Comments page - Exclude suspended users"""
    posts_with_pending = db.query(models.Post).join(models.User).join(models.Comment).filter(
        models.Comment.auto_review_action == "human_review_needed",
        models.Comment.status == "pending_review",
        models.User.is_suspended == False  # ADD THIS
    ).distinct().order_by(models.Post.created_at.desc()).all()
    
    result = []
    for post in posts_with_pending:
        # Count pending human review comments for this post
        pending_comments = [
            c for c in post.comments 
            if c.auto_review_action == "human_review_needed" and c.status == "pending_review"
        ]
        
        if len(pending_comments) > 0:
            # Get user statistics
            user = post.author
            total_user_comments = db.query(models.Comment).filter(models.Comment.user_id == user.id).count()
            flagged_user_comments = db.query(models.Comment).filter(
                models.Comment.user_id == user.id,
                models.Comment.is_abusive == 1
            ).count()
            
            abuse_rate = round((flagged_user_comments / max(total_user_comments, 1)) * 100, 1)
            
            result.append({
                "user_id": user.id,
                "username": user.username,
                "is_active": user.is_active,
                "abuse_rate_percent": abuse_rate,
                "user_created_at": user.created_at,
                "post_id": post.id,
                "post_content": post.content[:100] + "..." if len(post.content) > 100 else post.content,
                "post_created_at": post.created_at,
                "pending_comments_count": len(pending_comments),
                "needs_review": True
            })
    
    return {
        "page_title": "Review Comments - User Details",
        "navigation": "review_comments",
        "review_items": result,
        "message": "Table showing users with posts that need comment review"
    }

@app.get("/api/moderator/posts/{post_id}/review")
def get_post_for_review(
    post_id: int,
    moderator: models.User = Depends(get_current_moderator),
    db: Session = Depends(get_db)
):
    """Review Comments - Show only comments needing human review"""
    post = db.query(models.Post).filter(models.Post.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
   
    review_needed_comments = []
    for c in post.comments:
        if (c.auto_review_action == "human_review_needed" and 
            c.status == "pending_review"):
            comment_data = {
                "id": c.id,
                "text": c.text,
                "author_username": c.author.username,
                "created_at": c.created_at,
                "status": c.status,
                "is_abusive": c.is_abusive,
                "flagged_words": c.flagged_words,
                "confidence_score": c.confidence_score,
                "auto_review_action": c.auto_review_action,
                "auto_review_reason": c.auto_review_reason,
                "can_approve": True,
                "can_hide": True,
                "can_delete": True
            }
            review_needed_comments.append(comment_data)
    
    return {
        "post": {
            "id": post.id,
            "content": post.content,
            "author_username": post.author.username,
            "created_at": post.created_at
        },
        "comments": review_needed_comments,  # Only pending review comments
        "moderation_actions": ["approve", "hide", "delete"]
    }

@app.get("/api/moderator/flagged-comments")
def get_flagged_comments(
    user_id: Optional[int] = None,
    moderator: models.User = Depends(get_current_moderator),
    db: Session = Depends(get_db)
):
    """Flagged Comments page - Exclude suspended users"""
    query = db.query(models.Post).join(models.User).join(models.Comment).filter(
        models.Comment.is_abusive == 1,
        models.User.is_suspended == False  # ADD THIS
    )
    
    selected_user = None
    if user_id:
        selected_user = db.query(models.User).filter(models.User.id == user_id).first()
        if not selected_user:
            raise HTTPException(status_code=404, detail="User not found")
        query = query.filter(models.Post.author_id == user_id)
    
    posts_with_flagged = query.distinct().order_by(models.Post.created_at.desc()).all()
    
    result = []
    for post in posts_with_flagged:
        # Show only flagged/hidden comments for this post
        flagged_comments = []
        for c in post.comments:
            if c.is_abusive == 1:
                comment_data = {
                    "id": c.id,
                    "text": c.text,
                    "author_username": c.author.username,
                    "created_at": c.created_at,
                    "status": c.status,
                    "flagged_words": c.flagged_words,
                    "confidence_score": c.confidence_score,
                    "auto_review_action": c.auto_review_action,
                    "auto_review_reason": c.auto_review_reason,
                    "box_color": "red",  # All flagged comments show as red
                    "label": "HIDDEN" if c.status == "hidden" else "FLAGGED"
                }
                flagged_comments.append(comment_data)
        
        result.append({
            "id": post.id,
            "content": post.content,
            "author_username": post.author.username,
            "created_at": post.created_at,
            "flagged_comments": flagged_comments,
            "flagged_count": len(flagged_comments)
        })
    
    return {
        "page_title": "Flagged Comments",
        "navigation": "flagged_comments",
        "selected_user": {
            "id": selected_user.id,
            "username": selected_user.username
        } if selected_user else None,
        "posts": result
    }

@app.get("/api/moderator/statistics")
def get_statistics(
    username: Optional[str] = None,
    moderator: models.User = Depends(get_current_moderator),
    db: Session = Depends(get_db)
):
    """Statistics page - Overall stats first, then dropdown to select user by username"""
    
    if username:
        # User-specific statistics by username
        user = db.query(models.User).filter(models.User.username == username).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        total_posts = db.query(models.Post).filter(models.Post.author_id == user.id).count()
        total_comments = db.query(models.Comment).filter(models.Comment.user_id == user.id).count()
        
        approved_comments = db.query(models.Comment).filter(
            models.Comment.user_id == user.id,
            models.Comment.status == "approved"
        ).count()
        
        hidden_comments = db.query(models.Comment).filter(
            models.Comment.user_id == user.id,
            models.Comment.status == "hidden"
        ).count()
        
        pending_comments = db.query(models.Comment).filter(
            models.Comment.user_id == user.id,
            models.Comment.status == "pending_review",
            models.Comment.auto_review_action == "human_review_needed"
        ).count()
        
        flagged_comments = db.query(models.Comment).filter(
            models.Comment.user_id == user.id,
            models.Comment.is_abusive == 1
        ).count()
        
        spam_comments = db.query(models.Comment).filter(
            models.Comment.user_id == user.id,
            models.Comment.is_spam == 1
        ).count()
        
        # Calculate rates
        abuse_rate = round((flagged_comments / total_comments) * 100, 1) if total_comments > 0 else 0
        spam_rate = round((spam_comments / total_comments) * 100, 1) if total_comments > 0 else 0
        
        return {
            "type": "user_stats",
            "navigation": "statistics",
            "user": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "role": user.role,
                "created_at": user.created_at,
                "join_date": user.created_at.strftime("%Y-%m-%d")
            },
            "stats": {
                "total_posts": total_posts,
                "total_comments": total_comments,
                "approved_comments": approved_comments,
                "hidden_comments": hidden_comments,
                "pending_comments": pending_comments,
                "flagged_comments": flagged_comments,
                "spam_comments": spam_comments,
                "abuse_rate_percent": abuse_rate,
                "spam_rate_percent": spam_rate
            }
        }
    
    else:
        # Overall system statistics (main page)
        total_users = db.query(models.User).count()
        total_moderators = db.query(models.User).filter(models.User.role == "moderator").count()
        total_posts = db.query(models.Post).count()
        total_comments = db.query(models.Comment).count()
        
        clean_comments = db.query(models.Comment).filter(
            models.Comment.status == "approved",
            models.Comment.is_abusive == 0,
            models.Comment.is_spam == 0
        ).count()
        
        flagged_comments = db.query(models.Comment).filter(
            models.Comment.is_abusive == 1
        ).count()
        
        spam_comments = db.query(models.Comment).filter(
            models.Comment.is_spam == 1
        ).count()
        
        needs_review = db.query(models.Comment).filter(
            models.Comment.auto_review_action == "human_review_needed",
            models.Comment.status == "pending_review"
        ).count()
        
        auto_hidden = db.query(models.Comment).filter(
            models.Comment.auto_review_action.in_(["keep_hidden", "auto_hide_spam"])
        ).count()
        
        auto_approved = db.query(models.Comment).filter(
            models.Comment.auto_review_action.in_(["approve", "auto_approve"])
        ).count()
        
        # AI efficiency calculations
        ai_processed = auto_approved + auto_hidden
        ai_efficiency = round((ai_processed / total_comments) * 100, 1) if total_comments > 0 else 0
        abuse_detection_rate = round((flagged_comments / total_comments) * 100, 1) if total_comments > 0 else 0
        spam_detection_rate = round((spam_comments / total_comments) * 100, 1) if total_comments > 0 else 0
        
        return {
            "type": "overall_stats",
            "page_title": "Overall Statistics",
            "navigation": "statistics",
            "stats": {
                "total_users": total_users,
                "total_moderators": total_moderators,
                "total_posts": total_posts,
                "total_comments": total_comments,
                "clean_comments": clean_comments,
                "flagged_comments": flagged_comments,
                "spam_comments": spam_comments,
                "needs_review": needs_review,
                "auto_hidden": auto_hidden,
                "auto_approved": auto_approved,
                "ai_efficiency_percent": ai_efficiency,
                "abuse_detection_rate": abuse_detection_rate,
                "spam_detection_rate": spam_detection_rate
            },
            "message": "Select a user from dropdown to view user-specific statistics"
        }

@app.put("/api/moderator/comments/{comment_id}/review")
def review_comment(comment_id: int,
                  action: schemas.ModerationAction,
                  moderator: models.User = Depends(get_current_moderator),
                  db: Session = Depends(get_db)):
    """Moderator reviews a comment - Approve/Hide/Delete actions"""
    
    comment = db.query(models.Comment).filter(models.Comment.id == comment_id).first()
    if not comment:
        raise HTTPException(status_code=404, detail="Comment not found")
    
    if action.action == "approve":
        comment.status = "approved"
        comment.is_abusive = 0
        result_message = "Comment approved and made visible"
        
    elif action.action == "hide":
        comment.status = "hidden" 
        comment.is_abusive = 1
        result_message = "Comment hidden from public view"
        
    elif action.action == "delete":
        db.delete(comment)
        db.commit()
        return {"message": "Comment deleted permanently"}
    
    else:
        raise HTTPException(status_code=400, detail="Invalid action. Use: approve, hide, delete")
    
    comment.moderated_by = moderator.id
    comment.moderated_at = get_india_time()
    
    db.commit()
    return {
        "message": result_message,
        "comment_id": comment.id,
        "new_status": comment.status,
        "action_taken": action.action
    }

@app.delete("/api/moderator/users/{user_id}")
async def delete_user_account(
    user_id: int,
    moderator: models.User = Depends(get_current_moderator),
    db: Session = Depends(get_db)
):
    """Permanently delete a user account and all associated data"""
    user_to_delete = db.query(models.User).filter(models.User.id == user_id).first()
    
    if not user_to_delete:
        raise HTTPException(status_code=404, detail="User not found")
    
    if user_to_delete.id == moderator.id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    
    if user_to_delete.role == "moderator":
        raise HTTPException(status_code=403, detail="Cannot delete moderator accounts")
    
    try:
        deleted_username = user_to_delete.username
        deleted_email = user_to_delete.email
        
        db.query(models.Post).filter(models.Post.author_id == user_id).delete()
        db.query(models.Comment).filter(models.Comment.user_id == user_id).delete()
        db.query(models.UserBlock).filter(
            (models.UserBlock.blocker_id == user_id) | 
            (models.UserBlock.blocked_id == user_id)
        ).delete()
        
        db.delete(user_to_delete)
        db.commit()
        
        try:
            await email_service.send_email(
                to_email=deleted_email,
                subject="Account Deleted - SafeSpace",
                html_body=f"""
                <div style="font-family: Arial, sans-serif; padding: 20px;">
                    <h2>Account Deletion Confirmation</h2>
                    <p>Dear {deleted_username},</p>
                    <p>Your SafeSpace account has been permanently deleted by a moderator.</p>
                    <p>All your posts, comments, and personal data have been removed from our system.</p>
                    <p>If you believe this was done in error, please contact our support team.</p>
                    <p>Thank you for being part of SafeSpace.</p>
                </div>
                """
            )
        except Exception as e:
            print(f"Failed to send deletion email: {e}")
        
        return {
            "message": f"User account '{deleted_username}' deleted successfully",
            "deleted_user_id": user_id,
            "deleted_username": deleted_username,
            "deleted_by": moderator.username,
            "deleted_at": get_india_time().isoformat()
        }
        
    except Exception as e:
        db.rollback()
        print(f"Error deleting user: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete user account")

@app.get("/api/moderator/users/{user_id}/deletion-impact")
def check_deletion_impact(
    user_id: int,
    moderator: models.User = Depends(get_current_moderator),
    db: Session = Depends(get_db)
):
    """Check what will be deleted before confirming user deletion"""
    user = db.query(models.User).filter(models.User.id == user_id).first()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    posts_count = db.query(models.Post).filter(models.Post.author_id == user_id).count()
    comments_count = db.query(models.Comment).filter(models.Comment.user_id == user_id).count()
    comments_on_posts = db.query(models.Comment).join(
        models.Post, models.Comment.post_id == models.Post.id
    ).filter(models.Post.author_id == user_id).count()
    blocks_count = db.query(models.UserBlock).filter(
        (models.UserBlock.blocker_id == user_id) | 
        (models.UserBlock.blocked_id == user_id)
    ).count()
    
    return {
        "user_id": user_id,
        "username": user.username,
        "email": user.email,
        "impact": {
            "posts_to_delete": posts_count,
            "comments_to_delete": comments_count,
            "comments_on_posts_to_delete": comments_on_posts,
            "total_comments_affected": comments_count + comments_on_posts,
            "blocks_to_remove": blocks_count
        },
        "warning": "This action is permanent and cannot be undone",
        "can_delete": user.role != "moderator"
    }

# ==================== ADMIN ENDPOINTS ====================

def get_current_admin(current_user: models.User = Depends(get_current_user)):
    """Ensure current user is the admin"""
    if current_user.username != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    return current_user

@app.get("/api/admin/moderators")
def get_all_moderators(
    admin: models.User = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Admin: Get all moderators list"""
    moderators = db.query(models.User).filter(
        models.User.role == "moderator"
    ).order_by(models.User.created_at.desc()).all()
    
    moderators_data = []
    for mod in moderators:
        moderated_comments = db.query(models.Comment).filter(
            models.Comment.moderated_by == mod.id
        ).count()
        
        moderators_data.append({
            "id": mod.id,
            "username": mod.username,
            "email": mod.email,
            "role": mod.role,
            "is_active": mod.is_active,
            "is_suspended": mod.is_suspended,
            "created_at": mod.created_at,
            "last_login": mod.last_login,
            "moderated_comments": moderated_comments,
            "can_suspend": mod.username != "admin",
            "can_delete": mod.username != "admin"
        })
    
    return {"moderators": moderators_data}

@app.put("/api/admin/moderators/{moderator_id}/suspend")
async def suspend_moderator(
    moderator_id: int,
    suspension_data: dict,
    admin: models.User = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Admin: Suspend a moderator"""
    moderator = db.query(models.User).filter(models.User.id == moderator_id).first()
    
    if not moderator:
        raise HTTPException(status_code=404, detail="Moderator not found")
    
    if moderator.username == "admin":
        raise HTTPException(status_code=403, detail="Cannot suspend admin account")
    
    moderator.is_suspended = True
    moderator.is_active = False
    moderator.suspended_at = get_india_time()
    moderator.suspension_reason = suspension_data.get("reason", "Policy violation")
    db.commit()
    
    return {"message": f"Moderator '{moderator.username}' suspended successfully"}

@app.put("/api/admin/moderators/{moderator_id}/unsuspend")
async def unsuspend_moderator(
    moderator_id: int,
    admin: models.User = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Admin: Unsuspend a moderator"""
    moderator = db.query(models.User).filter(models.User.id == moderator_id).first()
    
    if not moderator:
        raise HTTPException(status_code=404, detail="Moderator not found")
    
    moderator.is_suspended = False
    moderator.is_active = True
    moderator.suspended_at = None
    moderator.suspension_reason = None
    db.commit()
    
    return {"message": f"Moderator '{moderator.username}' unsuspended successfully"}

@app.delete("/api/admin/moderators/{moderator_id}")
async def delete_moderator(
    moderator_id: int,
    deletion_data: dict,
    admin: models.User = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Admin: Delete a moderator"""
    moderator = db.query(models.User).filter(models.User.id == moderator_id).first()
    
    if not moderator:
        raise HTTPException(status_code=404, detail="Moderator not found")
    
    if moderator.username == "admin":
        raise HTTPException(status_code=403, detail="Cannot delete admin account")
    
    deleted_username = moderator.username
    db.delete(moderator)
    db.commit()
    
    return {"message": f"Moderator '{deleted_username}' deleted permanently"}

# ==================== UTILITY ENDPOINTS ====================

@app.get("/api/user/me")
def get_current_user_info(current_user: models.User = Depends(get_current_user)):
    """Get current user information for UI display"""
    return {
        "id": current_user.id,
        "username": current_user.username,
        "role": current_user.role,
        "email": current_user.email
    }

@app.get("/")
def root():
    return {"message": "Abuse Moderation API is running"}