import os
from typing import List
from decouple import config
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import aiosmtplib
import asyncio
from jinja2 import Environment, FileSystemLoader
from datetime import datetime
import logging

# Email Configuration
EMAIL_HOST = "smtp.gmail.com"
EMAIL_PORT = 465
EMAIL_USER = os.getenv("SMTP_USERNAME")
EMAIL_PASSWORD = os.getenv("SMTP_PASSWORD")
FROM_NAME = os.getenv("FROM_NAME", "SafeSpace Moderation System")
FROM_EMAIL = os.getenv("FROM_EMAIL")
EMAIL_FROM = f"{FROM_NAME} <{FROM_EMAIL}>"

# Template Environment
template_env = Environment(loader=FileSystemLoader(os.path.join(os.path.dirname(__file__), 'email_templates')))

class EmailService:
    def __init__(self):
        self.smtp_server = EMAIL_HOST
        self.smtp_port = EMAIL_PORT
        self.username = EMAIL_USER
        self.password = EMAIL_PASSWORD
        self.from_email = FROM_EMAIL
        self.from_name = FROM_NAME
        
    async def send_email(self, to_email: str, subject: str, html_body: str, text_body: str = None):
        """Send email using Gmail SMTP"""
        try:
            # Create message
            message = MIMEMultipart("alternative")
            message["Subject"] = subject
            message["From"] = f"{self.from_name} <{self.from_email}>"
            message["To"] = to_email
            
            # Add text version if provided
            if text_body:
                text_part = MIMEText(text_body, "plain")
                message.attach(text_part)
            
            # Add HTML version
            html_part = MIMEText(html_body, "html")
            message.attach(html_part)
            
            # Send email
            async with aiosmtplib.SMTP(hostname=self.smtp_server, port=self.smtp_port, use_tls=True) as server:
                await server.login(self.username, self.password)
                await server.send_message(message)
                
            logging.info(f"Email sent successfully to {to_email}")
            return True
            
        except Exception as e:
            logging.error(f"Failed to send email to {to_email}: {str(e)}")
            return False
    
    async def send_welcome_email(self, user_email: str, username: str):
        """Send welcome email to new users"""
        template = template_env.get_template('email.html')
        
        html_body = template.render(
            username=username,
            current_year=datetime.now().year,
            login_url="http://localhost:5173/login" 
        )
        
        subject = f"Welcome to SafeSpace, {username}!"
        
        return await self.send_email(
            to_email=user_email,
            subject=subject,
            html_body=html_body
        )
    
    async def send_warning_email(self, user_email: str, username: str, abuse_rate: float, threshold: float):
        """Send warning email when user approaches suspension"""
        template = template_env.get_template('warning_email.html')
        
        html_body = template.render(
            username=username,
            abuse_rate=abuse_rate,
            threshold=threshold,
            current_year=datetime.now().year
        )
        
        subject = "SafeSpace - Content Warning: Please Review Your Comments"
        
        return await self.send_email(
            to_email=user_email,
            subject=subject,
            html_body=html_body
        )
    
    async def send_suspension_email(self, user_email: str, username: str, reason: str):
        """Send suspension notification email"""
        template = template_env.get_template('suspension_email.html')
        
        html_body = template.render(
            username=username,
            reason=reason,
            appeal_email=self.from_email,
            current_year=datetime.now().year
        )
        
        subject = "SafeSpace - Account Suspended"
        
        return await self.send_email(
            to_email=user_email,
            subject=subject,
            html_body=html_body
        )
    
    async def send_blocking_notification(self, user_email: str, username: str, blocked_by_username: str):
        """Send notification when user is blocked by another user"""
        template = template_env.get_template('blocking_notif.html')
        
        html_body = template.render(
            username=username,
            blocked_by_username=blocked_by_username,
            current_year=datetime.now().year
        )
        
        subject = "SafeSpace - User Interaction Update"
        
        return await self.send_email(
            to_email=user_email,
            subject=subject,
            html_body=html_body
        )
    
    async def send_weekly_report(self, moderator_email: str, moderator_name: str, report_data: dict):
        """Send weekly moderation report to moderators"""
        template = template_env.get_template('weekly_report.html')
        
        html_body = template.render(
            moderator_name=moderator_name,
            report_data=report_data,
            week_start=report_data.get('week_start'),
            week_end=report_data.get('week_end'),
            current_year=datetime.now().year
        )
        
        subject = f"SafeSpace - Weekly Moderation Report ({report_data.get('week_start')} - {report_data.get('week_end')})"
        
        return await self.send_email(
            to_email=moderator_email,
            subject=subject,
            html_body=html_body
        )

# Global email service instance
email_service = EmailService()