import asyncio
from email_config import email_service

async def test_emails():
    print("Testing SafeSpace email system...")
    
    # Test welcome email - FIXED: Use send_welcome_email method
    result = await email_service.send_welcome_email(
        user_email="manasvigawde2005@gmail.com",
        username="TestUser"
    )
    
    print(f"Welcome email: {'✅ Sent' if result else '❌ Failed'}")

if __name__ == "__main__":
    asyncio.run(test_emails())