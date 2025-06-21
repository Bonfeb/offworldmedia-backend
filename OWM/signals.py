from django.contrib.auth import get_user_model
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.core.mail import send_mail
from django.conf import settings

CustomUser = get_user_model()

@receiver(post_save, sender=CustomUser)
def send_welcome_email(sender, instance, created, **kwargs):
    if created:
        subject = "Welcome to OffWorld Media Africa! "
        plain_message = f"Hi {instance.username},\n\nThank you for registering. We're excited to have you with us!"
        html_message = f"""
        <html>
                <body style="font-family: Arial, sans-serif; color: #333;">
                    <h2>Welcome, {instance.username}!</h2>
                    <p>Thank you for joining OffWorldMedia. We're excited to have you with us.</p>
                    <p>
                        Offworld Media Africa is a business company specializing in photography, videography, music production, graphic designing and digital broadcasting.
                    </p>
                    <p>If you have any questions or need help, just on our site's <i>Contact Us</i> page </p>
                    <br>
                    <p>Cheers,<br><strong>The Offworld Media Team</strong></p>
                </body>
            </html>
        """
        recipient_list = [instance.email]
        
        send_mail(
            subject,
            plain_message,
            settings.DEFAULT_FROM_EMAIL,
            recipient_list,
            fail_silently=False,
            html_message=html_message
        )
