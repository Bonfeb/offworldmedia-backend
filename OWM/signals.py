from django.contrib.auth import get_user_model
from django.db.models.signals import post_save
from django.dispatch import receiver, Signal
from django.conf import settings
from django.core.mail import send_mail, EmailMultiAlternatives
from django.utils.html import strip_tags
from django.template.loader import render_to_string
from weasyprint import HTML
import tempfile
import datetime
from . models import *


CustomUser = get_user_model()
booking_successful = Signal()

@receiver(post_save, sender=CustomUser)
def send_welcome_email(sender, instance, created, **kwargs):
    if created:
        subject = "Welcome to OffWorld Media Africa! "
        plain_message = f"Hi {instance.username},\n\nThank you for registering. We're excited to have you with us!"

        html_message = render_to_string('OWM/welcome_email.html',{
            'username': instance.username,
        })
        
        recipient_list = [instance.email]
        
        send_mail(
            subject,
            plain_message,
            settings.DEFAULT_FROM_EMAIL,
            recipient_list,
            fail_silently=False,
            html_message=html_message
        )

@receiver(booking_successful)
def send_booking_email(sender, booking, **kwargs):
    user = booking.user
    service = booking.service
    price = f"{service.price:.2f}"

    # Generate invoice number
    invoice_number = booking.invoice_number

    subject = '🎉 Booking Confirmed – Your Invoice'
    from_email = 'noreply@yourdomain.com'
    to_email = [user.email]

    context = {
        'user': user,
        'service': service,
        'booking': booking,
        'price': price,
        'invoice_number': invoice_number,
        'logo_url': 'https://yourdomain.com/static/logo.png',
    }

    html_invoice = render_to_string('OWM/booking_email.html', context)
    text_email = strip_tags(html_invoice)

    # 🔧 Generate PDF
    pdf_file = HTML(string=html_invoice).write_pdf()

    # 📧 Create email with attachment
    email = EmailMultiAlternatives(subject, text_email, from_email, to_email)
    email.attach_alternative(html_invoice, "text/html")
    email.attach(f"{invoice_number}.pdf", pdf_file, 'application/pdf')
    email.send()