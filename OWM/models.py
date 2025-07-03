from django.contrib.auth.models import AbstractUser
from cloudinary.models import CloudinaryField
from django.db import models

# Custom User Model
class CustomUser(AbstractUser):
    first_name = models.CharField(max_length=20, null=False, blank=False)
    last_name = models.CharField(max_length=20, null=False, blank=False)
    username = models.CharField(max_length=20, unique=True, null=False, blank=False)
    phone = models.CharField(max_length=15, blank=True, null=True)
    profile_pic = CloudinaryField('profile_pic', blank=True, null=True)
    address = models.CharField(max_length=30, blank=False, null=False)

    class Meta:
        verbose_name = "CustomerUser"
        verbose_name_plural = "CustomUser"

    def __str__(self):
        return self.username

# Service Model
class Service(models.Model):
    CATEGORY_CHOICES = [
        ('video', 'Video Recording'),
        ('audio', 'Audio Recording'),
        ('photo', 'Photo Shooting'),
    ]

    AUDIO_SUBCATEGORY_CHOICES = [
        ('beat_making', 'Beat Making'),
        ('sound_recording', 'Sound Recording'),
        ('mixing', 'Mixing'),
        ('mastering', 'Mastering'),
        ('music_video', 'Music Video Production'),
    ]
    
    name = models.CharField(max_length=100)
    category = models.CharField(max_length=20, choices=CATEGORY_CHOICES)
    audio_category = models.CharField(max_length=20, choices=AUDIO_SUBCATEGORY_CHOICES, blank=True, null=True) # This field is optional and only required for audio services
    description = models.TextField()
    price = models.DecimalField(max_digits=10, decimal_places=2)
    image = CloudinaryField('service_images', blank=True, null=True)

    class Meta:
        verbose_name = "Service"
        verbose_name_plural = "Services"

    def save(self, *args, **kwargs):
        if self.category != 'audio':
            self.audio_category = None
        super().save(*args, **kwargs)

    def __str__(self):
        return self.name

# Booking Model
class Booking(models.Model):
    STATUS_CHOICES = [
        ('unpaid', 'Unpaid'),
        ('paid', 'Paid'),
        ('completed', 'Completed'),
        ('cancelled', 'Cancelled'),
    ]
    
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    service = models.ForeignKey(Service, on_delete=models.CASCADE)
    event_date = models.DateField()
    event_time = models.TimeField()
    event_location = models.CharField(max_length=100)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='unpaid')
    booked_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Booking"
        verbose_name_plural = "Bookings"

    def __str__(self):
        return f"{self.user.username} - {self.service.name} ({self.event_date} {self.event_time})"

class MpesaTransaction(models.Model):
    booking = models.ForeignKey(Booking, on_delete=models.CASCADE, related_name='transactions')
    phone_number = models.CharField(max_length=15)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    service = models.CharField(max_length=100, null=True, blank=True)
    merchant_request_id = models.CharField(max_length=100, null=True, blank=True)
    checkout_request_id = models.CharField(max_length=100, null=True, blank=True)
    result_code = models.IntegerField(null=True, blank=True)
    result_desc = models.TextField(null=True, blank=True)
    mpesa_receipt_number = models.CharField(max_length=100, null=True, blank=True)
    transaction_date = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=20, default='Pending')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Booking {self.booking_id} - {self.phone_number} - {self.amount} KES"

#Cart Model
class Cart(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    service = models.ForeignKey(Service, on_delete=models.CASCADE)
    event_date = models.DateField(null=False)
    event_location = models.CharField(max_length=255, null=False)
    event_time = models.TimeField(null=False)
    added_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.user.username} - {self.service.name} - {self.event_date}"
    
# Contact Model
class ContactUs(models.Model):
    STATUS_CHOICES = [
        ('read', 'Read'),
        ('unread', 'Unread'),
    ]
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    email = models.EmailField()
    subject = models.CharField(max_length=255)
    message = models.TextField()
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default='read')
    sent_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        verbose_name = "ContactUs"
        verbose_name_plural = "ContactUs"

    def __str__(self):
        return f"Message from {self.name} - {self.subject}"
    
# Team Member Model for Team UI
class TeamMember(models.Model):
    ROLE_CHOICES = [
        ('ceo', 'CEO'),
        ('producer', 'Producer'),
        ('director', 'Director'),
        ('editor', 'Editor'),
        ('photographer', 'Photographer'),
        ('videographer', 'Videographer')
    ]
    
    name = models.CharField(max_length=100)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES)
    profile_pic = CloudinaryField('team_images', blank=True, null=True)
    bio = models.TextField()

    class Meta:
        verbose_name = "TeamMember"
        verbose_name_plural = "TeamMembers"

    def __str__(self):
        return f"{self.name} - {self.get_role_display()}"

# Review Model
class Review(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    service = models.ForeignKey(Service, on_delete=models.CASCADE)
    rating = models.PositiveIntegerField()
    comment = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Review"
        verbose_name_plural = "Reviews"

    def __str__(self):
        return f"{self.user.username} - {self.service.name} ({self.rating}★)"

class Image(models.Model):
    image = CloudinaryField('gallery_images', blank=True, null=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Image"
        verbose_name_plural = "Images"

    def __str__(self):
        return f"Image {self.id} - Uploaded at {self.uploaded_at}"
    
class Video(models.Model):
    video = models.URLField(blank=True, null=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Video"
        verbose_name_plural = "Videos"

    def __str__(self):
        return f"Video {self.id} - Uploaded at {self.uploaded_at}"