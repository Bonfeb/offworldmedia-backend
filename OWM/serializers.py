from rest_framework import serializers
from rest_framework.fields import ImageField
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from .models import *
import logging

class CustomUserSerializer(serializers.ModelSerializer):
    profile_pic = serializers.ImageField(required=False)  # Make profile_pic optional

    class Meta:
        model = CustomUser
        fields = ['id', 'first_name', 'last_name', 'username', 'email', 'phone', 'profile_pic', 'password', 'address']
        extra_kwargs = {'password': {'write_only': True, 'required': False}}  # Make password optional

    def to_representation(self, instance):
        data = super().to_representation(instance)
        request = self.context.get("request")
        if request and data.get("profile_pic"):
            data["profile_pic"] = request.build_absolute_uri(data["profile_pic"])
        data.pop("password", None)
        return data

    def validate_email(self, value):
        """Ensure email is unique if changed"""
        user = self.instance
        if user and CustomUser.objects.exclude(id=user.id).filter(email=value).exists():
            raise serializers.ValidationError("This email is already in use.")
        return value

    def validate_username(self, value):
        """Ensure username is unique if changed"""
        user = self.instance
        if user and CustomUser.objects.exclude(id=user.id).filter(username=value).exists():
            raise serializers.ValidationError("This username is already taken.")
        return value
    
    def create(self, validated_data):
        # Remove password from validated_data to set it manually
        password = validated_data.pop("password", None)
        user = CustomUser(**validated_data)
        if password:
            user.set_password(password)
        user.save()
        return user

    def update(self, instance, validated_data):
        """Handle profile updates, including optional image uploads"""
        profile_pic = validated_data.pop("profile_pic", None)
        password = validated_data.pop("password", None)

        if profile_pic:
            instance.profile_pic = profile_pic  # Update profile picture

        if password:
            instance.set_password(password)  # Use `set_password()` instead of `make_password()`

        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        instance.save()
        return instance

    def to_representation(self, instance):
        """Modify response to return full URL for profile_pic"""
       
        representation = super().to_representation(instance)
        request = self.context.get("request")  # Get request context for full URL
        if hasattr(instance, "profile_pic") and instance.profile_pic:
            profile_pic_url = instance.profile_pic.url
            if profile_pic_url.startswith("http://"):
                profile_pic_url = profile_pic_url.replace("http://", "https://")
            if request:
                profile_pic_url = request.build_absolute_uri(profile_pic_url)
            representation["profile_pic"] = profile_pic_url
        return representation
    
class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        data = super().validate(attrs)
        request = self.context.get("request")

        # Get full profile picture URL if available
        profile_pic_url = None
        if self.user.profile_pic:
            try:
                relative_url = self.user.profile_pic.url
                profile_pic_url = (
                    request.build_absolute_uri(relative_url)
                    if request else relative_url
                )
            except ValueError:
                profile_pic_url = None

        data["username"] = self.user.username
        data["groups"] = list(self.user.groups.values_list("name", flat=True))
        data["profile_pic"] = profile_pic_url

        return data

class ServiceSerializer(serializers.ModelSerializer):
    image = serializers.SerializerMethodField()
    description = serializers.CharField(required=False, allow_blank=True)
    audio_category = serializers.ChoiceField(choices=Service.AUDIO_SUBCATEGORY_CHOICES, required=False, allow_null=True)
    category = serializers.ChoiceField(choices=Service.CATEGORY_CHOICES, required=True)

    class Meta:
        model = Service
        fields = ['id', 'name','audio_category', 'category', 'description', 'price', 'image']
    
    def get_image(self, obj):
        if not obj.image:
            return None
        
        image = obj.image.url
        
        # Cloudinary-specific handling
        if 'res.cloudinary.com' in image:
            # Ensure HTTPS for Cloudinary
            return image.replace('http://', 'https://')
        
        # Regular handling
        request = self.context.get('request')
        if request:
            return request.build_absolute_uri(image)
        
        return image
    
    def validate(self, data):
        category = data.get("category")
        audio_category = data.get("audio_category")

        if category == "audio" and not audio_category:
            # If category is audio, audio_category must be provided
            raise serializers.ValidationError({
                "audio_category": "Audio category is required for audio services."
            })

        if category != "audio":
            data["audio_category"] = None  # Ensure it's null for video/photo

        return data

class BookingSerializer(serializers.ModelSerializer):
    user = serializers.SerializerMethodField(read_only=True)  # Auto-fill user
    user_id = serializers.IntegerField(write_only=True, required=False)
    phone = serializers.SerializerMethodField()
    service = ServiceSerializer(read_only=True)  # Use ServiceSerializer to get full service details
    service_image_url = serializers.SerializerMethodField()
    service_id = serializers.IntegerField(write_only=True)

    class Meta:
        model = Booking
        fields = ['id', 'user','user_id', 'phone', 'service', 'service_id', 'status', 'event_date', 'event_time', 'event_location', 'booked_at', 'service_image_url']

    extra_kwargs = {
            'status': {'required': False},
            'booked_at': {'read_only': True}
        }
    
    def get_user(self, obj):
        return {
            'id': obj.user.id,
            'username': obj.user.username,
            #'full_name': f"{obj.user.first_name} {obj.user.last_name}"
        }
    
    def get_phone(self, obj):
        if obj.user:
            return getattr(obj.user, 'phone', None)
        return None
        
    def validate(self, data):
        request = self.context.get('request')
        
        # Admin can specify user_id, regular users get auto-assigned
        if 'user_id' in data:
            if not request.user.is_staff:
                raise serializers.ValidationError({"user_id": "Only admin can assign bookings to other users"})
            try:
                CustomUser.objects.get(id=data['user_id'])
            except CustomUser.DoesNotExist:
                raise serializers.ValidationError({"user_id": "User not found"})
        elif not request.user.is_authenticated:
            raise serializers.ValidationError("Authentication required")
        
        if 'event_date' in data and 'event_time' in data and 'service_id' in data:
            existing_booking = Booking.objects.filter(
                service_id=data['service_id'],
                event_date=data['event_date'],
                event_time=data['event_time'],
            )

            if existing_booking.exists():
                raise serializers.ValidationError("This service is already booked for the selected date and time.")
        else:
            raise serializers.ValidationError("Event date and time are required")
        
        return data
    
    def create(self, validated_data):
        request = self.context.get('request')
        if 'user_id' in validated_data and request.user.is_staff:
            user_id = validated_data.pop('user_id')
            validated_data['user'] = CustomUser.objects.get(id=user_id)
        elif request.user.is_authenticated:
            validated_data['user'] = request.user
        else:
            raise serializers.ValidationError("Authentication required to create a booking")
        validated_data['status'] = 'pending'
        return super().create(validated_data)

    def get_service_image_url(self, obj):
        request = self.context.get('request')
        if obj.service and hasattr(obj.service, 'image') and obj.service.image:
            if request is not None:
                return request.build_absolute_uri(obj.service.image.url)  # ✅ Only use build_absolute_uri if request exists
            return obj.service.image.url  # ✅ Return relative URL if no request
        return None

class CartSerializer(serializers.ModelSerializer):
    user = serializers.HiddenField(default=serializers.CurrentUserDefault())
    service_name = serializers.CharField(source="service.name", read_only=True)
    service_id = serializers.IntegerField(source="service.id", read_only=True)
    service_price = serializers.DecimalField(source="service.price", max_digits=10, decimal_places=2, read_only=True)
    service_image = serializers.ImageField(source="service.image", read_only=True)
    added_at = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S")
    event_date = serializers.DateField()
    event_location = serializers.CharField()
    event_time = serializers.TimeField()
    
    class Meta:
        model = Cart
        fields = ["id", "user", "service", "service_id", "service_name", "service_price", "service_image", "added_at", "event_date", "event_location", "event_time"]

class ContactUsSerializer(serializers.ModelSerializer):
    class Meta:
        model = ContactUs
        fields = ['id', 'name', 'email', 'subject', 'message', 'sent_at']
        read_only_fields = ['sent_at'] 

class ReviewSerializer(serializers.ModelSerializer):
    user = serializers.SerializerMethodField(read_only=True)  # Auto-fill user
    service = serializers.PrimaryKeyRelatedField(queryset=Service.objects.all())
    service_details = serializers.SerializerMethodField(read_only=True)
    class Meta:
        model = Review
        fields = ['id', 'user', 'rating', 'created_at', 'comment', 'service', 'service_details']
        extra_kwargs = {'user': {'read_only': True}}
    
    def get_user(self, obj):
        if not obj.user:
            return {}
        return {
            "username": obj.user.username,
            "profile_pic": obj.user.profile_pic.url if obj.user.profile_pic else None
        }
    
    def get_service_details(self, obj):
        """Returns full service details"""
        return {
            "id": obj.service.id,
            "name": obj.service.name,
        }

    def create(self, validated_data):
        """Override create() to assign the user automatically"""
        request = self.context.get('request')
        if request and request.user.is_authenticated:
            validated_data["user"] = request.user  # ✅ Assign user correctly
        return super().create(validated_data)

class TeamMemberSerializer(serializers.ModelSerializer):
    profile_pic = serializers.ImageField()
    class Meta:
        model = TeamMember
        fields = ['id', 'name', 'role', 'profile_pic', 'bio']

    def validate_profile_pic(self, value):
        valid_extensions = ['jpg', 'jpeg', 'png', 'gif', 'webp']
        file_extension = value.name.lower().split('.')[-1]
        if file_extension not in valid_extensions:
            raise serializers.ValidationError("Profile picture must be a valid image file (jpg, jpeg, png, gif, webp).")
        
        valid_mime_types = ['image/jpeg', 'image/png', 'image/gif', 'image/webp']
        if hasattr(value, 'content_type'):
            content_type = value.content_type
            if content_type not in valid_mime_types:
                raise serializers.ValidationError("Profile picture must be a valid image file (jpg, jpeg, png, gif, webp).")
        
        return value
       
    def to_representation(self, instance):
        logger = logging.getLogger(__name__)
        representation = super().to_representation(instance)
        profile_pic = instance.profile_pic
        if not profile_pic:
            representation['profile_pic'] = None
        else:
            try:
               url = profile_pic.url
               if 'res.cloudinary.com' in url:
                url = url.replace('http://', 'https://')
                request = self.context.get('request')
                if request and not url.startswith(('http://', 'https://')):
                    url = request.build_absolute_uri(url)
                representation['profile_pic'] = url
            except Exception as e:
                logger.warning(f"Error getting profile picture URL: {e}")
                logger.exception("Failed to get profile picture URL for {instance.name}")
                representation['profile_pic'] = None
        return representation
        