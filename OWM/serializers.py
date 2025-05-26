from rest_framework import serializers
from rest_framework.fields import ImageField
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from .models import *

class CustomUserSerializer(serializers.ModelSerializer):
    profile_pic = serializers.ImageField(required=False)  # Make profile_pic optional

    class Meta:
        model = CustomUser
        fields = ['id', 'first_name', 'last_name', 'username', 'email', 'phone', 'profile_pic', 'password', 'address']
        extra_kwargs = {'password': {'write_only': True, 'required': False}}  # Make password optional

    def get(self, instance):
        """Retrieve the authenticated user's profile"""
        return {
            "id": instance.id,
            "username": instance.username,
            "email": instance.email,
            "first_name": instance.first_name,
            "last_name": instance.last_name,
            "profile_pic": instance.profile_pic.url if instance.profile_pic else None,
            "phone": instance.phone,
            "address": instance.address,
        }

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
    service = ServiceSerializer()
    service_image_url = serializers.SerializerMethodField()
    service_id = serializers.IntegerField(write_only=True)

    class Meta:
        model = Booking
        fields = ['id', 'user','user_id', 'phone', 'service', 'service_id', 'status', 'event_date', 'event_time', 'event_location', 'booked_at', 'service_image_url']

    extra_kwargs = {
            'status': {'required': False},
            'created_at': {'read_only': True}
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
        
        return data

    def get_service_image_url(self, obj):
        request = self.context.get('request')
        if obj.service and hasattr(obj.service, 'image') and obj.service.image:
            if request is not None:
                return request.build_absolute_uri(obj.service.image.url)  # ✅ Only use build_absolute_uri if request exists
            return obj.service.image.url  # ✅ Return relative URL if no request
        return None  # ✅ Return None if no image

class CartSerializer(serializers.ModelSerializer):
    service_name = serializers.CharField(source="service.name", read_only=True)
    service_price = serializers.DecimalField(source="service.price", max_digits=10, decimal_places=2, read_only=True)
    service_image = serializers.ImageField(source="service.image", read_only=True)
    added_at = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S")
    event_date = serializers.DateField()
    event_location = serializers.CharField()
    event_time = serializers.TimeField()
    
    class Meta:
        model = Cart
        fields = ["id", "service", "service_name", "service_price", "service_image", "added_at", "event_date", "event_location", "event_time"]

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
    profile_pic = serializers.ImageField(required=False, allow_null=True)
    profile_pic_url = serializers.SerializerMethodField()
    class Meta:
        model = TeamMember
        fields = ['id', 'name', 'role', 'profile_pic','profile_pic_url', 'bio']

    def get_profile_pic(self, obj):
        if obj.profile_pic:
            return obj.profile_pic.url.replace("http://", "https://")
        return None