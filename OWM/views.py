from rest_framework.views import APIView
from rest_framework import generics
from rest_framework.parsers import MultiPartParser, FormParser
from django.http import JsonResponse
from rest_framework.response import Response
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_decode
from django.shortcuts import get_object_or_404
from django.db.models import Count, Case, When, Value, IntegerField
from rest_framework import status
from django.conf import settings
from django.contrib.auth.models import Group
from django.core.mail import send_mail
from rest_framework.permissions import IsAuthenticated, AllowAny, IsAuthenticatedOrReadOnly
from django.contrib.auth import authenticate
from django.contrib.auth.hashers import make_password
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import InvalidToken
from django.utils.dateparse import parse_date, parse_time
from django.utils import timezone
from datetime import timedelta
from collections import defaultdict
import traceback, logging
from rest_framework.exceptions import ValidationError
from .models import *
from .serializers import *

# User Registration View
class RegisterView(APIView):
    permission_classes = [AllowAny]
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request):
        try:
            serializer = CustomUserSerializer(data=request.data)

            print(f"Request content type: {request.content_type}")
            print(f"Request data: {request.data}")
            
            if serializer.is_valid():
                user = serializer.save()

                customer_group, created = Group.objects.get_or_create(name="customer")
                user.groups.add(customer_group)

                refresh = RefreshToken.for_user(user)
                access_token = str(refresh.access_token)

                response = Response({"message": "Registration successful"}, status=status.HTTP_201_CREATED)
                response.set_cookie(
                    key="refresh_token",
                    value=str(refresh),
                    httponly=True,
                    secure=True,  # Set to True in production with HTTPS
                    samesite="Lax",
                    path="/api/token/refresh/"
                )
                response.set_cookie(
                    key="access_token",
                    value=access_token,
                    httponly=True,
                    secure=True,
                    samesite="Lax",
                    path="/"
                )
                return response
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except ValidationError as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        
        except Exception as e:
            # You can log the full traceback for debugging
            import traceback
            traceback.print_exc()
            return Response({"error": "Something went wrong", "detail": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# Login View (JWT Token Generation)
class LoginView(APIView):
    permission_classes = []

    def post(self, request):
        serializer = CustomTokenObtainPairSerializer(data=request.data, context={"request": request})

        if serializer.is_valid():
            user = serializer.user
            data = serializer.validated_data
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)

            response = JsonResponse({
                "message": "Login successful",
                "access_token": access_token,  # ✅ Send access token in response
                "username": data.get("username"),
                "profile_pic": data.get("profile_pic"),
                "groups": data.get("groups") 
            })

            # Store only refresh token in HTTP-only cookie
            response.set_cookie(
                key="refresh_token",
                value=str(refresh),
                httponly=True,
                secure=True,  # 🔒 Use True in production
                samesite=None,  # 🔒 Better CSRF protection
                path="/token/refresh/"  # 🔄 Only send with refresh endpoint
            )

            return response
        
        return Response({"error": "Invalid credentials"}, status=401)
        
#Logout View
class LogoutView(APIView):
    def post(self, request):
        response = JsonResponse({"message": "Logged out successfully"})
        response.delete_cookie("access_token")
        response.delete_cookie("refresh_token")
        return response

class ForgotPasswordView(APIView):
    CustomUser = get_user_model()
    def post(self, request):
        email = request.data.get("email")
        try:
            user = CustomUser.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)
            reset_link = f"{request.data.get('frontend_url')}/reset-password/{uid}/{token}/"
            send_mail(
                subject="Password Reset Request",
                message=f"Click here to reset your password: {reset_link}",
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[email],
            )
            return Response({"message": "Password reset link sent"}, status=status.HTTP_200_OK)
        except CustomUser.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

class ResetPasswordView(APIView):
    def post(self, request, uidb64, token):
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = CustomUser.objects.get(pk=uid)
            if default_token_generator.check_token(user, token):
                password = request.data.get("password")
                user.set_password(password)
                user.save()
                return Response({"message": "Password reset successful"}, status=status.HTTP_200_OK)
            return Response({"error": "Invalid token"}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": "Something went wrong"}, status=status.HTTP_400_BAD_REQUEST)
        
class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request):
        user = request.user
        old_password = request.data.get("old_password")
        new_password = request.data.get("new_password")

        if not user.check_password(old_password):
            return Response({"error": "Old password is incorrect"}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(new_password)
        user.save()
        return Response({"message": "Password changed successfully"}, status=status.HTTP_200_OK)

#Custom Token Refresh View
class CustomTokenRefreshView(TokenRefreshView):
    def post(self, request, *args, **kwargs):
        refresh_token = request.COOKIES.get("refresh_token")

        if not refresh_token:
            return Response({"error": "No refresh token found"}, status=status.HTTP_401_UNAUTHORIZED)

        try:
            refresh = RefreshToken(refresh_token)
            access_token = str(refresh.access_token)

            CustomUser = get_user_model()
            user_id = refresh["user_id"]
            user = CustomUser.objects.get(id=user_id)
            groups = list(user.groups.values_list("name", flat=True))

            profile_pic_url = user.profile_pic.url if user.profile_pic else None
            if profile_pic_url:
                profile_pic_url = request.build_absolute_uri(profile_pic_url)

            response = Response({
                "access_token": access_token,
                "groups": groups,
                "profile_pic_url": profile_pic_url
                })
            return response
        except Exception as e:
            return Response({"error": "Invalid refresh token"}, status=status.HTTP_401_UNAUTHORIZED)

#Profile View/Edit View
class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]  # Only authenticated users can access

    def get(self, request):
        """Retrieve the authenticated user's profile"""
        serializer = CustomUserSerializer(request.user, context={"request": request})
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request):
        """Update the authenticated user's profile"""
        serializer = CustomUserSerializer(request.user, data=request.data, partial=True, context={"request": request})

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Service List & Detail View
class ServiceView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, pk=None):
        if pk is not None:
            try:
                service = Service.objects.get(pk=pk)
                serializer = ServiceSerializer(service)
                
                return Response(serializer.data, status=status.HTTP_200_OK)
            except Service.DoesNotExist:
                return Response({"error": "Service Not Found"}, status=status.HTTP_404_NOT_FOUND)
            
        services = Service.objects.all()
        serialized_services = ServiceSerializer(services, many=True).data

        grouped_services = defaultdict(lambda: defaultdict(list))
        for service_data in serialized_services:
            category = service_data.get('category')
            if category == 'audio':
                audio_category = service_data.get('audio_category')
                if audio_category:
                   grouped_services[category][audio_category].append(service_data)
                else:
                    default_subcategory = f"{service.category}_services"
                    grouped_services[category][default_subcategory].append(service_data)
            else:
                default_subcategory = f"{service.category}_services"
                grouped_services[category][default_subcategory].append(service_data)

        formatted_grouped_services = {}
        for category, subcategories in grouped_services.items():
            formatted_grouped_services[category] = dict(subcategories)

        response_data = {
            "services": serializer.data,  # Flat list of all services
            "grouped_services": formatted_grouped_services  # Grouped by category and subcategory
        }
        
        return Response(response_data, status=status.HTTP_200_OK)
    
    def post(self, request):
        """Handle POST requests - create service"""
        if not (request.user.is_staff and request.user.is_authenticated):
            return Response({"error": "Forbidden: Authenticated Admins only"}, status=status.HTTP_403_FORBIDDEN)

        serializer = ServiceSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        print("Serializer errors:", serializer.errors)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def put(self, request, pk=None):
        service = get_object_or_404(Service, pk=pk)

        serializer = ServiceSerializer(service, data=request.data, partial=True)  # Partial update
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=400)

    def delete(self, request, pk=None):
        service = get_object_or_404(Service, pk=pk)
        service.delete()
        return Response({"message": "Service deleted successfully"}, status=204)

# Booking API
class BookingListCreateView(generics.ListCreateAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = BookingSerializer

    def get_queryset(self):
        booking = Booking.objects.filter(user=self.request.user)
        return booking

    def perform_create(self, serializer):
        service_id = self.request.data.get("service")
        event_date = parse_date(self.request.data.get("event_date"))

        if not service_id or not event_date:
            raise ValidationError({"error": "Service and date are required."})

        if Booking.objects.filter(service_id=service_id, event_date=event_date).exists():
            raise ValidationError({"error": "Service already booked on this date."})

        serializer.save(user=self.request.user)

class BookingView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, pk=None):
        """Fetches either a specific booking (if `pk` is provided) or all user bookings."""
        if pk:
            try:
                booking = Booking.objects.get(pk=pk, user=request.user)
                serializer = BookingSerializer(booking)
                return Response(serializer.data, status=status.HTTP_200_OK)
            except Booking.DoesNotExist:
                return Response({"error": "Booking not found"}, status=status.HTTP_404_NOT_FOUND)

        # Fetch all bookings for the logged-in user
        bookings = Booking.objects.filter(user=request.user).order_by("-event_date")
        serializer = BookingSerializer(bookings, many=True)

        return Response({"user_bookings": serializer.data}, status=status.HTTP_200_OK)
        
    def post(self, request, *args, **kwargs):
        user=request.user
        pk = kwargs.get("pk")
        print(f"pk: {pk}")  # Debug: Check if pk is being passed correctly
        print(f"kwargs: {kwargs}")  # Debug: Check all kwargs
        print(f"request data: {request.data}")  # Debug: Check request payload
        if pk is None:
            """
            Adds a service to the cart and stores event details.
            """
            service_id = request.data.get("service_id")
            event_date = request.data.get("event_date")
            event_time = request.data.get("event_time")
            event_location = request.data.get("event_location")

            if not service_id or not event_date or not event_time or not event_location:
                return Response({"error": "All fields are required"}, status=status.HTTP_400_BAD_REQUEST)

            service = Service.objects.filter(id=service_id).first()

            if not service:
                return Response({"error": "Service not found."}, status=status.HTTP_404_NOT_FOUND)
            
            cart_item = Cart.objects.create(
                user = user,
                service = service,
                event_date = event_date,
                event_location = event_location,
                event_time = event_time
            )

            return Response(
                {"message": "Event details saved and service added to cart!", "cart_item": CartSerializer(cart_item).data},
                status=status.HTTP_201_CREATED
            )

        else:
            #CASE 2: Create a booking from the cart when "Book" is clicked
            service_id = pk  # pk is provided in the URL, meaning we're booking this service
            print(f"Service ID from URL: {service_id}")
            print(f"User: {user}")
            cart_item = Cart.objects.filter(user=user, service_id=service_id).first()
            if not cart_item:
                return Response({"error": "Service not found in cart"}, status=status.HTTP_404_NOT_FOUND)

            # Extract event details from the cart item
            event_date = cart_item.event_date
            event_time = cart_item.event_time
            event_location = cart_item.event_location

            if not event_date or not event_time or not event_location:
                return Response({"error": "Missing event details"}, status=status.HTTP_400_BAD_REQUEST)

            existing_booking = Booking.objects.filter(
            service_id=service_id, event_date=event_date, event_time=event_time
        ).exclude(pk=pk).exists()

            if existing_booking:
                return Response(
                {"error": "Service already booked on this date."},
                status=status.HTTP_400_BAD_REQUEST
            )

            # Create a booking
            booking = Booking.objects.create(
                user=user,
                service=cart_item.service,
                event_date=event_date,
                event_time=event_time,
                event_location=event_location
            )

            # Get all admin/staff emails
            admin_emails = list(CustomUser.objects.filter(
                is_staff=True
            ).values_list('email', flat=True))
            
            # Prepare booking details for frontend
            booking_details = {
                'id': booking.id,
                'user_name': user.get_full_name(),
                'user_email': user.email,
                'service_name': booking.service.name,
                'event_date': booking.event_date,
                'event_time': booking.event_time,
                'event_location': booking.event_location,
                'created_at': booking.created_at,
                'admin_emails': admin_emails
            }

            # Remove the item from the cart after successful booking
            cart_item.delete()

            return Response(
                {
                    "message": "Service successfully booked!", 
                    "booking": BookingSerializer(booking).data,
                    "booking_details": booking_details,
                },
                status=status.HTTP_201_CREATED
            )

    def put(self, request, pk):
        """Updates an existing booking's event details."""
        print("Received Data:", request.data)
        booking = get_object_or_404(Booking, pk=pk, user=request.user)

        if booking.status not in ["Pending", "Cancelled"]:
            return Response(
                {"error": "Only Pending or Cancelled bookings can be edited."},
                status=status.HTTP_400_BAD_REQUEST
            )

        data = request.data.copy()
        data["user"] = request.user.id  # Ensure the correct user is set

        service_id = data.get("service")
        event_date = parse_date(data.get("event_date"))
        event_time = parse_time(data.get("event_time"))

        if not service_id:
            return Response({"error": "Service is required."}, status=status.HTTP_400_BAD_REQUEST)

        if not event_date:
            return Response({"error": "Valid event date is required."}, status=status.HTTP_400_BAD_REQUEST)

        # Ensure the same service is not double booked on the same date
        existing_booking = Booking.objects.filter(
            service_id=service_id, event_date=event_date, event_time=event_time
        ).exclude(pk=pk).exists()

        if existing_booking:
            return Response(
                {"error": "Service already booked on this date."},
                status=status.HTTP_400_BAD_REQUEST
            )

        serializer = BookingSerializer(booking, data=data, partial=True, context={"request": request})
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, pk):
        """Deletes a booking (user can delete their own, admin can delete any)."""
        user = request.user
        booking = get_object_or_404(Booking, pk=pk)

        if request.user != booking.user and not request.user.is_staff:
            return Response(
                {"error": "You do not have permission to delete this booking."},
                status=status.HTTP_403_FORBIDDEN
            )
        if booking.status not in ["Pending"] and not user.is_staff:
            return Response(
                {"error": "You do not have permission to delete a booking whose statsus is not Pending"}, status=status.HTTP_403_FORBIDDEN
                )
        
        booking.delete()
        return Response({"message": "Booking deleted successfully."}, status=status.HTTP_204_NO_CONTENT)

#User Dashboard View
class UserDashboardView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Fetch user details, bookings, and cart.
        user = request.user
        context = {'request': request}

        # Fetch user cart items
        cart_items = Cart.objects.filter(user=user).all()
        cart_data = CartSerializer(cart_items, many=True, context=context).data  

        print("serialized cart data:", cart_data)
        # Serialize user profile
        user_data = CustomUserSerializer(user).data

        # Categorize bookings *user
        bookings = Booking.objects.filter(user=user)
        pending = bookings.filter(status="Pending")
        completed = bookings.filter(status="Completed")
        cancelled = bookings.filter(status="Cancelled")


        return Response({
            "user": user_data,
            "bookings": {
                "pending": BookingSerializer(pending, many=True, context=context).data,
                "completed": BookingSerializer(completed, many=True, context=context).data,
                "cancelled": BookingSerializer(cancelled, many=True, context=context).data
            },
            "cart": cart_data  
        })
    
    def delete(self, request, pk):
        user = request.user

        cart_item = Cart.objects.filter(user=user, id=pk).first()

        if not cart_item:
            return Response({"error": "Item not found in cart"}, status=status.HTTP_404_NOT_FOUND)

        cart_item.delete()

        return Response({"message": "Item removed from cart", "cart": CartSerializer(Cart.objects.filter(user=user), many=True).data}, status=status.HTTP_200_OK)

class ContactUsView(APIView):
    permission_classes = [IsAuthenticatedOrReadOnly]
    def get(self, request):
        serializer = ContactUsSerializer
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    def post(self, request):
        # Automatically fill user details
        request.data["first_name"] = request.user.first_name
        request.data["last_name"] = request.user.last_name
        request.data["email"] = request.user.email

        serializer = ContactUsSerializer(data=request.data)
        if serializer.is_valid():
            contact_message = serializer.save()

            # Send email notification
            subject = f"New Contact Message from {contact_message.name}"
            message = f"""
            Name: {contact_message.first_name} {contact_message.last_name}
            Email: {contact_message.email}
            Subject: {contact_message.subject}
            
            Message:
            {contact_message.message}
            """
            studio_email = settings.DEFAULT_FROM_EMAIL  # Ensure this is set in settings.py
            
            try:
                send_mail(
                    subject,
                    message,
                    settings.DEFAULT_FROM_EMAIL,
                    [studio_email],  # Change this to the studio owner's email
                    fail_silently=False
                )
            except Exception as e:
                return Response({"error": "Message saved, but email could not be sent.", "details": str(e)},
                                status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            return Response({"message": "Your message has been sent!"}, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def put(self, request, pk):
        pass

# Review API
class ReviewView(APIView):
    permission_classes = [IsAuthenticatedOrReadOnly]

    def get(self, request):
        reviews = Review.objects.all()
        queryset = Review.objects.select_related("service", "user").all()
        serializer = ReviewSerializer(reviews, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request, pk):
        if not request.user.is_authenticated:
            return Response({"error": "You have to login to post a review"}, status=status.HTTP_401_UNAUTHORIZED)
        service = get_object_or_404(Service, pk=pk)  # Ensure service exists
        data = request.data.copy()
        data["user"] = request.user.id
        data["service"] = service.id  # Assign service to review
        
        print("Incoming Data:", data)
        context={
            'request': request
        }

        serializer = ReviewSerializer(data=data, context=context)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class TeamListView(APIView):
    permission_classes = [AllowAny]
    
    def get(self, request):
        member = TeamMember.objects.all()
        serializer = TeamMemberSerializer(member, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
class TestView(APIView):
    permission_classes = [AllowAny]
    def post(self, request, pk=None, *args, **kwargs):
        return Response({"pk": pk}, status=status.HTTP_200_OK)
        
#Admin Views
class AdminDashboardView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """Handle all GET requests - dashboard stats, bookings, users, messages or reviews"""
        if not request.user.is_staff:
            return Response({"error": "Forbidden: Admins only"}, status=status.HTTP_403_FORBIDDEN)
        
        action = request.query_params.get('action')
        if action == 'bookings':
            return self._get_bookings(request)
        elif action == 'users':
            return self._get_users_list()
        elif action == 'services':
            return self._get_services_list(request)
        elif action == 'booking-detail':
            return self._get_booking_detail(request)
        elif action == 'messages':
            return self._get_messages()
        elif action == 'reviews':
            return self._get_reviews()
        elif action == 'team':
            return self._get_team_members()
        return self._get_dashboard_overview()

    def post(self, request):
        """Handle POST requests - create booking"""
        if not request.user.is_staff:
            return Response({"error": "Forbidden: Admins only"}, status=status.HTTP_403_FORBIDDEN)

        serializer = BookingSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        print("Serializer errors:", serializer.errors)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, pk):
        """Handle PUT requests - update booking"""
        if not request.user.is_staff:
            return Response({"error": "Forbidden: Admins only"}, status=status.HTTP_403_FORBIDDEN)

        booking = get_object_or_404(Booking, pk=pk)
        serializer = BookingSerializer(
            booking, 
            data=request.data, 
            partial=True, 
            context={'request': request}
        )
        if serializer.is_valid():
            if 'user_id' not in request.data:
                serializer.validated_data['user'] = booking.user

            updated_booking = serializer.save()
            return Response(
                BookingSerializer(updated_booking, context={'request': request}).data,
            status=status.HTTP_200_OK
                )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        """Handle DELETE requests - delete booking"""
        if not request.user.is_staff:
            return Response({"error": "Forbidden: Admins only"}, status=status.HTTP_403_FORBIDDEN)

        booking = get_object_or_404(Booking, pk=pk)

        confirm = request.query_params.get('confirm', 'false').lower() == 'true'
        if not confirm:
            return Response(
            {"warning": "Add ?confirm=true to confirm deletion"},
            status=status.HTTP_400_BAD_REQUEST
        )

        booking.delete()
        return Response(
            {
                "success": True,
                "message": f"Booking {pk} deleted successfully",
                "deleted_at": timezone.now().isoformat()
            },
        status=status.HTTP_204_NO_CONTENT
        )

    def _get_dashboard_overview(self):
        logger = logging.getLogger(__name__)
        logger.info("Fetching admin dashboard overview")
        
        try:
            stats = {}
            try:
                stats["total_bookings"] = Booking.objects.count()
                stats["pending_bookings"] = Booking.objects.filter(status="pending").count()
                stats["completed_bookings"] = Booking.objects.filter(status="completed").count()
                stats["cancelled_bookings"] = Booking.objects.filter(status="canceled").count()
                logger.debug("Stats collected successfully")
            except Exception as e:
                logger.error(f"Error getting statistics: {str(e)}")
                stats = {
                    "total_bookings": 0,
                    "pending_bookings": 0,
                    "completed_bookings": 0,
                    "cancelled_bookings": 0
                }
                
            # Add recent bookings
            booking_data = []
            try:
                logger.debug("Querying recent bookings")
                recent_bookings = Booking.objects.select_related('user', 'service').order_by('-created_at')[:3]
                booking_data = BookingSerializer(recent_bookings, many=True).data
                logger.debug(f"Retrieved {len(booking_data)} recent bookings")
            except Exception as e:
                logger.error(f"Error retrieving recent bookings: {str(e)}", exc_info=True)

            # Add recent reviews   
            review_data = []
            try:
                logger.debug("Querying recent reviews")
                recent_reviews = Review.objects.select_related('user', 'service').order_by('-created_at')[:3]
                review_data = ReviewSerializer(recent_reviews, many=True).data
            except Exception as e:
                logger.error(f"Error retrieving recent reviews: {str(e)}", exc_info=True)

            message_data = []
            try:
                logger.debug("Querying recent messages")
                recent_messages = ContactUs.objects.order_by('-sent_at')[:3]
                message_data = ContactUsSerializer(recent_messages, many=True).data
            except Exception as e:
                logger.error(f"Error retrieving recent messages: {str(e)}", exc_info=True)
            # Return just the stats first to ensure this works
            return Response({
                "stats": stats,
                "recent_bookings": booking_data,
                "recent_reviews": review_data,
                "recent_messages": message_data
            })  
        except Exception as e:
            logger.error(f"Dashboard overview error: {str(e)}", exc_info=True)  # Add exc_info for stack trace
            return Response(
                {"error": f"Failed to load dashboard data: {str(e)}"},  # Include the actual error
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
    def _get_bookings(self, request):
        """Handle bookings retrieval with various filters and options"""
        booking_id = request.query_params.get('id')
        status_filter = request.query_params.get('status', None)

        if booking_id:
            booking = get_object_or_404(Booking, pk=booking_id)
            serializer = BookingSerializer(booking)
            return Response(serializer.data)

        try:
            queryset = Booking.objects.select_related('user', 'service')

            # Filter by status if provided
            if status_filter and status_filter.lower() != 'all':
                queryset = queryset.filter(status=status_filter.lower())

            # Always return ordered list
            bookings = queryset.order_by('-event_date', '-event_time')
            serializer = BookingSerializer(bookings, many=True)
            return Response(serializer.data)

        except Exception as e:
            print(f"🔥 Error in _get_bookings: {str(e)}")
            return Response({
                "error": "Failed to retrieve bookings",
                "details": str(e)
            }, status=500)

    def _get_users_list(self):
        """Return list of users or detailed info for a specific user"""
        user_id = self.request.query_params.get('id')
        
        # If no specific user ID is provided, return all users
        if not user_id:
            users = CustomUser.objects.all().order_by('first_name')
            serializer = CustomUserSerializer(users, many=True)
            return Response(serializer.data)
        
        # If a specific user ID is provided, return detailed info for that user
        try:
            user = CustomUser.objects.get(id=user_id)
            bookings = Booking.objects.filter(user=user)  # Changed from get() to filter()
            reviews = Review.objects.filter(user=user)
            messages = ContactUs.objects.filter(user=user)
            
            # Serialize all data
            user_data = CustomUserSerializer(user).data
            bookings_data = BookingSerializer(bookings, many=True).data
            reviews_data = ReviewSerializer(reviews, many=True).data
            messages_data = ContactUsSerializer(messages, many=True).data
            
            return Response({
                "user": user_data,
                "bookings": bookings_data,
                "reviews": reviews_data,
                "messages": messages_data
            })
        except CustomUser.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

    def _get_services_list(self, request):
        category_filter = request.query_params.get('category', None)
        services = Service.objects.all().order_by('name')

        if category_filter and category_filter.lower() != 'all':
            services = services.filter(category=category_filter.lower())

        serializer = ServiceSerializer(services, many=True)
        return Response(serializer.data)
    
    def _get_messages(self):
        message_id = self.request.query_params.get('id')
        if not message_id:
            messages = ContactUs.objects.all().order_by('sent_at')
            serializer = ContactUsSerializer(messages, many=True)
            return Response(serializer.data)
        try:
            message = ContactUs.objects.select_related('user').get(id=message_id)
            serializer = ContactUsSerializer(message)
            return Response(serializer.data)
        except ContactUs.DoesNotExist:
            return Response({'error': "Message Not Found"}, status=status.HTTP_404_NOT_FOUND)
    
    def _get_reviews(self):
        review_id = self.request.query_params.get('id')

        if not review_id:
            reviews = Review.objects.all().order_by('created_at')
            serializer = ReviewSerializer(reviews, many=True)
            return Response(serializer.data)
        try:
            review = Review.objects.select_related('user').get(id=review_id)
            serializer = ReviewSerializer(review)
            return Response(serializer.data)
        except Review.DoesNotExist:
            return Response({'error': "Review Not Found"}, status=status.HTTP_404_NOT_FOUND)
    
    def _get_team_members(self):
        member_id = self.request.query_params.get('id')

        if member_id:          
            try:
                member = TeamMember.objects.get(id=member_id)
                serializer = TeamMemberSerializer(member)
                return Response(serializer.data)
            except TeamMember.DoesNotExist:
                return Response({'error': "Team Member NOt Found"}, status=status.HTTP_404_NOT_FOUND)
        members = TeamMember.objects.all().order_by('role')
        serializer = TeamMemberSerializer(members, many=True)
        return Response(serializer.data)

    def _get_booking_detail(self, request):
        """Return details of a specific booking"""
        booking_id = request.query_params.get('id')
        if not booking_id:
            return Response({"error": "Booking ID required"}, status=status.HTTP_400_BAD_REQUEST)

        booking = get_object_or_404(Booking, pk=booking_id)
        serializer = BookingSerializer(booking)
        return Response(serializer.data)