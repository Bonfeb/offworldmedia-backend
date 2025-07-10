from rest_framework.views import APIView 
from rest_framework import generics
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from django.http import JsonResponse
from rest_framework.response import Response
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_decode
from django.shortcuts import get_object_or_404
from django_filters.rest_framework import DjangoFilterBackend
from django.db.models import Count, Case, When, Value, IntegerField
from rest_framework import status
from django.conf import settings
from django.core.paginator import Paginator
from django.contrib.auth.models import Group
from django.core.mail import send_mail
from rest_framework.permissions import IsAuthenticated, AllowAny, IsAuthenticatedOrReadOnly, IsAdminUser
from django.contrib.auth import authenticate
from django.contrib.auth.hashers import make_password
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import InvalidToken
from django.utils.dateparse import parse_date, parse_time
from django.utils import timezone
from django.utils.timezone import now
import base64, datetime, requests
from requests.auth import HTTPBasicAuth
from datetime import timedelta
from collections import defaultdict
import logging
from rest_framework.exceptions import ValidationError
import cloudinary.uploader
from .models import *
from .serializers import *
from .filters import *
from .utils import get_access_token, format_mpesa_phone_number

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
    permission_classes = [AllowAny]

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
    permission_classes = [AllowAny]
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
            print("Email sent successfully")
            return Response({"message": "Password reset link sent"}, status=status.HTTP_200_OK)
        except CustomUser.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            print(f"Error sending email: {str(e)}")
            return Response({"error": "Something went wrong"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class ResetPasswordView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request, uidb64, token):
        print(f"\n=== Received reset request ===")
        print(f"uidb64: {uidb64}")
        print(f"token: {token}")
        print(f"request data: {request.data}")
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = CustomUser.objects.get(pk=uid)
            
            if not default_token_generator.check_token(user, token):
                return Response({"error": "Invalid or expired token"}, 
                              status=status.HTTP_400_BAD_REQUEST)
                
            password = request.data.get("password")
            
            # Validate password strength
            try:
                validate_password(password, user)
            except ValidationError as e:
                return Response({"error": e.messages}, 
                              status=status.HTTP_400_BAD_REQUEST)
            
            user.set_password(password)
            user.save()
            return Response({"message": "Password reset successful"}, 
                          status=status.HTTP_200_OK)
            
        except (TypeError, ValueError, OverflowError, CustomUser.DoesNotExist):
            return Response({"error": "Invalid user"}, 
                          status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": str(e)}, 
                          status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class ChangePasswordView(APIView):
    permission_classes = [AllowAny]

    def put(self, request):
        print("\n=== Password Change Request ===") 
        print(f"User: {request.user.email}") 

        user = request.user
        old_password = request.data.get("old_password")
        new_password = request.data.get("new_password")

        if not user.check_password(old_password):
            print("Old password validation failed")
            return Response({"error": "Old password is incorrect"}, status=status.HTTP_400_BAD_REQUEST)
        
        # Validate new password strength
        try:
            validate_password(new_password, user)
        except ValidationError as e:
            print(f"New password validation failed: {e.messages}")
            return Response({"error": e.messages}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(new_password)
        user.save()
        print("Password changed successfully")
        
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
    parser_classes = [MultiPartParser, FormParser, JSONParser]

    def get(self, request, pk=None):
        if pk is not None:
            try:
                service = Service.objects.get(pk=pk)
                serializer = ServiceSerializer(service, context={'request': request})
                
                return Response(serializer.data, status=status.HTTP_200_OK)
            except Service.DoesNotExist:
                return Response({"error": "Service Not Found"}, status=status.HTTP_404_NOT_FOUND)
            
        services = Service.objects.all()
        serialized_services = ServiceSerializer(services, many=True, context={'request': request}).data

        grouped_services = defaultdict(lambda: defaultdict(list))
        for service_data in serialized_services:
            category = service_data.get('category')
            if category == 'audio':
                audio_category = service_data.get('audio_category')
                if audio_category:
                   grouped_services[category][audio_category].append(service_data)
                else:
                    default_subcategory = f"{category}_services"
                    grouped_services[category][default_subcategory].append(service_data)
            else:
                default_subcategory = f"{category}_services"
                grouped_services[category][default_subcategory].append(service_data)

        formatted_grouped_services = {
            cat: dict(subs) for cat, subs in grouped_services.items()
        }

        response_data = {
            "services": serialized_services,  # Flat list of all services
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
        user = request.user

        if not (user.is_staff and user.is_authenticated):
            return Response({"error": "Forbidden: Authenticated Admins only"}, status=status.HTTP_403_FORBIDDEN)
        
        try:
            service.delete()
            return Response({"message": "Service deleted successfully"}, status=204)
        except Exception as e:
            return Response({"error": "Error deleting service", "details": str(e)}, status=500)

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
        
    def post(self, request, pk, *args, **kwargs): 
        """Handles booking creation."""
        logger = logging.getLogger(__name__)
        user = request.user
        if not user.is_authenticated:
            return Response({"error": "You must be logged in to book a service."}, status=status.HTTP_401_UNAUTHORIZED)
        
        service_id = pk # pk is provided in the URL, meaning we're booking this service
        logger.info(f"Service ID from URL: {service_id}")
        logger.info(f"User: {user}")
        if not service_id:
            return Response({"error": "Service ID is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        cart_item = Cart.objects.select_related('service').filter(
            user=user, 
            service_id=service_id
        ).first()

        if not cart_item:
            return Response({"error": "Service not found in cart"}, status=status.HTTP_404_NOT_FOUND)

        booking_data = {
            "user": user.id,
            "service_id": service_id,
            "event_date": cart_item.event_date,
            "event_time": cart_item.event_time,
            "event_location": cart_item.event_location,
            "status": "unpaid"  # Default status for new bookings
        }
        logger.info(f"Booking data: {booking_data}")
        serializer = BookingSerializer(data=booking_data, context={"request": request})

        if not serializer.is_valid():
            print("Serializer errors:", serializer.errors)
            return Response({"error": "Validation Failed", "details": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
        
        if Booking.objects.filter(
            service_id=service_id,
            event_date=booking_data['event_date'],
            event_time=booking_data['event_time']
        ).exists():
            return Response(
                {"error": "Service already booked on this date and time."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            booking = serializer.save()
            logger.info(f"Booking created successfully: {booking.id}")
        except Exception as e:
            logger.error(f"Error creating booking: {str(e)}")
            return Response({"error": "Failed to create booking"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        cart_item.delete()

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
            'booked_at': booking.booked_at,
            'admin_emails': admin_emails
        }

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

        if booking.status not in ["unpaid", "cancelled"]:
            return Response(
                {"error": "Only Unpaid or Cancelled bookings can be edited."},
                status=status.HTTP_400_BAD_REQUEST
            )

        data = request.data.copy()
        data["user"] = request.user.id  # Ensure the correct user is set

        service_id = data.get("service_id")
        event_date = parse_date(data.get("event_date"))
        event_time = parse_time(data.get("event_time"))

        if not service_id:
            return Response({"error": "Service is required."}, status=status.HTTP_400_BAD_REQUEST)

        if not event_date:
            return Response({"error": "Valid event date is required."}, status=status.HTTP_400_BAD_REQUEST)

        # Ensure the same service is not double booked on the same date and time
        existing_booking = Booking.objects.filter(
            service_id=service_id, event_date=event_date, event_time=event_time
        ).exclude(pk=pk).exists()

        if existing_booking:
            return Response(
                {"error": "Service already booked on this date and Time."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if booking.user != request.user:
            return Response(
                {"error": "You do not have permission to edit this booking."},
                status=status.HTTP_403_FORBIDDEN
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
        if booking.status not in ["unpaid"] and not user.is_staff:
            return Response(
                {"error": "You do not have permission to delete a booking whose status is not Unpaid"}, status=status.HTTP_403_FORBIDDEN
                )
        try:
            booking.delete()
            return Response({"message": "Booking deleted successfully."}, status=status.HTTP_204_NO_CONTENT)
        except Exception as e:
            return Response({"error": "Error deleting booking", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class STKPushView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        raw_phone_number = request.data.get("phone_number")
        phone_number = format_mpesa_phone_number(raw_phone_number)
        amount = request.data.get("amount")
        booking_id = request.data.get("booking_id")

        if not all([phone_number, amount, booking_id]):
            return Response({"error": "Phone number, amount, and booking ID are required."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            booking = Booking.objects.get(id=booking_id, user=user)
        except Booking.DoesNotExist:
            return Response({"error": "Booking not found."}, status=status.HTTP_404_NOT_FOUND)
        
        service = booking.service.name if hasattr(booking.service, 'name') else str(booking.service)

        timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        password = base64.b64encode((settings.SHORTCODE + settings.PASSKEY + timestamp).encode()).decode()

        access_token = get_access_token()
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }

        payload = {
            "BusinessShortCode": settings.SHORTCODE,
            "Password": password,
            "Timestamp": timestamp,
            "TransactionType": "CustomerBuyGoodsOnline", #"CustomerToCustomerTransfer"
            "Amount": amount,
            "PartyA": phone_number,
            "PartyB": settings.SHORTCODE,
            "PhoneNumber": phone_number,
            "CallBackURL": settings.CALLBACK_URL,
            "AccountReference": f"Booking-{booking.id}",
            "TransactionDesc": f"Payment for service {service}"
        }

        mpesa_response = requests.post(
            "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest",
            json=payload, headers=headers
        )
        print("STKK Push Sent to MPesa API")
        print(f"MPesa Response: {mpesa_response.status_code} - {mpesa_response.text}")

        if mpesa_response.status_code == 200:
            MpesaTransaction.objects.create(
                booking=booking,
                phone_number=phone_number,
                amount=amount,
                service=service,
                merchant_request_id=mpesa_response.json().get("MerchantRequestID"),
                checkout_request_id=mpesa_response.json().get("CheckoutRequestID"),
                status="Unpaid"
            )
            print("Mpesa transaction created successfully")
            print(f"Mpesa Transaction ID: {mpesa_response.json().get('CheckoutRequestID')}")
            data = mpesa_response.json()
            return Response(data, status=status.HTTP_200_OK)
            
        print(f"MPesa Error Response: {mpesa_response.status_code} - {mpesa_response.text}")
        return Response({"error": mpesa_response.json()}, status=mpesa_response.status_code)

# Mpesa Callback View
class MpesaCallbackView(APIView):
    def post(self, request):
        data = request.data
        callback = data.get('Body', {}).get('stkCallback', {})
        checkout_id = callback.get('CheckoutRequestID')
        result_code = callback.get('ResultCode')
        result_desc = callback.get('ResultDesc')

        try:
            transaction = MpesaTransaction.objects.get(checkout_request_id=checkout_id)
            transaction.result_code = result_code
            transaction.result_desc = result_desc
            transaction.status = 'Success' if result_code == 0 else 'Failed'

            if result_code == 0:
                items = callback.get('CallbackMetadata', {}).get('Item', [])
                for item in items:
                    name = item['Name']
                    if name == 'MpesaReceiptNumber':
                        transaction.mpesa_receipt_number = item['Value']
                    elif name == 'TransactionDate':
                        from datetime import datetime
                        raw_date = str(item['Value'])
                        transaction.transaction_date = datetime.strptime(raw_date, "%Y%m%d%H%M%S")
            
                transaction.booking.status = 'paid'
                transaction.booking.save()

                subject = "Payment Received!"
                message = f"""
                <html>
                    <body style="font-family: Arial, sans-serif; background-color: #f2f2f2; margin: 0; padding: 20px;">
                        <div style="background-color: #ffffff; border-radius: 10px; padding: 30px; max-width: 600px; margin: auto; box-shadow: 0 4px 10px rgba(0,0,0,0.1);">
                        <h2 style="color: #2c3e50;">Payment Confirmation</h2>

                        <p style="font-size: 16px; color: #333333; line-height: 1.6;">
                            Hello dear <strong>{transaction.booking.user.username}</strong>,
                        </p>

                        <p style="font-size: 16px; color: #333333; line-height: 1.6;">
                            Your payment of <strong>Ksh {transaction.amount}</strong> for the service <strong>‘{transaction.service}’</strong> has been successfully received.
                        </p>

                        <div style="margin: 20px 0; padding: 15px; background-color: #f7f7f7; border-radius: 8px;">
                            <p style="font-size: 16px; color: #333333; line-height: 1.6;">
                            <strong>MPesa Receipt Number:</strong> {transaction.mpesa_receipt_number}
                            </p>
                        </div>

                        <p style="font-size: 16px; color: #333333; line-height: 1.6;">
                            Thank you for choosing our services!
                        </p>

                        <p style="font-size: 16px; color: #333333; line-height: 1.6;">
                            Best regards,<br>
                            <strong>Offworld Media Team</strong>
                        </p>

                        <div style="margin-top: 30px; font-size: 14px; color: #777777; text-align: center;">
                            &copy; now().year Offworld Media Africa. All rights reserved.
                        </div>
                        </div>
                    </body>
                </html>

                """
                recipient_email = transaction.booking.user.email
                send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [recipient_email])
                
            transaction.save()
        except MpesaTransaction.DoesNotExist:
            print(f"Transaction with CheckoutRequestID {checkout_id} not found.")
            return Response({"error": "Transaction not found"}, status=status.HTTP_404_NOT_FOUND)

        return Response({"ResultCode": 0, "ResultDesc": "Callback received"})

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
        unpaid = bookings.filter(status="unpaid")
        paid = bookings.filter(status="paid")
        completed = bookings.filter(status="completed")
        cancelled = bookings.filter(status="cancelled")

        return Response({
            "user": user_data,
            "bookings": {
                "unpaid": BookingSerializer(unpaid, many=True, context=context).data,
                "paid": BookingSerializer(paid, many=True, context=context).data,
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
    
    def post(self, request, *args, **kwargs):
        user = request.user
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
            user=user,
            service=service,
            event_date=event_date,
            event_location=event_location,
            event_time=event_time
        )

        return Response(
            {
                "message": "Event details saved and service added to cart!",
                "cart_item": CartSerializer(cart_item).data
            },
            status=status.HTTP_201_CREATED
        )

class ContactUsView(APIView):
    permission_classes = [AllowAny]
    def get(self, request):
        serializer = ContactUsSerializer()
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    def post(self, request):
        user = request.user
        data = request.data.copy()

        if user.is_authenticated:
            data.update({
                "first_name": request.user.first_name,
                "last_name": request.user.last_name,
                "email": request.user.email,
                "user": request.user.id
            })

        serializer = ContactUsSerializer(data=data)
        if serializer.is_valid():
            contact_message = serializer.save()

            subject = f"New Contact Message from {contact_message.first_name} {contact_message.last_name}"
            message = f"""
            Name: {contact_message.first_name} {contact_message.last_name}
            Email: {contact_message.email}
            Subject: {contact_message.subject}
            
            Message:
            {contact_message.message}
            """

            studio_email = settings.DEFAULT_FROM_EMAIL
            user_email = contact_message.email

            try:
                send_mail(
                    subject,
                    message,
                    studio_email,
                    recipient_list=[user_email],
                    fail_silently=False
                )

                return Response({"message": "Your message has been sent successfully!"},
                                status=status.HTTP_201_CREATED)
            except Exception as e:
                return Response({"error": "Message saved, but email could not be sent.", "details": str(e)},
                                status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, pk):
        contact_us = get_object_or_404(ContactUs, pk=pk)
        serializer = ContactUsSerializer(contact_us, data=request.data, partial=True)

        if serializer.is_valid():
            serializer.save()
            return Response("Message Status Updated Successfully!", status=status.HTTP_200_OK)
        
        return Response("Could not Update Message Status! Try Again!", status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, pk):
        contact_us = get_object_or_404(ContactUs, pk=pk)
        if not request.user.is_staff:
            return Response({"error": "Forbidden: Authenticated Admins only"}, status=status.HTTP_403_FORBIDDEN)
        try:
            contact_us.delete()
            return Response({"message": "Contact Message deleted Successfully!"}, status=204)
        except:
            return Response({"message": "Error deleting Contact Message!"})

class ImageView(APIView):
    permission_classes = [AllowAny]
    parser_classes = [MultiPartParser, FormParser]

    def get(self, request):
        images = Image.objects.all()
        serializer = ImageSerializer(images, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        serializer = ImageSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def put(self, request, pk):
        image = get_object_or_404(Image, pk=pk)
        serializer = ImageSerializer(image, data=request.data, partial=True)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
class VideoView(APIView):
    permission_classes = [AllowAny]
    parser_classes = [MultiPartParser, FormParser]

    def get(self, request):
        videos = Video.objects.all()
        serializer = VideoSerializer(videos, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request, *args, **kwargs):
        print("Video File:", request.FILES)
        if 'video' not in request.FILES:
            return Response({"error": "No video file provided"}, status=status.HTTP_400_BAD_REQUEST)

        video_file = request.FILES['video']

        try:
            upload_result = cloudinary.uploader.upload(
                video_file,
                resource_type="video",
                folder="gallery_videos"
            )

            video = Video.objects.create(
                video=upload_result.get("secure_url"),
                uploaded_at=timezone.now()
            )
            print("Video Uploaded Successfully!", video)

            serializer = VideoSerializer(video)
            print("Uploaded Video Data:", serializer.data)
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        except Exception as e:
            print(f"Error uploading video: {str(e)}")
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def put(self, request, pk):
        video = get_object_or_404(Video, pk=pk)

        if 'video' not in request.FILES:
            return Response({"error": "No video file provided"}, status=status.HTTP_400_BAD_REQUEST)

        video_file = request.FILES['video']

        try:
            upload_result = cloudinary.uploader.upload(
                video_file,
                resource_type="video",
                folder="gallery_videos"
            )

            # Save new video URL
            video.video = upload_result.get("secure_url")
            video.uploaded_at = timezone.now()
            video.save()

            serializer = VideoSerializer(video)
            return Response(serializer.data, status=status.HTTP_200_OK)

        except Exception as e:
            print(f"Error updating video: {str(e)}")
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# Review API
class ReviewView(APIView):
    permission_classes = [IsAuthenticatedOrReadOnly]

    def get(self, request):
        reviews = Review.objects.select_related("service", "user").all()
        if request.user.is_staff:
            queryset = ReviewFilter(request.GET, queryset=reviews).qs
        else:
            queryset = reviews
        serializer = ReviewSerializer(queryset, many=True)
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
    
    def put(self, request, pk):
        user = request.user
        if not user.is_authenticated:
            return Response("Please Login to update Review", status=status.HTTp_400_BAD_REQUEST)
        
        review = get_object_or_404(Review, pk=pk)
        if review.user != user and not user.is_staff:
            return Response("You do not have permission to update this review", status=status.HTTP_403_FORBIDDEN)
        
        serializer = ReviewSerializer(review, data=request.data, partial=True)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, pk):
        user = request.user
        
        review = get_object_or_404(Review, pk=pk)
        if not user.is_staff:
            return Response("You do not have permission to delete this review", status=status.HTTP_403_FORBIDDEN)
        
        try:
            review.delete()
            return Response({"message": "Review deleted Successfully!"}, status=204)
        except:
            return Response({"message": "Error deleting Review!"})

class TeamView(APIView):
    parser_classes = [MultiPartParser, FormParser]

    def get_permissions(self):
        if self.request.method == 'GET':
            return [AllowAny()]
        return [IsAdminUser(), IsAuthenticated()]
    
    def get(self, request):
        member = TeamMember.objects.all()
        serializer = TeamMemberSerializer(member, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    def post(self, request):
        logger = logging.getLogger(__name__)
        try:
            serializer = TeamMemberSerializer(data=request.data, context={'request': request})
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.exception(f"Error creating team member: {str(e)}")
            return Response({"error": "Failed to create team member"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def put(self, request, pk):
        try:
            logger = logging.getLogger(__name__)
            if not request.user.is_staff:
                logger.warning(f"Unauthorized access attempt by user {request.user.username} to update team member {pk}")
                return Response({"error": "Forbidden: Authenticated Admins only"}, status=status.HTTP_403_FORBIDDEN)
            
            member = get_object_or_404(TeamMember, pk=pk)
            serializer = TeamMemberSerializer(member, data=request.data, partial=True, context={'request': request})

            if serializer.is_valid():
                serializer.save()
                logger.info(f"Team Member {member.name} updated successfully")
                return Response(serializer.data, status=status.HTTP_200_OK)
            logger.error(f"Failed to update team member {pk}: {serializer.errors}")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.exception(f"Error updating team member {pk}: {str(e)}")
            return Response({"error": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def delete(self, request, pk):
        logger = logging.getLogger(__name__)
        try:
            if not request.user.is_staff:
                logger.warning(f"Unauthorized access attempt by user {request.user.username} to delete team member {pk}")
                return Response({"error": "Forbidden: Authenticated Admins only"}, status=status.HTTP_403_FORBIDDEN)
            
            member = get_object_or_404(TeamMember, pk=pk)

            logger.warning(f"Deleting team member {member.name} by user {request.user.username}")

            member.delete()
            return Response({"message": "Team member deleted successfully"}, status=status.HTTP_204_NO_CONTENT)
        
        except Exception as e:
            logger.exception(f"Error deleting team member {pk}: {str(e)}")
            return Response({
                "error": "Failed to delete team member",
                "details": str(e)
                }, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

#Admin Views
class AdminDashboardView(APIView):
    permission_classes = [IsAdminUser]
    parser_classes = [MultiPartParser, FormParser]

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
        serializer = BookingSerializer(data=request.data, context={'request': request})
        if not serializer.is_valid():
            print("Serializer errors:", serializer.errors)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        except Exception as e:
            print(f"Error saving booking: {str(e)}")
            return Response({"error": "Failed to create booking"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def put(self, request, pk):
        """Handle PUT requests - update booking"""
        if not request.user.is_staff:
            return Response({"error": "Forbidden: Admins only"}, status=status.HTTP_403_FORBIDDEN)
        
        booking_update = 'service' in request.data or 'event_date' in request.data or 'event_time' in request.data

        user_update = 'username' in request.data or 'email' in request.data or 'first_name' in request.data

        if booking_update:
            booking = get_object_or_404(Booking, pk=pk)
            data = request.data.copy()
            data["user"] = request.user.id  # Ensure the correct user is set

            service_id = data.get("service_id")
            event_date = parse_date(data.get("event_date"))
            event_time = parse_time(data.get("event_time"))

            existing_booking = Booking.objects.filter(
                service_id=service_id, event_date=event_date, event_time=event_time
            ).exclude(pk=pk).exists()

            if existing_booking:
                return Response(
                    {"error": "Service already booked on this date."},
                    status=status.HTTP_400_BAD_REQUEST
                )

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
            return Response(
                {"error": "Booking Update Failed", "details": serializer.errors}, 
                status=status.HTTP_400_BAD_REQUEST)
        
        elif user_update:
            user = get_object_or_404(CustomUser, pk=pk)
            if not request.user.is_staff:
                return Response({"error": "Forbidden: Admins only"}, status=status.HTTP_403_FORBIDDEN)
            
            serializer = CustomUserSerializer(user, data=request.data, partial=True, context={'request': request})
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(
                {"error": "User Update Failed", "details": serializer.errors}, 
                status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response(
                {"error": "Invalid request: Specify either booking or user data to update"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
    def delete(self, request, pk):
        if not request.user.is_staff:
            return Response({"error": "Forbidden: Admins only"}, status=status.HTTP_403_FORBIDDEN)

        confirm = request.query_params.get('confirm', 'false').lower() == 'true'
        if not confirm:
            return Response(
            {"warning": "Add ?confirm=true to confirm deletion"},
            status=status.HTTP_400_BAD_REQUEST
        )

        model_type = request.query_params.get('type', 'booking')

        if model_type == 'user':
            try:
                user = get_object_or_404(CustomUser, pk=pk)

                if user == request.user:
                    return Response({"error": "You cannot delet your own account here."}, status=status.HTTP_400_BAD_REQUEST)
                if user.is_superuser and not request.user.is_superuser:
                    return Response({"error": "Only superusers can delete other superusers"}, status=status.HTTP_403_FORBIDDEN)
                user.delete()
                return Response({
                    "success": True,
                    "message": f"User {user.username} deleted successfully!",
                    "deleted_at": timezone.now().isoformat()
                })
            except Exception as e:
                return Response({
                    "error": str(e)},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                    )
        else:
            booking = get_object_or_404(Booking, pk=pk)
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
                stats["unpaid_bookings"] = Booking.objects.filter(status="unpaid").count()
                stats["paid_bookings"] = Booking.objects.filter(status="paid").count()
                stats["completed_bookings"] = Booking.objects.filter(status="completed").count()
                stats["cancelled_bookings"] = Booking.objects.filter(status="cancelled").count()
                logger.debug("Stats collected successfully")
            except Exception as e:
                logger.error(f"Error getting statistics: {str(e)}")
                stats = {
                    "total_bookings": 0,
                    "unpaid_bookings": 0,
                    "paid_bookings": 0,
                    "completed_bookings": 0,
                    "cancelled_bookings": 0
                }
                
            # Add recent bookings
            booking_data = []
            try:
                logger.debug("Querying recent bookings")
                recent_bookings = Booking.objects.select_related('user', 'service').order_by('-booked_at')[:3]
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

        # DEBUG: Log the incoming request
        print(f"🔍 _get_bookings called with params: {dict(request.query_params)}")
        print(f"🔍 Status filter: '{status_filter}'")

        if booking_id:
            booking = get_object_or_404(Booking, pk=booking_id)
            serializer = BookingSerializer(booking)
            return Response(serializer.data)

        try:
            base_queryset = Booking.objects.select_related('user', 'service')
            print(f"🔍 Total bookings in database: {base_queryset.count()}")
            
            # Start with base queryset
            queryset = base_queryset
            
            # Apply status filter FIRST (most important filter)
            if status_filter and status_filter.lower() != 'all':
                print(f"🔍 Filtering by status: '{status_filter.lower()}'")
                queryset = queryset.filter(status=status_filter.lower())
                print(f"🔍 After status filter: {queryset.count()}")
                
                # DEBUG: Show what statuses actually exist
                all_statuses = base_queryset.values_list('status', flat=True).distinct()
                print(f"🔍 All statuses in database: {list(all_statuses)}")
            
            # Apply other filters using BookingFilter (but only if there are other filters)
            other_filters = ['user', 'service', 'event_location']
            applied_filters = any(
                param in request.query_params
                for param in other_filters
            )
            
            if applied_filters:
                print(f"🔍 Applying additional filters: {[param for param in other_filters if param in request.query_params]}")
                # Apply BookingFilter to the already status-filtered queryset
                filtered_bookings = BookingFilter(request.query_params, queryset=queryset).qs
                print(f"🔍 After additional filters: {filtered_bookings.count()}")
                queryset = filtered_bookings.order_by('user__username')
            else:
                # No additional filters, just order by date
                queryset = queryset.order_by('-event_date', '-event_time')

            # DEBUG: Final queryset
            print(f"🔍 Final queryset count: {queryset.count()}")
            
            # DEBUG: Show first few bookings 
            for booking in queryset[:5]:
                print(f"🔍 Booking {booking.id}: status='{booking.status}', user={booking.user.username}")

            serializer = BookingSerializer(queryset, many=True)
            
            # DEBUG: Serialized data
            print(f"🔍 Serialized data length: {len(serializer.data)}")
            
            return Response(serializer.data)

        except Exception as e:
            print(f"🔥 Error in _get_bookings: {str(e)}")
            import traceback
            traceback.print_exc()
            return Response({
                "error": "Failed to retrieve bookings",
                "details": str(e)
            }, status=500)

    def _get_users_list(self):
        logger = logging.getLogger(__name__)
        """Return list of users or detailed info for a specific user"""
        print("Received request with params:", self.request.GET)
        user_id = self.request.query_params.get('user_id')
        logger.info(f"User ID from request: {user_id}")
        if user_id:
            try:
                user_id = int(user_id)
            except ValueError:
                return Response({"error": "Invalid user ID"}, status=status.HTTP_400_BAD_REQUEST)

        page = int(self.request.query_params.get('page', 1))
        page_size = int(self.request.query_params.get('page_size', 10))

        users = CustomUser.objects.all()
        print("Initial user queryset:", users.query)

        queryset = CustomUserFilter(self.request.GET, queryset=users).qs
        print("Filtered user queryset:", queryset.query)
        print("Filtered user count:", queryset.count())
        
        # If no specific user ID is provided, return all users
        if not user_id:
            queryset = queryset.order_by('first_name')
            paginator = Paginator(queryset, page_size)
            users_page = paginator.get_page(page)
            serializer = CustomUserSerializer(users_page, many=True, context={'request': self.request})
            return Response({
                'results': serializer.data,
                'total': queryset.count(),
                'page': page,
                'page_size': page_size
            })
        
        # If a specific user ID is provided, return detailed info for that user
        try:
            user = CustomUser.objects.get(id=user_id)
            bookings = Booking.objects.filter(user=user)
            total_bookings = bookings.count()
            reviews = Review.objects.filter(user=user)
            total_reviews = reviews.count()
            messages = ContactUs.objects.filter(user=user)
            total_messages = messages.count()

            logger.info(f"User {user.username} found with {total_bookings} bookings, {total_reviews} reviews, and {total_messages} messages.")
            
            # Serialize all data
            user_data = CustomUserSerializer(user, context={'request': self.request}).data
            bookings_data = BookingSerializer(bookings, many=True).data
            reviews_data = ReviewSerializer(reviews, many=True).data
            messages_data = ContactUsSerializer(messages, many=True).data
            
            return Response({
                "user": user_data,
                "bookings": bookings_data,
                "total_bookings": total_bookings,
                "reviews": reviews_data,
                "total_reviews": total_reviews,
                "messages": messages_data,
                "total_messages": total_messages
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
    
class AdminUserView(APIView):
    permission_classes = [IsAdminUser]
    parser_classes = [MultiPartParser, FormParser]

    def get(self, request):
        users = CustomUser.objects.all()
        serializer = CustomUserSerializer(users, many=True, context={'request': request}).data

        print("Users List:", users)

        return Response(serializer, status=status.HTTP_200_OK)

    def put(self, request, pk):
        """Update user details by admin"""
        if not request.user.is_staff:
            return Response({"error": "Forbidden: Admins only"}, status=status.HTTP_403_FORBIDDEN)
        try:
            user = get_object_or_404(CustomUser, pk=pk)
            serializer = CustomUserSerializer(user, data=request.data, partial=True, context={'request': request})

            if serializer.is_valid():
                serializer.save()
                print(f"✅ User {user.username} updated successfully")
                return Response(serializer.data, status=status.HTTP_200_OK)
            
            return Response({"error": "User Update Failed.", "details": serializer.erros}, status=status.HTTP_400_BAD_REQUEST)
        
        except Exception as e:
            print(f"🔥 Error updating user {pk}: {str(e)}")
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        
    def delete(self, request, pk):
        if not request.user.is_staff:
            return Response({"error": "Forbidden: Admins only"}, status=status.HTTP_403_FORBIDDEN)
        
        try:
            user = get_object_or_404(CustomUser, pk=pk)

            if user == request.user:
                return Response({"error": "You cannot delete your own account here."}, status=status.HTTP_400_BAD_REQUEST)
            
            if user.is_superuser and not request.user.is_superuser:
                return Response({"error": "Only superusers can delete other superusers"}, status=status.HTTP_403_FORBIDDEN)
            
            user.delete()
            return Response({
                "success": True,
                "message": f"User {user.username} deleted successfully!",
                "deleted_at": timezone.now().isoformat()
            }, status=status.HTTP_204_NO_CONTENT)
        
        except Exception as e:
            print(f"🔥 Error deleting user {pk}: {str(e)}")
            return Response({"error": "Failed to delete user", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class AdminBookingView(APIView):
    permission_classes = [IsAdminUser]
    parser_classes = [MultiPartParser, FormParser, JSONParser]

    def put(self, request, pk):
        """Update booking details by admin"""
        if not request.user.is_staff:
            return Response({"error": "Forbidden: Admins only"}, status=status.HTTP_403_FORBIDDEN)
        
        try:
            booking = get_object_or_404(Booking, pk=pk)
            data = request.data.copy()

            service_id = data.get("service_id")
            event_date = parse_date(data.get("event_date"))
            event_time = parse_time(data.get("event_time"))

            if service_id and event_date and event_time:
                existing_booking = Booking.objects.filter(
                    service_id=service_id,
                    event_date=event_date,
                    event_time=event_time
                ).exclude(pk=pk).exists()

                if existing_booking:
                    print("Service Already Booked on this date and Time!")
                    return Response({"error": "Servie Already Booked on this Date and Time"}, status=status.HTTP_400_BAD_REQUEST)
                
            serializer = BookingSerializer(booking,data=request.data, partial=True, context={"request": request})

            if serializer.is_valid():
                serializer.save()
                print(f"Booking {pk} updated Successful")
                return Response({"message": "Booking Updated Successful", "details": serializer.data}, status=status.HTTP_200_OK)
            
            return Response({"error": "Booking Update Failed", "details": serializer.errors})
        
        except Exception as e:
            print(f"🔥 Error updating booking {pk}: {str(e)}")
            return Response({"error": "Booking not found. Internal server error"}, status=status.HTTP_404_NOT_FOUND)
        
    def delete(self, request, pk):
        if not request.user.is_staff:
            return Response({"error": "Forbidden: Admins only"}, status=status.HTTP_403_FORBIDDEN)
        
        try:
            booking = get_object_or_404(Booking, pk=pk)
            booking.delete()
            return Response({
                "success": True,
                "message": f"Booking {booking.id} deleted successfully!",
                "deleted_at": timezone.now().isoformat()
            }, status=status.HTTP_204_NO_CONTENT)
        
        except Exception as e:
            print(f"🔥 Error deleting booking {pk}: {str(e)}")
            return Response({"error": "Failed to delete booking", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            