from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework.response import Response
from rest_framework import status
from django.conf import settings
import os, json

def get_announcements_file_path():
    return getattr(settings, 'ANNOUNCEMENTS_FILE', 'announcements.json')

def read_announcements():
    try:
        file_path = get_announcements_file_path()
        if os.path.exists(file_path):
            with open(file_path, "r") as file:
                return json.load(file)
        return []
    except Exception as e:
        print(f"Error reading announcements: {e}")
        return []

def write_announcements(announcements):
    try:
        file_path = get_announcements_file_path()
        with open(file_path, "w") as file:
            json.dump(announcements, file, indent=2)
        return True
    except Exception as e:
        print(f"Error writing announcements: {e}")
        return False
    
class AnnouncementsView(APIView):
    permission_classes = []  # Public endpoint

    def get(self, request):
        announcements = read_announcements()
        return Response({"announcements": announcements})

    
class UpdateAnnouncementsView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUser]

    def post(self, request):
        announcements = request.data.get("announcements", [])
        if write_announcements(announcements):
            return Response({"status": "success"})
        return Response({"error": "Failed to save"}, status=500)

class DeleteAnnouncementView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUser]

    def delete(self, request, announcement_id):
        announcement_id = str(announcement_id)
        announcements = read_announcements()

        filtered = [a for a in announcements if str(a["id"]) != announcement_id]

        if len(filtered) == len(announcements):
            return Response(
                {"error": "Announcement not found"},
                status=status.HTTP_404_NOT_FOUND,
            )

        write_announcements(filtered)

        return Response({"status": "success"})
