import json
import os
from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.contrib.auth.decorators import login_required, user_passes_test

# Helper function to check if user is staff
def staff_required(view_func):
    return login_required(user_passes_test(lambda u: u.is_staff)(view_func))

# Helper function to read/write announcements
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

# Helper function to compare IDs (handles both string and number IDs)
def compare_ids(id1, id2):
    """
    Compare two IDs that could be strings or numbers.
    Converts both to strings for comparison to handle cases like:
    - id1 = "1" and id2 = 1 (should match)
    - id1 = "123" and id2 = 123 (should match)
    - id1 = "abc" and id2 = "abc" (should match)
    """
    return str(id1) == str(id2)

# Helper function to normalize ID for URL (convert to string for consistency)
def normalize_id_for_url(announcement_id):
    """
    Convert URL parameter to string to handle both string and int IDs from URLs
    """
    return str(announcement_id)

@csrf_exempt
@require_http_methods(["GET"])
def get_announcements(request):
    try:
        announcements = read_announcements()
        return JsonResponse({"announcements": announcements, "status": "success"})
    except Exception as e:
        return JsonResponse({"error": str(e), "status": "error"}, status=500)

@csrf_exempt
@require_http_methods(["POST"])
@staff_required
def update_announcements(request):
    try:
        data = json.loads(request.body)
        announcements = data.get("announcements", [])
        
        if write_announcements(announcements):
            return JsonResponse({"status": "success", "message": "Announcements updated successfully"})
        else:
            return JsonResponse({"error": "Failed to save announcements", "status": "error"}, status=500)
            
    except Exception as e:
        return JsonResponse({"error": str(e), "status": "error"}, status=500)

@csrf_exempt
@require_http_methods(["DELETE", "POST"])
@staff_required
def delete_announcement(request, announcement_id):
    """
    Handles both string and integer IDs from URL
    Uses <str:announcement_id> in URL pattern to accept both
    """
    try:
        # Normalize the ID from URL (convert to string for consistent comparison)
        normalized_id = normalize_id_for_url(announcement_id)
        announcements = read_announcements()
        
        # Find the announcement to delete using our comparison function
        announcement_to_delete = None
        for announcement in announcements:
            if compare_ids(announcement.get("id"), normalized_id):
                announcement_to_delete = announcement
                break
        
        if not announcement_to_delete:
            return JsonResponse({
                "error": f"Announcement with ID {announcement_id} not found", 
                "status": "error"
            }, status=404)
        
        # Remove the announcement
        new_announcements = [
            item for item in announcements 
            if not compare_ids(item.get("id"), normalized_id)
        ]
        
        if write_announcements(new_announcements):
            return JsonResponse({
                "status": "success", 
                "message": "Announcement deleted successfully",
                "id": announcement_id,
                "normalized_id": normalized_id,
                "deleted_announcement": {
                    "id": announcement_to_delete.get("id"),
                    "title": announcement_to_delete.get("title")
                }
            })
        else:
            return JsonResponse({"error": "Failed to delete announcement", "status": "error"}, status=500)
            
    except Exception as e:
        return JsonResponse({"error": str(e), "status": "error"}, status=500)

# Additional view to get a specific announcement by ID
@csrf_exempt
@require_http_methods(["GET"])
def get_announcement_by_id(request, announcement_id):
    try:
        # Normalize the ID from URL
        normalized_id = normalize_id_for_url(announcement_id)
        announcements = read_announcements()
        
        # Find the announcement using our comparison function
        announcement = None
        for ann in announcements:
            if compare_ids(ann.get("id"), normalized_id):
                announcement = ann
                break
        
        if announcement:
            return JsonResponse({"announcement": announcement, "status": "success"})
        else:
            return JsonResponse({
                "error": f"Announcement with ID {announcement_id} not found", 
                "status": "error"
            }, status=404)
            
    except Exception as e:
        return JsonResponse({"error": str(e), "status": "error"}, status=500)