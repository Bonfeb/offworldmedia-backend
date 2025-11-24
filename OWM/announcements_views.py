import json
from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.admin.views.decorators import staff_member_required

def get_announcements(request):
    try:
        with open(settings.ANNOUNCEMENTS_FILE, "r") as file:
            data = json.load(file)
        return JsonResponse({"announcements": data})
    except:
        return JsonResponse({"announcements": []})


@csrf_exempt
@staff_member_required
def update_announcements(request):
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=400)

    try:
        data = json.loads(request.body)
        with open(settings.ANNOUNCEMENTS_FILE, "w") as file:
            json.dump(data["announcements"], file, indent=2)
        return JsonResponse({"status": "success"})
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

@csrf_exempt
@staff_member_required
def delete_announcement(request, announcement_id):
    if request.method != "DELETE":
        return JsonResponse({"error": "DELETE required"}, status=400)

    try:
        # Load current announcements
        with open(settings.ANNOUNCEMENTS_FILE, "r") as file:
            data = json.load(file)

        # Remove matching ID
        new_data = [item for item in data if str(item["id"]) != str(announcement_id)]

        # Save back
        with open(settings.ANNOUNCEMENTS_FILE, "w") as file:
            json.dump(new_data, file, indent=2)

        return JsonResponse({"status": "deleted", "id": announcement_id})

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)
