import json
from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .feature_extractor import predict_url
from .models import ScanHistory

def get_scans_data():
    """Returns past scans from database serialized as a list of dicts."""
    scans = ScanHistory.objects.all()[:100]
    return [
        {
            "id": s.id,
            "url": s.url,
            "domain": s.domain,
            "status": s.prediction,
            "confidence": s.confidence,
            "timestamp": s.scanned_at.strftime("%b %d, %Y %H:%M:%S"),
        }
        for s in scans
    ]


def index(request):
    """Main view for PhishGuard.AI single page application."""
    if request.method == "POST":
        url_input = request.POST.get("url", "").strip()
        if url_input:
            try:
                result = predict_url(url_input)
                ScanHistory.objects.create(
                    url=result["url"],
                    domain=result["summary"]["domain"],
                    prediction=result["prediction"],
                    is_phishing=result["is_phishing"],
                    confidence=result["confidence"],
                    phishing_probability=result["phishing_probability"],
                    risk_level=result["risk_level"],
                    features_summary=result["summary"]
                )
            except Exception:
                pass

    scans_data = get_scans_data()
    context = {
        "active_tab": "scanner",
        "scans_json": json.dumps(scans_data),
    }
    return render(request, "detector/index.html", context)


def history_view(request):
    """Renders the single page application with the History tab active."""
    scans_data = get_scans_data()
    context = {
        "active_tab": "history",
        "scans_json": json.dumps(scans_data),
    }
    return render(request, "detector/index.html", context)


def analytics_view(request):
    """Renders the single page application with the Analytics tab active."""
    scans_data = get_scans_data()
    context = {
        "active_tab": "analytics",
        "scans_json": json.dumps(scans_data),
    }
    return render(request, "detector/index.html", context)


@csrf_exempt
def clear_history(request):
    """Clears all scan history from the database."""
    if request.method == "POST":
        ScanHistory.objects.all().delete()
        if request.headers.get("x-requested-with") == "XMLHttpRequest" or request.content_type == "application/json":
            return JsonResponse({"status": "success", "message": "History cleared"})
    return redirect("history")


@csrf_exempt
def api_scan(request):
    """REST API endpoint to scan URLs programmatically and with AJAX."""
    if request.method != "POST":
        return JsonResponse({"error": "POST method required"}, status=405)

    try:
        if request.content_type == "application/json":
            data = json.loads(request.body.decode("utf-8"))
            url = data.get("url", "").strip()
        else:
            url = request.POST.get("url", "").strip()

        if not url:
            return JsonResponse({"error": "Missing 'url' parameter"}, status=400)

        result = predict_url(url)

        # Save to database
        ScanHistory.objects.create(
            url=result["url"],
            domain=result["summary"]["domain"],
            prediction=result["prediction"],
            is_phishing=result["is_phishing"],
            confidence=result["confidence"],
            phishing_probability=result["phishing_probability"],
            risk_level=result["risk_level"],
            features_summary=result["summary"]
        )

        return JsonResponse({
            "status": "success",
            "data": result
        })
    except Exception as e:
        return JsonResponse({"status": "error", "message": str(e)}, status=500)
