from django.contrib import admin
from .models import ScanHistory

@admin.register(ScanHistory)
class ScanHistoryAdmin(admin.ModelAdmin):
    list_display = ('url', 'prediction', 'confidence', 'is_phishing', 'scanned_at')
    list_filter = ('prediction', 'is_phishing', 'scanned_at')
    search_fields = ('url', 'domain')
    ordering = ('-scanned_at',)
