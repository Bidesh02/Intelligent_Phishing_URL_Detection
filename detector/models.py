from django.db import models

class ScanHistory(models.Model):
    url = models.URLField(max_length=2048)
    domain = models.CharField(max_length=255, blank=True)
    prediction = models.CharField(max_length=20)  # 'Phishing' or 'Legitimate'
    is_phishing = models.BooleanField(default=False)
    confidence = models.FloatField()
    phishing_probability = models.FloatField(default=0.0)
    risk_level = models.CharField(max_length=50, default='Safe')
    scanned_at = models.DateTimeField(auto_now_add=True)
    features_summary = models.JSONField(default=dict)

    class Meta:
        ordering = ['-scanned_at']
        verbose_name_plural = 'Scan Histories'

    def __str__(self):
        return f"{self.url} - {self.prediction} ({self.confidence}%)"
