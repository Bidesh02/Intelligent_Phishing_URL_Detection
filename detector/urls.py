from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('history/', views.history_view, name='history'),
    path('analytics/', views.analytics_view, name='analytics'),
    path('history/clear/', views.clear_history, name='clear_history'),
    path('api/scan/', views.api_scan, name='api_scan'),
]
