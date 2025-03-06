from django.urls import path
from .views import register, user_login, user_logout, dashboard

urlpatterns = [
        path('register/', register, name='register'),
        path('login/', user_login, name='login'),
        path('dashboard/', dashboard, name='dashboard'),
        path('logout/', user_logout, name='logout'),
]
