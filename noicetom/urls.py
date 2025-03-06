from django.urls import path
from .views import home

urlpatterns = [
    path('', home, name='home'),
    #path('login/', user_login, name='login'),
    #path('logout/', user_logout, name='logout'),
]

