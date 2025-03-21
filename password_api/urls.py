from django.contrib import admin
from django.urls import path, include
from generator.views import home  

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', home, name='home'),  
    path('api/', include('generator.urls')),  # Forward to the generator API URLs
]
