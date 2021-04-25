from django.urls import path

from . import views

urlpatterns = [
  path('authorise-url', views.AuthoriseUrlView.as_view()),
  path('personal-data', views.PersonalDataView.as_view()),
]
