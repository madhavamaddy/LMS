# Importing required libraries
from django.urls import path
from . import views
from django.contrib.auth.views import PasswordResetView,PasswordResetConfirmView,PasswordResetDoneView,PasswordResetCompleteView



# Url patterns for Books app module of Library Management System
urlpatterns = [
    path("", views.home, name="home"),
    path("issue", views.issue, name="issue"),
    path("login/", views.login, name="login"),
    path("register/", views.register, name="register"),
    path("logout", views.logout, name="logout"),
    path("return_item", views.return_item, name="return_item"),
    path("history", views.history, name="history"),
    #path('admin/', admin.site.urls),


    # path('password_reset/',PasswordResetView.as_view(),name="password_reset"),
    # path('password_reset/done/',PasswordResetDoneView.as_view(),name="password_reset_done"),
    # path('password_reset/confirm/<uidb64>/<token>/',PasswordResetConfirmView.as_view(),name="password_reset_confirm"),
    # path('password_reset/complete/',PasswordResetCompleteView.as_view(),name="password_reset_complete"),
    path("password_change/", views.password_change, name="password_change"),
    path("password_reset/", views.password_reset_request, name="password_reset"),
    path('reset/<uidb64>/<token>', views.passwordResetConfirm, name='password_reset_confirm'),
]