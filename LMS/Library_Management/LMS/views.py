# Importing required libraries
from django.shortcuts import redirect, render
from .models import Book, IssuedItem
from django.contrib import messages
from django.contrib.auth.models import auth, User
from django.db.models import Q
from django.contrib.auth.decorators import login_required
from datetime import date
from django.core.paginator import Paginator
from django.urls import reverse_lazy
from django.contrib.auth.views import PasswordResetView
from django.contrib.messages.views import SuccessMessageMixin

from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.mail import EmailMessage
from django.template.loader import render_to_string
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str

from . form import SetPasswordForm, PasswordResetForm
from .decorators import user_not_authenticated
from .tokens import account_activation_token

# ----------------- Library Management System Views -----------------

# password reset or change


# Home view
def home(request):
    return render(request, "home.html")


# Login view to login user
def login(request):

    # If request is post then get username and password from request
    if request.method == "POST":
        username = request.POST["username"]
        password = request.POST["password"]

        # Authenticate user
        user = auth.authenticate(username=username, password=password)

        # If user is authenticated then login user
        if user is not None:
            auth.login(request, user)

            # Redirect to home page
            return redirect("/")
        else:

            # If user is not authenticated then show error message
            # and redirect to login page
            messages.info(request, "Invalid Credential")
            return redirect("login")
    else:

        # If request is not post then render login page
        return render(request, "login.html")


# Register view to register user
def register(request):

    # If request is post then get user details from request
    if request.method == "POST":
        first_name = request.POST["first_name"]
        last_name = request.POST["last_name"]
        username = request.POST["username"]
        email = request.POST["email"]
        password1 = request.POST["password1"]
        password2 = request.POST["password2"]

        # Check if password and confirm password matches
        if password1 == password2:

            # Check if username or email already exists
            if User.objects.filter(username=username).exists():
                messages.info(request, "Username already exist")
                return redirect("register")
            
            elif User.objects.filter(first_name=first_name).exists():
                messages.info(request, "first name already exist")
                return redirect("register")

            # Check if email already exists
            elif User.objects.filter(email=email).exists():
                messages.info(request, "Email already registered")
                return redirect("register")

            # If username and email does not exists then create user
            else:

                # Create user
                user = User.objects.create_user(
                    first_name=first_name,
                    last_name=last_name,
                    username=username,
                    email=email,
                    password=password1,
                )

                # Save user
                user.save()

                # Redirect to login page
                return redirect("login")
        else:

            # If password and confirm password does not matches then show error message
            messages.info(request, "Password not matches")
            return redirect("register")
    else:

        # If request is not post then render register page
        return render(request, "register.html")


# Logout view to logout user
def logout(request):

    # Logout user and redirect to home page
    auth.logout(request)
    return redirect("/")


# Issue view to issue book to user
@login_required(login_url="login")
def issue(request):

    # If request is post then get book id from request
    if request.method == "POST":
        book_id = request.POST["book_id"]
        current_book = Book.objects.get(id=book_id)
        book = Book.objects.filter(id=book_id)
        issue_item = IssuedItem.objects.create(
            user_id=request.user, book_id=current_book
        )
        issue_item.save()
        book.update(quantity=book[0].quantity - 1)

        # Show success message and redirect to issue page
        messages.success(request, "Book issued successfully.")

    # Get all books which are not issued to user
    my_items = IssuedItem.objects.filter(
        user_id=request.user, return_date__isnull=True
    ).values_list("book_id")
    books = Book.objects.exclude(id__in=my_items).filter(quantity__gt=0)

    # Return issue page with books that are not issued to user
    return render(request, "issue_item.html", {"books": books})


# History view to show history of issued books to user
@login_required(login_url="login")
def history(request):

    # Get all issued books to user
    my_items = IssuedItem.objects.filter(user_id=request.user).order_by("-issue_date")

    # Paginate data
    paginator = Paginator(my_items, 10)

    # Get page number from request
    page_number = request.GET.get("page")
    show_data_final = paginator.get_page(page_number)

    # Return history page with issued books to user
    return render(request, "history.html", {"books": show_data_final})


# Return view to return book to library
@login_required(login_url="login")
def return_item(request):

    # If request is post then get book id from request
    if request.method == "POST":

        # Get book id from request
        book_id = request.POST["book_id"]

        # Get book object
        current_book = Book.objects.get(id=book_id)

        # Update book quantity
        book = Book.objects.filter(id=book_id)
        book.update(quantity=book[0].quantity + 1)

        # Update return date of book and show success message
        issue_item = IssuedItem.objects.filter(
            user_id=request.user, book_id=current_book, return_date__isnull=True
        )
        issue_item.update(return_date=date.today())
        messages.success(request, "Book returned successfully.")

    # Get all books which are issued to user
    my_items = IssuedItem.objects.filter(
        user_id=request.user, return_date__isnull=True
    ).values_list("book_id")

    # Get all books which are not issued to user
    books = Book.objects.exclude(~Q(id__in=my_items))

    # Return return page with books that are issued to user
    params = {"books": books}
    return render(request, "return_item.html", params)






@login_required
def password_change(request):
    user = request.user
    if request.method == 'POST':
        form = SetPasswordForm(user, request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, "Your password has been changed")
            return redirect('login')
        else:
            for error in list(form.errors.values()):
                messages.error(request, error)

    form = SetPasswordForm(user)
    return render(request, 'password_reset_confirm.html', {'form': form})

# @user_not_authenticated
@login_required
def password_reset_request(request):
    if request.method == 'POST':
        form = PasswordResetForm(request.POST)
        if form.is_valid():
            user_email = form.cleaned_data['email']
            associated_user = get_user_model().objects.filter(Q(email=user_email)).first()
            if associated_user:
                subject = "Password Reset request"
                message = render_to_string("template_reset_password.html", {
                    'user': associated_user,
                    'domain': get_current_site(request).domain,
                    'uid': urlsafe_base64_encode(force_bytes(associated_user.pk)),
                    'token': account_activation_token.make_token(associated_user),
                    "protocol": 'https' if request.is_secure() else 'http'
                })
                email = EmailMessage(subject, message, to=[associated_user.email])
                if email.send_mail:
                    messages.success(request,
                        """
                        <h2>Password reset sent</h2><hr>
                        <p>
                            We've emailed you instructions for setting your password, if an account exists with the email you entered. 
                            You should receive them shortly.<br>If you don't receive an email, please make sure you've entered the address 
                            you registered with, and check your spam folder.
                        </p>
                        """
                    )
                else:
                    messages.error(request, "Problem sending reset password email, <b>SERVER PROBLEM</b>")

            return redirect('home')

        for key, error in list(form.errors.items()):
            if key == 'captcha' and error[0] == 'This field is required.':
                messages.error(request, "You must pass the reCAPTCHA test")
                continue

    form = PasswordResetForm()
    return render(
        request=request, 
        template_name="password_reset.html", 
        context={"form": form}
        )

def passwordResetConfirm(request, uidb64, token):
    User = get_user_model()
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except:
        user = None

    if user is not None and account_activation_token.check_token(user, token):
        if request.method == 'POST':
            form = SetPasswordForm(user, request.POST)
            if form.is_valid():
                form.save()
                messages.success(request, "Your password has been set. You may go ahead and <b>log in </b> now.")
                return redirect('homepage')
            else:
                for error in list(form.errors.values()):
                    messages.error(request, error)

        form = SetPasswordForm(user)
        return render(request, 'password_reset_confirm.html', {'form': form})
    else:
        messages.error(request, "Link is expired")

    messages.error(request, 'Something went wrong, redirecting back to Homepage')
    return redirect("homepage")


def activate(request, uidb64, token):
    User = get_user_model()
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except:
        user = None

    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()

        messages.success(request, "Thank you for your email confirmation. Now you can login your account.")
        return redirect('login')
    else:
        messages.error(request, "Activation link is invalid!")

    return redirect('homepage')

def activateEmail(request, user, to_email):
    mail_subject = "Activate your user account."
    message = render_to_string("template_activate_account.html", {
        'user': user.username,
        'domain': get_current_site(request).domain,
        'uid': urlsafe_base64_encode(force_bytes(user.pk)),
        'token': account_activation_token.make_token(user),
        "protocol": 'https' if request.is_secure() else 'http'
    })
    email = EmailMessage(mail_subject, message, to=[to_email])
    if email.send():
        messages.success(request, f'Dear <b>{user}</b>, please go to you email <b>{to_email}</b> inbox and click on \
                received activation link to confirm and complete the registration. <b>Note:</b> Check your spam folder.')
    else:
        messages.error(request, f'Problem sending email to {to_email}, check if you typed it correctly.')