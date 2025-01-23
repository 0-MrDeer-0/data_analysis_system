# ------ Standard Library Imports ------

import json
import os
import re
import random
import hashlib

# ------ Third-Party Library Imports ------

from rich.console import Console
from rich.align import Align
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from rich.box import ROUNDED

# ------ Initializing Console for Rich Output ------

console = Console()

# ------ Defining Constants ------


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

USER_DATA_DIR = os.path.join(BASE_DIR, "users_data")
USERS_JSON_FILE = os.path.join(USER_DATA_DIR, "users.json")

PASSWORD_RESET_EMAILS_DIR = os.path.join(BASE_DIR, "password_reset_emails")

CSV_DATA_DIR = os.path.join(BASE_DIR, "csv_data")
ANALYSIS_DATA_FILE = os.path.join(CSV_DATA_DIR, "analysis_data.csv")


# ------ Directory and File Setup Functions ------


def create_directorie(directory_path):
    if not os.path.exists(directory_path):
        os.makedirs(directory_path)


def create_file(file_path, file_type):
    if not os.path.exists(file_path):
        if file_type == "json":
            with open(file_path, "w") as file:
                json.dump({}, file)
        elif file_type == "csv":
            with open(file_type, "w") as file:
                file.write("id,name,gender,age\n")
        else:
            with open(file_path, "w") as file:
                pass


def create_directories_and_files(directory_path, file_path, file_type):
    create_directorie(directory_path)
    create_file(file_path, file_type)


# ------ Helper Functions ------


def generate_random_code(length=6):
    characters = (
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%^&*!"
    )
    return "".join(random.choice(characters) for _ in range(length))


def hash_data(data):
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


# ------ Functions for Displaying Visual Elements ------


def show_banner():
    banner = """ ____                 ____  _        _   
|  _ \  ___  ___ _ __/ ___|| |_ __ _| |_ 
| | | || _ \| _ \ '__\___ \| __/ _` | __|
| |_| |  __/  __/ |   ___) | || (_| | |_ 
|____/ \___|\___|_|  |____/ \__\__,_|\__|
"""
    centered_banner = Align.center(banner, vertical="middle")
    console.print(centered_banner, style="bold green")


def show_menu(menu_name="user_actions"):
    menus = {
        "auth": {
            "items": [
                "[1] 🔐 Sign in",
                "[2] 📝 Sign up",
                "[3] ♻️  Reset password",
                "[0]🚪 Exit",
            ],
            "header": "User Authentication Menu",
        },
        "user_actions": {
            "items": [
                "[1] 📋 Display data",
                "[2] 📊 Statistical analysis",
                "[3] 🔎 Data search",
                "[0]🚪 Exit",
            ],
            "header": "Data Management Menu",
        },
    }
    menu_data = menus.get(menu_name, {})
    menu_items = menu_data.get("items", [])
    header_menu = menu_data.get("header", "Menu")
    if not menu_items:
        show_message("error", "Menu not found!")
        return None
    console.print(Align.center(header_menu, style="bold"))
    table = Table(
        show_header=False, expand=False, box=ROUNDED, pad_edge=True, style="dim grey70"
    )
    table.add_row(*menu_items)
    console.print(Align.center(table, vertical="middle"))
    return input("\n 🛎️  Enter your number choice: [ ]\033[12;32H")


def show_header(menu_name="user_actions"):
    console.clear()
    show_banner()
    choice = show_menu(menu_name)
    return choice


def show_message(type, message):
    panel_types = {
        "error": {"icon": "❌", "title": "[bold]Error[/bold]", "color": "#FF6F61"},
        "warning": {"icon": "⚠️", "title": "[bold]Warning[/bold]", "color": "#FFA726"},
        "success": {"icon": "🎉", "title": "[bold]Success[/bold]", "color": "#66BB6A"},
        "info": {"icon": "ℹ️", "title": "[bold]Info[/bold]", "color": "#42A5F5"},
    }
    default_type = "info"
    selected_type = panel_types.get(type, panel_types[default_type])
    console.print("\n")
    console.print(
        Panel(
            f"{message}",
            title=f"{selected_type['icon']}  {selected_type['title']}",
            style=selected_type["color"],
        )
    )
    input(" Press enter key to continue ...")


def show_process_progress(emoji, process_type, fields):
    table = Table(
        show_header=True,
        header_style="bold",
        box=ROUNDED,
        pad_edge=True,
        style="dim grey70",
    )

    table.add_column("Field", justify="center")
    table.add_column("Value", justify="center")
    table.add_column("Entered", justify="center")

    index = 0
    for field, value in fields.items():
        status = "✅" if value else "❌"
        display_value = (
            "*" * len(value)
            if "password" in field.lower() and value
            else (value or "None")
        )
        table.add_row(field, display_value, status)
        if index < len(fields) - 1:
            table.add_row()
        index += 1

    console.clear()
    show_banner()
    aligned_table = Align.center(table, vertical="middle")
    console.print(Align.center(f"{emoji} {process_type} Progress"), style="bold")
    console.print(aligned_table)


# ------ Functions to Manage User Data in users.json ------


def read_json_file():
    create_directories_and_files(USER_DATA_DIR, USERS_JSON_FILE, "json")
    with open(USERS_JSON_FILE, "r") as file:
        return json.load(file)


def write_json_file(data):
    create_directories_and_files(USER_DATA_DIR, USERS_JSON_FILE, "json")
    with open(USERS_JSON_FILE, "w") as file:
        json.dump(data, file, indent=4)


def find_user(lookup_key, lookup_value):
    users = read_json_file()
    for details in users.values():
        if details[lookup_key] == lookup_value:
            return details
    return None


def save_user(username, password, email):
    users = read_json_file()
    hashed_password = hash_data(password)
    users[username] = {
        "username": username,
        "password": hashed_password,
        "email": email,
    }
    write_json_file(users)


def update_user_data(lookup_key, lookup_value, update_key, new_value, hash_value=False):
    users = read_json_file()
    for user_data in users.values():
        if user_data[lookup_key] == lookup_value:
            if hash_value:
                new_value = hash_data(new_value)
            user_data[update_key] = new_value
            break
    write_json_file(users)
    show_message("success", f"Your {update_key} has been successfully updated!")


# ------ Validation Functions for User Input ------


def is_username_unique(username):
    user = find_user("username", username)
    return user is None


def is_email_unique(email):
    users = read_json_file()
    for user_data in users.values():
        if user_data["email"] == email:
            return False
    return True


def validate_non_empty(value):
    if not value:
        return "This field cannot be empty."
    return None


def validate_username(
    username,
    min_length=3,
    max_length=15,
    check_valid_chars=True,
    check_uniqueness=True,
    check_length=True,
):
    if not username:
        return "Username cannot be empty."
    if check_length and len(username) < min_length:
        return f"Username must be at least {min_length} characters long."
    if check_length and len(username) > max_length:
        return f"Username cannot exceed {max_length} characters."
    if check_valid_chars and not re.fullmatch("^[A-Za-z0-9_-]*$", username):
        return "Username can only contain letters, numbers, underscores, hyphens."
    if check_uniqueness and not is_username_unique(username):
        return "Username already exists. Please choose another one."
    return None


def validate_password(
    password, min_length=8, check_length=True, check_confirmation=True
):
    if not password:
        return "Password cannot be empty."
    if check_length and len(password) < min_length:
        return "Password must be at least 8 characters long."
    if check_confirmation and password != Prompt.ask(
        " 🔑 Confirm your password", password=True
    ):
        return "Passwords do not match."
    return None


def validate_email(email, check_valid_chars=True, check_uniqueness=True):
    email_regex = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    if not email:
        return "Email cannot be empty."
    if check_valid_chars and not re.match(email_regex, email):
        return "Invalid email format. Please try again."
    if check_uniqueness and not is_email_unique(email):
        return "This email is already registered. Please use a different one."
    return None


def get_input_with_validation(prompt_text, validator, secure=False):
    value = Prompt.ask(prompt_text, password=secure).strip()
    error = validator(value)
    if error:
        show_message("error", error)
    else:
        return value


# ------ User Registration Logic ------


def register_user():
    fields = {"👤 Username": None, "🔐 Password": None, "📧 Email": None}
    while not fields["👤 Username"]:
        show_process_progress("📝", "Registration", fields)
        fields["👤 Username"] = get_input_with_validation(
            " 👤 Please enter your desired username", validate_username
        )
    while not fields["🔐 Password"]:
        show_process_progress("📝", "Registration", fields)
        fields["🔐 Password"] = get_input_with_validation(
            " 🔑 Enter a secure password [#FFA500](at least 8 characters)[/#FFA500]",
            validate_password,
            secure=True,
        )
    while not fields["📧 Email"]:
        show_process_progress("📝", "Registration", fields)
        fields["📧 Email"] = get_input_with_validation(
            " 📧 Enter your email address", validate_email
        )
    show_process_progress("📝", "Registration", fields)
    confirmation = Prompt.ask(
        " 🤝 Do you want to proceed with the registration?", choices=["yes", "no"]
    )
    if confirmation == "yes":
        save_user(fields["👤 Username"], fields["🔐 Password"], fields["📧 Email"])
        show_message("success", "User registered successfully!")
    else:
        show_message("info", "Registration canceled.")


# ------ Authentication and Login Functions ------


def authenticate_user(username, password):
    user = find_user("username", username)
    if user:
        hashed_password = hash_data(password)
        if user["password"] == hashed_password:
            return True
    return False


def handle_login_tries(max_tries=3):
    remaining_tries = max_tries
    while remaining_tries > 0:
        fields = {"👤 Username": None, "🔐 Password": None}
        while not fields["👤 Username"]:
            show_process_progress("🔐", "Sign in", fields)
            fields["👤 Username"] = get_input_with_validation(
                " 👤 Please enter your username",
                lambda username: validate_username(
                    username,
                    check_length=False,
                    check_uniqueness=False,
                    check_valid_chars=False,
                ),
            )
        while not fields["🔐 Password"]:
            show_process_progress("📝", "Registration", fields)
            fields["🔐 Password"] = get_input_with_validation(
                " 🔑 Enter your password to continue",
                lambda password: validate_password(
                    password, check_length=False, check_confirmation=False
                ),
                secure=True,
            )
        if authenticate_user(fields["👤 Username"], fields["🔐 Password"]):
            show_process_progress("🔐", "Sign in", fields)
            return True
        else:
            remaining_tries -= 1
            show_process_progress("🔐", "Sign in", fields)
            message = (
                "All attempts used. If you forgot your password, use the 'Reset Password'."
                if remaining_tries == 0
                else f"Invalid username or password, {remaining_tries} attempt(s) left! Please try again."
            )
            show_message("error", message)
    return False


def login_user():
    if handle_login_tries():
        show_message(
            "success",
            "Welcome back! You have successfully logged in.",
        )
        return True
    else:
        return False


# ------ Password Reset Process with Email Verification ------


def mock_send_verification_email(email, username, random_code):
    email_massage = f"""
    <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>♻️ Reset account password</title>
            <script src="https://cdn.tailwindcss.com"></script>
        </head>
        <body class="bg-[#f0f8ff] text-[#242424]">
            <main class="container px-12 pt-5 text-center space-y-8 mx-auto">
                <p class="text-8xl">👀</p>
                <h2 class="text-5xl font-semibold">Password reset</h2>
                <div class="bg-white rounded-md space-y-4 py-12 px-20 shadow-lg">
                    <p class="font-bold text-2xl">Hi {username}, Someone requested that the password be reset for the following account</p>
                    <p>To proceed, please copy the following verification code by clicking the button below and paste it in the app to reset your password:</p>
                    <button id="btn_copy_code" class="bg-[#3498db] shadow-md hover:bg-[#5dade2] hover:scale-105 hover:shadow-lg active:bg-[#2e86c1] active:scale-100 active:shadow-sm text-white py-4 px-8 rounded-lg transition-all">{random_code}</button>
                    <p>Your email: <span class="text-[#3b82f6]">{email}</span> </p>
                    <p>if this was a mistake. just ignore this email and nothing will happen.</p>
                </div>
                <div id="card_message" class="invisible opacity-0 fixed bottom-2 left-2 margin-auto bg-[#4caf50] text-white p-3 flex items-center gap-2 rounded-lg transition-all">
                    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" class="size-8">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75 11.25 15 15 9.75M21 12c0 1.268-.63 2.39-1.593 3.068a3.745 3.745 0 0 1-1.043 3.296 3.745 3.745 0 0 1-3.296 1.043A3.745 3.745 0 0 1 12 21c-1.268 0-2.39-.63-3.068-1.593a3.746 3.746 0 0 1-3.296-1.043 3.745 3.745 0 0 1-1.043-3.296A3.745 3.745 0 0 1 3 12c0-1.268.63-2.39 1.593-3.068a3.745 3.745 0 0 1 1.043-3.296 3.746 3.746 0 0 1 3.296-1.043A3.746 3.746 0 0 1 12 3c1.268 0 2.39.63 3.068 1.593a3.746 3.746 0 0 1 3.296 1.043 3.746 3.746 0 0 1 1.043 3.296A3.745 3.745 0 0 1 21 12Z" />
                    </svg>
                    Your verification code has been copied. Please paste it in the required field to proceed.
                </div>
            </main>
            <script>
                const btnCopyCode = document.getElementById("btn_copy_code");
                const cardMessage = document.getElementById("card_message");
                btnCopyCode.addEventListener("click", () => {{
                navigator.clipboard.writeText(btnCopyCode.textContent);
                cardMessage.classList.remove("invisible" , "opacity-0");
                setTimeout(() => {{
                    cardMessage.classList.add("invisible", "opacity-0");
                    }} , 2000)
                }}
                );
            </script>
        </body>
        </html>
    """
    file_name = f"{email}.html"
    file_path = os.path.join(PASSWORD_RESET_EMAILS_DIR , file_name)
    create_directorie(PASSWORD_RESET_EMAILS_DIR)
    with open(file_path, "w") as file:
        file.write(email_massage)


def reset_password():
    fields = {"📧 Email": None, "📩 Confrim Code": None, "🔐 New Password": None}
    while not fields["📧 Email"]:
        show_process_progress("♻️ ", "Reset Password", fields)
        fields["📧 Email"] = get_input_with_validation(
            " 📧 Enter your registered email for reset code",
            lambda email: validate_email(email, check_uniqueness=False),
        )
    user = find_user("email", fields["📧 Email"])
    if not user:
        show_process_progress("♻️ ", "Reset Password", fields)
        show_message(
            "error",
            "This email is not registered with us. Please enter a valid registered email.",
        )
        return
    else:
        confrim_code = generate_random_code()
        mock_send_verification_email(user["email"], user["username"], confrim_code)
        while not fields["📩 Confrim Code"]:
            show_process_progress("♻️ ", "Reset Password", fields)
            fields["📩 Confrim Code"] = get_input_with_validation(
                " 📩 Enter the confrim code sent to your email in 'password_reset_emails' folder",
                validate_non_empty,
            )
        if confrim_code == fields["📩 Confrim Code"]:
            while not fields["🔐 New Password"]:
                show_process_progress("♻️ ", "Reset Password", fields)
                fields["🔐 New Password"] = get_input_with_validation(
                    " 🔑 Set a new password for your account", validate_password, True
                )
            show_process_progress("♻️ ", "Reset Password", fields)
            update_user_data(
                "email", fields["📧 Email"], "password", fields["🔐 New Password"], True
            )
        else:
            show_message(
                "error",
                "The code is incorrect or expired. Please request a new reset code.",
            )


# ------ Main Entry Point for Program Execution ------


def init():
    while True:
        user_choice = show_header("auth")
        if user_choice == "0":
            console.clear()
            return
        elif user_choice == "1":
            if login_user():
                show_header()
            else:
                console.clear()
                return
        elif user_choice == "2":
            register_user()
        elif user_choice == "3":
            reset_password()
        else:
            show_message("error", "Your choice not found!")


init()
