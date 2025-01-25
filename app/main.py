# ------ Standard Library Imports ------

import json
import os
import re
import random
import hashlib
import csv

# ------ Third-Party Library Imports ------

from rich.console import Console
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


def create_and_display_table(title, show_header, headers, data, padding=(0, 1)):
    table = Table(
        title=title,
        title_style="bold",
        show_header=show_header,
        header_style="bold",
        expand=False,
        box=ROUNDED,
        pad_edge=True,
        style="dim grey70",
        padding=padding,
    )
    if show_header:
        for header in headers:
            table.add_column(header, justify="center")
    if not isinstance(data[0], list):
        data = [data]
    for row in data:
        table.add_row(*row)
        if not row == data[-1]:
            table.add_row()
    show_banner()
    console.print(table, justify="center")


def show_banner():
    banner = """___                 ____  _        _   
|  _ \  ___  ___ _ __/ ___|| |_ __ _| |_ 
| | | || _ \| _ \ '__\___ \| __/ _` | __|
| |_| |  __/  __/ |   ___) | || (_| | |_ 
|____/ \___|\___|_|  |____/ \__\__,_|\__|
"""
    console.clear()
    console.print(banner, style="bold green", justify="center")


def show_menu(menu_name="user_actions"):
    menus = {
        "auth": {
            "items": [
                "[1] 🔐 Sign in",
                "[2] 📝 Sign up",
                "[3] ♻️  Reset password",
                "[0] 🚪 Exit",
            ],
            "title": "User Authentication Menu",
        },
        "user_actions": {
            "items": [
                "[1] ✍️  Update data",
                "[2] 📋 Display data",
                "[3] 📊 Analysis",
                "[4] 🔎 Search",
                "[0] 🚪 Log out",
            ],
            "title": "Data Management Menu",
        },
        "data_modification": {
            "items": [
                "[1] ✏️  Add data",
                "[2] 🗑️  Delete data",
                "[0] 🔙 Back to Main Menu",
            ],
            "title": "Update Data Menu",
        },
    }
    menu_data = menus.get(menu_name, {})
    menu_items = menu_data.get("items", [])
    title = menu_data.get("title", "Menu")
    if not menu_items:
        show_message("error", "Menu not found!")
        return None
    create_and_display_table(title, False, None, menu_items)
    return input("\n 🛎️  Enter your number choice: [ ]\033[12;32H")


def show_header(menu_name="user_actions"):
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
    title = f"{emoji}  {process_type} Progress"
    headers = ["Field", "Value", "Entered"]
    table_items = []
    for field, value in fields.items():
        status = "✅" if value else "❌"
        display_value = (
            "*" * len(value)
            if "password" in field.lower() and value
            else (value or "None")
        )
        table_items.append([field, display_value, status])
    create_and_display_table(title, True, headers, table_items)


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


# ------ Functions to Manage csv data in analysis_data.csv ------


def read_csv_file():
    create_directories_and_files(CSV_DATA_DIR, ANALYSIS_DATA_FILE, "csv")
    with open(ANALYSIS_DATA_FILE, mode="r", newline="") as file:
        reader = csv.reader(file)
        rows = [row for row in reader if row]
    return rows


def write_csv_file(data):
    create_directorie(CSV_DATA_DIR)
    with open(ANALYSIS_DATA_FILE, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        for row in data:
            writer.writerow(row)


def generate_new_id(target_id):
    rows = read_csv_file()
    largest_id = int(rows[-1][0])
    if target_id == 1:
        return 1
    elif target_id == largest_id:
        return largest_id + 1
    else:
        if largest_id >= target_id:
            return target_id
        else:
            return largest_id + 1


def update_ids(update_from, rows):
    if update_from < len(rows):
        field_index = update_from
        for row in rows[update_from:]:
            row[0] = str(field_index)
            field_index += 1
    return rows


def append_or_insert_row(insert_index, row):
    rows = read_csv_file()
    rows.insert(insert_index, row)
    rows = update_ids(insert_index, rows)
    write_csv_file(rows)


def map_position_to_id(position, action):
    rows = read_csv_file()
    max_id = int(rows[-1][0])
    if position == "start":
        return 1
    elif position == "end":
        if action == "add":
            return max_id + 1
        else:
            return max_id
    return int(position)


def find_rows_by_header(value, header="id", limit=1):
    rows = read_csv_file()
    headers = rows[0]
    if header not in headers:
        available_headers = ", ".join(headers)
        show_message(
            "error",
            f"Header '{header}' not found in the CSV file. Available headers are: {available_headers}.",
        )
        return None
    header_index = headers.index(header)
    matching_rows = []
    for row in rows[1:]:
        if row[header_index] == str(value):
            matching_rows.append(row)
            if len(matching_rows) >= limit:
                break
    if not matching_rows:
        show_message("error", f"No rows found with {header} by '{value}'.")
        return None
    if limit == 1:
        return matching_rows[0]
    return matching_rows


def remove_row(row_to_delete):
    rows = read_csv_file()
    filtered_rows = []
    for row in rows:
        if row != row_to_delete:
            filtered_rows.append(row)
    update_ids(int(row_to_delete[0]), filtered_rows)
    write_csv_file(filtered_rows)


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


def is_numeric(value):
    try:
        float(value)
        return None
    except ValueError:
        return "Input must be a valid number."


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
    if error := validate_non_empty(username):
        return error
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
    if error := validate_non_empty(password):
        return error
    if check_length and len(password) < min_length:
        return "Password must be at least 8 characters long."
    if check_confirmation and password != Prompt.ask(
        " 🔑 Confirm your password", password=True
    ):
        return "Passwords do not match."
    return None


def validate_email(email, check_valid_chars=True, check_uniqueness=True):
    email_regex = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    if error := validate_non_empty(email):
        return error
    if check_valid_chars and not re.match(email_regex, email):
        return "Invalid email format. Please try again."
    if check_uniqueness and not is_email_unique(email):
        return "This email is already registered. Please use a different one."
    return None


def validate_person_name(name):
    person_name_regex = r"^[A-Za-z ]+$"
    if error := validate_non_empty(name):
        return error
    if not re.match(person_name_regex, name):
        return "Name should only contain letters and spaces."
    return None


def validate_gender(gender):
    if error := validate_non_empty(gender):
        return error
    options = ["male", "female", "other"]
    if gender not in options:
        return f"Invalid gender. Please enter one of the {', '.join(options)}."
    return None


def validate_id(value, action):
    rows = read_csv_file()
    largest_id = int(rows[-1][0])
    if error := validate_non_empty(value):
        return error
    if value != "start" and value != "end" and not value.isdigit():
        return "Position must be either 'start', 'end', or a valid ID field."
    if value.isdigit() and int(value) < 1:
        return "ID must be a positive integer greater than 0."
    if action != "add" and value.isdigit() and int(value) >= largest_id:
        return f"Id {value} is greater than the largest existing id, which is {rows[-1][0]}."


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
    file_path = os.path.join(PASSWORD_RESET_EMAILS_DIR, file_name)
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


# ------ Add data process ------


def add_data_process():
    fields = {
        "🆔 Id": "Auto generate",
        "👤 Name": None,
        "🚻 Gender": None,
        "⏳ Age": None,
    }
    target = None
    while not fields["👤 Name"]:
        show_process_progress("✍️", "Update Data Progress", fields)
        fields["👤 Name"] = get_input_with_validation(
            " 👤 Please enter the person's full name", validate_person_name
        )
    while not fields["🚻 Gender"]:
        show_process_progress("✍️", "Update Data Progress", fields)
        fields["🚻 Gender"] = get_input_with_validation(
            " 🚻 Enter the gender of the person [male , female , other]",
            validate_gender,
        )
    while not fields["⏳ Age"]:
        show_process_progress("✍️", "Update Data Progress", fields)
        fields["⏳ Age"] = get_input_with_validation(
            " ⏳ Enter the person's age", is_numeric
        )
    while not target:
        show_process_progress("✍️", "Update Data Progress", fields)
        target = get_input_with_validation(
            f" 🆔 Please specify the position where you would add data ['start', 'end', or a specific row number]",
            lambda value: validate_id(value, action="add"),
        )
    target_id = map_position_to_id(target, "add")
    fields["🆔 Id"] = str(generate_new_id(target_id))
    show_process_progress("✍️", "Update Data Progress", fields)
    confirmation = Prompt.ask(
        "🤝 Do you confirm to proceed with adding these details?", choices=["yes", "no"]
    )
    if confirmation == "yes":
        new_row = [
            fields["🆔 Id"],
            fields["👤 Name"],
            fields["🚻 Gender"],
            fields["⏳ Age"],
        ]
        append_or_insert_row(target_id, new_row)
        show_message("success", "Data has been successfully added to the file!")
    else:
        show_message("info", "Data entry has been canceled. No changes were made.")


# ------ Remove data process ------


def remove_data_proess():
    target = None
    while not target:
        show_banner()
        target = get_input_with_validation(
            f" 🆔 Please specify the position where you would remove data ['start', 'end', or a specific row number]",
            lambda value: validate_id(value, action="remove"),
        )
    target_id = map_position_to_id(target, "remove")
    row_to_delete = find_rows_by_header(target_id)
    if row_to_delete:
        create_and_display_table(
            "🔎 The following row has been found",
            True,
            ["🆔 ID", "👤 Name", "🚻 Gender", "⏳ Age"],
            row_to_delete,
        )
        confirmation = Prompt.ask(
            " ⚠️  Are you sure you want to delete this row?", choices=["yes", "no"]
        )
        if confirmation == "yes":
            remove_row(row_to_delete)
        else:
            show_message("info", "Deletion cancelled. No changes were made.")


# ------ Display csv data functions ------


def display_rows_between_ids(start_id, end_id):
    rows = read_csv_file()
    data = rows[1:]
    filtered_rows = data[start_id - 1 : end_id]
    create_and_display_table(
        "🗓️  Rows Displayed Between Given IDs",
        True,
        ["🆔 Id", "👤 Name", "🚻 Gender", "⏳ Age"],
        filtered_rows,
        padding=(0, 3),
    )
    show_message("success", "Your data has been successfully displayed.")


def display_data_proess():
    fields = {"🔽 Start": None, "🔼 End": None}
    show_process_progress("🆔", "Specifying IDs", fields)
    is_range_correct = False
    start_id = end_id = None
    while not is_range_correct:
        while not fields["🔽 Start"]:
            show_process_progress("🆔", "Specifying IDs", fields)
            fields["🔽 Start"] = get_input_with_validation(
                " 🔽 Please specify the position where you would start displaying data ['start', 'end', or a specific row number]",
                lambda value: validate_id(value, action="find"),
            )
        while not fields["🔼 End"]:
            show_process_progress("🆔", "Specifying IDs", fields)
            fields["🔼 End"] = get_input_with_validation(
                " 🔽 Please specify the position where you would end displaying data ['start', 'end', or a specific row number]",
                lambda value: validate_id(value, action="find"),
            )
        start_id = map_position_to_id(fields["🔽 Start"], "find")
        end_id = map_position_to_id(fields["🔼 End"], "find")
        is_range_correct = True if start_id < end_id else False
    display_rows_between_ids(start_id, end_id)


# ------ Main Entry Point for Program Execution ------


def init():
    while True:
        auth_choice = show_header("auth")
        if auth_choice == "0":
            console.clear()
            return
        elif auth_choice == "1":
            if login_user():
                while True:
                    post_login_choice = show_header()
                    if post_login_choice == "0":
                        break
                    elif post_login_choice == "1":
                        while True:
                            data_modification_choice = show_header("data_modification")
                            if data_modification_choice == "0":
                                break
                            elif data_modification_choice == "1":
                                add_data_process()
                            elif data_modification_choice == "2":
                                remove_data_proess()
                            else:
                                show_message("error", "Your choice not found!")
                    elif post_login_choice == "2":
                        display_data_proess()
            else:
                console.clear()
                return
        elif auth_choice == "2":
            register_user()
        elif auth_choice == "3":
            reset_password()
        else:
            show_message("error", "Your choice not found!")


init()
