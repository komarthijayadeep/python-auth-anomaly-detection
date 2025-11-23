import re
import hashlib
import os  
from datetime import datetime



def generate_salt():
    """Generates a random 16-byte salt and returns it as a hex string."""
    return os.urandom(16).hex()

def hash_password(password, salt):
    """Combines password and salt, then returns the SHA-256 hash."""
    combined = password + salt
    return hashlib.sha256(combined.encode()).hexdigest()

def is_strong_password(password):
    """Checks if a password meets the defined strength criteria."""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r'[A-Z]', password):
        return False, "Password must include at least one uppercase letter."
    if not re.search(r'[0-9]', password):
        return False, "Password must include at least one number."
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must include at least one special symbol."
    return True, "Password is strong"

# --- Auditing and Logging ---

def log_event(event):
    """Writes a timestamped event to the audit log file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("audit_log.txt", "a") as log_file:
        log_file.write(f"[{timestamp}] {event}\n")

# --- AI Anomaly Detection Helper Function ---

def update_user_baseline(username, login_hour):
    """Updates the user's record with their first successful login hour."""
    with open("users.txt", "r") as file:
        users = file.readlines()

    updated_users = []
    for user in users:
        stored_username, stored_salt, stored_hash, _ = user.strip().split(":")
        if username == stored_username:
            # Update the line for the current user with their new baseline hour
            updated_users.append(f"{stored_username}:{stored_salt}:{stored_hash}:{login_hour}\n")
        else:
            updated_users.append(user)

    with open("users.txt", "w") as file:
        file.writelines(updated_users)

# --- Core User Management Functions ---

def register_user():
    """Handles new user registration, including salting and AI baseline setup."""
    username = input("Enter a Username: ")
    
    # Check if user already exists
    try:
        with open("users.txt", "r") as file:
            for line in file:
                if line.startswith(f"{username}:"):
                    print("Username already exists. Please choose another one.")
                    log_event(f"Failed registration attempt for existing username '{username}'")
                    return
    except FileNotFoundError:
        pass  # File doesn't exist yet, which is fine.

    password = input("Enter a password: ")
    is_valid, feedback = is_strong_password(password)
    if not is_valid:
        print("Password is not strong enough:")
        print(feedback)
        log_event(f"Registration failed for user '{username}' due to weak password")
        return

    # Generate salt and hash the password with it
    salt = generate_salt()
    hashed_password = hash_password(password, salt)

    # Store username, salt, hash, and a 'None' placeholder for the baseline hour
    # The format is: username:salt:hashed_password:normal_hour
    with open("users.txt", "a") as file:
        file.write(f"{username}:{salt}:{hashed_password}:None\n")
    
    print("User Registration was Successful")
    log_event(f"User '{username}' successfully registered")

def login_user():
    """Handles user login, salting verification, and AI anomaly detection."""
    username = input("Enter your Username: ")
    password = input("Enter your Password: ")

    try:
        with open("users.txt", "r") as file:
            users = file.readlines()
    except FileNotFoundError:
        print("Invalid username or password")
        log_event(f"Failed login attempt for user '{username}' (no users registered)")
        return

    for user in users:
        try:
            # Split into four parts to include the normal_hour
            stored_username, stored_salt, stored_hash, normal_hour = user.strip().split(":")
        except ValueError:
            continue  # Skip malformed lines in the user file

        # Hash the entered password with the stored salt for comparison
        if username == stored_username and hash_password(password, stored_salt) == stored_hash:
            print("\nLogin Successful!")
            
            # --- AI ANOMALY DETECTION LOGIC ---
            current_hour = datetime.now().hour
            
            if normal_hour == 'None':
                # First successful login, establish the baseline
                print("Security baseline established for your account.")
                update_user_baseline(username, current_hour)
                log_event(f"User '{username}' successfully logged in. Baseline established at hour: {current_hour}.")
            else:
                # Compare current login time to the baseline
                baseline_hour = int(normal_hour)
                # Anomaly is defined as a login > 4 hours away from the baseline
                if abs(current_hour - baseline_hour) > 4:
                    print("\n*** SECURITY ALERT ***")
                    print(f"This login at hour {current_hour} is unusual for you.")
                    print("If this was not you, please secure your account immediately.")
                    log_event(f"ANOMALY DETECTED: User '{username}' logged in at unusual hour: {current_hour}.")
                else:
                    log_event(f"User '{username}' successfully logged in.")
            # --- END OF AI LOGIC ---

            post_login_menu(username)
            return
            
    print("Invalid username or password")
    log_event(f"Failed login attempt for user '{username}'")

# --- Post-Login Menu and Log Viewing ---

def post_login_menu(username):
    """Displays the menu after a user has successfully logged in."""
    while True:
        print("\nPost-Login Menu")
        print("1. View my Logs")
        print("2. Logout")
        choice = input("What would you like to do? ")
        if choice == "1":
            view_logs(username)
        elif choice == "2":
            log_event(f"User '{username}' logged out")
            print("Logged out successfully")
            break
        else:
            print("Invalid choice. Please try again")

def view_logs(username):
    """Allows a logged-in user to view their specific entries in the audit log."""
    print(f"\nLogs for user '{username}':")
    try:
        with open("audit_log.txt", "r") as log_file:
            logs = log_file.readlines()
    except FileNotFoundError:
        print("No log file found.")
        return
    
    # A more precise way to find user-specific logs
    user_log_pattern = f"'{username}'"
    user_logs = [log.strip() for log in logs if user_log_pattern in log]

    if user_logs:
        for log in user_logs:
            print(log)
    else:
        print("No logs were found for your account.")

# --- Main Program Loop ---

def main():
    """The main function that runs the primary user interface loop."""
    while True:
        print("\nWelcome to the Secure User System")
        print("1. Register")
        print("2. Login")
        print("3. Exit")
        choice = input("What would you like to do? ")
        if choice == "1":
            register_user()
        elif choice == "2":
            login_user()
        elif choice == "3":
            log_event("System exit requested by user")
            print("Exiting the system")
            break
        else:
            print("Invalid choice. Please try again.")

# This ensures the main() function only runs when the script is executed directly.
if __name__ == "__main__":
    main()