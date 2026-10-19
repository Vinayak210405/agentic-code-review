import os

def run_user_command(user_input):
    # Intentional command injection risk for agent testing
    os.system(f"echo Executing: {user_input}")

def calculate_square(number):
    return number ** 2
