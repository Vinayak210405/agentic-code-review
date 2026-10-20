import subprocess


def run_user_command(user_input: str) -> None:
    """Executes ping safely without shell injection vulnerability."""
    if not user_input or not isinstance(user_input, str):
        raise ValueError("Invalid user input provided.")

    # Replaces os.system(f"ping -c 1 {user_input}")
    # Safe argument array bypasses the system shell parser entirely
    subprocess.run(["ping", "-c", "1", user_input], check=True)