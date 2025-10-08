import multiprocessing
import time
import sys

# We wrap the imports inside the functions to ensure they are only loaded
# within the child process, which is a good practice for multiprocessing.

def check_dependencies():
    """Checks for critical external dependencies like Npcap before launching."""
    print("Launcher: Checking for dependencies...")
    try:
        # Scapy is the core dependency that relies on Npcap
        from scapy.all import get_if_list
        if not get_if_list():
            raise RuntimeError("No network interfaces found.")
        print("Launcher: Scapy and network interfaces found.")
        return True
    except (ImportError, RuntimeError, OSError) as e:
        # This block catches a missing Scapy install or, more likely, a missing Npcap driver.
        import tkinter as tk
        from tkinter import messagebox
        root = tk.Tk()
        root.withdraw() # Hide the main window
        messagebox.showerror(
            "Critical Dependency Missing",
            "Aegis Hub could not start.\n\nError: Npcap driver not found or not working correctly.\n\nPlease install Npcap from https://npcap.com and try again."
        )
        print(f"Launcher: Dependency check failed: {e}")
        return False

def run_service():
    """Target function to run the backend IPS service."""
    print("Launcher: Starting Aegis IPS Service process...")
    try:
        from aegis_ips_service import AegisIPS
        ips_service = AegisIPS()
        ips_service.run()
    except Exception as e:
        print(f"Launcher: Aegis IPS Service process failed: {e}")

if __name__ == '__main__':
    multiprocessing.freeze_support()

    if not check_dependencies():
        sys.exit(1)

    print("Launcher: Initializing Aegis Hub...")
    service_process = multiprocessing.Process(target=run_service, name="AegisServiceProcess")
    service_process.start()

    print("\nAegis IPS Service is running in the background.")
    print("To access the Aegis Security Hub, open 'web/index.html' in your browser.")
    print("To stop the service, close this window.\n")

    service_process.join()
    print("Launcher: Aegis Hub is shutting down.")