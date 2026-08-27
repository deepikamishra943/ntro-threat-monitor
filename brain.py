print("🤖 AI Brain Starting...")
print("Scanning network traffic for hackers...\n")

# Open our clean list of websites
with open("clean_dns.txt", "r") as file:
    for line in file:
        # Split the line into IP and Website
        columns = line.split()
        
        # Make sure the line has exactly 2 pieces of data
        if len(columns) == 2:
            ip = columns[0]
            website = columns[1]
            
            # --- THE BRAIN LOGIC ---
            # Normal websites are short. Hacker DGA websites are long.
            # If the website name is longer than 20 characters, sound the alarm!
            if len(website) > 20:
                print("🚨 ALARM! DGA MALWARE DETECTED! 🚨")
                print(f"   Hacker IP Address: {ip}")
                print(f"   Suspicious Website: {website}")
                print("-" * 40)
