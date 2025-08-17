import re
import os
from datetime import datetime

def extract_iocs_from_folder():
    folder_name = input("Enter folder name (in same directory): ")
    
    if not os.path.exists(folder_name):
        print(f"Error: Folder '{folder_name}' not found.")
        return
    
    # YARA rule patterns converted to Python regex (based on your iocRules.yara)
    patterns = {
        "Obfuscated_DLL_URL": re.compile(r'\w*\.?\w*\s\\\\\?\\\w?\W?\\\\\w*\\\\\w*\\\\[A-Za-z0-9_-]+\.?\w*', re.IGNORECASE),
        
        "Cron_Reboot_Persistence": re.compile(r'@reboot', re.IGNORECASE),
        "Hidden_Python_Cron": re.compile(r'@reboot\s+\/\w+\/\w+\/\w+\s+\/\w+\/\.\w+\/\.\w+\.py', re.IGNORECASE),
        
        "Obfuscated_Domain_Bracket": re.compile(r'\w+\[\.\]\w+\.(org|com|net|edu|gov|\w{1,4})', re.IGNORECASE),
        "Obfuscated_Domain_Dot": re.compile(r'\w+(dot)\w+\.(org|com|net|edu|gov|\w{1,4})', re.IGNORECASE),
        "Obfuscated_Domain_Bracket_Dot": re.compile(r'\w+\[dot\]\w+\.(org|com|net|edu|gov|\w{1,4})', re.IGNORECASE),
        "Hex_IP_Address": re.compile(r'0x[0-9a-f]{1,2}\.0x[0-9a-f]{1,2}\.0x[0-9a-f]{1,2}\.0x[0-9a-f]{1,2}', re.IGNORECASE),
        "Obfuscated_Domain_Simple": re.compile(r'[a-zA-Z]+\[\.\][a-zA-Z]+', re.IGNORECASE),
        "Obfuscated_IP_Bracket": re.compile(r'[0-9]{1,3}\[\.\][0-9]{1,3}\[\.\][0-9]{1,3}\[\.\][0-9]{1,3}', re.IGNORECASE),
        "Obfuscated_IP_Spaced": re.compile(r'[0-9]{3}\s+\[\.\]\s+[0-9]{3}\s+\[\.\]\s+[0-9]{2}\s+\[\.\]\s+[0-9]{2}', re.IGNORECASE),
        
        "Obfuscated_HTTPS_URL": re.compile(r'hxxps?:\/\/[a-zA-Z]+\[\.\][a-zA-Z]+\/[a-zA-Z]+\.[a-zA-Z]+', re.IGNORECASE),
        "HTTP_URL": re.compile(r'http:\/\/[a-zA-Z]+\.[a-zA-Z]+\/[a-zA-Z]+', re.IGNORECASE),
        "DLL_Path": re.compile(r'C:\\[a-zA-Z]+\\[a-zA-Z]+\\[a-zA-Z]+\\[a-zA-Z]+\.dll', re.IGNORECASE),
        "Obfuscated_Print": re.compile(r'print\s*\(\s*"exf"\s*,\s*"i"\s*\+\s*"ltr"\s*\+\s*"ate"\s*\)', re.IGNORECASE),
        
        "Host_Dot_Obfuscated": re.compile(r'[a-zA-Z]+\[dot\][a-zA-Z]+', re.IGNORECASE),
        "C2_Beacon_Socket": re.compile(r'"c2:\/\/"\s*\+\s*\w+\.replace\s*\(\s*"\[dot\]"\s*,\s*"\."\s*\)\s*\+\s*":\d+"', re.IGNORECASE)
    }
    
    all_iocs = {}
    total_files_scanned = 0
    
    print(f"\nScanning folder: {folder_name}")
    print("=" * 50)
    
    # Scan all files in the folder
    for filename in os.listdir(folder_name):
        file_path = os.path.join(folder_name, filename)
        
        if os.path.isfile(file_path):
            total_files_scanned += 1
            print(f"Scanning: {filename}")
            
            try:
                with open(file_path, "r", errors="ignore", encoding="utf-8") as f:
                    content = f.read()
                
                # Check each pattern against file content
                for pattern_name, pattern in patterns.items():
                    matches = pattern.findall(content)
                    if matches:
                        if pattern_name not in all_iocs:
                            all_iocs[pattern_name] = []
                        all_iocs[pattern_name].extend(matches)
                        
            except Exception as e:
                print(f"  Error reading {filename}: {e}")
    
    # Process and display results
    if all_iocs:
        print(f"\n" + "=" * 60)
        print(f"IoC EXTRACTION RESULTS FROM {folder_name.upper()}")
        print("=" * 60)
        print(f"Files scanned: {total_files_scanned}")
        
        total_iocs = 0
        unique_iocs = {}
        
        for pattern_name, matches in all_iocs.items():
            unique_matches = sorted(set(matches))
            unique_iocs[pattern_name] = unique_matches
            total_iocs += len(matches)
            
            print(f"\n[{pattern_name}]")
            print(f"  Total matches: {len(matches)}")
            print(f"  Unique matches: {len(unique_matches)}")
            for match in unique_matches:
                print(f"    {match}")
        
        print(f"\nSUMMARY:")
        print(f"  Total IoCs found: {total_iocs}")
        print(f"  Unique IoC types: {len(unique_iocs)}")
        
        # Save results to file
        output_file = "IoCs_Found.txt"
        with open(output_file, "a", encoding="utf-8") as out:
            out.write("\n" + "=" * 70 + "\n")
            out.write(f"IoC Extraction Results from folder: {folder_name}\n")
            out.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            out.write(f"Files Scanned: {total_files_scanned}\n")
            out.write(f"Total IoCs Found: {total_iocs}\n")
            out.write("=" * 70 + "\n\n")
            
            for pattern_name, unique_matches in unique_iocs.items():
                out.write(f"[{pattern_name}] - {len(unique_matches)} unique matches:\n")
                for match in unique_matches:
                    out.write(f"  {match}\n")
                out.write("\n")
            
            out.write("=" * 70 + "\n\n")
        
        print(f"\nResults saved to {output_file}")
        
    else:
        print(f"\nNo IoCs found in {folder_name} based on YARA rules.")
        print(f"Files scanned: {total_files_scanned}")

def show_supported_patterns():
    print("\nSupported IoC Patterns (from your iocRules.yara):")
    print("=" * 50)
    patterns_info = [
        "1. Obfuscated DLL URLs and paths",
        "2. Cron @reboot persistence entries", 
        "3. Hidden Python cron jobs",
        "4. Obfuscated domains ([.] and [dot] formats)",
        "5. Hexadecimal IP addresses",
        "6. Obfuscated IP addresses with brackets",
        "7. Obfuscated URLs (hxxp/hxxps)",
        "8. HTTP URLs and DLL paths",
        "9. Obfuscated print statements",
        "10. C2 beacon and socket communications"
    ]
    
    for info in patterns_info:
        print(f"  {info}")

if __name__ == "__main__":
    print("YARA-based IoC Extractor")
    print("========================")
    print("This script scans files in a folder using YARA rule patterns")
    
    choice = input("\nDo you want to see supported patterns first? (y/n): ").lower()
    if choice == 'y':
        show_supported_patterns()
        input("\nPress Enter to continue...")
    
    extract_iocs_from_folder()
