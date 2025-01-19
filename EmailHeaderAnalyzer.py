import re
import dns.resolver
from email import message_from_string

def extract_headers(email_content):
    """
    Parse email headers and return key fields as a dictionary.
    """
    email = message_from_string(email_content)
    headers = {}
    for key in ['From', 'To', 'Subject', 'Date', 'Received']:
        headers[key] = email.get(key, 'Not Available')
    return headers

def analyze_received_headers(received_headers):
    """
    Analyze 'Received' headers to extract sender IP addresses and flag unusual behavior.
    """
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ip_addresses = re.findall(ip_pattern, received_headers)
    print("\nSender IPs Detected:")
    if ip_addresses:
        for ip in ip_addresses:
            print(f" - {ip}")
    else:
        print("No IP addresses found in 'Received' headers.")
    return ip_addresses

def validate_spf(domain):
    """
    Check SPF record for the sender domain.
    If SPF is missing, print a warning message.
    """
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        spf_record_found = False
        for answer in answers:
            if 'v=spf1' in str(answer):
                print(f"SPF Record for {domain}: {answer}")
                spf_record_found = True
                break
        if not spf_record_found:
            print(f"⚠️ Warning: No valid SPF record found for {domain}. This could be a sign of email spoofing.")
    except Exception as e:
        print(f"⚠️ Error: Could not retrieve SPF record for {domain}: {e}")
        print(f"⚠️ Warning: SPF record is missing or inaccessible. This could be a sign of email spoofing.")

def main():
    print("Email Header Analyzer\n")
    print("Options:")
    print("1. Paste email headers manually")
    print("2. Load email headers from a file")

    choice = input("\nEnter your choice (1 or 2): ")
    
    if choice == "1":
        email_content = input("\nPaste the email headers here:\n")
    elif choice == "2":
        file_path = input("\nEnter the file path containing email headers: ")
        try:
            with open(file_path, "r") as file:
                email_content = file.read()
        except FileNotFoundError:
            print("File not found. Please check the path and try again.")
            return
    else:
        print("Invalid choice. Exiting.")
        return

    print("\nParsing email headers...\n")
    headers = extract_headers(email_content)
    for key, value in headers.items():
        print(f"{key}: {value}")
    
    print("\nAnalyzing 'Received' headers...\n")
    ip_addresses = analyze_received_headers(headers.get('Received', ''))

    sender_email = headers.get('From', '').split()[-1].strip('<>')
    sender_domain = sender_email.split('@')[-1] if '@' in sender_email else None

    if sender_domain:
        print("\nChecking SPF records...\n")
        validate_spf(sender_domain)
    else:
        print("\nCould not extract sender domain from 'From' header.")

if __name__ == "__main__":
    main()
