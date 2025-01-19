# Email-Spoof-Checker
This script analyzes email headers to detect potential spoofing attempts by extracting key information such as the sender’s domain and IP address. It performs SPF (Sender Policy Framework) validation to ensure the sender's domain is authenticated, printing warnings if the SPF record is missing or invalid.

Overview
This python script is designed to parse email headers and check for certain indicators of potential email spoofing. Email spoofing is a technique used by attackers to forge the sender’s email address to appear as though it comes from a trusted source. The script performs two primary tasks: extracting key information from email headers and analyzing the sender's domain for SPF (Sender Policy Framework) records, which help prevent spoofing. Additionally, the script extracts sender IP addresses from the email's Received headers and prints warnings if any suspicious patterns or missing records are detected.

Script Breakdown
1. Email Header Parsing

The script starts by presenting the user with a choice: whether to manually input the email headers or load them from a file. If the user opts for manual input, they paste the email headers directly into the terminal or command prompt. These headers are parsed using the email.message_from_string() function, which converts the raw email text into a structured message object. This object allows easy extraction of specific fields such as From, To, Subject, Date, and Received. These fields are stored in a dictionary for easy access and displayed to the user.

For example, the script will extract the From address, which could look like test@example.com, and the Received header, which provides information about the email’s routing path. The Received header is particularly important as it often contains the IP address of the server that sent the email, which can help determine whether the message came from a legitimate source or a potentially malicious server.

2. Analyzing the 'Received' Headers

One of the key features of this script is its ability to extract sender IP addresses from the Received headers. The Received headers in an email are added by mail servers as the message travels through different systems. The headers typically contain information about the originating server's IP address. By parsing the Received header with a regular expression, the script identifies any IP addresses that may indicate the source of the email.

This information can be useful in detecting suspicious activity. For example, if the email claims to be from a trusted sender but originates from an unexpected IP address, it could be a sign of spoofing. The script prints any detected IP addresses so the user can cross-check them for legitimacy. If no IP address is found in the Received headers, the script will notify the user that no IP addresses were detected.

3. SPF Record Validation

One of the most important ways to verify the authenticity of an email is through SPF (Sender Policy Framework). SPF is a method used to verify that an email message was sent from an authorized mail server for the domain it claims to be from. The script uses the dns.resolver module to query the domain’s DNS records and retrieve its SPF record, if available.

The validate_spf function takes the domain extracted from the From address and performs a DNS lookup for TXT records associated with the domain. These TXT records often contain the SPF policy, which specifies which mail servers are authorized to send emails on behalf of that domain. If a valid SPF record is found, it is printed to the screen. However, if the SPF record is missing or invalid, the script prints a warning message, alerting the user to the possibility of email spoofing.

4. Handling Missing or Invalid SPF Records

If the SPF record is missing or the domain is unreachable, the script flags this as a potential spoofing attempt by printing a warning. This warning informs the user that the absence of an SPF record is a red flag, as it makes it easier for attackers to send emails that appear legitimate. This functionality is crucial in detecting whether an email is likely to be spoofed.

In situations where the script cannot retrieve the SPF record due to a DNS error or other issue, it will also print an error message and alert the user that the SPF record is missing or inaccessible.

Conclusion
In summary, the Email Header Analyzer Python script is a useful tool for detecting potential email spoofing attempts. By parsing key email headers and performing a DNS lookup to validate SPF records, it helps users assess the legitimacy of the sender’s domain. The script also provides clear warnings when suspicious patterns are detected, such as missing or invalid SPF records, and allows the user to manually input headers or load them from a file for analysis. This tool can be a valuable resource for cybersecurity professionals or anyone concerned with email security and phishing prevention.
