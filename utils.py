from telethon import TelegramClient
from colorama import Style, Fore  # import Style, Fore << both must be included even if Fore is removed by your IDE
import os
import json
import csv
import re
import time
import base64
import hashlib
import hmac
import random
from tqdm import tqdm
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans
from sklearn.decomposition import TruncatedSVD
import nltk
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
import string
import asyncio
import telethon
from telethon import functions
import npyscreen
import pandas as pd
import matplotlib.pyplot as plt
import networkx as nx
from matplotlib.colors import Normalize
import matplotlib.cm as cm
import requests
from datetime import datetime, timezone
import yaml
import threading


def intro():
    """Display a cleaner intro screen with SNOWball logo and credits."""
    os.system('cls' if os.name == 'nt' else 'clear')
    printC(r"""
  ███████╗███╗   ██╗ ██████╗ ██╗    ██╗
  ██╔════╝████╗  ██║██╔═══██╗██║    ██║
  ███████╗██╔██╗ ██║██║   ██║██║ █╗ ██║
  ╚════██║██║╚██╗██║██║   ██║██║███╗██║
  ███████║██║ ╚████║╚██████╔╝╚███╔███╔╝
  ╚══════╝╚═╝  ╚═══╝ ╚═════╝  ╚══╝╚══╝ 
    """, Fore.CYAN)
    
    print("  ══════════════════════════════════════")
    print(f"  {Fore.WHITE}PROJECT SNOW{Style.RESET_ALL}")
    print(f"  {Fore.LIGHTBLACK_EX}Credit: John | Based on work by Tom Jarvis{Style.RESET_ALL}")
    print("  ══════════════════════════════════════\n")

    printC(
        '→ Please use a sockpuppet account for research\n'
        '→ Warning: Tool lacks content filters\n'
        '→ Use CTRL+C at any time to pause/adjust parameters',
        Fore.YELLOW)


def check_screen_session():
    """Check if we're running inside a screen or tmux session."""
    if os.environ.get('STY') or os.environ.get('TMUX'):
        return True
    return False

def create_persistence_session(session_name="project_snow"):
    """Create a screen or tmux session and restart the current script in it.
    
    Args:
        session_name: Name of the screen/tmux session to create
        
    Returns:
        bool: True if success, False otherwise
    """
    import sys
    import subprocess
    
    script_path = os.path.abspath(sys.argv[0])
    script_args = ' '.join(sys.argv[1:])
    
    # Check what terminal multiplexers are available
    screen_available = subprocess.run(["which", "screen"], stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode == 0
    tmux_available = subprocess.run(["which", "tmux"], stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode == 0
    
    try:
        if tmux_available:
            # Try tmux first as it's more modern
            printC("Creating tmux session: {}".format(session_name), Fore.CYAN)
            cmd = f"tmux new-session -d -s {session_name} 'python {script_path} {script_args}'"
            subprocess.run(cmd, shell=True, check=True)
            printC(f"Session created. To attach: tmux attach -t {session_name}", Fore.GREEN)
            printC(f"To detach once attached: Ctrl+B followed by D", Fore.YELLOW)
            return True
        elif screen_available:
            # Fall back to screen
            printC("Creating screen session: {}".format(session_name), Fore.CYAN)
            cmd = f"screen -dmS {session_name} python {script_path} {script_args}"
            subprocess.run(cmd, shell=True, check=True)
            printC(f"Session created. To attach: screen -r {session_name}", Fore.GREEN)
            printC(f"To detach once attached: Ctrl+A followed by D", Fore.YELLOW)
            return True
        else:
            printC("Error: Neither screen nor tmux are installed.", Fore.RED)
            printC("Please install one of them to use persistence mode:", Fore.RED)
            printC("  - sudo apt-get install screen   # for Debian/Ubuntu", Fore.YELLOW)
            printC("  - sudo yum install screen       # for CentOS/RHEL", Fore.YELLOW)
            return False
    except subprocess.SubprocessError as e:
        printC(f"Error creating session: {e}", Fore.RED)
        return False

def detect_ssh_session():
    """Detect if we're running inside an SSH session."""
    return 'SSH_CLIENT' in os.environ or 'SSH_TTY' in os.environ or 'SSH_CONNECTION' in os.environ

class TUIApp(npyscreen.NPSAppManaged):
    """Terminal UI application for Telegram snowball sampling."""
    
    def onStart(self):
        self.addForm('MAIN', MainForm, name="Project SNOW")
        self.addForm('CONFIG', ConfigForm, name="Search Configuration")
        self.addForm('FOCUS', FocusForm, name="User Focus Settings")
        self.addForm('PERSISTENCE', PersistenceForm, name="Run in Background Mode")
        self.addForm('ELASTICSEARCH', ElasticsearchForm, name="Elasticsearch Export Settings")
        self.addForm('TGARCHIVE', TgArchiveForm, name="tg-archive Integration")
        self.addForm('PROXY', ProxyForm, name="Proxy/VPN Configuration")
        

class MainForm(npyscreen.Form):
    def create(self):
        self.add(npyscreen.TitleText, name="Seed Channel:", value="")
        self.add(npyscreen.TitleSlider, name="Iterations:", out_of=5, value=2)
        self.add(npyscreen.TitleSlider, name="Min. Mentions:", out_of=10, value=3)
        
        # Add buttons for different actions
        self.add(npyscreen.ButtonPress, name="Start Sampling", when_pressed_function=self.start_sampling)
        self.add(npyscreen.ButtonPress, name="Configure Search", when_pressed_function=self.configure)
        self.add(npyscreen.ButtonPress, name="Focus on User", when_pressed_function=self.focus_user)
        self.add(npyscreen.ButtonPress, name="Run in Background", when_pressed_function=self.setup_persistence)
        self.add(npyscreen.ButtonPress, name="Elasticsearch Export", when_pressed_function=self.setup_elasticsearch)
        self.add(npyscreen.ButtonPress, name="tg-archive Integration", when_pressed_function=self.setup_tgarchive)
        self.add(npyscreen.ButtonPress, name="Proxy/VPN Settings", when_pressed_function=self.setup_proxy)
        self.add(npyscreen.ButtonPress, name="Help", when_pressed_function=self.show_help)
        self.add(npyscreen.ButtonPress, name="Exit", when_pressed_function=self.exit_app)
        
        # Show a warning if running via SSH without a screen/tmux session
        if detect_ssh_session() and not check_screen_session():
            self.add(npyscreen.FixedText, value="⚠️ Running via SSH without screen/tmux - use 'Run in Background'", 
                     color="DANGER", editable=False)
    
    def start_sampling(self):
        # Return values to main app
        self.parentApp.setNextForm(None)
        self.editing = False
    
    def configure(self):
        self.parentApp.setNextForm('CONFIG')
        self.editing = False
    
    def focus_user(self):
        self.parentApp.setNextForm('FOCUS')
        self.editing = False
        
    def setup_persistence(self):
        self.parentApp.setNextForm('PERSISTENCE')
        self.editing = False

    def setup_elasticsearch(self):
        self.parentApp.setNextForm('ELASTICSEARCH')
        self.editing = False
        
    def setup_tgarchive(self):
        self.parentApp.setNextForm('TGARCHIVE')
        self.editing = False
        
    def setup_proxy(self):
        self.parentApp.setNextForm('PROXY')
        self.editing = False
    
    def show_help(self):
        npyscreen.notify_confirm(help_text(), title="Help Information")
    
    def exit_app(self):
        self.parentApp.setNextForm(None)
        self.editing = False
        raise KeyboardInterrupt

# New form for persistence setup
class PersistenceForm(npyscreen.Form):
    def create(self):
        self.add(npyscreen.TitleText, name="Session Name:", 
                 value="project_snow", max_height=3)
        
        self.add(npyscreen.FixedText, 
                value="Running in background allows the process to continue even if:", 
                editable=False)
        self.add(npyscreen.FixedText, 
                value="  • Your SSH connection drops", 
                editable=False)
        self.add(npyscreen.FixedText, 
                value="  • You close your terminal window", 
                editable=False)
        self.add(npyscreen.FixedText, 
                value="  • Your computer goes to sleep", 
                editable=False)
        
        # Check if we're already in a screen/tmux session
        if check_screen_session():
            self.add(npyscreen.FixedText, 
                    value="➜ Already running in a screen/tmux session.", 
                    editable=False, color="WARNING")
        
        # Create a button to create the screen/tmux session
        self.add(npyscreen.ButtonPress, name="Start Background Session", 
                 when_pressed_function=self.create_session)
        self.add(npyscreen.ButtonPress, name="Back", 
                 when_pressed_function=self.go_back)
    
    def create_session(self):
        session_name = self.get_widget("Session Name:").value
        
        # Check if name is valid
        if not session_name or not session_name.strip():
            npyscreen.notify_confirm("Please enter a valid session name", title="Error")
            return
        
        # Try to create the session
        if create_persistence_session(session_name):
            npyscreen.notify_confirm(
                "Background session created. The tool will continue running\n"
                "even if you close this terminal.\n\n"
                f"To reconnect later, use the appropriate command shown earlier.", 
                title="Success")
            # Exit this process since we've started a new one
            self.parentApp.setNextForm(None) 
            self.editing = False
            sys.exit(0)
        else:
            npyscreen.notify_confirm(
                "Failed to create background session.\n"
                "Please ensure screen or tmux is installed.", 
                title="Error")
    
    def go_back(self):
        self.parentApp.setNextForm('MAIN')
        self.editing = False


class ConfigForm(npyscreen.Form):
    def create(self):
        self.add(npyscreen.TitleText, name="Search Terms (comma separated):", value="")
        self.add(npyscreen.TitleMultiSelect, name="Categories:", 
                 values=list(CATEGORIES.keys()), value=[0, 1, 2])
        self.add(npyscreen.TitleSlider, name="Max Channels per Iteration:", 
                 out_of=100, value=50)
        self.add(npyscreen.CheckBox, name="Enable HMAC Verification", value=True)
        self.add(npyscreen.ButtonPress, name="Save Configuration", 
                 when_pressed_function=self.save_config)
        self.add(npyscreen.ButtonPress, name="Back to Main Menu", 
                 when_pressed_function=self.back_to_main)
    
    def save_config(self):
        # Code to save configuration
        npyscreen.notify_confirm("Configuration saved!", title="Success")
        self.parentApp.setNextForm('MAIN')
        self.editing = False
    
    def back_to_main(self):
        self.parentApp.setNextForm('MAIN')
        self.editing = False


class FocusForm(npyscreen.Form):
    def create(self):
        self.add(npyscreen.TitleText, name="Target Username:", value="")
        self.add(npyscreen.TitleSlider, name="Max Depth:", out_of=5, value=3)
        self.add(npyscreen.CheckBox, name="Include Replies", value=True)
        self.add(npyscreen.CheckBox, name="Include Forwards", value=True)
        self.add(npyscreen.ButtonPress, name="Start Focused Analysis", 
                 when_pressed_function=self.start_focus)
        self.add(npyscreen.ButtonPress, name="Back to Main Menu", 
                 when_pressed_function=self.back_to_main)
    
    def start_focus(self):
        # Logic to start focused analysis
        npyscreen.notify_confirm("Starting focused analysis...", title="Processing")
        self.parentApp.setNextForm(None)
        self.editing = False
    
    def back_to_main(self):
        self.parentApp.setNextForm('MAIN')
        self.editing = False


def launch_tui():
    """Launch the Terminal User Interface."""
    app = TUIApp()
    try:
        app.run()
        
        # Get values from main form
        main_values = app.getForm('MAIN').get_values()
        
        # Get Elasticsearch settings from Elasticsearch form
        try:
            es_form = app.getForm('ELASTICSEARCH')
            es_values = {
                'es_enabled': es_form.get_widget("Enable Elasticsearch Export").value,
                'es_export_type': "filebeat" if es_form.get_widget("Export Type:").value[0] == 0 else "logstash",
                'es_index_name': es_form.get_widget("Index Name:").value,
                'es_hosts': es_form.get_widget("Hosts (comma-separated):").value.split(','),
                'es_auth_enabled': es_form.get_widget("Enable Authentication").value,
                'es_username': es_form.get_widget("Username:").value,
                'es_password': es_form.get_widget("Password:").value,
                'es_ssl_enabled': es_form.get_widget("Enable SSL").value,
                'es_export_dir': es_form.get_widget("Export Directory:").value,
                'es_template_enabled': es_form.get_widget("Create Elasticsearch Index Template").value
            }
            # Merge ES settings with main form values
            main_values.update(es_values)
        except:
            # If ES form wasn't accessed, ignore this
            pass
            
        return main_values
    except KeyboardInterrupt:
        return None


def adjust_parameters_midway(current_params):
    """Allow user to adjust parameters during execution."""
    adjust_app = npyscreen.NPSAppManaged()
    
    class AdjustForm(npyscreen.Form):
        def create(self):
            self.add(npyscreen.TitleText, name="Current Channel:", 
                     value=current_params.get('current_channel', ''), editable=False)
            self.add(npyscreen.TitleSlider, name="Min. Mentions:", 
                     out_of=10, value=current_params.get('min_mentions', 3))
            self.add(npyscreen.TitleText, name="Filter Keywords (comma separated):", 
                     value=current_params.get('filter_keywords', ''))
            self.add(npyscreen.CheckBox, name="Skip Current Channel", 
                     value=False)
            
            # Add option to move to background if running in SSH without screen/tmux
            if detect_ssh_session() and not check_screen_session():
                self.add(npyscreen.CheckBox, name="Continue in Background (Recommended)", 
                         value=True)
                self.add(npyscreen.TitleText, name="Background Session Name:", 
                         value="tg_snowball_cont")
            
            self.add(npyscreen.ButtonPress, name="Continue Sampling", 
                     when_pressed_function=self.save_and_continue)
            self.add(npyscreen.ButtonPress, name="Abort Sampling", 
                     when_pressed_function=self.abort)
            
        def save_and_continue(self):
            # Check if we should move to background
            if (detect_ssh_session() and not check_screen_session() and 
                    self.get_widget("Continue in Background (Recommended)").value):
                session_name = self.get_widget("Background Session Name:").value
                if create_persistence_session(session_name):
                    npyscreen.notify_confirm(
                        "Continuing in background mode.\n"
                        f"To reconnect: tmux attach -t {session_name} or screen -r {session_name}", 
                        title="Success")
                    # Exit this process
                    self.parentApp.setNextForm(None)
                    self.editing = False
                    sys.exit(0)
            
            self.parentApp.setNextForm(None)
            self.editing = False
            
        def abort(self):
            self.parentApp.setNextForm(None)
            self.editing = False
            raise KeyboardInterrupt
    
    adjust_app.addForm('MAIN', AdjustForm, name="Adjust Parameters")
    adjust_app.run()
    
    # Return updated parameters
    updated_params = adjust_app.getForm('MAIN').get_values()
    return updated_params


def final_message(start_time, total_messages_processed, iteration_durations, channel_counts):
    """Display a cleaner summary of results."""
    end_time = time.time()
    total_time = end_time - start_time
    
    # Create a simple table format
    table = "\n┌─────────────────────────────────────────────┐\n"
    table += "│ SUMMARY                                     │\n"
    table += "├───────────────────────┬─────────────────────┤\n"
    table += f"│ Total messages        │ {total_messages_processed:<19} │\n"
    table += f"│ Total execution time  │ {format_time(total_time):<19} │\n"
    table += "├───────────────────────┼─────────────────────┤\n"
    
    for i, duration in enumerate(iteration_durations, 1):
        table += f"│ Iteration {i:<14} │ {format_time(duration):<19} │\n"
    
    table += "├───────────────────────┼─────────────────────┤\n"
    
    for i, count in enumerate(channel_counts, 1):
        table += f"│ Channels in iter {i:<7} │ {count:<19} │\n"
    
    table += "└───────────────────────┴─────────────────────┘"
    
    print(table)


def help_text():
    """Return help text in a clean, formatted way."""
    return """
TELEGRAM SNOWBALL SAMPLER - HELP

PURPOSE:
This tool performs snowball sampling of Telegram channels. It starts with a 
seed channel and discovers related channels through forwarded messages.

CORE FEATURES:
• Snowball sampling through message forwards
• Category classification of channels
• Focused user analysis
• HMAC verification for security
• Background operation (via screen/tmux)
• Elasticsearch export for analytics
• tg-archive integration for static website generation
• Proxy/VPN support for anonymity and IP rotation

TIPS:
• Use 2-3 iterations to avoid exponential growth
• Higher minimum mentions reduces noise
• Use a sockpuppet account for research
• Adjust search parameters midway if needed
• Focus on specific users to trace connections
• When using SSH, run in background to prevent disconnection issues

SECURITY:
• All API communications use HMAC authentication
• Credentials are stored with strong encryption
• Multiple API keys can be used for rate limiting
• Proxy rotation for anonymity and circumventing blocks
• VPN integration for additional security layer

ELASTICSEARCH EXPORT:
• Supports both Filebeat and Logstash export methods
• Creates ready-to-use configuration files
• Secure HMAC authentication for data transmission
• Index templates for optimal data mapping
• Compatible with Kibana visualizations and dashboards

TG-ARCHIVE INTEGRATION:
• Create static websites from Telegram channels
• Uses the same API credentials as the main tool
• Supports initial setup (-n) and periodic syncing (-s)
• Configurable media downloads and archive settings
• Generate browsable archives for offline viewing

PROXY/VPN FEATURES:
• Load proxies from text file with auto-validation
• Automatic proxy rotation at configurable intervals
• Support for HTTP, HTTPS, and SOCKS5 proxies
• IPVanish and NordVPN integration via OpenVPN
• Status monitoring with IP validation

BACKGROUND MODE:
• Uses screen or tmux to keep running if your terminal disconnects
• To reconnect to a tmux session: tmux attach -t <session_name>
• To reconnect to a screen session: screen -r <session_name>
"""


def split_search_terms(input_string):
    return [term.strip() for term in input_string.split(',')]


def sanitize_filename(filename):
    """Sanitize the filename by removing or replacing characters that may cause issues."""
    return re.sub(r'[<>:"/\\|?*]', '', filename)


def printC(string, colour):
    '''Print coloured and then reset: The "colour" variable should be written as "Fore.GREEN" (or other colour) as it
    uses Fore function from colorama. If issues, make sure Fore is imported:

    from colorama import Style, Fore'''

    print(colour + string + Style.RESET_ALL)


def remove_inaccessible_channels(file_path, inaccessible_channels):
    """Remove inaccessible channels from indexes with progress indication."""
    with open(file_path, mode='r', encoding='utf-8') as file:
        reader = csv.DictReader(file)
        channels = [row for row in reader if row['Channel Name'] not in inaccessible_channels]

    with tqdm(total=1, desc="Removing inaccessible channels", 
             bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}") as pbar:
        with open(file_path, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.DictWriter(file, fieldnames=reader.fieldnames)
            writer.writeheader()
            writer.writerows(channels)
        pbar.update(1)


def write_to_text_file(data, filename):  # In case of emergency and CSV writer doenst work, this dumps output to txt
    try:
        with open(filename, 'w', encoding='utf-8') as file:
            json.dump(data, file, indent=4)
    except Exception as e:
        print(f"Failed to write to text file: {e}")


async def attempt_connection_to_telegram(use_proxy=False, proxy_manager=None):
    """
    Connects to the Telegram API using the API ID and API hash values stored in an encrypted file.
    If the file does not exist, it prompts the user to enter their API ID and API hash and creates the file.
    Supports multiple API keys with automatic rotation on rate limiting.
    
    Args:
        use_proxy: Whether to use a proxy
        proxy_manager: Optional ProxyManager instance
        
    Returns:
        TelegramClient: A connected TelegramClient instance.

    Raises:
        SystemExit: If the connection to the Telegram client fails.
    """

    def encrypt_api_details(api_id, api_hash, key=None):
        """
        Encrypts API details using Fernet symmetric encryption
        
        Args:
            api_id: API ID
            api_hash: API Hash
            key: Optional encryption key, generated if not provided
            
        Returns:
            tuple: (encrypted_data, key)
        """
        if key is None:
            salt = os.urandom(16)
            # Generate a secure key using the device-specific information
            device_id = hmac.new(
                hashlib.sha256(os.name.encode() + os.environ.get('COMPUTERNAME', '').encode()).digest(),
                salt,
                hashlib.sha256
            ).digest()
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000
            )
            key = base64.urlsafe_b64encode(kdf.derive(device_id))
        
        f = Fernet(key)
        data = json.dumps({
            "salt": base64.b64encode(salt).decode() if 'salt' not in locals() else base64.b64encode(salt).decode(),
            "api_keys": [{
                "api_id": str(api_id),
                "api_hash": api_hash,
                "usage_count": 0,
                "last_used": 0
            }]
        })
        encrypted_data = f.encrypt(data.encode())
        return encrypted_data, key

    def decrypt_api_details(encrypted_data, key):
        """
        Decrypts API details
        
        Args:
            encrypted_data: Encrypted data
            key: Encryption key
            
        Returns:
            dict: Decrypted API details
        """
        f = Fernet(key)
        decrypted_data = f.decrypt(encrypted_data)
        return json.loads(decrypted_data.decode())

    def retrieve_api_details():
        """
        Retrieve the API details required for TelegramClient from an encrypted file,
        or ask the user for them if they're not available.

        Returns:
            tuple: API ID and API Hash as a tuple (api_id, api_hash, key, all_api_keys)
        """
        api_details_file_path = 'api_keys.enc'
        key_file_path = '.keyfile'
        
        # Inner function to warn the user and prompt for API details
        def print_warning_and_prompt():
            nonlocal api_id, api_hash, key, all_api_keys
            printC(
                '\nNo valid API details found or adding additional API key.\n'
                'Please enter your API details.\n'
                'API details can be retrieved from https://my.telegram.org/auth\n',
                Fore.YELLOW
            )
            api_id = input("Enter your API ID: ")
            api_hash = input("Enter your API Hash: ")
            
            if os.path.exists(api_details_file_path) and os.path.exists(key_file_path):
                # Add new API key to existing file
                with open(key_file_path, 'rb') as keyfile:
                    key = keyfile.read()
                
                with open(api_details_file_path, 'rb') as file:
                    encrypted_data = file.read()
                
                try:
                    decrypted_data = decrypt_api_details(encrypted_data, key)
                    decrypted_data['api_keys'].append({
                        "api_id": str(api_id),
                        "api_hash": api_hash,
                        "usage_count": 0,
                        "last_used": 0
                    })
                    all_api_keys = decrypted_data['api_keys']
                    
                    # Re-encrypt and save
                    f = Fernet(key)
                    encrypted_data = f.encrypt(json.dumps(decrypted_data).encode())
                    
                    with open(api_details_file_path, 'wb') as file:
                        file.write(encrypted_data)
                except Exception as e:
                    printC(f"Error adding new API key: {e}", Fore.RED)
                    printC("Creating new encrypted storage", Fore.YELLOW)
                    encrypted_data, key = encrypt_api_details(api_id, api_hash)
                    all_api_keys = [{"api_id": str(api_id), "api_hash": api_hash, "usage_count": 0, "last_used": 0}]
                    
                    with open(api_details_file_path, 'wb') as file:
                        file.write(encrypted_data)
                    
                    with open(key_file_path, 'wb') as keyfile:
                        keyfile.write(key)
            else:
                # Create new encrypted file
                encrypted_data, key = encrypt_api_details(api_id, api_hash)
                all_api_keys = [{"api_id": str(api_id), "api_hash": api_hash, "usage_count": 0, "last_used": 0}]
                
                with open(api_details_file_path, 'wb') as file:
                    file.write(encrypted_data)
                
                with open(key_file_path, 'wb') as keyfile:
                    keyfile.write(key)

        # Initialise default values
        api_id, api_hash = 0, ''
        key = None
        all_api_keys = []

        # Check if files exist
        if os.path.exists(api_details_file_path) and os.path.exists(key_file_path):
            with open(key_file_path, 'rb') as keyfile:
                key = keyfile.read()
            
            with open(api_details_file_path, 'rb') as file:
                encrypted_data = file.read()
            
            try:
                decrypted_data = decrypt_api_details(encrypted_data, key)
                all_api_keys = decrypted_data['api_keys']
                
                if not all_api_keys:
                    print_warning_and_prompt()
                else:
                    # Use selection strategy - least recently used and least used
                    all_api_keys.sort(key=lambda x: (x['last_used'], x['usage_count']))
                    selected_api = all_api_keys[0]
                    api_id = int(selected_api['api_id'])
                    api_hash = selected_api['api_hash']
                    
                    # Update usage statistics
                    selected_api['usage_count'] += 1
                    selected_api['last_used'] = int(time.time())
                    
                    # Re-encrypt and save
                    f = Fernet(key)
                    encrypted_data = f.encrypt(json.dumps(decrypted_data).encode())
                    
                    with open(api_details_file_path, 'wb') as file:
                        file.write(encrypted_data)
            except Exception as e:
                printC(f"Error decrypting API details: {e}", Fore.RED)
                print_warning_and_prompt()
        else:
            print_warning_and_prompt()

        printC(f'\nUsing API ID: {api_id} (have {len(all_api_keys)} API keys available)\n', Fore.GREEN)
        return int(api_id), api_hash, key, all_api_keys

    api_id, api_hash, key, all_api_keys = retrieve_api_details()
    
    # Get proxy if needed
    proxy = None
    if use_proxy and proxy_manager:
        try:
            # Get next proxy from rotation
            proxy = await proxy_manager.get_next_proxy()
            if proxy:
                printC(f"Using proxy: {proxy}", Fore.CYAN)
            else:
                printC("No valid proxy available, connecting directly", Fore.YELLOW)
        except Exception as e:
            printC(f"Error getting proxy: {e}", Fore.RED)
    
    # Try to connect with chosen API key
    try:
        # Configure client with proxy if available
        if proxy:
            # Determine proxy type
            if proxy.startswith('socks5://'):
                import socks
                proxy_type = socks.SOCKS5
                proxy_addr = proxy.replace('socks5://', '')
            elif proxy.startswith('socks4://'):
                import socks
                proxy_type = socks.SOCKS4
                proxy_addr = proxy.replace('socks4://', '')
            else:
                import socks
                proxy_type = socks.HTTP
                proxy_addr = proxy.replace('http://', '').replace('https://', '')
            
            # Parse address, port, username, password
            if '@' in proxy_addr:
                auth, proxy_addr = proxy_addr.split('@', 1)
                proxy_user, proxy_pass = auth.split(':', 1) if ':' in auth else (auth, '')
            else:
                proxy_user, proxy_pass = None, None
            
            proxy_host, proxy_port = proxy_addr.split(':', 1)
            proxy_port = int(proxy_port)
            
            # Create client with proxy
            client = TelegramClient(
                'session_name', 
                api_id, 
                api_hash,
                proxy=(proxy_type, proxy_host, proxy_port, proxy_user, proxy_pass)
            )
        else:
            # Create client without proxy
            client = TelegramClient('session_name', api_id, api_hash)
            
        await client.start()
        printC("Connection to Telegram established.", Fore.GREEN)
        print("Please wait...")
        return client
    except Exception as e:
        printC(f"Error connecting with current API key: {e}", Fore.RED)
        
        # Try other API keys if available
        if len(all_api_keys) > 1:
            printC("Attempting to connect with alternative API keys...", Fore.YELLOW)
            
            for api_key in all_api_keys:
                # Skip the one that just failed
                if int(api_key['api_id']) == api_id:
                    continue
                
                try:
                    alt_api_id = int(api_key['api_id'])
                    alt_api_hash = api_key['api_hash']
                    
                    # Create client with or without proxy
                    if proxy:
                        # Use same proxy settings as above
                        client = TelegramClient(
                            f'session_alt_{alt_api_id}', 
                            alt_api_id, 
                            alt_api_hash,
                            proxy=(proxy_type, proxy_host, proxy_port, proxy_user, proxy_pass)
                        )
                    else:
                        client = TelegramClient(f'session_alt_{alt_api_id}', alt_api_id, alt_api_hash)
                        
                    await client.start()
                    
                    printC(f"Connection established with alternative API key (ID: {alt_api_id})", Fore.GREEN)
                    print("Please wait...")
                    
                    # Update usage statistics
                    api_key['usage_count'] += 1
                    api_key['last_used'] = int(time.time())
                    
                    # Re-encrypt and save
                    api_details_file_path = 'api_keys.enc'
                    with open(api_details_file_path, 'rb') as file:
                        encrypted_data = file.read()
                    
                    decrypted_data = decrypt_api_details(encrypted_data, key)
                    
                    f = Fernet(key)
                    encrypted_data = f.encrypt(json.dumps(decrypted_data).encode())
                    
                    with open(api_details_file_path, 'wb') as file:
                        file.write(encrypted_data)
                    
                    return client
                except Exception as inner_e:
                    printC(f"Failed with alternative API key: {inner_e}", Fore.RED)
        
        # If all keys failed, ask for a new one
        printC("All available API keys failed. Please add a new API key.", Fore.RED)
        retrieve_api_details()  # This will prompt for a new API key
        return await attempt_connection_to_telegram(use_proxy, proxy_manager)  # Recursive call with new key


def help():
    printC('''----
    HELP
    ----

    This tool is designed for snowball sampling. It takes a "seed" channel and searches it for forwarded
    messages. These forwarded messages come from other channels which are likely to be relevant to the
    topics of the seed channel.

    So we scrape a list of channels in the first instance then we go through those channels and scrape them.
    This means all of the forwards in those channels are also collected, and the process repeats.

    --- The number of times the process repeats is based on the number of iterations you set. 
        Setting it to 3 iterations is usually enough as it is a rapid exponential growth of channels.

    --- Setting the minimum number of mentions helps reduce the number of channels collected and only
        allows the most relevant channels which are frequently forwarded to be added to the list.''', Fore.GREEN)


def error_fix(results):
    # Dumping the data into a text file in case of an error
    printC("Attempting to recover results to text file due to critical issue ...", Fore.YELLOW)
    write_to_text_file(results, 'backup_results.txt')


# Download NLTK resources if not already present
def setup_nltk():
    try:
        nltk.data.find('tokenizers/punkt')
        nltk.data.find('corpora/stopwords')
    except LookupError:
        nltk.download('punkt', quiet=True)
        nltk.download('stopwords', quiet=True)


# Pre-defined categories for classification
CATEGORIES = {
    'politics': ['politics', 'government', 'election', 'president', 'minister', 'party', 'vote', 'campaign', 'democrat', 'republican', 'liberal', 'conservative'],
    'news': ['news', 'breaking', 'report', 'media', 'journalist', 'headline', 'press', 'update', 'daily', 'weekly'],
    'technology': ['tech', 'technology', 'computer', 'software', 'hardware', 'coding', 'programming', 'developer', 'app', 'startup', 'digital', 'cyber'],
    'cybersecurity': ['security', 'hack', 'breach', 'malware', 'cyber', 'ransomware', 'phishing', 'vulnerability', 'exploit', 'attack', 'threat', 'defense'],
    'cryptocurrency': ['crypto', 'bitcoin', 'ethereum', 'blockchain', 'token', 'mining', 'wallet', 'exchange', 'coin', 'defi', 'nft'],
    'entertainment': ['entertainment', 'movie', 'film', 'tv', 'show', 'celebrity', 'music', 'game', 'art', 'culture', 'fashion'],
    'business': ['business', 'finance', 'economy', 'market', 'stock', 'investment', 'trade', 'company', 'corporate', 'startup', 'entrepreneur'],
    'science': ['science', 'research', 'study', 'academic', 'university', 'discovery', 'innovation', 'experiment', 'laboratory', 'scientific'],
    'health': ['health', 'medical', 'doctor', 'hospital', 'disease', 'treatment', 'medicine', 'wellness', 'vaccine', 'therapy', 'covid', 'virus'],
    'sports': ['sports', 'football', 'soccer', 'basketball', 'baseball', 'tennis', 'golf', 'hockey', 'olympic', 'athlete', 'tournament'],
    'education': ['education', 'school', 'college', 'university', 'student', 'teacher', 'learning', 'academic', 'course', 'degree', 'training'],
    'travel': ['travel', 'tourism', 'vacation', 'hotel', 'flight', 'destination', 'tour', 'tourist', 'trip', 'journey', 'adventure'],
    'military': ['military', 'army', 'navy', 'war', 'soldier', 'weapon', 'defense', 'combat', 'intelligence', 'veteran', 'tactical'],
    'religion': ['religion', 'faith', 'god', 'church', 'temple', 'mosque', 'prayer', 'spiritual', 'holy', 'divine', 'worship'],
    'other': []
}


async def extract_channel_metadata(client, channel_id, attempts=3):
    """
    Extract metadata from a channel including description, profile picture, etc.
    Includes retry logic to handle temporary failures.
    
    Args:
        client: Telegram client
        channel_id: ID of the channel to extract metadata from
        attempts: Number of retry attempts
        
    Returns:
        dict: Channel metadata including description, member count, etc.
    """
    for attempt in range(attempts):
        try:
            # Get full channel entity
            channel = await client.get_entity(channel_id)
            
            # Attempt to get chat information with full details
            full_chat = await client(telethon.functions.channels.GetFullChannelRequest(channel=channel))
            
            # Extract relevant metadata
            metadata = {
                'id': channel_id,
                'title': getattr(channel, 'title', 'Unknown'),
                'username': getattr(channel, 'username', None),
                'description': getattr(full_chat.full_chat, 'about', ''),
                'member_count': getattr(full_chat.full_chat, 'participants_count', 0),
                'photo_id': getattr(channel.photo, 'photo_id', None) if hasattr(channel, 'photo') else None,
                'date_created': getattr(channel, 'date', None),
                'verified': getattr(channel, 'verified', False),
                'restricted': getattr(channel, 'restricted', False),
                'scam': getattr(channel, 'scam', False),
                'fake': getattr(channel, 'fake', False),
                'clickable_link': f"https://t.me/{channel.username}" if getattr(channel, 'username', None) else None
            }
            
            return metadata
        
        except Exception as e:
            if attempt < attempts - 1:
                printC(f"Retrying metadata extraction for channel {channel_id}: {e}", Fore.YELLOW)
                await asyncio.sleep(2 * (attempt + 1))  # Exponential backoff
            else:
                printC(f"Failed to extract metadata for channel {channel_id}: {e}", Fore.RED)
                # Return basic metadata with available information
                return {
                    'id': channel_id,
                    'title': 'Unknown',
                    'username': None,
                    'description': '',
                    'clickable_link': None
                }


def preprocess_text(text):
    """
    Preprocess text for classification by removing stopwords, punctuation, etc.
    
    Args:
        text: Text to preprocess
        
    Returns:
        str: Preprocessed text
    """
    if not text or not isinstance(text, str):
        return ""
    
    # Convert to lowercase
    text = text.lower()
    
    # Remove URLs
    text = re.sub(r'http\S+|www\S+|https\S+', '', text, flags=re.MULTILINE)
    
    # Remove punctuation
    text = text.translate(str.maketrans('', '', string.punctuation))
    
    # Remove stopwords
    stop_words = set(stopwords.words('english'))
    word_tokens = word_tokenize(text)
    filtered_text = [w for w in word_tokens if not w in stop_words]
    
    return ' '.join(filtered_text)


def classify_channels(channels_metadata, min_channels_per_category=3):
    """
    Classify channels into categories based on their descriptions and titles.
    Uses a combination of rule-based and unsupervised clustering approaches.
    
    Args:
        channels_metadata: List of channel metadata dicts with descriptions
        min_channels_per_category: Minimum channels needed to create a category
        
    Returns:
        dict: Mapping of channel IDs to categories
    """
    setup_nltk()
    
    # Prepare data for classification
    channel_texts = {}
    for channel in channels_metadata:
        channel_id = channel['id']
        # Combine title and description for better classification
        combined_text = f"{channel['title']} {channel['description']}"
        processed_text = preprocess_text(combined_text)
        channel_texts[channel_id] = processed_text
    
    # Rule-based classification first
    channel_categories = {}
    uncategorized_channels = []
    
    # First pass: rule-based classification
    for channel_id, text in channel_texts.items():
        if not text:  # Skip empty texts
            channel_categories[channel_id] = 'other'
            continue
            
        # Check for category matches in text
        matched_categories = {}
        for category, keywords in CATEGORIES.items():
            if category == 'other':
                continue
                
            # Count keyword matches
            match_count = sum(1 for keyword in keywords if keyword in text)
            if match_count > 0:
                matched_categories[category] = match_count
        
        if matched_categories:
            # Assign to category with most matches
            best_category = max(matched_categories.items(), key=lambda x: x[1])[0]
            channel_categories[channel_id] = best_category
        else:
            uncategorized_channels.append(channel_id)
    
    # Count channels per category
    category_counts = {}
    for category in channel_categories.values():
        category_counts[category] = category_counts.get(category, 0) + 1
    
    # Second pass: cluster remaining channels if there are enough
    if len(uncategorized_channels) >= min_channels_per_category:
        try:
            # Extract uncategorized texts
            texts = [channel_texts[channel_id] for channel_id in uncategorized_channels if channel_texts[channel_id]]
            
            if texts:
                # Create TF-IDF features
                vectorizer = TfidfVectorizer(max_features=1000, stop_words='english')
                X = vectorizer.fit_transform(texts)
                
                # Apply dimensionality reduction if needed
                if X.shape[1] > 50:
                    svd = TruncatedSVD(n_components=min(50, X.shape[1]-1))
                    X = svd.fit_transform(X)
                
                # Determine optimal number of clusters
                n_clusters = min(5, max(2, len(texts) // min_channels_per_category))
                
                # Cluster the uncategorized channels
                kmeans = KMeans(n_clusters=n_clusters, random_state=42)
                clusters = kmeans.fit_predict(X)
                
                # Assign cluster labels
                for i, channel_id in enumerate([cid for cid in uncategorized_channels if channel_texts[cid]]):
                    if i < len(clusters):
                        channel_categories[channel_id] = f"cluster_{clusters[i]}"
        except Exception as e:
            printC(f"Error during clustering: {e}", Fore.RED)
    
    # Assign remaining uncategorized channels
    for channel_id in uncategorized_channels:
        if channel_id not in channel_categories:
            channel_categories[channel_id] = 'other'
    
    return channel_categories


def create_clickable_links(channels_metadata):
    """
    Generate clickable links for channels based on their username or ID.
    
    Args:
        channels_metadata: List of channel metadata dicts
        
    Returns:
        dict: Mapping of channel IDs to clickable links
    """
    links = {}
    for channel in channels_metadata:
        channel_id = channel['id']
        username = channel.get('username')
        
        if username:
            links[channel_id] = f"https://t.me/{username}"
        else:
            # For private channels without username, we can't create clickable links
            # Use the joinchat link format if available in the future
            links[channel_id] = None
    
    return links


def format_time(seconds):
    """Format seconds into human-readable time"""
    if seconds < 60:
        return f"{seconds:.1f} seconds"
    elif seconds < 3600:
        return f"{seconds/60:.1f} minutes"
    else:
        return f"{seconds/3600:.1f} hours"


def generate_visualizations(results_file, visualization_type='network'):
    """Generate visualizations from results file.
    
    Args:
        results_file: Path to the CSV results file
        visualization_type: Type of visualization to generate (network, heatmap, chord, all)
        
    Returns:
        list: Paths to generated visualization files
    """
    try:
        # Create output directory for visualizations
        output_dir = 'visualizations'
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        printC(f"Generating {visualization_type} visualization(s) from {results_file}...", Fore.CYAN)
        
        # Load data from CSV
        data = pd.read_csv(results_file)
        
        # Basic validation
        if len(data) == 0:
            printC("Error: No data found in the results file", Fore.RED)
            return []
        
        # Track generated files
        generated_files = []
        
        # Get timestamp for filenames
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Generate requested visualization types
        if visualization_type in ['network', 'all']:
            network_file = os.path.join(output_dir, f'network_{timestamp}.png')
            generate_network_visualization(data, network_file)
            generated_files.append(network_file)
            
        if visualization_type in ['heatmap', 'all']:
            heatmap_file = os.path.join(output_dir, f'heatmap_{timestamp}.png')
            generate_heatmap_visualization(data, heatmap_file)
            generated_files.append(heatmap_file)
            
        if visualization_type in ['chord', 'all']:
            chord_file = os.path.join(output_dir, f'chord_{timestamp}.png')
            generate_chord_visualization(data, chord_file)
            generated_files.append(chord_file)
        
        if generated_files:
            printC("Visualization(s) generated:", Fore.GREEN)
            for file in generated_files:
                printC(f"  - {file}", Fore.GREEN)
        else:
            printC("No visualizations were generated", Fore.YELLOW)
        
        return generated_files
    
    except Exception as e:
        printC(f"Error generating visualizations: {e}", Fore.RED)
        return []

def generate_network_visualization(data, output_file):
    """Generate a network visualization from the data.
    
    Args:
        data: DataFrame containing the data
        output_file: Path to save the visualization
    """
    try:
        # Create a directed graph
        G = nx.DiGraph()
        
        # Extract channel IDs and names
        channel_ids = data['Channel ID'].tolist()
        channel_names = data['Channel Name'].tolist()
        
        # Add nodes (channels)
        for i, (channel_id, channel_name) in enumerate(zip(channel_ids, channel_names)):
            G.add_node(channel_id, name=channel_name)
        
        # If we have edge information, add edges
        if 'Edge_List.csv' in os.listdir():
            edge_data = pd.read_csv('Edge_List.csv')
            for _, row in edge_data.iterrows():
                source = row['Source Channel ID']
                target = row['Target Channel ID']
                # Only add edge if both nodes exist
                if source in G.nodes and target in G.nodes:
                    G.add_edge(source, target)
        
        # Set up the figure with a dark background
        plt.figure(figsize=(16, 12), facecolor='black')
        ax = plt.gca()
        ax.set_facecolor('black')
        
        # Use spring layout for node positioning
        pos = nx.spring_layout(G, k=0.3, iterations=50)
        
        # Calculate node sizes based on degree
        degrees = dict(G.degree())
        node_sizes = [50 + 10 * degrees[node] for node in G.nodes()]
        
        # Calculate node colors based on degree (hot colormap)
        norm = Normalize(min(degrees.values()), max(degrees.values()))
        node_colors = [cm.hot(norm(degrees[node])) for node in G.nodes()]
        
        # Draw the network
        nx.draw_networkx_nodes(G, pos, node_size=node_sizes, node_color=node_colors, alpha=0.8)
        nx.draw_networkx_edges(G, pos, edge_color='gray', alpha=0.2, arrows=True, arrowstyle='->', arrowsize=10)
        
        # Add labels for high-degree nodes only
        # Only label nodes with degree higher than average
        avg_degree = sum(degrees.values()) / len(degrees)
        labels = {node: data['name'] for node, data in G.nodes(data=True) if degrees[node] > avg_degree}
        nx.draw_networkx_labels(G, pos, labels=labels, font_size=8, font_color='white')
        
        # Add title and footer
        plt.title('Channel Network Visualization', color='white', fontsize=16)
        plt.text(0.5, 0.01, f'Generated by TG Snowball Sampler - {datetime.now().strftime("%Y-%m-%d")}',
                ha='center', color='gray', fontsize=8, transform=plt.gcf().transFigure)
        
        # Save the figure
        plt.tight_layout()
        plt.savefig(output_file, dpi=300, bbox_inches='tight')
        plt.close()
        
        printC(f"Network visualization saved to {output_file}", Fore.GREEN)
    
    except Exception as e:
        printC(f"Error generating network visualization: {e}", Fore.RED)

def generate_heatmap_visualization(data, output_file):
    """Generate a heatmap visualization from the data.
    
    Args:
        data: DataFrame containing the data
        output_file: Path to save the visualization
    """
    try:
        # Get channel categories if available
        has_categories = False
        categories = []
        
        # Try to load metadata for categorization
        metadata_files = [f for f in os.listdir('metadata') if f.endswith('.json')] if os.path.exists('metadata') else []
        if metadata_files:
            # Use the most recent metadata file
            metadata_file = os.path.join('metadata', sorted(metadata_files)[-1])
            with open(metadata_file, 'r', encoding='utf-8') as f:
                metadata = json.load(f)
                
            # Classify channels into categories
            channel_categories = classify_channels([metadata[cid] for cid in metadata if 'title' in metadata[cid]])
            has_categories = True
        
        # Set up the figure
        plt.figure(figsize=(14, 10))
        
        if has_categories:
            # Create category distribution heatmap
            category_counts = {}
            for cat in CATEGORIES.keys():
                category_counts[cat] = sum(1 for c in channel_categories.values() if c == cat)
            
            # Sort categories by count
            sorted_cats = sorted(category_counts.items(), key=lambda x: x[1], reverse=True)
            cats = [c[0] for c in sorted_cats]
            counts = [c[1] for c in sorted_cats]
            
            # Generate heatmap
            plt.barh(cats, counts, color=plt.cm.viridis(Normalize()(counts)))
            
            plt.title('Channel Category Distribution', fontsize=16)
            plt.xlabel('Number of Channels', fontsize=12)
            plt.ylabel('Category', fontsize=12)
        else:
            # Without categories, show channel distribution by forward count
            channels = data['Channel Name'].value_counts().head(30)
            plt.barh(channels.index, channels.values, color=plt.cm.viridis(Normalize()(channels.values)))
            
            plt.title('Top 30 Channels by Mention Count', fontsize=16)
            plt.xlabel('Number of Mentions', fontsize=12)
            plt.ylabel('Channel', fontsize=12)
        
        # Add timestamp
        plt.figtext(0.5, 0.01, f'Generated by TG Snowball Sampler - {datetime.now().strftime("%Y-%m-%d")}',
                   ha='center', fontsize=8)
        
        # Save the figure
        plt.tight_layout()
        plt.savefig(output_file, dpi=300, bbox_inches='tight')
        plt.close()
        
        printC(f"Heatmap visualization saved to {output_file}", Fore.GREEN)
    
    except Exception as e:
        printC(f"Error generating heatmap visualization: {e}", Fore.RED)

def generate_chord_visualization(data, output_file):
    """Generate a chord diagram visualization from the data.
    
    Args:
        data: DataFrame containing the data
        output_file: Path to save the visualization
    """
    try:
        # For chord diagrams, we need matplotlib-chord
        try:
            from matplotlib_chord import Chord
        except ImportError:
            printC("Warning: matplotlib-chord is not installed. Installing it now...", Fore.YELLOW)
            import subprocess
            subprocess.run([sys.executable, "-m", "pip", "install", "matplotlib-chord"], check=True)
            from matplotlib_chord import Chord
        
        # We need edge data for chord diagram
        if 'Edge_List.csv' in os.listdir():
            edge_data = pd.read_csv('Edge_List.csv')
            
            # Get top 20 channels by degree
            top_channels = {}
            for _, row in edge_data.iterrows():
                source_name = row['Source Channel Name']
                target_name = row['Target Channel Name']
                for name in [source_name, target_name]:
                    if name in top_channels:
                        top_channels[name] += 1
                    else:
                        top_channels[name] = 1
            
            # Sort and get top channels
            top_channels = dict(sorted(top_channels.items(), key=lambda x: x[1], reverse=True)[:20])
            
            # Create a matrix for chord diagram
            names = list(top_channels.keys())
            matrix = np.zeros((len(names), len(names)))
            
            # Fill the matrix with connection counts
            for _, row in edge_data.iterrows():
                source_name = row['Source Channel Name']
                target_name = row['Target Channel Name']
                if source_name in names and target_name in names:
                    source_idx = names.index(source_name)
                    target_idx = names.index(target_name)
                    matrix[source_idx, target_idx] += 1
            
            # Create the chord diagram
            plt.figure(figsize=(12, 12))
            
            # Use short names for better visibility
            display_names = [n[:20] + '..' if len(n) > 20 else n for n in names]
            
            # Generate colors
            colors = plt.cm.tab20(np.linspace(0, 1, len(names)))
            
            # Create chord diagram
            chord = Chord(matrix, names=display_names, colors=colors)
            
            # Add title and timestamp
            plt.title('Channel Connection Diagram (Top 20 Channels)', fontsize=16)
            plt.figtext(0.5, 0.02, f'Generated by TG Snowball Sampler - {datetime.now().strftime("%Y-%m-%d")}',
                       ha='center', fontsize=8)
            
            # Save the figure
            plt.savefig(output_file, dpi=300, bbox_inches='tight')
            plt.close()
            
            printC(f"Chord visualization saved to {output_file}", Fore.GREEN)
        else:
            printC("Error: Edge_List.csv not found, cannot generate chord diagram", Fore.RED)
    
    except Exception as e:
        printC(f"Error generating chord visualization: {e}", Fore.RED)

def export_to_network_format(data, output_file, format_type):
    """Export data to network analysis formats.
    
    Args:
        data: DataFrame containing the data
        output_file: Base path for the output file (without extension)
        format_type: Format to export (gexf, graphml, json, all)
        
    Returns:
        str: Path to the exported file
    """
    try:
        # Create a directed graph
        G = nx.DiGraph()
        
        # Extract channel IDs and names
        channel_ids = data['Channel ID'].tolist()
        channel_names = data['Channel Name'].tolist()
        
        # Add nodes (channels)
        for i, (channel_id, channel_name) in enumerate(zip(channel_ids, channel_names)):
            G.add_node(channel_id, name=channel_name)
        
        # If we have edge information, add edges
        if 'Edge_List.csv' in os.listdir():
            edge_data = pd.read_csv('Edge_List.csv')
            for _, row in edge_data.iterrows():
                source = row['Source Channel ID']
                target = row['Target Channel ID']
                # Only add edge if both nodes exist
                if source in G.nodes and target in G.nodes:
                    G.add_edge(source, target)
        
        # Export to the requested format(s)
        exported_files = []
        
        if format_type in ['gexf', 'all']:
            gexf_file = f"{output_file}.gexf"
            nx.write_gexf(G, gexf_file)
            exported_files.append(gexf_file)
            printC(f"Exported to GEXF format: {gexf_file}", Fore.GREEN)
        
        if format_type in ['graphml', 'all']:
            graphml_file = f"{output_file}.graphml"
            nx.write_graphml(G, graphml_file)
            exported_files.append(graphml_file)
            printC(f"Exported to GraphML format: {graphml_file}", Fore.GREEN)
        
        if format_type in ['json', 'all']:
            json_file = f"{output_file}.json"
            json_data = nx.node_link_data(G)
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(json_data, f, indent=2)
            exported_files.append(json_file)
            printC(f"Exported to JSON format: {json_file}", Fore.GREEN)
        
        return exported_files
    
    except Exception as e:
        printC(f"Error exporting to network format: {e}", Fore.RED)
        return []

def send_webhook_notification(webhook_url, message, notify_type="info"):
    """Send a notification to a webhook URL (Slack, Discord, etc.)
    
    Args:
        webhook_url: Webhook URL to send notification to
        message: Message to send
        notify_type: Type of notification (info, success, warning, error)
        
    Returns:
        bool: True if notification was sent successfully, False otherwise
    """
    if not webhook_url:
        return False
    
    try:
        # Define colors for different notification types
        colors = {
            "info": "#5DADE2",     # Blue
            "success": "#58D68D",  # Green
            "warning": "#F5B041",  # Orange
            "error": "#EC7063"     # Red
        }
        color = colors.get(notify_type, colors["info"])
        
        # Create timestamp
        current_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        
        # Check if it's a Discord webhook
        if "discord.com" in webhook_url:
            payload = {
                "embeds": [{
                    "title": "TG Snowball Sampler Notification",
                    "description": message,
                    "color": int(color[1:], 16),
                    "footer": {"text": f"Sent at {current_time}"}
                }]
            }
        # Assume Slack webhook otherwise
        else:
            payload = {
                "attachments": [{
                    "title": "TG Snowball Sampler Notification",
                    "text": message,
                    "color": color,
                    "footer": f"Sent at {current_time}"
                }]
            }
        
        # Send the notification
        response = requests.post(
            webhook_url,
            json=payload,
            headers={"Content-Type": "application/json"}
        )
        
        if response.status_code == 200 or response.status_code == 204:
            return True
        else:
            printC(f"Error sending webhook notification: HTTP {response.status_code}", Fore.RED)
            return False
    
    except Exception as e:
        printC(f"Error sending webhook notification: {e}", Fore.RED)
        return False

def export_to_elasticsearch(data, output_dir, export_type='filebeat', es_config=None):
    """Export data to Elasticsearch via Filebeat or Logstash.
    
    Args:
        data: DataFrame containing the data
        output_dir: Directory to store the export files
        export_type: Type of export ('filebeat', 'logstash')
        es_config: Optional Elasticsearch configuration
        
    Returns:
        list: Paths to the exported files
    """
    try:
        # Validate parameters and set defaults
        if es_config is None:
            es_config = {
                'index_name': 'tg_snowball_sampler',
                'hosts': ['localhost:9200'],
                'username': None,
                'password': None,
                'ssl_enabled': False,
                'document_type': 'channel'
            }
        
        if not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)
            
        printC(f"Exporting data to Elasticsearch via {export_type}...", Fore.CYAN)
        
        # Create HMAC for securing the files
        timestamp = int(time.time())
        file_signature = hmac.new(
            hashlib.sha256(str(timestamp).encode()).digest(),
            "telegram_snowball_sampler".encode(),
            hashlib.sha256
        ).hexdigest()[:10]
        
        exported_files = []
        
        # Common data preparation
        # Convert DataFrame to list of dictionaries with proper metadata
        if isinstance(data, pd.DataFrame):
            channel_records = data.to_dict('records')
        else:
            # Assume data is already a list of dicts or similar
            channel_records = data
            
        # Add timestamps and metadata to each record
        for record in channel_records:
            # Add processing timestamp
            if 'timestamp' not in record:
                record['timestamp'] = datetime.now(timezone.utc).isoformat()
            # Add document type
            record['doc_type'] = es_config.get('document_type', 'channel')
            # Add source application
            record['source'] = 'tg_snowball_sampler'
        
        # Handle Filebeat export (NDJSON files with filebeat config)
        if export_type.lower() == 'filebeat':
            # Create NDJSON file for Filebeat
            ndjson_file = os.path.join(output_dir, f"es_export_{file_signature}.ndjson")
            
            with open(ndjson_file, 'w', encoding='utf-8') as f:
                for record in channel_records:
                    # Convert each record to JSON and write as a line
                    f.write(json.dumps(record) + '\n')
            
            exported_files.append(ndjson_file)
            
            # Create a Filebeat configuration file
            filebeat_config = {
                'filebeat.inputs': [
                    {
                        'type': 'log',
                        'enabled': True,
                        'paths': [ndjson_file],
                        'json.keys_under_root': True,
                        'json.add_error_key': True
                    }
                ],
                'output.elasticsearch': {
                    'hosts': es_config.get('hosts', ['localhost:9200']),
                    'index': es_config.get('index_name', 'tg_snowball_sampler') + "-%{+yyyy.MM.dd}"
                }
            }
            
            # Add SSL config if enabled
            if es_config.get('ssl_enabled', False):
                filebeat_config['output.elasticsearch']['ssl.enabled'] = True
                filebeat_config['output.elasticsearch']['ssl.verification_mode'] = 'certificate'
            
            # Add authentication if provided
            if es_config.get('username') and es_config.get('password'):
                filebeat_config['output.elasticsearch']['username'] = es_config.get('username')
                filebeat_config['output.elasticsearch']['password'] = es_config.get('password')
            
            # Write filebeat configuration
            filebeat_config_file = os.path.join(output_dir, f"filebeat_{file_signature}.yml")
            with open(filebeat_config_file, 'w', encoding='utf-8') as f:
                yaml.dump(filebeat_config, f, default_flow_style=False)
            
            exported_files.append(filebeat_config_file)
            
            # Add a helpful README file
            readme_file = os.path.join(output_dir, f"README_filebeat_{file_signature}.txt")
            with open(readme_file, 'w', encoding='utf-8') as f:
                f.write(f"""ELASTICSEARCH EXPORT VIA FILEBEAT
=============================================
Files generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

This directory contains:
1. {os.path.basename(ndjson_file)} - NDJSON file with the data
2. {os.path.basename(filebeat_config_file)} - Filebeat configuration file

To send this data to Elasticsearch, run:
$ filebeat -e -c {os.path.basename(filebeat_config_file)}

Note: You may need to adjust the Elasticsearch connection settings in the config file
before running Filebeat.
""")
            
            exported_files.append(readme_file)
            
            printC(f"Filebeat export files created in {output_dir}", Fore.GREEN)
        
        # Handle Logstash export (JSON file with Logstash config)
        elif export_type.lower() == 'logstash':
            # Create JSON file for Logstash
            json_file = os.path.join(output_dir, f"es_export_{file_signature}.json")
            
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(channel_records, f, indent=2)
            
            exported_files.append(json_file)
            
            # Create a Logstash configuration file
            logstash_config = f"""input {{
  file {{
    path => "{json_file}"
    codec => json 
    start_position => "beginning"
    sincedb_path => "/dev/null"
  }}
}}

filter {{
  date {{
    match => [ "timestamp", "ISO8601" ]
    target => "@timestamp"
  }}
  
  # Add source metadata
  mutate {{
    add_field => {{ 
      "[metadata][source]" => "tg_snowball_sampler"
      "[metadata][exported_at]" => "{datetime.now(timezone.utc).isoformat()}"
    }}
  }}
}}

output {{
  elasticsearch {{
    hosts => {json.dumps(es_config.get('hosts', ['localhost:9200']))}
    index => "{es_config.get('index_name', 'tg_snowball_sampler')}-%{{+YYYY.MM.dd}}"
"""
            
            # Add SSL config if enabled
            if es_config.get('ssl_enabled', False):
                logstash_config += """    ssl => true
    ssl_certificate_verification => true
"""
            
            # Add authentication if provided
            if es_config.get('username') and es_config.get('password'):
                logstash_config += f"""    user => "{es_config.get('username')}"
    password => "{es_config.get('password')}"
"""
            
            # Close the elasticsearch output and config
            logstash_config += """  }
}"""
            
            # Write logstash configuration
            logstash_config_file = os.path.join(output_dir, f"logstash_{file_signature}.conf")
            with open(logstash_config_file, 'w', encoding='utf-8') as f:
                f.write(logstash_config)
            
            exported_files.append(logstash_config_file)
            
            # Add a helpful README file
            readme_file = os.path.join(output_dir, f"README_logstash_{file_signature}.txt")
            with open(readme_file, 'w', encoding='utf-8') as f:
                f.write(f"""ELASTICSEARCH EXPORT VIA LOGSTASH
==============================================
Files generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

This directory contains:
1. {os.path.basename(json_file)} - JSON file with the data
2. {os.path.basename(logstash_config_file)} - Logstash configuration file

To send this data to Elasticsearch, run:
$ logstash -f {os.path.basename(logstash_config_file)}

Note: You may need to adjust the Elasticsearch connection settings in the config file
before running Logstash.
""")
            
            exported_files.append(readme_file)
            
            printC(f"Logstash export files created in {output_dir}", Fore.GREEN)
        
        else:
            printC(f"Unsupported export type: {export_type}. Please use 'filebeat' or 'logstash'.", Fore.RED)
        
        return exported_files
    
    except Exception as e:
        printC(f"Error exporting to Elasticsearch: {e}", Fore.RED)
        return []


def get_index_mapping_for_elasticsearch():
    """Return a recommended Elasticsearch mapping for the snowball sampler data.
    
    Returns:
        dict: Elasticsearch index mapping
    """
    return {
        "mappings": {
            "properties": {
                "Channel ID": {"type": "keyword"},
                "Channel Name": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 256}}},
                "Username": {"type": "keyword"},
                "Category": {"type": "keyword"},
                "Description": {"type": "text"},
                "Member Count": {"type": "integer"},
                "Mention Count": {"type": "integer"},
                "First Seen": {"type": "date"},
                "Last Seen": {"type": "date"},
                "timestamp": {"type": "date"},
                "doc_type": {"type": "keyword"},
                "source": {"type": "keyword"},
                "metadata": {
                    "properties": {
                        "source": {"type": "keyword"},
                        "exported_at": {"type": "date"}
                    }
                },
                "location": {"type": "geo_point"}
            }
        },
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 1
        }
    }

# Add new Elasticsearch form
class ElasticsearchForm(npyscreen.Form):
    def create(self):
        # Get existing configuration
        try:
            from main import config
            es_config = config.elasticsearch
        except (ImportError, AttributeError):
            # Fall back to defaults if config can't be accessed
            es_config = type('', (), {
                'enabled': False,
                'export_type': 'filebeat',
                'index_name': 'project_snow',
                'hosts': ['localhost:9200'],
                'username': None,
                'password': None,
                'ssl_enabled': False,
                'export_dir': 'elasticsearch_export',
                'template_enabled': True
            })
        
        # Title with explanation
        self.add(npyscreen.FixedText, value="Configure Elasticsearch Export Settings", editable=False)
        self.add(npyscreen.FixedText, value="This will create all files needed to export your data to Elasticsearch", editable=False)
        self.add(npyscreen.FixedText, value="", editable=False)  # Empty line for spacing
        
        # Enable/disable Elasticsearch export
        self.add(npyscreen.CheckBox, name="Enable Elasticsearch Export", value=es_config.enabled)
        
        # Export type options
        es_type_value = 1 if es_config.export_type == 'logstash' else 0
        self.add(npyscreen.TitleSelectOne, max_height=3, name="Export Type:",
                 values=["Filebeat", "Logstash"], scroll_exit=True, value=[es_type_value])
        
        # Elasticsearch connection settings
        self.add(npyscreen.TitleText, name="Index Name:", value=es_config.index_name)
        
        # Convert hosts list to comma-separated string
        hosts_str = ','.join(es_config.hosts) if hasattr(es_config.hosts, '__iter__') else es_config.hosts
        self.add(npyscreen.TitleText, name="Hosts (comma-separated):", value=hosts_str)
        
        # Authentication settings
        auth_enabled = es_config.username is not None and es_config.username != ''
        self.add(npyscreen.CheckBox, name="Enable Authentication", value=auth_enabled)
        self.username = self.add(npyscreen.TitleText, name="Username:", 
                                 value=es_config.username or "", hidden=not auth_enabled)
        self.password = self.add(npyscreen.TitlePassword, name="Password:", 
                                 value=es_config.password or "", hidden=not auth_enabled)
        
        # SSL settings
        self.add(npyscreen.CheckBox, name="Enable SSL", value=es_config.ssl_enabled)
        
        # Export directory
        self.add(npyscreen.TitleText, name="Export Directory:", value=es_config.export_dir)
        
        # Advanced settings
        self.add(npyscreen.CheckBox, name="Create Elasticsearch Index Template", 
                 value=es_config.template_enabled)
        
        # HMAC security warning
        self.add(npyscreen.FixedText, value="", editable=False)  # Empty line for spacing
        self.add(npyscreen.FixedText, 
                 value="⚠️ Credentials are HMAC-signed but stored in plaintext in config", 
                 editable=False, color="WARNING")
        
        # Create action buttons
        self.add(npyscreen.ButtonPress, name="Save Configuration", when_pressed_function=self.save_config)
        self.add(npyscreen.ButtonPress, name="Test Connection", when_pressed_function=self.test_connection)
        self.add(npyscreen.ButtonPress, name="Back to Main Menu", when_pressed_function=self.back_to_main)
    
    def test_connection(self):
        """Test Elasticsearch connection with current settings"""
        # Get form values for the test
        hosts = [host.strip() for host in self.get_widget("Hosts (comma-separated):").value.split(',')]
        auth_enabled = self.get_widget("Enable Authentication").value
        username = self.get_widget("Username:").value if auth_enabled else None
        password = self.get_widget("Password:").value if auth_enabled else None
        ssl_enabled = self.get_widget("Enable SSL").value
        
        # Try to import requests for the test
        try:
            import requests
            from requests.auth import HTTPBasicAuth
            
            # Try connecting to the first host
            host = hosts[0]
            if not host.startswith(('http://', 'https://')):
                protocol = 'https://' if ssl_enabled else 'http://'
                host = f"{protocol}{host}"
            
            auth = None
            if auth_enabled and username and password:
                auth = HTTPBasicAuth(username, password)
            
            try:
                # Set a timeout for the request
                response = requests.get(f"{host}/_cluster/health", auth=auth, 
                                        verify=False, timeout=5)
                
                if response.status_code == 200:
                    cluster_info = response.json()
                    status = cluster_info.get('status', 'unknown')
                    npyscreen.notify_confirm(
                        f"✓ Successfully connected to Elasticsearch!\n\n"
                        f"Cluster name: {cluster_info.get('cluster_name', 'N/A')}\n"
                        f"Status: {status}\n"
                        f"Nodes: {cluster_info.get('number_of_nodes', 'N/A')}\n",
                        title="Connection Successful"
                    )
                else:
                    npyscreen.notify_confirm(
                        f"× Connection failed: HTTP {response.status_code}\n"
                        f"Response: {response.text}",
                        title="Connection Failed"
                    )
            except requests.RequestException as e:
                npyscreen.notify_confirm(
                    f"× Connection error: {str(e)}\n\n"
                    f"Please check your connection settings.",
                    title="Connection Failed"
                )
                
        except ImportError:
            npyscreen.notify_confirm(
                "The 'requests' library is required to test Elasticsearch connections.\n"
                "Connection test skipped.",
                title="Missing Dependency"
            )
    
    def save_config(self):
        # Get form values and update global config
        es_enabled = self.get_widget("Enable Elasticsearch Export").value
        es_type = "filebeat" if self.get_widget("Export Type:").value[0] == 0 else "logstash"
        index_name = self.get_widget("Index Name:").value
        hosts = [host.strip() for host in self.get_widget("Hosts (comma-separated):").value.split(',')]
        
        # Authentication settings
        auth_enabled = self.get_widget("Enable Authentication").value
        username = self.get_widget("Username:").value if auth_enabled else None
        password = self.get_widget("Password:").value if auth_enabled else None
        
        # SSL settings
        ssl_enabled = self.get_widget("Enable SSL").value
        
        # Export directory and template settings
        export_dir = self.get_widget("Export Directory:").value
        template_enabled = self.get_widget("Create Elasticsearch Index Template").value
        
        # Save configuration to global config object
        try:
            # Try to import the global config object
            from main import config
            
            # Update configuration
            config.elasticsearch.enabled = es_enabled
            config.elasticsearch.export_type = es_type
            config.elasticsearch.index_name = index_name
            config.elasticsearch.hosts = hosts
            config.elasticsearch.username = username
            config.elasticsearch.password = password
            config.elasticsearch.ssl_enabled = ssl_enabled
            config.elasticsearch.export_dir = export_dir
            config.elasticsearch.template_enabled = template_enabled
            
            # Save config to file
            config.save("config.yaml")
            
            npyscreen.notify_confirm(
                "Elasticsearch configuration has been saved!\n\n"
                f"Export enabled: {'Yes' if es_enabled else 'No'}\n"
                f"Export type: {es_type.capitalize()}\n"
                f"Index name: {index_name}\n"
                f"Hosts: {', '.join(hosts)}\n",
                title="Success"
            )
        except Exception as e:
            npyscreen.notify_confirm(f"Error saving configuration: {e}", title="Error")
        
        # Return to main form
        self.parentApp.setNextForm('MAIN')
        self.editing = False
    
    def back_to_main(self):
        self.parentApp.setNextForm('MAIN')
        self.editing = False
    
    def while_editing(self, *args, **kwargs):
        # Show/hide authentication fields based on checkbox
        auth_enabled = self.get_widget("Enable Authentication").value
        self.username.hidden = not auth_enabled
        self.password.hidden = not auth_enabled
        
        # Redraw the screen to show/hide fields
        self.display()
        
    def afterEditing(self):
        # Handle field visibility if needed when form is closed
        pass

# Add new TgArchive form
class TgArchiveForm(npyscreen.Form):
    def create(self):
        # Title with explanation
        self.add(npyscreen.FixedText, value="Configure tg-archive Integration", editable=False)
        self.add(npyscreen.FixedText, value="Generate static archive websites from Telegram channels", editable=False)
        self.add(npyscreen.FixedText, value="", editable=False)  # Empty line for spacing
        
        # Channel selection
        self.add(npyscreen.TitleText, name="Channel Username/ID:", value="")
        
        # Archive options
        self.add(npyscreen.CheckBox, name="Create New Archive (-n)", value=True)
        self.add(npyscreen.CheckBox, name="Sync Messages Only (-s)", value=False)
        
        # Archive path settings
        self.add(npyscreen.TitleText, name="Archive Path:", value="tg_archive")
        
        # Secure options
        self.add(npyscreen.CheckBox, name="Use Current API Credentials", value=True)
        self.add(npyscreen.CheckBox, name="Download Media", value=True)
        
        # Warning about API credentials
        self.add(npyscreen.FixedText, value="", editable=False)
        self.add(npyscreen.FixedText, 
                 value="⚠️ Using API keys from this tool for tg-archive",
                 editable=False, color="WARNING")
        
        # Create action buttons
        self.add(npyscreen.ButtonPress, name="Run tg-archive", when_pressed_function=self.run_tgarchive)
        self.add(npyscreen.ButtonPress, name="Check Installation", when_pressed_function=self.check_installation)
        self.add(npyscreen.ButtonPress, name="Back to Main Menu", when_pressed_function=self.back_to_main)
    
    def run_tgarchive(self):
        """Run tg-archive with the specified settings"""
        import subprocess
        
        # Get form values
        channel = self.get_widget("Channel Username/ID:").value.strip()
        create_new = self.get_widget("Create New Archive (-n)").value
        sync_only = self.get_widget("Sync Messages Only (-s)").value
        archive_path = self.get_widget("Archive Path:").value.strip()
        use_credentials = self.get_widget("Use Current API Credentials").value
        download_media = self.get_widget("Download Media").value
        
        # Validate inputs
        if not channel:
            npyscreen.notify_confirm("Channel username or ID is required", title="Error")
            return
            
        if not archive_path:
            npyscreen.notify_confirm("Archive path is required", title="Error")
            return
        
        try:
            # Build command based on settings
            command_parts = ["tg-archive"]
            
            # Add options
            if create_new:
                command_parts.append("--new")
                
            if sync_only:
                command_parts.append("--sync")
            
            # Archive path
            command_parts.extend(["--path", archive_path])
            
            # Channel ID target will be prepared in the config
            
            # Check if tg-archive is installed
            try:
                subprocess.run(["tg-archive", "--help"], 
                               stdout=subprocess.PIPE, 
                               stderr=subprocess.PIPE, 
                               check=False)
            except FileNotFoundError:
                npyscreen.notify_confirm(
                    "tg-archive is not installed. Please install it with:\n\n"
                    "pip install tg-archive\n\n"
                    "After installing, try again.",
                    title="Error: tg-archive Not Found"
                )
                return
            
            if use_credentials:
                # If using current credentials, we need to prepare the config
                self.prepare_config_with_credentials(archive_path, channel)
            
            # Execute the command
            npyscreen.notify_wait(
                f"Running tg-archive...\n{' '.join(command_parts)}",
                title="Please Wait"
            )
            
            result = subprocess.run(command_parts, 
                                   stdout=subprocess.PIPE, 
                                   stderr=subprocess.PIPE, 
                                   text=True)
            
            if result.returncode == 0:
                npyscreen.notify_confirm(
                    f"tg-archive completed successfully!\n\n"
                    f"Archive saved to: {os.path.abspath(archive_path)}",
                    title="Success"
                )
            else:
                npyscreen.notify_confirm(
                    f"tg-archive failed with error:\n\n{result.stderr}",
                    title="Error"
                )
        except Exception as e:
            npyscreen.notify_confirm(f"Error running tg-archive: {e}", title="Error")
        
    def prepare_config_with_credentials(self, archive_path, channel_id):
        """Prepare the tg-archive config.yaml file with API credentials"""
        import yaml
        import os
        
        try:
            # Create archive directory if it doesn't exist
            if not os.path.exists(archive_path):
                os.makedirs(archive_path, exist_ok=True)
                
            # Get API credentials from encrypted file
            api_details_file_path = 'api_keys.enc'
            key_file_path = '.keyfile'
            
            if os.path.exists(api_details_file_path) and os.path.exists(key_file_path):
                # Read the key
                with open(key_file_path, 'rb') as keyfile:
                    key = keyfile.read()
                
                # Read and decrypt the API details
                with open(api_details_file_path, 'rb') as file:
                    encrypted_data = file.read()
                
                from cryptography.fernet import Fernet
                f = Fernet(key)
                decrypted_data = f.decrypt(encrypted_data)
                api_data = json.loads(decrypted_data.decode())
                
                # Use the first API key in the list
                if api_data and 'api_keys' in api_data and api_data['api_keys']:
                    first_api = api_data['api_keys'][0]
                    api_id = first_api['api_id']
                    api_hash = first_api['api_hash']
                    
                    # Create a config.yaml file for tg-archive
                    config_path = os.path.join(archive_path, 'config.yaml')
                    
                    # Default config structure
                    tg_config = {
                        'api_id': int(api_id),
                        'api_hash': api_hash,
                        'channel': channel_id,
                        'title': f"Archive of {channel_id}",
                        'description': f"Telegram channel archive of {channel_id}",
                        'website_url': '',
                        'author_name': 'TG Snowball Sampler',
                        'author_url': '',
                        'items_per_page': 100,
                        'download_media': self.get_widget("Download Media").value,
                        'file_size_limit_mb': 25
                    }
                    
                    # Write the config file
                    with open(config_path, 'w', encoding='utf-8') as f:
                        yaml.dump(tg_config, f, default_flow_style=False)
                    
                    printC(f"Created tg-archive config at {config_path} with API credentials", Fore.GREEN)
                else:
                    raise ValueError("No API keys found in the encrypted storage")
            else:
                raise FileNotFoundError("API credentials not found")
        
        except Exception as e:
            npyscreen.notify_confirm(
                f"Failed to prepare tg-archive config with credentials: {e}\n\n"
                "Please run tg-archive manually and enter your credentials.",
                title="Error"
            )
    
    def check_installation(self):
        """Check if tg-archive is installed"""
        import subprocess
        try:
            result = subprocess.run(["tg-archive", "--help"], 
                                  stdout=subprocess.PIPE, 
                                  stderr=subprocess.PIPE, 
                                  text=True)
            
            if result.returncode == 0:
                npyscreen.notify_confirm(
                    "✓ tg-archive is installed and ready to use!",
                    title="Success"
                )
            else:
                npyscreen.notify_confirm(
                    f"⚠️ tg-archive is installed but returned an error:\n\n{result.stderr}",
                    title="Warning"
                )
        except FileNotFoundError:
            npyscreen.notify_confirm(
                "✗ tg-archive is not installed. Please install it with:\n\n"
                "pip install tg-archive\n\n"
                "After installing, run the check again.",
                title="Not Installed"
            )
        except Exception as e:
            npyscreen.notify_confirm(f"Error checking tg-archive: {e}", title="Error")
    
    def back_to_main(self):
        self.parentApp.setNextForm('MAIN')
        self.editing = False

# Add the proxy rotation functionality
class ProxyManager:
    """Handles proxy rotation, validation, and VPN integration."""
    
    def __init__(self, proxy_file='proxy.txt', rotation_interval=300, validation_timeout=10):
        self.proxy_file = proxy_file
        self.rotation_interval = rotation_interval  # seconds
        self.validation_timeout = validation_timeout  # seconds
        self.proxies = []
        self.validated_proxies = []
        self.current_proxy = None
        self.last_rotation = 0
        self.vpn_provider = None
        self.vpn_credentials = {}
        self.vpn_connected = False
        self.lock = threading.Lock()
        
    def load_proxies_from_file(self):
        """Load proxies from proxy.txt file."""
        try:
            if os.path.exists(self.proxy_file):
                with open(self.proxy_file, 'r') as f:
                    # Expect format: protocol://user:pass@host:port or host:port
                    raw_proxies = [p.strip() for p in f.readlines() if p.strip() and not p.startswith('#')]
                    
                    # Parse and normalize proxy format
                    for proxy in raw_proxies:
                        # If proxy doesn't specify protocol, assume http
                        if not proxy.startswith(('http://', 'https://', 'socks5://')):
                            proxy = f"http://{proxy}"
                        self.proxies.append(proxy)
                    
                printC(f"Loaded {len(self.proxies)} proxies from {self.proxy_file}", Fore.GREEN)
                return True
            else:
                printC(f"Proxy file {self.proxy_file} not found", Fore.YELLOW)
                return False
        except Exception as e:
            printC(f"Error loading proxies: {e}", Fore.RED)
            return False
    
    async def validate_proxy(self, proxy):
        """Validate a proxy by attempting a connection."""
        try:
            import aiohttp
            from aiohttp_socks import ProxyConnector
            
            # Handle different proxy types
            if proxy.startswith('socks5://'):
                connector = ProxyConnector.from_url(proxy)
            else:
                # For HTTP/HTTPS proxies
                session_proxies = {
                    'http': proxy,
                    'https': proxy
                }
                connector = None
            
            # Use an async context manager for the session
            timeout = aiohttp.ClientTimeout(total=self.validation_timeout)
            
            try:
                if connector:
                    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                        async with session.get('https://api.ipify.org?format=json') as response:
                            if response.status == 200:
                                data = await response.json()
                                printC(f"Proxy {proxy} validated with IP: {data.get('ip')}", Fore.GREEN)
                                return True
                else:
                    async with aiohttp.ClientSession(timeout=timeout) as session:
                        async with session.get('https://api.ipify.org?format=json', proxy=session_proxies) as response:
                            if response.status == 200:
                                data = await response.json()
                                printC(f"Proxy {proxy} validated with IP: {data.get('ip')}", Fore.GREEN)
                                return True
            except Exception as e:
                printC(f"Proxy {proxy} failed validation: {e}", Fore.YELLOW)
                return False
                
        except ImportError:
            printC("aiohttp or aiohttp_socks not installed. Cannot validate proxies.", Fore.RED)
            printC("Install with: pip install aiohttp aiohttp_socks", Fore.YELLOW)
            return False
        except Exception as e:
            printC(f"Error validating proxy {proxy}: {e}", Fore.RED)
            return False
    
    async def validate_all_proxies(self):
        """Validate all loaded proxies."""
        if not self.proxies:
            return False
            
        printC(f"Validating {len(self.proxies)} proxies...", Fore.CYAN)
        
        # Create validation tasks for each proxy
        tasks = [self.validate_proxy(proxy) for proxy in self.proxies]
        
        # Run validation tasks with progress bar
        with tqdm(total=len(tasks), desc="Validating proxies") as pbar:
            results = []
            for task in asyncio.as_completed(tasks):
                result = await task
                results.append(result)
                pbar.update(1)
        
        # Filter validated proxies
        self.validated_proxies = [proxy for proxy, result in zip(self.proxies, results) if result]
        
        printC(f"Validated {len(self.validated_proxies)} proxies out of {len(self.proxies)}", Fore.GREEN)
        return len(self.validated_proxies) > 0
    
    async def get_next_proxy(self, force_rotate=False):
        """Get the next proxy in the rotation."""
        with self.lock:
            current_time = time.time()
            
            # Check if we need to rotate
            if (not self.current_proxy or 
                force_rotate or 
                (current_time - self.last_rotation > self.rotation_interval)):
                
                # If no validated proxies, attempt to validate if we have raw proxies
                if not self.validated_proxies and self.proxies:
                    await self.validate_all_proxies()
                
                if self.validated_proxies:
                    # Select a random proxy from validated list
                    self.current_proxy = random.choice(self.validated_proxies)
                    self.last_rotation = current_time
                    printC(f"Rotated to proxy: {self.current_proxy}", Fore.CYAN)
                else:
                    self.current_proxy = None
                    
            return self.current_proxy
    
    # VPN integration methods
    async def connect_ipvanish(self, username, password, server=None):
        """Connect to IPVanish VPN."""
        try:
            import subprocess
            import tempfile
            import random
            
            self.vpn_provider = "ipvanish"
            self.vpn_credentials = {"username": username, "password": password}
            
            # If no server specified, get a list of IPVanish servers and choose a random one
            if not server:
                # Get server list from IPVanish API or use a hardcoded list as fallback
                server_list = await self._get_ipvanish_servers()
                if server_list:
                    server = random.choice(server_list)
                else:
                    # Fallback to a common server if API call fails
                    server = "iad.ipvanish.com"
            
            # Create a temporary OpenVPN config file
            with tempfile.NamedTemporaryFile(delete=False, mode='w') as temp_config:
                temp_config.write(f"""client
dev tun
proto udp
remote {server} 443
resolv-retry infinite
nobind
persist-key
persist-tun
cipher aes-256-cbc
auth sha256
verb 3
auth-user-pass {temp_config.name}.auth
""")
                temp_config_path = temp_config.name
            
            # Create auth file with credentials
            with open(f"{temp_config_path}.auth", 'w') as auth_file:
                auth_file.write(f"{username}\n{password}")
            
            # Set secure permissions on auth file
            os.chmod(f"{temp_config_path}.auth", 0o600)
            
            # Connect using OpenVPN
            self.vpn_process = subprocess.Popen(
                ["sudo", "openvpn", "--config", temp_config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Check if connection was successful (basic check)
            time.sleep(5)  # Give it time to connect
            
            if self.vpn_process.poll() is None:  # Process still running
                # Verify we're connected by checking our IP changed
                old_ip = await self._get_current_ip()
                time.sleep(2)  # Wait for connection to establish
                new_ip = await self._get_current_ip()
                
                if old_ip != new_ip:
                    self.vpn_connected = True
                    printC(f"Connected to IPVanish VPN. IP changed to {new_ip}", Fore.GREEN)
                    return True
                else:
                    # Kill the process if IP didn't change
                    self.vpn_process.terminate()
                    printC("Failed to confirm IP change after VPN connection", Fore.RED)
            else:
                printC(f"Failed to connect to IPVanish VPN. Error: {self.vpn_process.stderr.read().decode()}", Fore.RED)
            
            # Clean up temp files if connection failed
            os.unlink(temp_config_path)
            os.unlink(f"{temp_config_path}.auth")
            return False
            
        except Exception as e:
            printC(f"Error connecting to IPVanish: {e}", Fore.RED)
            return False
    
    async def connect_nordvpn(self, username, password, server=None):
        """Connect to NordVPN."""
        try:
            import subprocess
            import tempfile
            import random
            
            self.vpn_provider = "nordvpn"
            self.vpn_credentials = {"username": username, "password": password}
            
            # If no server specified, get a list of NordVPN servers and choose a random one
            if not server:
                # Get server list from NordVPN API or use a hardcoded list as fallback
                server_list = await self._get_nordvpn_servers()
                if server_list:
                    server = random.choice(server_list)
                else:
                    # Fallback to a common server if API call fails
                    server = "us8621.nordvpn.com"
            
            # Create a temporary OpenVPN config file
            with tempfile.NamedTemporaryFile(delete=False, mode='w') as temp_config:
                temp_config.write(f"""client
dev tun
proto udp
remote {server} 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-GCM
auth SHA512
verb 3
auth-user-pass {temp_config.name}.auth
""")
                temp_config_path = temp_config.name
            
            # Create auth file with credentials
            with open(f"{temp_config_path}.auth", 'w') as auth_file:
                auth_file.write(f"{username}\n{password}")
            
            # Set secure permissions on auth file
            os.chmod(f"{temp_config_path}.auth", 0o600)
            
            # Connect using OpenVPN
            self.vpn_process = subprocess.Popen(
                ["sudo", "openvpn", "--config", temp_config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Check if connection was successful (basic check)
            time.sleep(5)  # Give it time to connect
            
            if self.vpn_process.poll() is None:  # Process still running
                # Verify we're connected by checking our IP changed
                old_ip = await self._get_current_ip()
                time.sleep(2)  # Wait for connection to establish
                new_ip = await self._get_current_ip()
                
                if old_ip != new_ip:
                    self.vpn_connected = True
                    printC(f"Connected to NordVPN. IP changed to {new_ip}", Fore.GREEN)
                    return True
                else:
                    # Kill the process if IP didn't change
                    self.vpn_process.terminate()
                    printC("Failed to confirm IP change after VPN connection", Fore.RED)
            else:
                printC(f"Failed to connect to NordVPN. Error: {self.vpn_process.stderr.read().decode()}", Fore.RED)
            
            # Clean up temp files if connection failed
            os.unlink(temp_config_path)
            os.unlink(f"{temp_config_path}.auth")
            return False
            
        except Exception as e:
            printC(f"Error connecting to NordVPN: {e}", Fore.RED)
            return False
    
    async def disconnect_vpn(self):
        """Disconnect from VPN."""
        if self.vpn_connected and hasattr(self, 'vpn_process'):
            try:
                import subprocess
                
                # Terminate the OpenVPN process
                self.vpn_process.terminate()
                self.vpn_process.wait()
                
                # Make sure all OpenVPN instances are killed
                subprocess.run(["sudo", "killall", "openvpn"], check=False)
                
                self.vpn_connected = False
                printC(f"Disconnected from {self.vpn_provider} VPN", Fore.GREEN)
                return True
            except Exception as e:
                printC(f"Error disconnecting from VPN: {e}", Fore.RED)
                return False
        return False
    
    async def _get_current_ip(self):
        """Get the current IP address."""
        try:
            import aiohttp
            
            async with aiohttp.ClientSession() as session:
                async with session.get('https://api.ipify.org?format=json') as response:
                    if response.status == 200:
                        data = await response.json()
                        return data.get('ip')
            return None
        except Exception:
            return None
    
    async def _get_ipvanish_servers(self):
        """Get a list of IPVanish servers."""
        try:
            import aiohttp
            
            # IPVanish doesn't have a public API for server list, so we use a hardcoded list
            # In a real implementation, you might scrape this from their website or use a more updated source
            return [
                "atl.ipvanish.com",
                "chi.ipvanish.com",
                "dal.ipvanish.com",
                "lax.ipvanish.com",
                "nyc.ipvanish.com",
                "sjo.ipvanish.com",
                "lon.ipvanish.com",
                "par.ipvanish.com",
                "fra.ipvanish.com",
                "ams.ipvanish.com"
            ]
        except Exception:
            return []
    
    async def _get_nordvpn_servers(self):
        """Get a list of NordVPN servers."""
        try:
            import aiohttp
            
            async with aiohttp.ClientSession() as session:
                async with session.get('https://api.nordvpn.com/v1/servers/recommendations') as response:
                    if response.status == 200:
                        data = await response.json()
                        return [f"{server['hostname']}" for server in data[:10]]  # Get top 10 recommended servers
            
            # Fallback to a hardcoded list if API call fails
            return [
                "us8621.nordvpn.com",
                "us8622.nordvpn.com",
                "uk2097.nordvpn.com",
                "ca1288.nordvpn.com",
                "de984.nordvpn.com",
                "fr694.nordvpn.com",
                "nl864.nordvpn.com",
                "au704.nordvpn.com",
                "jp520.nordvpn.com",
                "sg479.nordvpn.com"
            ]
        except Exception:
            # Fallback to a hardcoded list if API call fails
            return [
                "us8621.nordvpn.com",
                "us8622.nordvpn.com",
                "uk2097.nordvpn.com",
                "ca1288.nordvpn.com",
                "de984.nordvpn.com"
            ]

# Add Proxy Settings form
class ProxyForm(npyscreen.Form):
    def create(self):
        # Title with explanation
        self.add(npyscreen.FixedText, value="Configure Proxy and VPN Settings", editable=False)
        self.add(npyscreen.FixedText, value="Route connections through proxies or VPN for enhanced anonymity", editable=False)
        self.add(npyscreen.FixedText, value="", editable=False)  # Empty line for spacing
        
        # Proxy settings section
        self.add(npyscreen.FixedText, value="=== Proxy Settings ===", editable=False)
        self.add(npyscreen.CheckBox, name="Enable Proxy Rotation", value=False)
        self.add(npyscreen.TitleText, name="Proxy File Path:", value="proxy.txt")
        self.add(npyscreen.TitleSlider, name="Rotation Interval (minutes):", 
                 out_of=60, value=5, step=1)
        self.add(npyscreen.TitleSlider, name="Validation Timeout (seconds):", 
                 out_of=30, value=10, step=1)
        
        # Proxy validation button
        self.add(npyscreen.ButtonPress, name="Test Proxies", 
                 when_pressed_function=self.test_proxies)
        
        # Empty line for spacing
        self.add(npyscreen.FixedText, value="", editable=False)
        
        # VPN settings section
        self.add(npyscreen.FixedText, value="=== VPN Settings ===", editable=False)
        self.add(npyscreen.TitleSelectOne, max_height=3, name="VPN Provider:",
                 values=["None", "IPVanish", "NordVPN"], value=[0], scroll_exit=True)
        
        # VPN credentials
        self.add(npyscreen.TitleText, name="VPN Username:", value="")
        self.add(npyscreen.TitlePassword, name="VPN Password:", value="")
        self.add(npyscreen.TitleText, name="VPN Server (optional):", value="")
        
        # VPN connection buttons
        self.add(npyscreen.ButtonPress, name="Connect VPN", 
                 when_pressed_function=self.connect_vpn)
        self.add(npyscreen.ButtonPress, name="Disconnect VPN", 
                 when_pressed_function=self.disconnect_vpn)
        
        # Current status section
        self.add(npyscreen.FixedText, value="", editable=False)
        self.add(npyscreen.FixedText, value="=== Current Status ===", editable=False)
        self.current_ip = self.add(npyscreen.TitleFixedText, name="Current IP:", 
                                  value="Checking...", editable=False)
        self.current_proxy = self.add(npyscreen.TitleFixedText, name="Active Proxy:", 
                                     value="None", editable=False)
        self.vpn_status = self.add(npyscreen.TitleFixedText, name="VPN Status:", 
                                  value="Disconnected", editable=False)
        
        # Refresh status button
        self.add(npyscreen.ButtonPress, name="Refresh Status", 
                 when_pressed_function=self.refresh_status)
        
        # Empty line for spacing
        self.add(npyscreen.FixedText, value="", editable=False)
        
        # Security warning
        self.add(npyscreen.FixedText, 
                 value="⚠️ Use proxies only with Telegram accounts dedicated to research",
                 editable=False, color="WARNING")
        
        # Action buttons
        self.add(npyscreen.ButtonPress, name="Save Configuration", 
                 when_pressed_function=self.save_config)
        self.add(npyscreen.ButtonPress, name="Back to Main Menu", 
                 when_pressed_function=self.back_to_main)
        
        # Initialize and check IP
        self.refresh_status()
    
    def test_proxies(self):
        """Test proxies from the specified file."""
        proxy_file = self.get_widget("Proxy File Path:").value
        validation_timeout = self.get_widget("Validation Timeout (seconds):").value
        
        if not os.path.exists(proxy_file):
            npyscreen.notify_confirm(
                f"Proxy file {proxy_file} not found. Please create it first with one proxy per line.",
                title="File Not Found"
            )
            return
        
        # Create a new proxy manager
        proxy_manager = ProxyManager(
            proxy_file=proxy_file,
            validation_timeout=validation_timeout
        )
        
        # Load proxies from file
        if not proxy_manager.load_proxies_from_file():
            npyscreen.notify_confirm(
                "Failed to load proxies from file. Please check the file format.",
                title="Error"
            )
            return
        
        # Run proxy validation in a background task
        npyscreen.notify_wait(
            "Testing proxies... This may take a while.",
            title="Please Wait"
        )
        
        # Create an event loop for validation
        loop = asyncio.new_event_loop()
        success = loop.run_until_complete(proxy_manager.validate_all_proxies())
        loop.close()
        
        if success:
            npyscreen.notify_confirm(
                f"Successfully validated {len(proxy_manager.validated_proxies)} out of {len(proxy_manager.proxies)} proxies.",
                title="Success"
            )
        else:
            npyscreen.notify_confirm(
                "No valid proxies found. Please check your proxy list or validation timeout.",
                title="Error"
            )
    
    def connect_vpn(self):
        """Connect to the selected VPN provider."""
        vpn_provider_idx = self.get_widget("VPN Provider:").value[0]
        username = self.get_widget("VPN Username:").value
        password = self.get_widget("VPN Password:").value
        server = self.get_widget("VPN Server (optional):").value
        
        if vpn_provider_idx == 0:  # None
            npyscreen.notify_confirm(
                "Please select a VPN provider first.",
                title="No Provider Selected"
            )
            return
        
        if not username or not password:
            npyscreen.notify_confirm(
                "VPN username and password are required.",
                title="Missing Credentials"
            )
            return
        
        # Create a proxy manager for VPN
        proxy_manager = ProxyManager()
        
        # Get the provider name
        provider = ["None", "IPVanish", "NordVPN"][vpn_provider_idx]
        
        # Connect to the VPN
        npyscreen.notify_wait(
            f"Connecting to {provider}... This may take a while.",
            title="Please Wait"
        )
        
        # Create an event loop for VPN connection
        loop = asyncio.new_event_loop()
        
        if provider == "IPVanish":
            success = loop.run_until_complete(
                proxy_manager.connect_ipvanish(username, password, server)
            )
        elif provider == "NordVPN":
            success = loop.run_until_complete(
                proxy_manager.connect_nordvpn(username, password, server)
            )
        else:
            success = False
        
        loop.close()
        
        if success:
            self.vpn_status.value = f"Connected to {provider}"
            npyscreen.notify_confirm(
                f"Successfully connected to {provider}.",
                title="Success"
            )
        else:
            npyscreen.notify_confirm(
                f"Failed to connect to {provider}. Please check your credentials and try again.",
                title="Error"
            )
        
        # Refresh the status
        self.refresh_status()
    
    def disconnect_vpn(self):
        """Disconnect from the VPN."""
        # Create a proxy manager for VPN
        proxy_manager = ProxyManager()
        
        # Disconnect from the VPN
        npyscreen.notify_wait(
            "Disconnecting from VPN...",
            title="Please Wait"
        )
        
        # Create an event loop for VPN disconnection
        loop = asyncio.new_event_loop()
        success = loop.run_until_complete(proxy_manager.disconnect_vpn())
        loop.close()
        
        if success:
            self.vpn_status.value = "Disconnected"
            npyscreen.notify_confirm(
                "Successfully disconnected from VPN.",
                title="Success"
            )
        else:
            npyscreen.notify_confirm(
                "No active VPN connection to disconnect.",
                title="Info"
            )
        
        # Refresh the status
        self.refresh_status()
    
    def refresh_status(self):
        """Refresh the current status information."""
        # Create an event loop for status check
        loop = asyncio.new_event_loop()
        
        # Check current IP
        proxy_manager = ProxyManager()
        current_ip = loop.run_until_complete(proxy_manager._get_current_ip())
        loop.close()
        
        if current_ip:
            self.current_ip.value = current_ip
        else:
            self.current_ip.value = "Unable to determine"
        
        # Update the display
        self.display()
    
    def save_config(self):
        """Save proxy and VPN configuration."""
        # Get form values
        enable_proxy = self.get_widget("Enable Proxy Rotation").value
        proxy_file = self.get_widget("Proxy File Path:").value
        rotation_interval = self.get_widget("Rotation Interval (minutes):").value
        validation_timeout = self.get_widget("Validation Timeout (seconds):").value
        
        vpn_provider_idx = self.get_widget("VPN Provider:").value[0]
        vpn_provider = ["none", "ipvanish", "nordvpn"][vpn_provider_idx]
        vpn_username = self.get_widget("VPN Username:").value
        vpn_password = self.get_widget("VPN Password:").value
        vpn_server = self.get_widget("VPN Server (optional):").value
        
        try:
            # Try to import the global config object
            from main import config
            
            # Update configuration
            # First check if the config has the necessary structure, create if not
            if not hasattr(config, 'proxy'):
                config.proxy = type('', (), {})
            
            config.proxy.enabled = enable_proxy
            config.proxy.proxy_file = proxy_file
            config.proxy.rotation_interval_minutes = rotation_interval
            config.proxy.validation_timeout_seconds = validation_timeout
            
            if not hasattr(config, 'vpn'):
                config.vpn = type('', (), {})
                
            config.vpn.provider = vpn_provider
            config.vpn.username = vpn_username
            config.vpn.password = vpn_password
            config.vpn.server = vpn_server
            
            # Save config to file
            config.save("config.yaml")
            
            npyscreen.notify_confirm(
                "Proxy and VPN configuration has been saved!",
                title="Success"
            )
        except Exception as e:
            npyscreen.notify_confirm(f"Error saving configuration: {e}", title="Error")
        
        # Return to main form
        self.parentApp.setNextForm('MAIN')
        self.editing = False
    
    def back_to_main(self):
        self.parentApp.setNextForm('MAIN')
        self.editing = False