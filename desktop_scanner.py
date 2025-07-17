#!/usr/bin/env python3
import socket
import re
import customtkinter as ctk
import threading
from CTkMessagebox import CTkMessagebox # For styled message boxes

# --- Your Core Scanning Logic (slightly adapted) ---
ip_add_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
port_range_pattern = re.compile(r"([0-9]+)-([0-9]+)") # For parsing simple X-Y ranges

def parse_ports(port_str):
    """
    Parses a port string (e.g., "80", "1-100", "22,80,100-200")
    into a sorted list of unique integers.
    Returns None if parsing fails.
    """
    ports_to_scan = set()
    if not port_str.strip():
        return []

    segments = port_str.split(',')
    for segment in segments:
        segment = segment.strip()
        if not segment:
            continue
        if '-' in segment:
            parts = segment.split('-')
            if len(parts) == 2:
                try:
                    start_port = int(parts[0])
                    end_port = int(parts[1])
                    if 0 <= start_port <= 65535 and 0 <= end_port <= 65535 and start_port <= end_port:
                        ports_to_scan.update(range(start_port, end_port + 1))
                    else:
                        return None # Invalid port numbers in range
                except ValueError:
                    return None # Non-integer in range
            else:
                return None # Invalid range format
        else:
            try:
                port = int(segment)
                if 0 <= port <= 65535:
                    ports_to_scan.add(port)
                else:
                    return None # Invalid port number
            except ValueError:
                return None # Non-integer port

    return sorted(list(ports_to_scan))

def scan_port_worker(ip_address, port, results_list, app_instance):
    """
    Worker function to scan a single port.
    Appends to results_list if open.
    Uses app_instance.after to schedule GUI updates.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)  # Timeout for connection attempt
            s.connect((ip_address, port))
            # If connect succeeds, port is open
            app_instance.after(0, lambda: results_list.append(port)) # Thread-safe GUI update
            app_instance.after(0, lambda: app_instance.update_results_display(f"Port {port} is open", "open"))
            return True # Indicate port is open
    except (socket.timeout, socket.error):
        # Port is closed or filtered
        app_instance.after(0, lambda: app_instance.update_results_display(f"Port {port} is closed/filtered", "closed"))
        return False # Indicate port is closed/filtered
    except Exception as e:
        app_instance.after(0, lambda: app_instance.update_results_display(f"Error on port {port}: {e}", "error"))
        return False


# --- CustomTkinter Application ---
class PortScannerApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Retro Port Scanner")
        self.geometry("650x650") # Adjusted size
        # Theme inspired by your HTML (dark mode with a vibrant accent)
        ctk.set_appearance_mode("Dark")
        # Try a vibrant color. Options: "blue" (default), "dark-blue", "green"
        # For more custom colors, you'd typically modify the theme JSON or use specific widget colors.
        # Let's try 'blue' and then customize widget colors for the retro feel.
        ctk.set_default_color_theme("blue")

        # --- Colors (approximating your retro theme) ---
        self.BG_COLOR = "#1A1A2E"
        self.CONTAINER_COLOR = "#2A2A4E"
        self.TEXT_COLOR = "#E0F2E9"
        self.ACCENT_COLOR_PINK = "#FF007F"
        self.ACCENT_COLOR_TEAL = "#00F0B5"

        self.configure(fg_color=self.BG_COLOR)

        # --- Main Container Frame ---
        self.container_frame = ctk.CTkFrame(self, fg_color=self.CONTAINER_COLOR, border_color=self.ACCENT_COLOR_PINK, border_width=3, corner_radius=15)
        self.container_frame.pack(padx=20, pady=20, fill="both", expand=True)


        # --- Title ---
        self.title_label = ctk.CTkLabel(self.container_frame, text="PORT SCANNER",
                                        font=ctk.CTkFont(family="Press Start 2P", size=24, weight="bold"), # Using a common retro font name
                                        text_color=self.ACCENT_COLOR_TEAL)
        self.title_label.pack(pady=(15, 20)) # Increased top padding

        # --- IP Address Input ---
        self.ip_label = ctk.CTkLabel(self.container_frame, text="Target IP Address:", text_color=self.ACCENT_COLOR_TEAL, font=("VT323", 18))
        self.ip_label.pack(pady=(10,2), anchor="w", padx=20)
        self.ip_entry = ctk.CTkEntry(self.container_frame, placeholder_text="e.g., 192.168.1.1", width=300, height=35,
                                     fg_color=self.BG_COLOR, text_color=self.TEXT_COLOR,
                                     border_color=self.ACCENT_COLOR_PINK, font=("VT323", 16))
        self.ip_entry.pack(pady=(0,15), padx=20, fill="x")

        # --- Port Range Input ---
        self.port_label = ctk.CTkLabel(self.container_frame, text="Port Range / List:", text_color=self.ACCENT_COLOR_TEAL, font=("VT323", 18))
        self.port_label.pack(pady=(5,2), anchor="w", padx=20)
        self.port_entry = ctk.CTkEntry(self.container_frame, placeholder_text="e.g., 1-1024 or 22,80,443", width=300, height=35,
                                       fg_color=self.BG_COLOR, text_color=self.TEXT_COLOR,
                                       border_color=self.ACCENT_COLOR_PINK, font=("VT323", 16))
        self.port_entry.pack(pady=(0,20), padx=20, fill="x")

        # --- Scan Button ---
        self.scan_button = ctk.CTkButton(self.container_frame, text="Scan Ports", command=self.start_scan_thread,
                                         font=ctk.CTkFont(family="Press Start 2P", size=14),
                                         fg_color=self.ACCENT_COLOR_PINK, text_color=self.BG_COLOR,
                                         hover_color=self.ACCENT_COLOR_TEAL, height=40)
        self.scan_button.pack(pady=10, padx=20, fill="x")

        # --- Progress Bar ---
        self.progress_bar = ctk.CTkProgressBar(self.container_frame, orientation="horizontal", progress_color=self.ACCENT_COLOR_TEAL)
        self.progress_bar.set(0) # Initially hidden by not packing, pack when scan starts
        # self.progress_bar.pack(pady=(5,10), padx=20, fill="x") # Pack it later

        # --- Results Area ---
        self.results_label = ctk.CTkLabel(self.container_frame, text="Scan Results:", text_color=self.ACCENT_COLOR_TEAL, font=("VT323", 18))
        self.results_label.pack(pady=(15,5), anchor="w", padx=20)
        self.results_textbox = ctk.CTkTextbox(self.container_frame, width=300, height=200, activate_scrollbars=True,
                                              fg_color=self.BG_COLOR, text_color=self.TEXT_COLOR,
                                              border_color=self.ACCENT_COLOR_TEAL, border_width=2,
                                              font=("VT323", 14), wrap="word")
        self.results_textbox.pack(pady=(0,15), padx=20, fill="both", expand=True)
        self.results_textbox.configure(state="disabled") # Make it read-only initially

        self.open_ports_list = [] # To store open ports from the scan

        # Attempt to load retro fonts if available (may require font installation)
        # This is a best-effort; CustomTkinter will fall back to defaults if not found.
        try:
            ctk.CTkFont(family="Press Start 2P")
            ctk.CTkFont(family="VT323")
        except Exception:
            print("Retro fonts (Press Start 2P, VT323) not found. Using default fonts.")


    def update_results_display(self, message, message_type="info"):
        """Appends a message to the results textbox with appropriate color."""
        self.results_textbox.configure(state="normal") # Enable writing
        # Define text colors for different message types
        color_tag = "info_tag"
        if message_type == "open":
            color_tag = "open_tag"
            self.results_textbox.tag_config("open_tag", foreground=self.ACCENT_COLOR_TEAL)
        elif message_type == "closed":
            color_tag = "closed_tag"
            self.results_textbox.tag_config("closed_tag", foreground=self.TEXT_COLOR) # Default text color for closed
        elif message_type == "error":
            color_tag = "error_tag"
            self.results_textbox.tag_config("error_tag", foreground=self.ACCENT_COLOR_PINK)
        else: # info
             self.results_textbox.tag_config("info_tag", foreground=self.TEXT_COLOR)


        self.results_textbox.insert("end", message + "\n", color_tag)
        self.results_textbox.see("end") # Scroll to the end
        self.results_textbox.configure(state="disabled") # Make read-only again

    def show_message(self, title, message, icon="info"):
        """Displays a CTkMessagebox."""
        # icon can be "info", "warning", "error", "check", "question"
        CTkMessagebox(title=title, message=message, icon=icon, option_1="OK", button_color=self.ACCENT_COLOR_PINK, button_hover_color=self.ACCENT_COLOR_TEAL)


    def scan_ports_logic(self, ip_to_scan, ports_to_scan):
        """The actual scanning logic to be run in a thread."""
        self.open_ports_list.clear()
        self.after(0, lambda: self.results_textbox.configure(state="normal"))
        self.after(0, lambda: self.results_textbox.delete("1.0", "end")) # Clear previous results
        self.after(0, lambda: self.results_textbox.configure(state="disabled"))
        self.after(0, lambda: self.update_results_display(f"Starting scan on {ip_to_scan} for {len(ports_to_scan)} port(s)...", "info"))
        self.after(0, lambda: self.progress_bar.pack(pady=(5,10), padx=20, fill="x")) # Show progress bar
        self.after(0, lambda: self.progress_bar.set(0))


        total_ports = len(ports_to_scan)
        scanned_count = 0

        active_threads = []
        max_threads = 50 # Limit concurrent scanning threads

        for port in ports_to_scan:
            # Basic threading approach for I/O bound tasks like port scanning
            # More advanced would use an asyncio event loop if CustomTkinter supported it directly,
            # or a thread pool executor.
            while threading.active_count() > max_threads + 1: # +1 for main thread
                # Simple way to wait for some threads to finish if too many are active
                # This is a basic form of concurrency limiting
                ctk.CTk.update_idletasks(self) # Keep GUI responsive
                ctk.CTk.update(self)
                socket.timeout(0.05) # Small sleep

            thread = threading.Thread(target=scan_port_worker, args=(ip_to_scan, port, self.open_ports_list, self))
            active_threads.append(thread)
            thread.start()

            scanned_count += 1
            progress = scanned_count / total_ports
            self.after(0, lambda p=progress: self.progress_bar.set(p)) # Update progress bar

        # Wait for all threads to complete
        for thread in active_threads:
            thread.join() # Wait for each thread to finish

        self.after(0, lambda: self.scan_button.configure(state="normal", text="Scan Ports")) # Re-enable button
        self.after(0, lambda: self.progress_bar.pack_forget()) # Hide progress bar

        if not self.open_ports_list:
            self.after(0, lambda: self.update_results_display(f"\nScan complete. No open ports found in the specified range on {ip_to_scan}.", "info"))
        else:
            self.after(0, lambda: self.update_results_display(f"\nScan complete for {ip_to_scan}. Found {len(self.open_ports_list)} open port(s).", "info"))
            # The individual open port messages are already printed by scan_port_worker

        # Optionally show a summary messagebox
        # self.after(0, lambda: self.show_message("Scan Finished", f"Scan completed for {ip_to_scan}.\nFound {len(self.open_ports_list)} open port(s)."))


    def start_scan_thread(self):
        ip_to_scan = self.ip_entry.get().strip()
        port_str = self.port_entry.get().strip()

        if not ip_add_pattern.search(ip_to_scan):
            self.show_message("Error", "Invalid IP Address format.", icon="cancel")
            return

        ports_to_scan = parse_ports(port_str)
        if ports_to_scan is None:
            self.show_message("Error", "Invalid Port Range format or values.\nUse e.g., 1-100 or 22,80,443", icon="cancel")
            return
        if not ports_to_scan:
            self.show_message("Info", "No ports specified to scan.", icon="info")
            return

        self.scan_button.configure(state="disabled", text="Scanning...")
        self.results_textbox.configure(state="normal")
        self.results_textbox.delete("1.0", "end") # Clear previous results
        self.results_textbox.configure(state="disabled")

        # Run the scanning logic in a separate thread to keep the GUI responsive
        scan_thread = threading.Thread(target=self.scan_ports_logic, args=(ip_to_scan, ports_to_scan), daemon=True)
        scan_thread.start()


if __name__ == "__main__":
    app = PortScannerApp()
    app.mainloop()
