#!/usr/bin/env python3
import socket
import re
import customtkinter as ctk
import threading
from CTkMessagebox import CTkMessagebox
import nmap

ip_add_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")

def parse_ports(port_str):
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
                        return None
                except ValueError:
                    return None
            else:
                return None
        else:
            try:
                port = int(segment)
                if 0 <= port <= 65535:
                    ports_to_scan.add(port)
                else:
                    return None
            except ValueError:
                return None
    return sorted(list(ports_to_scan))

class PortScannerApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Retro Port Scanner")
        self.geometry("700x750")
        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("blue")

        self.BG_COLOR = "#1A1A2E"
        self.CONTAINER_COLOR = "#2A2A4E"
        self.TEXT_COLOR = "#E0F2E9"
        self.ACCENT_COLOR_PINK = "#FF007F"
        self.ACCENT_COLOR_TEAL = "#00F0B5"

        self.configure(fg_color=self.BG_COLOR)

        self.container_frame = ctk.CTkFrame(self, fg_color=self.CONTAINER_COLOR, border_color=self.ACCENT_COLOR_PINK, border_width=3, corner_radius=15)
        self.container_frame.pack(padx=20, pady=20, fill="both", expand=True)

        self.title_label = ctk.CTkLabel(self.container_frame, text="PORT SCANNER",
                                        font=ctk.CTkFont(family="Press Start 2P", size=24, weight="bold"),
                                        text_color=self.ACCENT_COLOR_TEAL)
        self.title_label.pack(pady=(15, 20))

        self.ip_label = ctk.CTkLabel(self.container_frame, text="Target IP Address:", text_color=self.ACCENT_COLOR_TEAL, font=("VT323", 18))
        self.ip_label.pack(pady=(10,2), anchor="w", padx=20)
        self.ip_entry = ctk.CTkEntry(self.container_frame, placeholder_text="e.g., 192.168.1.1", width=300, height=35,
                                     fg_color=self.BG_COLOR, text_color=self.TEXT_COLOR,
                                     border_color=(self.ACCENT_COLOR_PINK, self.ACCENT_COLOR_TEAL), # Pink normal, Teal on focus
                                     border_width=2,
                                     font=("VT323", 16))
        self.ip_entry.pack(pady=(0,15), padx=20, fill="x")

        self.port_label = ctk.CTkLabel(self.container_frame, text="Port Range / List:", text_color=self.ACCENT_COLOR_TEAL, font=("VT323", 18))
        self.port_label.pack(pady=(5,2), anchor="w", padx=20)
        self.port_entry = ctk.CTkEntry(self.container_frame, placeholder_text="e.g., 1-1024 or 22,80,443", width=300, height=35,
                                       fg_color=self.BG_COLOR, text_color=self.TEXT_COLOR,
                                       border_color=(self.ACCENT_COLOR_PINK, self.ACCENT_COLOR_TEAL), # Pink normal, Teal on focus
                                       border_width=2,
                                       font=("VT323", 16))
        self.port_entry.pack(pady=(0,20), padx=20, fill="x")

        self.scan_button = ctk.CTkButton(self.container_frame, text="Scan Ports & Services", command=self.start_port_scan_thread,
                                         font=ctk.CTkFont(family="Press Start 2P", size=14),
                                         fg_color=self.ACCENT_COLOR_PINK, text_color=self.BG_COLOR,
                                         hover_color=self.ACCENT_COLOR_TEAL, height=40)
        self.scan_button.pack(pady=(10,5), padx=20, fill="x")

        self.os_scan_button = ctk.CTkButton(self.container_frame, text="Detect OS", command=self.start_os_detection_thread,
                                            font=ctk.CTkFont(family="Press Start 2P", size=14),
                                            fg_color=self.ACCENT_COLOR_PINK, # Changed: Pink by default
                                            text_color=self.BG_COLOR,
                                            hover_color=self.ACCENT_COLOR_TEAL, # Changed: Teal on hover
                                            height=40)
        self.os_scan_button.pack(pady=(5,10), padx=20, fill="x")
        
        self.progress_bar = ctk.CTkProgressBar(self.container_frame, orientation="horizontal", progress_color=self.ACCENT_COLOR_TEAL)
        self.progress_bar.set(0)

        self.results_label = ctk.CTkLabel(self.container_frame, text="Scan Results:", text_color=self.ACCENT_COLOR_TEAL, font=("VT323", 18))
        self.results_label.pack(pady=(15,5), anchor="w", padx=20)
        self.results_textbox = ctk.CTkTextbox(self.container_frame, width=300, height=250, activate_scrollbars=True,
                                              fg_color=self.BG_COLOR, text_color=self.TEXT_COLOR,
                                              border_color=self.ACCENT_COLOR_TEAL, border_width=2,
                                              font=("VT323", 14), wrap="word")
        self.results_textbox.pack(pady=(0,15), padx=20, fill="both", expand=True)
        self.results_textbox.configure(state="disabled")

        self.open_ports_list = []
        
        try:
            ctk.CTkFont(family="Press Start 2P")
            ctk.CTkFont(family="VT323")
        except Exception:
            pass

    def update_results_display(self, message, message_type="info"):
        self.results_textbox.configure(state="normal")
        color_tag = message_type + "_tag"
        
        if message_type == "open":
            self.results_textbox.tag_config(color_tag, foreground=self.ACCENT_COLOR_TEAL)
        elif message_type == "error":
            self.results_textbox.tag_config(color_tag, foreground=self.ACCENT_COLOR_PINK)
        elif message_type == "info_strong":
            self.results_textbox.tag_config(color_tag, foreground=self.ACCENT_COLOR_TEAL, font=("VT323", 14, "bold"))
        else:
             self.results_textbox.tag_config(color_tag, foreground=self.TEXT_COLOR)

        self.results_textbox.insert("end", message + "\n", color_tag)
        self.results_textbox.see("end")
        self.results_textbox.configure(state="disabled")

    def show_message(self, title, message, icon="info"):
        CTkMessagebox(title=title, message=message, icon=icon, option_1="OK", button_color=self.ACCENT_COLOR_PINK, button_hover_color=self.ACCENT_COLOR_TEAL)

    def get_service_info(self, ip_to_scan, port):
        nm = nmap.PortScanner()
        try:
            nm.scan(ip_to_scan, arguments=f'-p {port} -sV -T4 --script banner')
            if ip_to_scan in nm.all_hosts() and 'tcp' in nm[ip_to_scan] and port in nm[ip_to_scan]['tcp']:
                port_info = nm[ip_to_scan]['tcp'][port]
                service_name = port_info.get('name', 'unknown')
                product = port_info.get('product', '')
                version = port_info.get('version', '')
                extrainfo = port_info.get('extrainfo', '')
                banner = port_info.get('script', {}).get('banner', '')

                details = f"Service: {service_name}"
                if product: details += f" | Product: {product}"
                if version: details += f" | Version: {version}"
                if extrainfo: details += f" | Extra: {extrainfo}"
                if banner:
                    banner_clean = banner.strip().replace('\n', ' ').replace('\r', '')
                    details += f" | Banner: {banner_clean[:150]}"
                return details.strip()
            return "No specific service/version info"
        except nmap.nmap.PortScannerError:
            return "Nmap service scan error (is Nmap installed and in PATH?)"
        except Exception:
            return "Error fetching service details"

    def scan_port_worker(self, ip_address, port, app_instance):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                s.connect((ip_address, port))
                service_details = self.get_service_info(ip_address, port)
                
                app_instance.after(0, lambda p=port: app_instance.open_ports_list.append(p))
                app_instance.after(0, lambda p=port: app_instance.update_results_display(f"Port {p} is open", "open"))
                if service_details:
                    app_instance.after(0, lambda sd=service_details: app_instance.update_results_display(f"  ∟ {sd}", "info"))
        except (socket.timeout, socket.error):
            pass
        except Exception as e:
            app_instance.after(0, lambda p=port, err=e: app_instance.update_results_display(f"Error on port {p}: {err}", "error"))

    def port_scan_logic(self, ip_to_scan, ports_to_scan):
        self.open_ports_list.clear()
        self.after(0, lambda: self.results_textbox.configure(state="normal"))
        self.after(0, lambda: self.results_textbox.delete("1.0", "end"))
        self.after(0, lambda: self.results_textbox.configure(state="disabled"))
        self.after(0, lambda: self.update_results_display(f"Starting Port & Service scan on {ip_to_scan} for {len(ports_to_scan)} port(s)...", "info"))
        
        self.after(0, lambda: self.progress_bar.pack(pady=(5,10), padx=20, fill="x"))
        self.after(0, lambda: self.progress_bar.set(0))

        active_threads = []
        max_threads = 10 
        total_ports_to_scan_count = len(ports_to_scan)
        scanned_count = 0

        for port in ports_to_scan:
            while threading.active_count() > max_threads +1 :
                self.update() 
                socket.timeout(0.01) 

            thread = threading.Thread(target=self.scan_port_worker, args=(ip_to_scan, port, self), daemon=True)
            active_threads.append(thread)
            thread.start()
            
            scanned_count += 1
            if total_ports_to_scan_count > 0:
                progress = scanned_count / total_ports_to_scan_count
                self.after(0, lambda p=progress: self.progress_bar.set(p))
        
        for thread in active_threads:
            thread.join()

        self.after(0, lambda: self.scan_button.configure(state="normal", text="Scan Ports & Services"))
        self.after(0, lambda: self.os_scan_button.configure(state="normal"))
        self.after(0, lambda: self.progress_bar.pack_forget())

        if not self.open_ports_list:
            self.after(0, lambda: self.update_results_display(f"\nPort & Service scan complete. No open ports detected or services identified.", "info"))
        else:
            self.after(0, lambda: self.update_results_display(f"\nPort & Service scan complete for {ip_to_scan}. Found {len(self.open_ports_list)} potentially open port(s) with details above.", "info"))

    def start_port_scan_thread(self):
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
            self.show_message("Info", "No ports specified for Port & Service scan.", icon="info")
            return

        self.scan_button.configure(state="disabled", text="Scanning Ports...")
        self.os_scan_button.configure(state="disabled")
        self.results_textbox.configure(state="normal")
        self.results_textbox.delete("1.0", "end")
        self.results_textbox.configure(state="disabled")

        scan_thread = threading.Thread(target=self.port_scan_logic, args=(ip_to_scan, ports_to_scan), daemon=True)
        scan_thread.start()

    def os_detection_logic(self, ip_to_scan):
        self.after(0, lambda: self.results_textbox.configure(state="normal"))
        self.after(0, lambda: self.results_textbox.delete("1.0", "end")) 
        self.after(0, lambda: self.update_results_display(f"Starting OS Detection for {ip_to_scan}...", "info"))
        self.after(0, lambda: self.update_results_display("Note: Accurate OS detection often requires admin/root privileges.", "info"))
        self.after(0, lambda: self.results_textbox.configure(state="disabled"))
        
        self.after(0, lambda: self.progress_bar.pack(pady=(5,10), padx=20, fill="x"))
        self.after(0, lambda: self.progress_bar.configure(mode="indeterminate"))
        self.after(0, lambda: self.progress_bar.start())

        os_info_str = "OS: Detection failed or no match."
        try:
            nm_os = nmap.PortScanner()
            nm_os.scan(ip_to_scan, arguments='-O -T4 --version-intensity 0') 
            
            if ip_to_scan in nm_os.all_hosts():
                host_info = nm_os[ip_to_scan]
                if 'osmatch' in host_info and host_info['osmatch']:
                    os_match = host_info['osmatch'][0]
                    os_info_str = f"OS Guess: {os_match['name']} (Accuracy: {os_match['accuracy']}%)"
                    if 'osclass' in os_match and os_match['osclass']:
                        for osc in os_match['osclass']:
                             os_info_str += f"\n  ∟ Type: {osc.get('type', 'N/A')}, Vendor: {osc.get('vendor', 'N/A')}, Family: {osc.get('osfamily', 'N/A')}, Gen: {osc.get('osgen', 'N/A')}"
                             if 'cpe' in osc and osc['cpe']:
                                 os_info_str += f" (CPE: {', '.join(osc['cpe'])})"
                elif 'osclass' in host_info and host_info['osclass']:
                    os_class = host_info['osclass'][0]
                    os_info_str = f"OS Class: Type: {os_class.get('type', '')}, Vendor: {os_class.get('vendor', '')}, Family: {os_class.get('osfamily','')}, Gen: {os_class.get('osgen','')}"
                    if 'accuracy' in os_class: os_info_str += f" (Accuracy: {os_class['accuracy']}%)"
                else:
                    os_info_str = "OS: No accurate match found. Nmap might need open/closed ports or admin privileges."
            else:
                os_info_str = f"OS: Host {ip_to_scan} not found in Nmap scan results."

            self.after(0, lambda: self.update_results_display(f"\n--- OS Detection Results for {ip_to_scan} ---", "info_strong"))
            self.after(0, lambda: self.update_results_display(os_info_str, "info"))

        except nmap.nmap.PortScannerError as e:
            err_msg = str(e)
            if "root privileges" in err_msg.lower() or "administrator privileges" in err_msg.lower():
                self.after(0, lambda: self.update_results_display(f"OS Detection Nmap Error: Nmap requires root/administrator privileges for -O scan. Please try running the application as admin/root.", "error"))
            else:
                self.after(0, lambda: self.update_results_display(f"OS Detection Nmap error: {err_msg[:150]}", "error"))
        except Exception as e:
            self.after(0, lambda: self.update_results_display(f"OS Detection general error: {str(e)[:150]}", "error"))
        finally:
            self.after(0, lambda: self.scan_button.configure(state="normal"))
            self.after(0, lambda: self.os_scan_button.configure(state="normal", text="Detect OS"))
            self.after(0, lambda: self.progress_bar.stop())
            self.after(0, lambda: self.progress_bar.pack_forget())
            self.after(0, lambda: self.progress_bar.configure(mode="determinate"))


    def start_os_detection_thread(self):
        ip_to_scan = self.ip_entry.get().strip()

        if not ip_add_pattern.search(ip_to_scan):
            self.show_message("Error", "Invalid IP Address format for OS Detection.", icon="cancel")
            return

        self.os_scan_button.configure(state="disabled", text="Detecting OS...")
        self.scan_button.configure(state="disabled") 
        
        self.results_textbox.configure(state="normal")
        self.results_textbox.delete("1.0", "end") 
        self.results_textbox.configure(state="disabled")

        os_scan_thread = threading.Thread(target=self.os_detection_logic, args=(ip_to_scan,), daemon=True)
        os_scan_thread.start()

if __name__ == "__main__":
    app = PortScannerApp()
    app.mainloop()
