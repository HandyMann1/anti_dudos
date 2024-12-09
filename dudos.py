import scapy.all as scapy
import tkinter as tk
from tkinter import ttk
import threading
import subprocess

ip_statistics = {}
suspicious_set = set()
blocked_set = set()
monitoring_active = False

login_attempts = {}
spam_count = {}


def handle_packet(packet):
    global ip_statistics, suspicious_set
    if packet.haslayer(scapy.IP):
        source_ip = packet[scapy.IP].src
        packet_size = len(packet)
        print(f"Captured packet from {source_ip} of size {packet_size}")

        if source_ip not in ip_statistics:
            ip_statistics[source_ip] = 0
        ip_statistics[source_ip] += packet_size

        suspicion_reasons = check_suspicion(source_ip)

        if suspicion_reasons and source_ip not in suspicious_set:
            suspicious_set.add(source_ip)
            update_suspicious_ips_table(source_ip, ", ".join(suspicion_reasons))

        if source_ip not in blocked_set:
            port = packet[scapy.IP].sport
            add_to_all_ips_table(source_ip, port, packet_size)


def check_suspicion(ip):
    reasons = []

    if ip_statistics.get(ip, 0) > 1024:
        reasons.append("packet size is too big")

    if is_sending_spam(ip):
        reasons.append("Sending spam emails")

    if is_hosting_malware(ip):
        reasons.append("Hosting malware")

    if is_brute_force_attempt(ip):
        reasons.append("High rate of login attempts")


    return reasons


def is_sending_spam(ip):
    return spam_count.get(ip, 0) > 100

def is_hosting_malware(ip):
    malicious_ips = {"192.192.1.192", "203.0.203.3"}
    return ip in malicious_ips


def is_brute_force_attempt(ip):
    if ip not in login_attempts:
        login_attempts[ip] = 0

    login_attempts[ip] += 1

    return login_attempts[ip] > 5




def begin_monitoring():
    global monitoring_active
    reset_tables()

    if not monitoring_active:
        monitoring_active = True
        monitor_thread = threading.Thread(target=sniff_traffic)
        monitor_thread.daemon = True
        monitor_thread.start()


def sniff_traffic():
    scapy.sniff(prn=handle_packet, store=False)


def end_monitoring():
    global monitoring_active
    monitoring_active = False


def add_to_blocked_ips(ip):
    global blocked_set
    if ip not in blocked_set:
        blocked_set.add(ip)
        update_blocked_ips_table(ip)
        apply_iptables_block(ip)
        remove_from_suspicious_ips_table(ip)


def remove_from_blocked_ips(ip):
    global blocked_set
    if ip in blocked_set:
        blocked_set.remove(ip)
        apply_iptables_unblock(ip)

def add_to_all_ips_table(ip, port, size):
    all_ips_tree.insert("", "end", values=(ip, port, size))

def unblock_selected_ip():
    selected_item = blocked_ips_tree.selection()
    if selected_item:
        ip_to_unblock = blocked_ips_tree.item(selected_item)['values'][0]
        remove_from_blocked_ips(ip_to_unblock)
        delete_from_blocked_ips_table(ip_to_unblock)
    else:
        print("No IP selected for unblocking.")


def delete_from_blocked_ips_table(ip):
    for item in blocked_ips_tree.get_children():
        if blocked_ips_tree.item(item)['values'][0] == ip:
            blocked_ips_tree.delete(item)
            break


def apply_iptables_block(ip):
    try:
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Failed to block IP address {ip}: {e}")


def apply_iptables_unblock(ip):
    try:
        subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Failed to unblock IP address {ip}: {e}")


def reset_tables():
    suspicious_ips_tree.delete(*suspicious_ips_tree.get_children())
    all_ips_tree.delete(*all_ips_tree.get_children())

def update_suspicious_ips_table(ip, reason):
    suspicious_ips_tree.insert("", "end", values=(ip, reason))


def remove_from_suspicious_ips_table(ip):
    for item in suspicious_ips_tree.get_children():
        if suspicious_ips_tree.item(item)['values'][0] == ip:
            suspicious_ips_tree.delete(item)
            break


def update_blocked_ips_table(ip):
    blocked_ips_tree.insert("", "end", values=(ip,))



app_window = tk.Tk()
app_window.title("Network Traffic Monitor")
app_window.geometry("1300x500")
app_window.configure(bg="#F0F0F0")

incoming_ips_frame = tk.Frame(app_window, bg="#FFFFFF", bd=2, relief="groove")
incoming_ips_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

suspicious_frame = tk.Frame(app_window, bg="#FFFFFF", bd=2, relief="groove")
suspicious_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")

blocked_frame = tk.Frame(app_window, bg="#FFFFFF", bd=2, relief="groove")
blocked_frame.grid(row=0, column=2, padx=10, pady=10, sticky="nsew")

app_window.grid_rowconfigure(0, weight=1)
app_window.grid_columnconfigure(0, weight=1)
app_window.grid_columnconfigure(1, weight=1)
app_window.grid_columnconfigure(2, weight=1)

tk.Label(incoming_ips_frame, text="Incoming IPs", bg="#FFFFFF", fg="#333333", font=("Helvetica", 16)).pack(side="top",
                                                                                                           pady=(5, 0))

all_ips_tree = ttk.Treeview(incoming_ips_frame, columns=("IP", "Port", "Size"), show="headings")
all_ips_tree.heading("IP", text="IP Address")
all_ips_tree.heading("Port", text="Port")
all_ips_tree.heading("Size", text="Size")

style = ttk.Style()
style.configure("Treeview", background="#FAFAFA", foreground="#333333", fieldbackground="#FAFAFA")

all_ips_tree.pack(side="top", fill="both", expand=True)

tk.Button(incoming_ips_frame, text="Start Monitoring", command=begin_monitoring,
          bg="#5CB85C", fg="white", font=("Helvetica", 12), relief="flat").pack(fill="x", padx=5, pady=(5, 2))

tk.Button(incoming_ips_frame, text="Stop Monitoring", command=end_monitoring,
          bg="#D9534F", fg="white", font=("Helvetica", 12), relief="groove").pack(fill="x", padx=5)

tk.Label(suspicious_frame, text="Suspicious IPs", bg="#FFFFFF", fg="#333333", font=("Helvetica", 16)).pack(side="top",
                                                                                                           pady=(5, 0))

suspicious_ips_tree = ttk.Treeview(suspicious_frame, columns=("IP", "Reason"), show="headings")
suspicious_ips_tree.heading("IP", text="IP Address")
suspicious_ips_tree.heading("Reason", text="Reason")

suspicious_ips_tree.pack(side="top", fill="both", expand=True)

tk.Button(suspicious_frame, text="Block IP",
          command=lambda: add_to_blocked_ips(suspicious_ips_tree.item(suspicious_ips_tree.selection())['values'][0]),
          bg="#5CB85C", fg="white", font=("Helvetica", 12), relief="flat").pack(fill="x", padx=5)

# Blocked IPs Table
tk.Label(blocked_frame, text="Blocked IPs", bg="#FFFFFF", fg="#333333", font=("Helvetica", 16)).pack(side="top",
                                                                                                     pady=(5, 0))

blocked_ips_tree = ttk.Treeview(blocked_frame, columns=("IP",), show="headings")
blocked_ips_tree.heading("IP", text="IP Address")

blocked_ips_tree.pack(side="top", fill="both", expand=True)

tk.Button(blocked_frame, text="Unblock IP",
          command=lambda: unblock_selected_ip(),
          bg="#D9534F", fg="white", font=("Helvetica", 12), relief="flat").pack(fill="x", padx=5)


def on_enter(event):
    event.widget['bg'] = '#4CAF50' if event.widget['text'] == 'Start Monitoring' else '#C9302C'


def on_leave(event):
    event.widget['bg'] = '#5CB85C' if event.widget['text'] == 'Start Monitoring' else '#D9534F'


for widget in incoming_ips_frame.winfo_children():
    if isinstance(widget, tk.Button):
        widget.bind("<Enter>", on_enter)
        widget.bind("<Leave>", on_leave)

for widget in suspicious_frame.winfo_children():
    if isinstance(widget, tk.Button):
        widget.bind("<Enter>", on_enter)
        widget.bind("<Leave>", on_leave)

for widget in blocked_frame.winfo_children():
    if isinstance(widget, tk.Button):
        widget.bind("<Enter>", on_enter)
        widget.bind("<Leave>", on_leave)

app_window.mainloop()