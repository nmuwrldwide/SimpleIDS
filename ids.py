import threading
import tkinter as tk
from tkinter.scrolledtext import ScrolledText
from scapy.all import sniff, IP, TCP
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import os
import win32evtlog

stop_flags = {
    "scan": False,
    "file": False,
    "log": False
}

class IDSApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Simple IDS - GUI")
        self.root.geometry("700x500")

        self.text_area = ScrolledText(root, wrap=tk.WORD, height=25, width=80)
        self.text_area.pack(pady=10)

        btn_frame = tk.Frame(root)
        btn_frame.pack()

        tk.Button(btn_frame, text="Start Port Scan Detection", command=self.start_port_scan).grid(row=0, column=0, padx=5)
        tk.Button(btn_frame, text="Start File Monitor", command=self.start_file_monitor).grid(row=0, column=1, padx=5)
        tk.Button(btn_frame, text="Start Log Monitor", command=self.start_log_monitor).grid(row=0, column=2, padx=5)

        tk.Button(btn_frame, text="Stop All", command=self.stop_all).grid(row=1, column=1, pady=10)

    def log(self, message):
        self.text_area.insert(tk.END, message + '\n')
        self.text_area.see(tk.END)

    def start_port_scan(self):
        stop_flags["scan"] = False
        thread = threading.Thread(target=self.port_scan_detector)
        thread.daemon = True
        thread.start()
        self.log("[+] Port scan detector started...")

    def port_scan_detector(self):
        from collections import defaultdict
        scan_counts = defaultdict(int)

        def detect(packet):
            if stop_flags["scan"]:
                return
            if packet.haslayer(TCP) and packet[TCP].flags == 'S':
                ip = packet[IP].src
                scan_counts[ip] += 1
                self.log(f"[!] SYN from {ip} (count: {scan_counts[ip]})")
                if scan_counts[ip] > 10:
                    self.log(f"[!!!] Possible Port Scan from {ip}")

        sniff(filter="tcp", prn=detect, store=0, stop_filter=lambda x: stop_flags["scan"])

    def start_file_monitor(self):
        stop_flags["file"] = False
        thread = threading.Thread(target=self.file_monitor)
        thread.daemon = True
        thread.start()
        self.log("[+] File monitor started...")

    def file_monitor(self):
        class WatchHandler(FileSystemEventHandler):
            def on_modified(self, event):
                self.log(f"[!] Modified: {event.src_path}")

            def on_created(self, event):
                self.log(f"[+] Created: {event.src_path}")

            def on_deleted(self, event):
                self.log(f"[-] Deleted: {event.src_path}")

            def log(self, msg):
                if not stop_flags["file"]:
                    self_outer.log(msg)

        path = "/etc" if os.name != 'nt' else "C:\\Windows"
        event_handler = WatchHandler()
        observer = Observer()
        observer.schedule(event_handler, path=path, recursive=True)
        observer.start()
        self_outer = self

        try:
            while not stop_flags["file"]:
                time.sleep(1)
        finally:
            observer.stop()
            observer.join()

    def start_log_monitor(self):
        stop_flags["log"] = False
        thread = threading.Thread(target=self.log_monitor)
        thread.daemon = True
        thread.start()
        self.log("[+] SSH log monitor started...")

    def log_monitor(self):
        server = 'localhost'
        log_type = 'Security'

        query = "*[System[EventID=4625]]"

        try:
            while not stop_flags["log"]:
                events = win32evtlog.EvtQuery(log_type, win32evtlog.EvtQueryChannelPath, query)
                event = win32evtlog.EvtNext(events, 1)
                if event:
                    event_data = win32evtlog.EvtRender(event[0], win32evtlog.EvtRenderEventXml)
                    if event_data:
                        self.log(f"[!] Failed login attempt detected: {event_data}")
                time.sleep(1)
        except Exception as e:
            self.log(f"[!] Error while reading event logs: {e}")

    def stop_all(self):
        for key in stop_flags:
            stop_flags[key] = True
        self.log("[X] All monitoring stopped.")

if __name__ == "__main__":
    root = tk.Tk()
    app = IDSApp(root)
    root.mainloop()
