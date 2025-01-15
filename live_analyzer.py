import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog
from scapy.all import sniff, rdpcap
from packet_analysis import analyze_packet
import threading

class PacketAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Analyzer")
        self.root.geometry("1000x800")

        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        self.packet_analysis_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.packet_analysis_tab, text="Paket Analizi")

        self.build_packet_analysis_tab()

    def build_packet_analysis_tab(self):
        ttk.Label(self.packet_analysis_tab, text="Paket Analiz Arayüzü", font=("Helvetica", 16)).pack(pady=10)

        control_frame = ttk.Frame(self.packet_analysis_tab)
        control_frame.pack(pady=5)

        self.start_button = ttk.Button(control_frame, text="Başlat", command=self.start_sniffing)
        self.start_button.grid(row=0, column=0, padx=5)

        self.stop_button = ttk.Button(control_frame, text="Durdur", command=self.stop_sniffing, state="disabled")
        self.stop_button.grid(row=0, column=1, padx=5)

        self.browse_button = ttk.Button(control_frame, text="Gözat", command=self.browse_file)
        self.browse_button.grid(row=0, column=2, padx=5)

        self.analyze_button = ttk.Button(control_frame, text="Manuel Analiz", command=self.analyze_manual_packet)
        self.analyze_button.grid(row=0, column=3, padx=5)

        self.file_entry = ttk.Entry(control_frame, width=50)
        self.file_entry.grid(row=1, column=0, columnspan=4, pady=5)

        self.status_label = ttk.Label(self.packet_analysis_tab, text="Durum: Bekliyor", font=("Helvetica", 12))
        self.status_label.pack(pady=10)

        self.tree = ttk.Treeview(self.packet_analysis_tab, columns=("time", "summary", "result"), show="headings", height=15)
        self.tree.pack(fill=tk.BOTH, expand=True, pady=10)

        self.tree.heading("time", text="Zaman")
        self.tree.heading("summary", text="Özet")
        self.tree.heading("result", text="Sonuç")

        self.tree.column("time", width=150)
        self.tree.column("summary", width=600)
        self.tree.column("result", width=150)

        ttk.Label(self.packet_analysis_tab, text="Paket Detayları", font=("Helvetica", 12)).pack(pady=5)
        self.details_box = scrolledtext.ScrolledText(self.packet_analysis_tab, width=120, height=10, state="disabled")
        self.details_box.pack(pady=10)

        self.tree.bind("<<TreeviewSelect>>", self.show_packet_details)

        self.sniffing = False
        self.packets = []

    def start_sniffing(self):
        self.sniffing = True
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.status_label.config(text="Durum: İzleme Başladı")
        threading.Thread(target=self.sniffer, daemon=True).start()

    def stop_sniffing(self):
        self.sniffing = False
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")
        self.status_label.config(text="Durum: İzleme Durduruldu")

    def sniffer(self):
        sniff(filter="ip", prn=self.add_packet_to_tree, stop_filter=lambda x: not self.sniffing)

    def add_packet_to_tree(self, packet):
        analyze_packet(packet, self.tree, self.details_box, self.packets)

    def analyze_manual_packet(self):
        file_path = self.file_entry.get()
        if not file_path:
            self.details_box.config(state="normal")
            self.details_box.insert(tk.END, "Hata: Lütfen bir dosya seçin.\n")
            self.details_box.yview(tk.END)
            self.details_box.config(state="disabled")
            return

        try:
            packets = rdpcap(file_path)
            for packet in packets:
                self.add_packet_to_tree(packet)
        except Exception as e:
            self.details_box.config(state="normal")
            self.details_box.insert(tk.END, f"Hata: {e}\n")
            self.details_box.yview(tk.END)
            self.details_box.config(state="disabled")

    def browse_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("PCAP Files", "*.pcap"), ("All Files", "*.*")])
        if file_path:
            self.file_entry.delete(0, tk.END)
            self.file_entry.insert(0, file_path)

    def show_packet_details(self, event):
        selected_item = self.tree.selection()
        if not selected_item:
            return

        index = self.tree.index(selected_item[0])
        packet = self.packets[index]

        self.details_box.config(state="normal")
        self.details_box.delete("1.0", tk.END)
        self.details_box.insert(tk.END, packet.show(dump=True))
        self.details_box.config(state="disabled")


if __name__ == "__main__":
    root = tk.Tk()
    app = PacketAnalyzerApp(root)
    root.mainloop()
