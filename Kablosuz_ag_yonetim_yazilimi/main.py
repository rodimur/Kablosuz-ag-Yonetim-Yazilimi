# main.py
import tkinter as tk
from tkinter import ttk
from scapy.all import ARP, Ether, srp
import psutil


# Ağ Cihazlarını Tespit Etme
def scan_network(ip_range):
    print(f"Scanning network: {ip_range}")

    # ARP isteği oluşturma
    arp_request = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_request

    # Paketi göndermeyi ve cevapları almaya başla
    result = srp(packet, timeout=2, verbose=False)[0]

    # Cevapları işle
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices


# Ağ Durumu İzleme
def get_network_status():
    network_stats = psutil.net_if_stats()
    status = {}
    for interface, stats in network_stats.items():
        status[interface] = {
            'is_up': stats.isup,
            'speed': stats.speed,
            'mtu': stats.mtu,
        }
    return status


# Cihaz Yönetimi
class DeviceManager:
    def __init__(self):
        self.devices = []

    def add_device(self, ip, mac):
        self.devices.append({'ip': ip, 'mac': mac})

    def remove_device(self, ip):
        self.devices = [device for device in self.devices if device['ip'] != ip]

    def list_devices(self):
        return self.devices


# Ağ Güvenliği Yönetimi
class SecurityManager:
    def __init__(self, allowed_devices):
        self.allowed_devices = allowed_devices  # İzin verilen cihazlar

    def check_security(self, detected_devices):
        unauthorized_devices = [
            device for device in detected_devices if device['mac'] not in self.allowed_devices
        ]
        return unauthorized_devices


# Kullanıcı Arayüzü
class NetworkManagementApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Kablosuz Ağ Kontrol Yazılımı")

        self.device_manager = DeviceManager()
        self.allowed_devices = []  # İzin verilen cihazlar
        self.security_manager = SecurityManager(self.allowed_devices)

        # Tarama Arayüzü
        self.label = ttk.Label(root, text="IP Aralığını Girin:")
        self.label.pack(pady=10)

        self.ip_entry = ttk.Entry(root)
        self.ip_entry.pack(pady=10)

        self.scan_button = ttk.Button(root, text="Tarama Başlat", command=self.start_scan)
        self.scan_button.pack(pady=10)

        # Durum İzleme Arayüzü
        self.status_button = ttk.Button(root, text="Ağ Durumunu Göster", command=self.show_network_status)
        self.status_button.pack(pady=10)

        self.result_box = tk.Text(root, width=50, height=20)
        self.result_box.pack(pady=10)

        # Cihaz Yönetimi Arayüzü
        self.device_label = ttk.Label(root, text="Cihaz Ekle (IP ve MAC):")
        self.device_label.pack(pady=10)

        self.device_ip_entry = ttk.Entry(root)
        self.device_ip_entry.pack(pady=5)

        self.device_mac_entry = ttk.Entry(root)
        self.device_mac_entry.pack(pady=5)

        self.add_device_button = ttk.Button(root, text="Cihaz Ekle", command=self.add_device)
        self.add_device_button.pack(pady=10)

        self.remove_device_button = ttk.Button(root, text="Cihazı Kaldır", command=self.remove_device)
        self.remove_device_button.pack(pady=10)

        self.list_devices_button = ttk.Button(root, text="Cihazları Listele", command=self.list_devices)
        self.list_devices_button.pack(pady=10)

    def start_scan(self):
        ip_range = self.ip_entry.get()
        self.result_box.delete(1.0, tk.END)  # Önceki sonuçları temizle
        devices = scan_network(ip_range)
        for device in devices:
            self.result_box.insert(tk.END, f"IP: {device['ip']}, MAC: {device['mac']}\n")
            self.device_manager.add_device(device['ip'], device['mac'])  # Cihazı ekle

    def show_network_status(self):
        status = get_network_status()
        self.result_box.delete(1.0, tk.END)  # Önceki sonuçları temizle
        for interface, info in status.items():
            self.result_box.insert(tk.END,
                                   f"Arayüz: {interface}, Durum: {'Açık' if info['is_up'] else 'Kapalı'}, Hız: {info['speed']} Mbps, MTU: {info['mtu']}\n")

    def add_device(self):
        ip = self.device_ip_entry.get()
        mac = self.device_mac_entry.get()
        self.device_manager.add_device(ip, mac)
        self.device_ip_entry.delete(0, tk.END)
        self.device_mac_entry.delete(0, tk.END)
        self.result_box.insert(tk.END, f"Cihaz Eklendi: IP: {ip}, MAC: {mac}\n")

    def remove_device(self):
        ip = self.device_ip_entry.get()
        self.device_manager.remove_device(ip)
        self.device_ip_entry.delete(0, tk.END)
        self.result_box.insert(tk.END, f"Cihaz Kaldırıldı: IP: {ip}\n")

    def list_devices(self):
        devices = self.device_manager.list_devices()
        self.result_box.delete(1.0, tk.END)  # Önceki sonuçları temizle
        for device in devices:
            self.result_box.insert(tk.END, f"IP: {device['ip']}, MAC: {device['mac']}\n")


if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkManagementApp(root)
    root.mainloop()
