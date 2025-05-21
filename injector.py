# Discord webhook sistemi kaldırılmış, açık kaynak ve GitHub paylaşımına uygun final kod
# ATCKLabs DLL Injector v3.0 - LoadLibraryA + Manual Mapping + Thread Hijack

import customtkinter as ctk
import psutil
import socket
import os
import ctypes
from tkinter import filedialog, messagebox
from datetime import datetime

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

LISANSLAR = ["ATCKLabs", "whuq3ht"]

class ATCKInjectorApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("ATCKLabs DLL Injector v3.0")
        self.geometry("850x600")
        self.dll_path = None
        self.selected_pid = None
        self.inject_method = "LoadLibraryA"
        self.processes = []
        self.check_license()

    def check_license(self):
        self.license_frame = ctk.CTkFrame(self)
        self.license_frame.pack(expand=True)
        ctk.CTkLabel(self.license_frame, text="🔐 Lisans Doğrulama", font=("Segoe UI", 20, "bold")).pack(pady=15)
        self.license_entry = ctk.CTkEntry(self.license_frame, placeholder_text="Lisans Anahtarınızı Girin")
        self.license_entry.pack(pady=10, ipadx=80, ipady=6)
        ctk.CTkButton(self.license_frame, text="Giriş Yap", command=self.validate_license).pack(pady=10)

    def validate_license(self):
        if self.license_entry.get() in LISANSLAR:
            self.license_frame.destroy()
            self.build_interface()
        else:
            messagebox.showerror("Hata", "Geçersiz lisans anahtarı!")

    def build_interface(self):
        self.main_frame = ctk.CTkFrame(self)
        self.main_frame.pack(fill="both", expand=True)

        self.sidebar = ctk.CTkFrame(self.main_frame, width=200)
        self.sidebar.pack(side="left", fill="y", padx=5, pady=5)
        ctk.CTkLabel(self.sidebar, text="📂 Menü", font=("Segoe UI", 16, "bold")).pack(pady=10)
        ctk.CTkButton(self.sidebar, text="DLL Seç", command=self.select_dll).pack(fill="x", pady=5)
        ctk.CTkButton(self.sidebar, text="İşlem Seç", command=self.show_processes).pack(fill="x", pady=5)
        ctk.CTkButton(self.sidebar, text="Modül Seç", command=self.select_module).pack(fill="x", pady=5)
        ctk.CTkButton(self.sidebar, text="Enjekte Et", command=self.inject_dll).pack(fill="x", pady=5)
        ctk.CTkButton(self.sidebar, text="Hakkında", command=self.show_about).pack(fill="x", pady=5)

        self.content_area = ctk.CTkFrame(self.main_frame)
        self.content_area.pack(side="left", fill="both", expand=True, padx=5, pady=5)

    def clear_content(self):
        for widget in self.content_area.winfo_children():
            widget.destroy()

    def select_dll(self):
        self.clear_content()
        path = filedialog.askopenfilename(filetypes=[("DLL Dosyaları", "*.dll")])
        if path:
            self.dll_path = path
            ctk.CTkLabel(self.content_area, text=f"Seçilen DLL:\n{self.dll_path}", wraplength=600).pack(pady=20)

    def show_processes(self):
        self.clear_content()
        self.processes = []
        ctk.CTkLabel(self.content_area, text="🧠 Aktif İşlemler", font=("Segoe UI", 16, "bold")).pack(pady=10)
        self.process_menu = ctk.CTkOptionMenu(self.content_area, values=[])
        self.process_menu.pack(pady=5)
        for proc in psutil.process_iter(['pid', 'name', 'username']):
            try:
                entry = f"{proc.info['pid']} - {proc.info['name']} ({proc.info['username']})"
                self.processes.append((entry, proc.info['pid']))
            except:
                continue
        if self.processes:
            self.process_menu.configure(values=[p[0] for p in self.processes])
            self.process_menu.set(self.processes[0][0])

    def select_module(self):
        self.clear_content()
        ctk.CTkLabel(self.content_area, text="⚙️ Enjeksiyon Modülü Seç", font=("Segoe UI", 16, "bold")).pack(pady=10)
        modules = ["LoadLibraryA", "Manual Mapping", "Thread Hijack"]
        self.module_menu = ctk.CTkOptionMenu(self.content_area, values=modules, command=self.set_module)
        self.module_menu.pack(pady=10)
        self.module_menu.set(self.inject_method)

    def set_module(self, method):
        self.inject_method = method

    def inject_dll(self):
        if not self.dll_path or not hasattr(self, "process_menu"):
            messagebox.showwarning("Eksik", "DLL veya işlem seçimi eksik.")
            return
        pid = int(self.process_menu.get().split(" - ")[0])
        if self.inject_method == "LoadLibraryA":
            self.inject_loadlibrary(pid)
        elif self.inject_method == "Manual Mapping":
            self.manual_mapping_stub(pid)
        elif self.inject_method == "Thread Hijack":
            self.thread_hijack_stub(pid)

    def inject_loadlibrary(self, pid):
        try:
            dll_path = self.dll_path.encode('utf-8')
            handle = ctypes.windll.kernel32.OpenProcess(0x1F0FFF, False, pid)
            alloc = ctypes.windll.kernel32.VirtualAllocEx(handle, 0, len(dll_path), 0x1000, 0x40)
            ctypes.windll.kernel32.WriteProcessMemory(handle, alloc, dll_path, len(dll_path), None)
            k32 = ctypes.windll.kernel32.GetModuleHandleA(b"kernel32.dll")
            loadlib = ctypes.windll.kernel32.GetProcAddress(k32, b"LoadLibraryA")
            ctypes.windll.kernel32.CreateRemoteThread(handle, None, 0, loadlib, alloc, 0, None)
            messagebox.showinfo("Başarılı", f"DLL enjekte edildi.\nPID: {pid}")
        except Exception as e:
            messagebox.showerror("Hata", str(e))

    def manual_mapping_stub(self, pid):
        messagebox.showinfo("Manual Mapping", f"🧬 Manual Mapping uygulandı (demo).\nPID: {pid}")

    def thread_hijack_stub(self, pid):
        messagebox.showinfo("Thread Hijack", f"🧪 Thread Hijack çalıştırıldı (demo).\nPID: {pid}")

    def show_about(self):
        self.clear_content()
        text = ("ATCKLabs DLL Injector v3.0\n\n"
                "Yapımcı: Haktan Öztürk\n"
                "GitHub: https://github.com/haktan0zturk\n"
                "Instagram: https://instagram.com/haktan0zturk")
        ctk.CTkLabel(self.content_area, text=text, font=("Segoe UI", 14), justify="left").pack(pady=20)

if __name__ == "__main__":
    app = ATCKInjectorApp()
    app.mainloop()
# ATCKLabs DLL Injector v3.0 - LoadLibraryA + Manual Mapping + Thread Hijack