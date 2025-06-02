import os
import subprocess
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, Toplevel, PhotoImage
from PIL import Image, ImageTk
from concurrent.futures import ThreadPoolExecutor

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

class AppState:
    def __init__(self):
        self.info_window = None

app_state = AppState()

def obtener_redes_wifi():
    try:
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = subprocess.SW_HIDE

        output_profiles = subprocess.check_output(
            ['netsh', 'wlan', 'show', 'profiles'],
            startupinfo=si,
            encoding='utf-8',
            errors='ignore'
        )

        profiles = output_profiles.split('\n')
        network_names = []

        for line in profiles:
            if "Perfil de todos los usuarios" in line:
                network_name = line.split(":")[1].strip()
                network_names.append(network_name)

        def obtener_clave(name):
            try:
                output_key = subprocess.check_output(
                    ['netsh', 'wlan', 'show', 'profile', f'name={name}', 'key=clear'],
                    startupinfo=si,
                    encoding='utf-8',
                    errors='ignore'
                )
                for line in output_key.split('\n'):
                    if "Contenido de la clave" in line:
                        key = line.split(":")[1].strip()
                        return f"{name} = {key}\n"
                return f"{name} = No disponible\n"
            except subprocess.CalledProcessError:
                return f"{name} = Error al obtener el password\n"

        with ThreadPoolExecutor() as executor:
            wifi_info = ''.join(executor.map(obtener_clave, network_names))

        return wifi_info

    except Exception as e:
        messagebox.showerror("Error", f"Error al obtener las redes Wi-Fi: {str(e)}")
        return "Error al obtener redes Wi-Fi.\n"

def mostrar_redes():
    wifi_info = obtener_redes_wifi()
    if wifi_info:
        text_box.config(state=tk.NORMAL)
        text_box.delete('1.0', tk.END)
        text_box.insert(tk.END, wifi_info)
        text_box.config(state=tk.DISABLED)

def guardar_archivo():
    ruta = filedialog.asksaveasfilename(
        defaultextension=".txt",
        initialfile="Reporte WiFi.txt",
        filetypes=[("Text files", "*.txt")]
    )
    if ruta:
        wifi_info = obtener_redes_wifi()
        with open(ruta, 'w', encoding='utf-8') as file:
            file.write("Nombres de Red y Contraseñas:\n\n")
            file.write(wifi_info)

def centrar_ventana(ventana, ancho, alto):
    ventana.update_idletasks()
    pantalla_ancho = ventana.winfo_screenwidth()
    pantalla_alto = ventana.winfo_screenheight()
    x = (pantalla_ancho // 2) - (ancho // 2)
    y = (pantalla_alto // 2) - (alto // 2)
    ventana.geometry(f'{ancho}x{alto}+{x}+{y}')

def mostrar_informacion():
    if app_state.info_window is None or not app_state.info_window.winfo_exists():
        app_state.info_window = Toplevel(ventana)
        app_state.info_window.withdraw()
        app_state.info_window.title("Información")
        app_state.info_window.config(bg='#023047')
        app_state.info_window.resizable(0, 0)
        app_state.info_window.iconbitmap(os.path.join(BASE_DIR, 'images/logo.ico'))

        ancho = 370
        alto = 198
        centrar_ventana(app_state.info_window, ancho, alto)
        app_state.info_window.deiconify()

        frame_info = tk.Frame(app_state.info_window, bg='#023047')
        frame_info.pack(pady=10, padx=10)

        img = PhotoImage(file=os.path.join(BASE_DIR, 'images/robot.png'))
        img_label = tk.Label(frame_info, image=img, bg='#023047')
        img_label.image = img
        img_label.grid(row=0, column=0, padx=10, pady=5, rowspan=3)

        message = tk.Label(
            frame_info,
            text="Desarrollado por: \nPablo Téllez A.\n \nTarija - 2024.",
            justify="center",
            bg='#023047', fg='white',
            font=("Comic Sans MS", 14, "bold"),
            anchor="center"
        )
        message.grid(row=0, column=1, padx=8, pady=10, sticky="n")

        close_button = crear_boton("Cerrar", app_state.info_window.destroy, frame_info)
        close_button.grid(row=2, column=1, padx=10, pady=(0, 5), sticky="n")

# Crear ventana principal oculta para evitar parpadeo
ventana = tk.Tk()
ventana.withdraw()

SCREEN_WIDTH = ventana.winfo_screenwidth()
SCREEN_HEIGHT = ventana.winfo_screenheight()
WINDOW_WIDTH = 410
WINDOW_HEIGHT = 260
POSITION_TOP = int(SCREEN_HEIGHT / 2 - WINDOW_HEIGHT / 2)
POSITION_RIGHT = int(SCREEN_WIDTH / 2 - WINDOW_WIDTH / 2)
ventana.geometry(f'{WINDOW_WIDTH}x{WINDOW_HEIGHT}+{POSITION_RIGHT}+{POSITION_TOP}')
ventana.config(bg='#023047')
ventana.title("WiFi Scanner")
ventana.iconbitmap(os.path.join(BASE_DIR, 'images/logo.ico'))
ventana.resizable(0, 0)

text_box_frame = tk.Frame(ventana, bg='#023047', padx=10, pady=5, bd=2, relief="flat")
text_box_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(5, 0))

text_box = scrolledtext.ScrolledText(
    text_box_frame, width=48, height=8, font=("Comic Sans MS", 10),
    wrap=tk.WORD, relief=tk.FLAT, borderwidth=10
)
text_box.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)
text_box.config(borderwidth=0, highlightthickness=0, wrap=tk.WORD, state=tk.DISABLED)

separator = tk.Frame(ventana, height=2, bd=0, relief="solid", bg="#219ebc")
separator.pack(fill=tk.X, padx=10, pady=5)

button_frame = tk.Frame(ventana, bg='#023047')
button_frame.pack(pady=(0, 10))

button_image = Image.open(os.path.join(BASE_DIR, 'images/boton.png'))
button_image = button_image.resize((100, 40), Image.LANCZOS)
button_image = ImageTk.PhotoImage(button_image)

def crear_boton(texto, comando, parent=button_frame):
    boton = tk.Button(
        parent, image=button_image, text=texto, compound="center", fg='white',
        font=("Comic Sans MS", 10, "bold"), bd=0, bg='#033077', highlightthickness=0,
        relief="flat", activebackground='#023047', activeforeground='#ffdd57'
    )
    boton.config(command=comando)
    boton.bind("<Enter>", lambda event: boton.config(fg='#ffdd57'))
    boton.bind("<Leave>", lambda event: boton.config(fg='white'))
    return boton

btn_scan = crear_boton("SCAN", mostrar_redes)
btn_save = crear_boton("SAVE", guardar_archivo)
btn_info = crear_boton("INFO", mostrar_informacion)

btn_scan.grid(row=0, column=0, padx=5)
btn_save.grid(row=0, column=1, padx=5)
btn_info.grid(row=0, column=2, padx=5)

# Mostrar ventana ya configurada sin parpadeo
ventana.deiconify()
ventana.mainloop()
