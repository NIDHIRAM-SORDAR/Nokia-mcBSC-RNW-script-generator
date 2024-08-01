import tkinter as tk
from tkinter import ttk, filedialog, simpledialog, messagebox
from ttkthemes import ThemedTk
import json

# Initialize variables
BCXUs = {}
ETMEs = {}
ETMAs = 0
omusig_entries = []
trxsig_entries = []
static_route_entries = []

m_plane_ip_omusig = None
subnet_omusig = None

# Function to load configuration
def load_config(bsc_name):
    with open('config.json', 'r') as file:
        config = json.load(file)
    return config.get(bsc_name, {})

# Function to select and load BSC configuration
def select_bsc():
    global BCXUs, ETMEs, ETMAs
    if not bsc_var.get():
        messagebox.showwarning("Warning", "Please select a BSC!", parent=root)
        return
    
    bsc_name = bsc_var.get()

    config = load_config(bsc_name)
    if not config:
        messagebox.showerror("Error", "BSC configuration not found!", parent=root)
        return None

    BCXUs = config.get("BCXUs", {})
    ETMEs = config.get("ETMEs", {})
    ETMAs = config.get("ETMAs", 0)

    # Update the Combobox values
    update_bcxu_combobox()

    messagebox.showinfo("Info", f"{bsc_name} configuration loaded successfully!", parent=root)
    
    # Enable tabs after successful selection
    tab_control.tab(omusig_tab, state="normal")
    tab_control.tab(trxsig_tab, state="normal")
    tab_control.tab(static_route_tab, state="normal")
    generate_button.config(state=tk.NORMAL)
    save_button.config(state=tk.NORMAL)

def update_bcxu_combobox():
    if 'bcxu_menu' in globals():
        bcxu_menu['values'] = list(BCXUs.keys())
        trxsig_bcxu_menu['values'] = list(BCXUs.keys())
        static_route_etme_menu['values'] = list(ETMEs.keys())

def add_omusig_entry():
    global m_plane_ip_omusig, subnet_omusig
    name = name_var.get().upper()
    m_plane_ip = m_plane_ip_var.get()
    subnet = subnet_var.get()
    bcxu = bcxu_var.get()
    tei = tei_var.get()
    omusig_entries.append((name, m_plane_ip, subnet, bcxu, tei))
    omusig_listbox.insert(tk.END, f"{name}, {m_plane_ip}, {subnet}, {bcxu}, {tei}")
    m_plane_ip_omusig = m_plane_ip
    subnet_omusig = subnet

def delete_omusig_entry():
    selected_indices = omusig_listbox.curselection()
    if not selected_indices:
        return
    for index in selected_indices[::-1]:
        omusig_listbox.delete(index)
        del omusig_entries[index]

def get_trx_number(trx_name):
    last_char = trx_name[-1]
    if last_char.isdigit():
        return int(last_char)
    else:
        return ord(last_char) - ord('A') + 10

def add_trxsig_entry():
    trx_name = trx_name_var.get().upper()
    trx_number = get_trx_number(trx_name)
    bcxu = trxsig_bcxu_var.get()
    trxsig_entries.append((trx_name, trx_number, bcxu,))
    trxsig_listbox.insert(tk.END, f"{trx_name}, {trx_number}, {bcxu}")

# Function to set IP & Subnet for TRXSIG
def set_ip_and_subnet():
    global m_plane_ip_omusig, subnet_omusig
    m_plane_ip_omusig = simpledialog.askstring("Input", "Enter M-Plane IP for TRXSIG:", parent=root)
    subnet_omusig = simpledialog.askstring("Input", "Enter Subnet for TRXSIG:", parent=root)
    if not m_plane_ip_omusig or not subnet_omusig:
        messagebox.showwarning("Warning", "Both M-Plane IP and Subnet must be provided!", parent=root)
    else:
        messagebox.showinfo("Info", "M-Plane IP and Subnet set successfully!", parent=root)

# TRXSIG Tab
def delete_trxsig_entry():
    selected_indices = trxsig_listbox.curselection()
    if not selected_indices:
        return
    for index in selected_indices[::-1]:
        trxsig_listbox.delete(index)
        del trxsig_entries[index]

# Static Route Tab
def delete_static_route_entry():
    selected_indices = static_route_listbox.curselection()
    if not selected_indices:
        return
    for index in selected_indices[::-1]:
        static_route_listbox.delete(index)
        del static_route_entries[index]

def add_static_route_entry():
    etme = static_route_etme_var.get()
    network_ip = network_ip_var.get()
    subnet_static = subnet_var_static.get()
    static_route_entries.append((etme, network_ip, subnet_static ))
    static_route_listbox.insert(tk.END, f"{etme}, {network_ip}, {subnet_static}")

def generate_omusig_script(entries):
    script = ""
    for name, m_plane_ip, subnet, bcxu, tei in entries:
        bcxu_number = bcxu[-1]
        script += (
            f"ZOYX:{name}:IUA:S:BCXU,{bcxu_number}:AFAST:1;\n"
            f"ZOYP:IUA:{name}:\"{BCXUs[bcxu]['OMUSIG']}\",,49152:\"{m_plane_ip}\",{subnet},,,49152;\n"
            f"ZDWP:{name}:BCXU,{bcxu_number}:62,{tei}:{name};\n"
            f"ZOYS:IUA:{name}:ACT;\n\n"
        )
    return script

def generate_trxsig_script(entries):
    script = ""
    for trx_name, trx_number, bcxu in entries:
        bcxu_number = bcxu[-1]
        port = 49153 + (trx_number - 1)
        global m_plane_ip_omusig, subnet_omusig
        
        while not m_plane_ip_omusig:
            m_plane_ip_omusig = simpledialog.askstring("Input", "Enter M-Plane IP:", parent=root)
            if not m_plane_ip_omusig:
                messagebox.showwarning("Warning", "M-Plane IP cannot be empty!", parent=root)
        
        while not subnet_omusig:
            subnet_omusig = simpledialog.askstring("Input", "Enter Subnet:", parent=root)
            if not subnet_omusig:
                messagebox.showwarning("Warning", "Subnet cannot be empty!", parent=root)
        
        script += (
            f"ZOYX:{trx_name}:IUA:S:BCXU,{bcxu_number}:AFAST:2;\n"
            f"ZOYP:IUA:{trx_name}:\"{BCXUs[bcxu]['TRXSIG']}\",,{port}:\"{m_plane_ip_omusig}\",{subnet_omusig},,,{port};\n"
            f"ZDWP:{trx_name}:BCXU,{bcxu_number}:0,{trx_number}:{trx_name};\n"
            f"ZOYS:IUA:{trx_name}:ACT;\n\n"
        )
    return script



def generate_static_route_script(entries):
    script = ""
    for etme, network_ip, subnet_static in entries:
        for etma in range(ETMAs):
            script += (
                f"ZQKC:ETMA,{etma}::\"{network_ip}\",{subnet_static}:\"{ETMEs[etme]}\":LOG:;\n"
            )
    return script

def generate_all_scripts():
    omusig_script = generate_omusig_script(omusig_entries)
    trxsig_script = generate_trxsig_script(trxsig_entries)
    static_route_script = generate_static_route_script(static_route_entries)

    all_scripts = omusig_script + "\n" + trxsig_script + "\n" + static_route_script

    script_text.delete(1.0, tk.END)
    script_text.insert(tk.END, all_scripts)

def save_all_scripts():
    omusig_script = generate_omusig_script(omusig_entries)
    trxsig_script = generate_trxsig_script(trxsig_entries)
    static_route_script = generate_static_route_script(static_route_entries)

    all_scripts = omusig_script + "\n" + trxsig_script + "\n" + static_route_script

    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
    if file_path:
        with open(file_path, 'w') as file:
            file.write(all_scripts)

root = ThemedTk(theme="plastik")
root.title("Script Generator")

tab_control = ttk.Notebook(root)
load_bsc = ttk.Frame(tab_control)
omusig_tab = ttk.Frame(tab_control)
trxsig_tab = ttk.Frame(tab_control)
static_route_tab = ttk.Frame(tab_control)

tab_control.add(load_bsc, text='Load BSC_data')
tab_control.add(omusig_tab, text='OMUSIG')
tab_control.add(trxsig_tab, text='TRXSIG')
tab_control.add(static_route_tab, text='Static Route')
tab_control.pack(expand=1, fill='both')

# Initially disable all tabs except the first one
tab_control.tab(omusig_tab, state="disabled")
tab_control.tab(trxsig_tab, state="disabled")
tab_control.tab(static_route_tab, state="disabled")

# Add radio buttons to load_bsc tab
bsc_var = tk.StringVar(value="")

ttk.Radiobutton(load_bsc, text="KHLBSC", value="KHLBSC", variable=bsc_var).grid(row=0, column=0, padx=10, pady=10)
ttk.Radiobutton(load_bsc, text="BARBSC", value="BARBSC", variable=bsc_var).grid(row=0, column=1, padx=10, pady=10)

# Add button to load BSC configuration
ttk.Button(load_bsc, text="Load BSC Configuration", command=select_bsc).grid(row=1, column=0, columnspan=2, padx=10, pady=10)

# OMUSIG Tab
ttk.Label(omusig_tab, text="Name:").grid(row=0, column=0, padx=10, pady=5)
name_var = tk.StringVar()
ttk.Entry(omusig_tab, textvariable=name_var).grid(row=0, column=1, padx=10, pady=5)

ttk.Label(omusig_tab, text="M-Plane IP:").grid(row=1, column=0, padx=10, pady=5)
m_plane_ip_var = tk.StringVar()
ttk.Entry(omusig_tab, textvariable=m_plane_ip_var).grid(row=1, column=1, padx=10, pady=5)

ttk.Label(omusig_tab, text="Subnet:").grid(row=2, column=0, padx=10, pady=5)
subnet_var = tk.StringVar()
ttk.Entry(omusig_tab, textvariable=subnet_var).grid(row=2, column=1, padx=10, pady=5)

ttk.Label(omusig_tab, text="TEI:").grid(row=3, column=0, padx=10, pady=5)
tei_var = tk.StringVar()
ttk.Entry(omusig_tab, textvariable=tei_var).grid(row=3, column=1, padx=10, pady=5)

ttk.Label(omusig_tab, text="BCXU:").grid(row=4, column=0, padx=10, pady=5)
bcxu_var = tk.StringVar()
bcxu_menu = ttk.Combobox(omusig_tab, textvariable=bcxu_var, values=list(BCXUs.keys()))
bcxu_menu.grid(row=4, column=1, padx=10, pady=5)

ttk.Button(omusig_tab, text="Add OMUSIG Entry", command=add_omusig_entry).grid(row=5, column=0, columnspan=2, pady=10)

omusig_listbox_frame = ttk.Frame(omusig_tab)
omusig_listbox_frame.grid(row=6, column=0, columnspan=2, padx=10, pady=5)
omusig_listbox = tk.Listbox(omusig_listbox_frame, height=6, width=50)
omusig_listbox.pack(side=tk.LEFT, fill=tk.BOTH)

omusig_scrollbar = ttk.Scrollbar(omusig_listbox_frame, orient=tk.VERTICAL, command=omusig_listbox.yview)
omusig_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

omusig_listbox.config(yscrollcommand=omusig_scrollbar.set)

ttk.Button(omusig_tab, text="Delete OMUSIG Entry", command=delete_omusig_entry).grid(row=6, column=4, columnspan=2, padx=10, pady=10)

# TRXSIG Tab
ttk.Label(trxsig_tab, text="TRX Name:").grid(row=0, column=0, padx=10, pady=5)
trx_name_var = tk.StringVar()
ttk.Entry(trxsig_tab, textvariable=trx_name_var).grid(row=0, column=1, padx=10, pady=5)

ttk.Label(trxsig_tab, text="BCXU:").grid(row=1, column=0, padx=10, pady=5)
trxsig_bcxu_var = tk.StringVar()
trxsig_bcxu_menu = ttk.Combobox(trxsig_tab, textvariable=trxsig_bcxu_var, values=list(BCXUs.keys()))
trxsig_bcxu_menu.grid(row=1, column=1, padx=10, pady=5)

# Frame to contain the buttons
button_frame = ttk.Frame(trxsig_tab)
button_frame.grid(row=3, column=0, columnspan=2, pady=10)

# Add "Add TRXSIG Entry" button
ttk.Button(button_frame, text="Add TRXSIG Entry", command=add_trxsig_entry).pack(side=tk.LEFT, padx=10)

# Add "Set IP & Subnet" button
ttk.Button(button_frame, text="Set IP & Subnet", command=set_ip_and_subnet).pack(side=tk.LEFT, padx=10)

# TRXSIG Listbox with Vertical Scrollbar
trxsig_listbox_frame = ttk.Frame(trxsig_tab)
trxsig_listbox_frame.grid(row=4, column=0, columnspan=2, padx=10, pady=5)

trxsig_listbox = tk.Listbox(trxsig_listbox_frame, height=6, width=50)
trxsig_listbox.pack(side=tk.LEFT, fill=tk.BOTH)

trxsig_scrollbar = ttk.Scrollbar(trxsig_listbox_frame, orient=tk.VERTICAL, command=trxsig_listbox.yview)
trxsig_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

trxsig_listbox.config(yscrollcommand=trxsig_scrollbar.set)

ttk.Button(trxsig_tab, text="Delete TRXSIG Entry", command=delete_trxsig_entry).grid(row=4, column=4, columnspan=2, padx=10, pady=10)

# Static Route Tab
ttk.Label(static_route_tab, text="ETME:").grid(row=0, column=0, padx=10, pady=5)
static_route_etme_var = tk.StringVar()
static_route_etme_menu = ttk.Combobox(static_route_tab, textvariable=static_route_etme_var, values=list(ETMEs.keys()))
static_route_etme_menu.grid(row=0, column=1, padx=10, pady=5)



ttk.Label(static_route_tab, text="Network IP:").grid(row=1, column=0, padx=10, pady=5)
network_ip_var = tk.StringVar()
ttk.Entry(static_route_tab, textvariable=network_ip_var).grid(row=1, column=1, padx=10, pady=5)

ttk.Label(static_route_tab, text="Subnet:").grid(row=2, column=0, padx=10, pady=5)
subnet_var_static = tk.StringVar()
ttk.Entry(static_route_tab, textvariable=subnet_var_static).grid(row=2, column=1, padx=10, pady=5)

ttk.Button(static_route_tab, text="Add Static Route Entry", command=add_static_route_entry).grid(row=3, column=0, columnspan=2, pady=10)
# Static Route Listbox with Vertical Scrollbar
static_route_listbox_frame = ttk.Frame(static_route_tab)
static_route_listbox_frame.grid(row=4, column=0, columnspan=2, padx=10, pady=5)

static_route_listbox = tk.Listbox(static_route_listbox_frame, height=6, width=50)
static_route_listbox.pack(side=tk.LEFT, fill=tk.BOTH)

static_route_scrollbar = ttk.Scrollbar(static_route_listbox_frame, orient=tk.VERTICAL, command=static_route_listbox.yview)
static_route_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

static_route_listbox.config(yscrollcommand=static_route_scrollbar.set)

ttk.Button(static_route_tab, text="Delete Static Route Entry", command=delete_static_route_entry).grid(row=4, column=4, columnspan=2, padx=10, pady=10)

# Generate and Save All Scripts Buttons
generate_button = ttk.Button(root, text="Generate All Scripts", command=generate_all_scripts, state=tk.DISABLED)
generate_button.pack(pady=10)
save_button = ttk.Button(root, text="Save All Scripts", command=save_all_scripts, state=tk.DISABLED)
save_button.pack(pady=10)

# Script Display with Vertical Scrollbar
script_text_frame = ttk.Frame(root)
script_text_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

script_text = tk.Text(script_text_frame, height=10, wrap=tk.WORD)
script_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

script_scrollbar = ttk.Scrollbar(script_text_frame, orient=tk.VERTICAL, command=script_text.yview)
script_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

script_text.config(yscrollcommand=script_scrollbar.set)


root.mainloop()
