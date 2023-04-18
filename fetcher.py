import tkinter as tk
import vtscan
MP=''
# define the tkinter window
root = tk.Tk()
root.geometry('600x400')
root.title("VirusTotal Scan Result")

# define the tkinter frames
top_frame = tk.Frame(root, width=600, height=100, bg='white')
top_frame.pack(side=tk.TOP)

mid_frame = tk.Frame(root, width=600, height=200, bg='lightgray')
mid_frame.pack(side=tk.TOP)

bottom_frame = tk.Frame(root, width=600, height=100, bg='white')
bottom_frame.pack(side=tk.BOTTOM)

# define the tkinter labels and text boxes
file_path_label = tk.Label(top_frame, text="File Path: ")
file_path_label.grid(row=0, column=0, padx=10, pady=10)

file_path_text = tk.Entry(top_frame, width=50)
file_path_text.grid(row=0, column=1, padx=10, pady=10)
file_path_text.insert(tk.END, MP)

status_label = tk.Label(top_frame, text="Scan Status: ")
status_label.grid(row=1, column=0, padx=10, pady=10)

status_text = tk.Entry(top_frame, width=50)
status_text.grid(row=1, column=1, padx=10, pady=10)

malicious_label = tk.Label(mid_frame, text="Malicious Engines: ")
malicious_label.grid(row=0, column=0, padx=10, pady=10)

malicious_text = tk.Text(mid_frame, width=80, height=8)
malicious_text.grid(row=1, column=0, padx=10, pady=10)

# define the tkinter functions
def scan_file():
    global MP
    MP = file_path_text.get()
    vtscan.run(MP)
    status_text.insert(tk.END, "Scan Complete!")
    malicious_text.insert(tk.END, "Malicious Engines: \n")
    malicious_text.insert(tk.END, "Engine Name\tVersion\tCategory\tResult\tMethod\tUpdate\n")

    for k in results:
        if results[k].get("category") == "malicious":
            engine_name = results[k].get("engine_name")
            engine_version = results[k].get("engine_version")
            category = results[k].get("category")
            result = results[k].get("result")
            method = results[k].get("method")
            engine_update = results[k].get("engine_update")
            malicious_text.insert(tk.END, "{}\t{}\t{}\t{}\t{}\t{}\n".format(engine_name, engine_version, category, result, method, engine_update))

# define the tkinter buttons
scan_button = tk.Button(bottom_frame, text="Scan File", command=scan_file)
scan_button.pack(side=tk.LEFT, padx=10, pady=10)

exit_button = tk.Button(bottom_frame, text="Exit", command=root.destroy)
exit_button.pack(side=tk.RIGHT, padx=10, pady=10)

# run the tkinter window
root.mainloop()
