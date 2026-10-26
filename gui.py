import tkinter as tk, time, re, os

LOG = "alerts.log"
root = tk.Tk()
root.title("Wireless IDS")
root.geometry("700x420")

status = tk.Label(root, text="NORMAL", font=("Arial", 36, "bold"),
                  bg="green", fg="white", height=2)
status.pack(fill="x")
rate = tk.Label(root, text="Deauth frames per second: 0", font=("Arial", 16))
rate.pack(pady=6)
box = tk.Text(root, height=12, font=("Courier", 10))
box.pack(fill="both", expand=True, padx=8, pady=8)

pos = os.path.getsize(LOG) if os.path.exists(LOG) else 0
last_alert = 0

def poll():
    global pos, last_alert
    if os.path.exists(LOG):
        if os.path.getsize(LOG) < pos:      # log was cleared
            pos = 0
        with open(LOG) as f:
            f.seek(pos)
            new = f.read()
            pos = f.tell()
        for line in new.splitlines():
            box.insert("end", line + "\n")
            box.see("end")
            m = re.search(r"(\d+) frames/s", line)
            if "[ALERT]" in line and m:
                last_alert = time.time()
                rate.config(text=f"Deauth frames per second: {m.group(1)}")
    if time.time() - last_alert < 2:
        status.config(text="ATTACK!", bg="red")
    else:
        status.config(text="NORMAL", bg="green")
        rate.config(text="Deauth frames per second: 0")
    root.after(500, poll)

poll()
root.mainloop()
