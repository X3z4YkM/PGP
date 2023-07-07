import tkinter as tk

# Create the main Tkinter window
root = tk.Tk()
root.title("Custom Title Bar")
root.geometry("400x300")
root.configure(bg='#212121')  # Set background color to dark gray

# Disable default title bar
root.overrideredirect(True)

# Create custom frame for title bar
frame_title = tk.Frame(root, bg='#2e7d32', height=30)
frame_title.pack(fill='x')

# Add widgets to the custom title bar
label_title = tk.Label(frame_title, text="Custom Title Bar", fg='white', bg='#2e7d32')
label_title.pack(side='left', padx=10)

button_minimize = tk.Button(frame_title, text="-", fg='white', bg='#2e7d32')
button_minimize.pack(side='right')

button_maximize = tk.Button(frame_title, text="□", fg='white', bg='#2e7d32')
button_maximize.pack(side='right')

button_close = tk.Button(frame_title, text="X", fg='white', bg='#2e7d32', command=root.destroy)
button_close.pack(side='right')

# Create content frame
frame_content = tk.Frame(root, bg='white')
frame_content.pack(fill='both', expand=True)

# Add content widgets to the content frame
label_content = tk.Label(frame_content, text="Hello, World!", font=('Arial', 16), padx=20, pady=20)
label_content.pack()

root.mainloop()