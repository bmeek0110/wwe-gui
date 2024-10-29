import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
import hashlib
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

class PredictionApp:
    def __init__(self, master):
        self.master = master
        self.master.title("WWE Premium Live Event Prediction App")
        self.master.geometry("600x600")
        self.master.configure(bg="#34495e")

        # Database connection
        self.create_db()
        
        self.current_user = None

        # Create UI
        self.create_login_frame()
        self.create_prediction_frame()
        
    def create_db(self):
        """Create the SQLite database and users table."""
        conn = sqlite3.connect('predictions.db')
        cursor = conn.cursor()

        # Create users table if it doesn't exist
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        );
        ''')

        # Create predictions table if it doesn't exist
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS predictions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            event TEXT,
            match1 TEXT,
            match2 TEXT,
            match3 TEXT,
            match4 TEXT,
            outcome1 TEXT,
            outcome2 TEXT,
            outcome3 TEXT,
            outcome4 TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        );
        ''')
        
        conn.commit()
        conn.close()

    def create_login_frame(self):
        """Create the login frame."""
        self.login_frame = ttk.Frame(self.master, padding="10", relief="groove", borderwidth=2)
        self.login_frame.pack(pady=20)

        self.username_label = ttk.Label(self.login_frame, text="Username:", background="#34495e", foreground="white")
        self.username_label.grid(row=0, column=0, padx=5, sticky="e")
        self.username_entry = ttk.Entry(self.login_frame)
        self.username_entry.grid(row=0, column=1, padx=5)

        self.password_label = ttk.Label(self.login_frame, text="Password:", background="#34495e", foreground="white")
        self.password_label.grid(row=1, column=0, padx=5, sticky="e")
        self.password_entry = ttk.Entry(self.login_frame, show='*')
        self.password_entry.grid(row=1, column=1, padx=5)

        self.register_button = ttk.Button(self.login_frame, text="Register", command=self.register_user, style='TButton')
        self.register_button.grid(row=2, column=0, padx=5, pady=5)

        self.login_button = ttk.Button(self.login_frame, text="Login", command=self.login_user, style='TButton')
        self.login_button.grid(row=2, column=1, padx=5, pady=5)

    def create_prediction_frame(self):
        """Create the prediction frame."""
        self.match_frame = ttk.Frame(self.master, padding="10", relief="groove", borderwidth=2)
        self.match_frame.pack(pady=20)

        self.event_var = tk.StringVar(value="Select an Event")
        self.event_label = ttk.Label(self.match_frame, text="Select Event:", background="#34495e", foreground="white")
        self.event_label.grid(row=0, column=0, padx=5, sticky="e")

        self.event_dropdown = ttk.Combobox(self.match_frame, textvariable=self.event_var, state="readonly")
        self.event_dropdown['values'] = ("WrestleMania", "Royal Rumble", "Survivor Series")
        self.event_dropdown.grid(row=0, column=1, padx=5)
        self.event_dropdown.bind("<<ComboboxSelected>>", self.load_matches)

        self.matches = {f"Match {i + 1}": tk.StringVar() for i in range(4)}
        for i in range(4):
            ttk.Label(self.match_frame, text=f"Match {i + 1} Prediction:", background="#34495e", foreground="white").grid(row=i + 1, column=0, padx=5, sticky="e")
            ttk.Entry(self.match_frame, textvariable=self.matches[f"Match {i + 1}"]).grid(row=i + 1, column=1, padx=5)

        self.submit_button = ttk.Button(self.match_frame, text="Submit Predictions", command=self.submit_predictions, style='TButton')
        self.submit_button.grid(row=5, column=0, columnspan=2, pady=5)

        self.results_button = ttk.Button(self.match_frame, text="View Results", command=self.view_results, style='TButton')
        self.results_button.grid(row=6, column=0, columnspan=2, pady=5)

        self.visualize_button = ttk.Button(self.match_frame, text="Visualize Accuracy", command=self.visualize_accuracy, style='TButton')
        self.visualize_button.grid(row=7, column=0, columnspan=2, pady=5)

        self.visualize_per_match_button = ttk.Button(self.match_frame, text="Visualize Predictions per Match", command=self.visualize_predictions_per_match, style='TButton')
        self.visualize_per_match_button.grid(row=8, column=0, columnspan=2, pady=5)

    def load_matches(self, event):
        """Load matches based on the selected event."""
        selected_event = self.event_var.get()
        matches = []

        if selected_event == "WrestleMania":
            matches = ["John Cena vs. The Rock", "Becky Lynch vs. Charlotte Flair", "Roman Reigns vs. Seth Rollins", "AJ Styles vs. Randy Orton"]
        elif selected_event == "Royal Rumble":
            matches = ["Men's Royal Rumble", "Women's Royal Rumble", "Daniel Bryan vs. The Fiend", "Finn Balor vs. Edge"]
        elif selected_event == "Survivor Series":
            matches = ["Team Raw vs. Team SmackDown", "The Miz vs. Otis", "Asuka vs. Sasha Banks", "Drew McIntyre vs. Roman Reigns"]

        for i, match in enumerate(matches):
            self.matches[f"Match {i + 1}"].set(match)

    def register_user(self):
        """Register a new user."""
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter a username and password.")
            return
        
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        conn = sqlite3.connect('predictions.db')
        cursor = conn.cursor()
        try:
            cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
            conn.commit()
            messagebox.showinfo("Success", "Registration successful!")
        except sqlite3.IntegrityError:
            messagebox.showerror("Error", "Username already exists.")
        finally:
            conn.close()

    def login_user(self):
        """Log in an existing user."""
        username = self.username_entry.get()
        password = self.password_entry.get()

        if not username or not password:
            messagebox.showerror("Error", "Please enter a username and password.")
            return
        
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        conn = sqlite3.connect('predictions.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, hashed_password))
        user = cursor.fetchone()
        conn.close()

        if user:
            self.current_user = user[0]  # Store user ID
            messagebox.showinfo("Success", "Login successful!")
        else:
            messagebox.showerror("Error", "Invalid username or password.")

    def submit_predictions(self):
        """Submit the user's predictions."""
        if self.current_user is None:
            messagebox.showerror("Error", "You must log in to submit predictions.")
            return

        event = self.event_var.get()
        predictions = {match: self.matches[match].get() for match in self.matches}
        if any(prediction == "" for prediction in predictions.values()):
            messagebox.showerror("Error", "Please fill in all match predictions.")
            return

        # Simulate outcomes (for demonstration purposes)
        outcomes = {
            "Match 1": "John Cena",  # Placeholder for actual match outcome
            "Match 2": "Becky Lynch",  # Placeholder for actual match outcome
            "Match 3": "Roman Reigns",  # Placeholder for actual match outcome
            "Match 4": "Seth Rollins"  # Placeholder for actual match outcome
        }

        conn = sqlite3.connect('predictions.db')
        cursor = conn.cursor()
        cursor.execute('INSERT INTO predictions (user_id, event, match1, match2, match3, match4, outcome1, outcome2, outcome3, outcome4) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                       (self.current_user, event, predictions["Match 1"], predictions["Match 2"], predictions["Match 3"], predictions["Match 4"],
                        outcomes["Match 1"], outcomes["Match 2"], outcomes["Match 3"], outcomes["Match 4"]))
        conn.commit()
        conn.close()

        messagebox.showinfo("Success", "Predictions submitted successfully!")

    def view_results(self):
        """View all user predictions."""
        if self.current_user is None:
            messagebox.showerror("Error", "You must log in to view your predictions.")
            return
        
        conn = sqlite3.connect('predictions.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM predictions WHERE user_id = ?', (self.current_user,))
        rows = cursor.fetchall()
        conn.close()

        if not rows:
            messagebox.showinfo("Results", "No predictions found.")
            return

        results_window = tk.Toplevel(self.master)
        results_window.title("Your Predictions")
        results_window.geometry("400x400")
        
        for row in rows:
            tk.Label(results_window, text=f"Event: {row[2]}").pack()
            tk.Label(results_window, text=f"Match 1 Prediction: {row[3]} (Outcome: {row[7]})").pack()
            tk.Label(results_window, text=f"Match 2 Prediction: {row[4]} (Outcome: {row[8]})").pack()
            tk.Label(results_window, text=f"Match 3 Prediction: {row[5]} (Outcome: {row[9]})").pack()
            tk.Label(results_window, text=f"Match 4 Prediction: {row[6]} (Outcome: {row[10]})").pack()
            tk.Label(results_window, text="").pack()

    def visualize_accuracy(self):
        """Visualize prediction accuracy."""
        if self.current_user is None:
            messagebox.showerror("Error", "You must log in to visualize your predictions.")
            return

        conn = sqlite3.connect('predictions.db')
        cursor = conn.cursor()
        cursor.execute('SELECT outcome1, outcome2, outcome3, outcome4 FROM predictions WHERE user_id = ?', (self.current_user,))
        rows = cursor.fetchall()
        conn.close()

        if not rows:
            messagebox.showinfo("Results", "No predictions found to visualize.")
            return

        correct_predictions = [0, 0, 0, 0]
        total_predictions = len(rows)

        for row in rows:
            for i in range(4):
                if row[i] == "John Cena":  # Simulate checking against actual outcomes
                    correct_predictions[i] += 1

        accuracy = [cp / total_predictions * 100 for cp in correct_predictions]

        # Plotting the results
        plt.figure(figsize=(6, 4))
        plt.bar(range(1, 5), accuracy, color='blue')
        plt.xlabel('Matches')
        plt.ylabel('Accuracy (%)')
        plt.title('Prediction Accuracy')
        plt.xticks(range(1, 5), ['Match 1', 'Match 2', 'Match 3', 'Match 4'])
        plt.ylim(0, 100)

        plt.show()

    def visualize_predictions_per_match(self):
        """Visualize predictions per match."""
        if self.current_user is None:
            messagebox.showerror("Error", "You must log in to visualize predictions per match.")
            return

        conn = sqlite3.connect('predictions.db')
        cursor = conn.cursor()
        cursor.execute('SELECT match1, match2, match3, match4 FROM predictions WHERE user_id = ?', (self.current_user,))
        rows = cursor.fetchall()
        conn.close()

        if not rows:
            messagebox.showinfo("Results", "No predictions found to visualize.")
            return

        predictions = [[], [], [], []]  # Match 1, Match 2, Match 3, Match 4

        for row in rows:
            for i in range(4):
                predictions[i].append(row[i])

        # Plotting the results
        fig, ax = plt.subplots(figsize=(8, 6))

        for i, pred in enumerate(predictions):
            ax.hist(pred, bins=5, alpha=0.5, label=f'Match {i + 1}')

        ax.set_xlabel('Predictions')
        ax.set_ylabel('Count')
        ax.set_title('Predictions per Match')
        ax.legend()

        plt.show()

if __name__ == "__main__":
    root = tk.Tk()
    app = PredictionApp(root)
    root.mainloop()
