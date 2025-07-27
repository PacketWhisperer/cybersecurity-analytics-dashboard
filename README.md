# Cybersecurity Analytics Dashboard 🛡️📊

This project analyzes Linux authentication log files (`auth.log`) to identify failed SSH login attempts. 
It visualizes suspicious login behavior using a clean, interactive HTML dashboard powered by Chart.js.

---

## 🔍 Features

- Parses log files to extract failed SSH login attempts
- Counts how many times each IP address failed to log in
- Flags suspicious IPs with multiple failed attempts
- Visualizes data using an interactive bar chart
- Includes a summary table for quick analysis

---

## 🧠 What I Learned

- How to read and process real-world system log files
- Detecting brute-force login attempts using pattern matching
- Python scripting for log analysis using RegEx
- Data formatting and exporting as JSON
- Building a browser-based dashboard with HTML + Chart.js

---

## 🛠️ Technologies Used

- Python (log parsing & JSON export)
- RegEx (IP extraction)
- HTML, CSS (dashboard layout)
- Chart.js (interactive chart visualization)
- JavaScript (data binding and rendering)

---

## 🚀 How to Run

1. Run the Python script to generate `failed_login_data.json`
2. Open `dashboard.html` in your browser
3. Explore the chart and table to see suspicious IP activity

---

## 📁 Files Included

- `sample_auth.log` – Sample Linux authentication log
- `log_parser.py` – Python script to analyze the logs
- `failed_login_data.json` – Output data from parser
- `dashboard.html` – Interactive dashboard visualization

---

## 📄 License

MIT – Free for personal and educational use.


