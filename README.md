Advanced Network Sniffer
<img width="875" height="671" alt="image" src="https://github.com/user-attachments/assets/aa4cde95-a503-422d-89fb-0e95f3288b93" />

Overview
This project is a sophisticated, real-time network packet sniffer with a modern web-based user interface. It allows users to capture, analyze, and visualize network traffic flowing through their system. Built with a Python backend for packet capture (leveraging Scapy) and a dynamic React frontend for interactive data display, this tool provides insights into network communication, protocol structures, and data flow.

It moves beyond basic command-line sniffing by offering a user-friendly interface with filtering, searching, and detailed packet inspection capabilities, making network analysis more accessible and intuitive.

Key Features
Real-time Packet Capture: Captures live network traffic using Scapy in the Python backend.

Interactive Web Interface: A responsive React frontend provides a clear and intuitive dashboard for monitoring packets.

Detailed Packet Inspection: Click on any packet to view a comprehensive breakdown of its layers (Ethernet, IP, TCP, UDP, ICMP) and a full payload representation (in hexadecimal and decoded text).

Advanced Filtering: Filter packets by specific criteria including Source IP, Destination IP, Protocol (TCP, UDP, ICMP), Source Port, and Destination Port.

Global Search: A powerful search bar allows you to find specific text or values across all displayed packet fields.

Clear Data Functionality: Easily clear all captured packets from the display.

Cross-Platform (Backend): The Python backend is designed to run on Windows, Linux, and macOS (requires appropriate permissions).

Modern UI/UX: Built with Tailwind CSS for a clean, responsive, and visually appealing design.

Technologies Used
Frontend
React.js: A JavaScript library for building user interfaces.

Vite: A fast build tool that provides a rapid development environment for React.

Tailwind CSS: A utility-first CSS framework for rapid UI development and responsive design.

npm: Node Package Manager for managing frontend dependencies.

Backend
Python 3: The core programming language for the backend logic.

Scapy: A powerful Python library for packet manipulation (sniffing, crafting, sending, parsing).

Flask: A lightweight Python web framework used to create the API endpoints.

Flask-SocketIO: Enables real-time, bidirectional communication between the Flask backend and the React frontend using WebSockets.

Flask-CORS: Manages Cross-Origin Resource Sharing to allow the frontend to communicate with the backend.

pip: Python's package installer for managing backend dependencies.

How to Run
To get this project up and running on your local machine, follow these steps:

Prerequisites
Node.js & npm: Download and install from nodejs.org.

Python 3: Download and install from python.org.

Npcap (for Windows): Required for Scapy to function on Windows. Download from nmap.org/npcap.

VS Code (Recommended IDE): code.visualstudio.com

Setup Instructions
Clone the Repository (or create folders manually):
If you've downloaded a zip or created folders manually, ensure your project structure looks like this:

network-sniffer-project/
├── frontend/
│   ├── ... (React files)
└── backend/
    ├── app.py
    └── requirements.txt
Backend Setup:

Open a new terminal in VS Code.

Navigate to the backend directory:

Bash

cd network-sniffer-project/backend
Install Python dependencies:

Bash

pip install -r requirements.txt
Run the Flask backend (requires Administrator/root privileges for sniffing):

On Linux/macOS:

Bash

sudo python app.py
(Enter your password when prompted)

On Windows:

Crucially, open VS Code itself as an Administrator (right-click VS Code shortcut -> "Run as administrator").

Then, in the terminal within that Administrator-level VS Code, navigate to backend and run:

Bash

python app.py
You should see output indicating the Flask server is running (e.g., on http://127.0.0.1:5000).

Frontend Setup:

Open a second, separate terminal in VS Code (this one does not need Administrator privileges).

Navigate to the frontend directory:

Bash

cd network-sniffer-project/frontend
Install Node.js dependencies:

Bash

npm install
Start the React development server:

Bash

npm run dev
You should see output indicating the Vite development server is running (e.g., on http://localhost:5173/).

Access the Application:

Open your web browser and navigate to the address provided by the frontend (e.g., http://localhost:5173/).

Once the page loads, click the "Start Sniffing" button. If both backend and frontend are running correctly, you should start seeing real-time network packets displayed in the table!

Future Enhancements
Packet Export/Import: Add functionality to save captured packets to PCAP files and load them for offline analysis.

Traffic Statistics & Visualizations: Implement charts (e.g., using Chart.js or D3.js) to visualize bandwidth usage, top protocols, and most active hosts.

Alerting System: Configure rules to trigger notifications for suspicious network activity (e.g., port scans, high error rates).

Protocol Decoders: Enhance the packet detail view with more in-depth decoding for various application-layer protocols (HTTP, DNS, FTP, etc.).

Network Interface Selection: Allow users to select which network interface to sniff on directly from the frontend.

Authentication & Authorization: For multi-user environments, implement user login and role-based access control.

Dark Mode: Add a toggle for a dark theme.
