# Fest[Studio] 🎉

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-Framework-black.svg)](https://flask.palletsprojects.com/)
[![Supabase](https://img.shields.io/badge/Supabase-Backend-green.svg)](https://supabase.io/)
[![Socket.IO](https://img.shields.io/badge/Real--Time-Socket.IO-orange.svg)](https://socket.io/)
[![TailwindCSS](https://img.shields.io/badge/Frontend-TailwindCSS-38B2AC.svg)](https://tailwindcss.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Deployment: Railway](https://img.shields.io/badge/Deploy-Railway-purple.svg)](https://railway.app/)

Fest[Studio] is a full-stack web application for hosting events and building real-time chat communities, powered by Flask and Supabase. It allows users to create customizable event pages and engage through a feature-rich chat system.

🔗 **Live Demo:** **https://web-production-aa741.up.railway.app**

---

## ✨ Features

### 🎪 Event Hosting

- **Create & Manage Events**: Host events with details like title, venue, agenda, schedule, and images.
- **Custom Event Pages**: Each event gets a dedicated, modern landing page with beautiful parallax scrolling effects.
- **Live Preview**: See a live preview of your event page as you fill out the hosting form.

### 💬 Real-Time Community Chat

- **Public & Private Groups**: Create and join communities based on your interests.
- **Live Messaging**: Real-time messaging powered by Flask-SocketIO, complete with typing indicators.
- **Message Threads**: Reply to specific messages to keep conversations organized.
- **Interactive Polls**: Create and vote on polls within your community.
- **Member List**: See who is currently active in a community.

### 👤 User Authentication & Profiles

- **Secure Auth**: User registration and login are securely managed by Supabase Auth.
- **Custom Profiles**: Personalize your profile with an avatar and description.

### 🛢 Supabase Integration

- **Database**: PostgreSQL for reliable and scalable data storage.
- **Authentication**: Manages user identity and session security.
- **File Storage**: Handles uploads for user avatars and event images.

---

## 🛠 Tech Stack

| Category            | Technologies                                         |
| ------------------- | ---------------------------------------------------- |
| **Backend**         | Flask, Flask-SocketIO, `python-socketio`, `eventlet` |
| **Frontend**        | HTML, Tailwind CSS, JavaScript, jQuery               |
| **Database & BaaS** | Supabase (PostgreSQL, Auth, Storage)                 |
| **Security**        | Flask-WTF (CSRF Protection), Flask-Limiter           |
| **Deployment**      | Railway                                              |

---

## ⚙️ Local Setup and Installation

### Prerequisites

- Python 3.10+
- `pip` for package management
- A Supabase account with a project created.

### Installation Guide

1.  **Clone the Repository**

    ```bash
    git clone https://github.com/satyam2006-cmd/Fest--studio.git
    cd Fest--studio
    ```

2.  **Create and Activate a Virtual Environment**
    - On **Windows**:
      ```bash
      python -m venv venv
      .\venv\Scripts\activate
      ```
    - On **macOS/Linux**:
      ```bash
      python3 -m venv venv
      source venv/bin/activate
      ```

3.  **Install Dependencies**

    ```bash
    pip install -r requirements.txt
    ```

4.  **Configure Supabase**
    - In your Supabase project dashboard, go to the **SQL Editor**.
    - Run the entire `update_schema.sql` script to set up your database tables and functions.
    - Go to **Project Settings** > **API**.
    - Copy your **Project URL** and **anon (public) key**.

5.  **Create an Environment File**
    - Create a file named `.env` in the root of the project.
    - Add your Supabase credentials to it:
      ```
      SUPABASE_URL=YOUR_SUPABASE_PROJECT_URL
      SUPABASE_KEY=YOUR_SUPABASE_ANON_KEY
      ```

6.  **Run the Application**
    ```bash
    python app.py
    ```
    You can now access the application in your browser at: **http://127.0.0.1:5000**

---

## 📁 Project Structure

```
.
├── app.py              # Main Flask application, routes, and logic
├── chat_routes.py      # Blueprint for chat routes and SocketIO events
├── requirements.txt    # Project dependencies
├── update_schema.sql   # SQL script for Supabase database schema
├── static/             # Static files (CSS, JS, images)
│   ├── css/
│   ├── images/
│   └── uploads/        # User-uploaded files
├── templates/          # Jinja2 HTML templates
│   ├── chat/           # HTML templates for the chat system
│   └── ...
└── .env.example        # Example environment file
```

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! Feel free to check the issues page or submit a pull request.

## 📄 License

This project is licensed under the MIT License. See the `LICENSE` file for more details.
