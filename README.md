# Fest[Studio] 🎉

Fest[Studio] is a full-stack web application designed for hosting events and building real-time chat communities, powered by Flask and Supabase. It provides a platform for users to create, manage, and promote events with customizable event pages. Additionally, it features a robust community chat system with features like public/private groups, real-time messaging, polls, and user profiles.

## Features

-   **Event Hosting**: Users can create and host their own events, providing details like name, venue, agenda, and registration links.
-   **Customizable Event Pages**: Hosted events get a dedicated, beautifully designed landing page with parallax scrolling effects.
-   **Live Event Preview**: See a live preview of your event page as you fill out the hosting form.
-   **Community Chat**:
    -   Create and join public or private communities.
    -   Real-time messaging with typing indicators.
    -   Reply to specific messages.
    -   Create and vote on polls within communities.
    -   View active members in a community.
-   **User Authentication**: Secure user registration and login managed by Supabase Auth.
-   **User Profiles**: Customizable user profiles with descriptions and avatars.
-   **Supabase Integration**: Uses Supabase for the database (PostgreSQL), authentication, and file storage.

## Tech Stack

-   **Backend**: Flask, Flask-SocketIO
-   **Frontend**: HTML, Tailwind CSS, JavaScript, jQuery
-   **Database & Backend-as-a-Service**: Supabase (PostgreSQL, Auth, Storage)
-   **Real-time Engine**: `python-socketio` with `eventlet`
-   **Security**: Flask-WTF for CSRF protection, Flask-Limiter for rate limiting.

## Local Setup and Installation

### Prerequisites

-   Python 3.10+
-   `pip` for package management
-   A Supabase account with a project created.

### Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/Fest--studio.git
    cd Fest--studio
    ```

2.  **Create and activate a virtual environment:**
    ```bash
    # On Windows
    python -m venv venv
    .\venv\Scripts\activate

    # On macOS/Linux
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  **Install the required packages:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Set up your Supabase environment:**
    -   In your Supabase project dashboard, go to the **SQL Editor**.
    -   Run the entire `update_schema.sql` script to set up your database tables and functions.
    -   Go to **Project Settings** > **API**.
    -   Find your **Project URL** and **anon (public) key**.

5.  **Create an environment file:**
    -   Create a file named `.env` in the root of the project.
    -   Add your Supabase credentials to it like this:
        ```
        SUPABASE_URL=YOUR_SUPABASE_PROJECT_URL
        SUPABASE_KEY=YOUR_SUPABASE_ANON_KEY
        ```

6.  **Run the application:**
    ```bash
    python app.py
    ```

7.  **Access the application:**
    Open your web browser and go to `http://127.0.0.1:5000`.

## Project Structure

```
.
├── app.py              # Main Flask application file, routes, and logic
├── chat_routes.py      # Blueprint for all community chat-related routes and SocketIO events
├── requirements.txt    # Project dependencies
├── static/             # CSS, JavaScript, images, and user uploads
│   ├── css/
│   ├── images/
│   └── uploads/
├── templates/          # HTML templates for the main application
│   ├── chat/           # HTML templates for the chat blueprint
│   └── ...
└── instance/           # Automatically created folder for the SQLite database
```

---
# Fest--studio
