# SSO Authentication System

Welcome to the **SSO Authentication System**! This is a robust and secure authentication platform built with Java and Spring Boot. It is designed to handle user management, Single Sign-On (SSO), and secure access using modern standards like JWT (JSON Web Tokens) and OIDC (OpenID Connect).

Whether you are looking to integrate secure login into your apps or manage multiple tenants, this project provides a solid foundation to get started.

---

## 🚀 Key Features
- **Secure User Management:** Sign up, login, and role-based access control.
- **Single Sign-On (SSO):** Support for OIDC and JWT-based SSO integration (e.g., with miniOrange).
- **Multi-Tenancy:** Architecture designed to support multiple organizations or tenants.
- **Database Integration:** Specific schema for handling users, tokens, and audit logs using PostgreSQL.
- **Docker Ready:** Easily containerize the application for consistent deployment.

---

## 🛠️ Prerequisites
Before you begin, please ensure you have the following installed on your machine:
- **Java 17** (Required to run the application)
- **PostgreSQL** (For the database)
- **Docker** (Optional, if you prefer running in a container)

---

## ⚙️ Installation & Setup

Follow these steps to get the project running locally.

### 1. Database Setup
This application uses PostgreSQL. You need to create a database and set up the required tables.

1. Open your PostgreSQL tool (like pgAdmin or the command line).
2. Create a new database named `sso_auth_db`.
3. Run the initialization script provided in the project: `sso_auth_db.sql`.
    - *This script will create necessary tables like `users`, `sso_provider_configs`, and `audit_logs`.*
    - *It also inserts default admin credentials for testing.*

### 2. Configure the Application
We need to tell the application how to connect to your database and secure your tokens.

1. Navigate to `src/main/resources/application.properties`.
2. **Database Connection:** Update the username and password to match your local PostgreSQL credentials:
    ```properties
    spring.datasource.username=postgres
    spring.datasource.password=your_password_here
    ```
3. **Security Keys:** Find the `jwt.secret` property and replace the placeholder with a secure, random string:
    ```properties
    jwt.secret=YOUR_SECURE_RANDOM_SECRET_KEY
    ```

### 3. Build the Project
Open your terminal in the project root directory and run:

**Using Maven Wrapper (Recommended):**
```bash
./mvnw clean install
```

---

## 🏃 Usage
You can run the application either directly on your machine or inside a Docker container.

### Option A: Run Locally
Once the build is complete, start the application with:
```bash
./mvnw spring-boot:run
```
The application will start on port `8080`.

### Option B: Run with Docker
If you prefer Docker, we have a multi-stage Dockerfile ready for you.

**Build the Image:**
```bash
docker build -t sso-auth-system .
```

**Run the Container:**
```bash
docker run -p 8080:8080 sso-auth-system
```

---

## 🌐 Accessing the System
Once the app is running, open your web browser and go to: [http://localhost:8080](http://localhost:8080).

Create an Organization or Tenant and Try the Single Sign-On Authentication Protocols


---

## 🤝 Contributing
We love contributions! If you'd like to help improve the SSO Authentication System, here is how you can get involved:

1. **Fork the Repository:** Click the "Fork" button at the top right of this page.
2. **Create a Branch:** Create a new branch for your feature or bug fix:
    ```bash
    git checkout -b feature/AmazingFeature
    ```
3. **Commit Changes:** Make your changes and commit them:
    ```bash
    git commit -m 'Add some AmazingFeature'
    ```
4. **Push to Branch:** Push your changes to your fork:
    ```bash
    git push origin feature/AmazingFeature
    ```
5. **Open a Pull Request:** Submit a pull request so we can review your changes.

---
