# Flask Product CRUD API
A RESTful Product CRUD API built with **Python, Flask, MongoDB Atlas, and JWT authentication**.
The project includes authentication, role-based authorization, input validation, Swagger/OpenAPI documentation, automated testing, database indexing, logging, security headers, Docker containerization, and cloud deployment.

## 🚀 Live API
**Base URL:**
https://flasapi-python-productcrudbackend.onrender.com
**Swagger API Documentation:**
https://flasapi-python-productcrudbackend.onrender.com/apidocs/

---
## 📌 Project Overview

This project was developed to practice building a production-oriented REST API using Flask.

The API provides:

* User authentication
* JWT access and refresh tokens
* Role-based authorization
* Product CRUD operations
* Pagination
* Filtering
* Searching
* Sorting
* Input validation
* Error handling
* Token revocation
* Database indexing
* Logging
* CORS configuration
* HTTP security headers
* Swagger/OpenAPI documentation
* Pytest automated tests
* Docker containerization
* Cloud deployment using Render

---

## 🛠️ Tech Stack

### Backend

* Python
* Flask
* PyMongo
* REST API

### Database

* MongoDB
* MongoDB Atlas

### Authentication & Security

* JWT
* bcrypt password hashing
* Access tokens
* Refresh tokens
* Token revocation
* Role-based authorization
* CORS
* HTTP security headers
* Environment variables

### API Documentation

* Swagger / OpenAPI
* Flasgger

### Testing

* Pytest

### Deployment

* Docker
* Render
* MongoDB Atlas

### Development Tools

* Git
* GitHub
* Postman

---

## ✨ Features

### 1. User Authentication

Users can log in using their email and password.

Passwords are securely hashed using bcrypt.

Successful login returns:

* Access token
* Refresh token

---

### 2. JWT Authentication

The API uses JSON Web Tokens for authentication.

The access token contains information such as:

* User ID
* User role
* Token type
* JWT ID
* Expiration time

Access tokens are short-lived, while refresh tokens have a longer expiration period.

---

### 3. Refresh Token

When an access token expires, a valid refresh token can be used to generate a new access token.

Refresh tokens are also validated and can be revoked.

---

### 4. Token Revocation / Logout

The API supports logout by revoking JWT tokens.

Revoked tokens are stored separately and checked when accessing protected routes.

This prevents a logged-out token from being reused.

---

### 5. Role-Based Authorization

Different users have different permissions.

For example:

**Admin**

* Create products
* Update products
* Delete products
* View products

**Regular User**

* View products
* Cannot perform admin-only operations

Protected routes use role-based authorization decorators.

---

## 📦 Product CRUD Operations

The API supports complete CRUD operations.

### Create

```http
POST /products
```

### Read

```http
GET /products
```

### Update

```http
PUT /products/<product_id>
```

### Delete

```http
DELETE /products/<product_id>
```

---

## 🔎 Product Search, Filtering & Sorting

The product listing endpoint supports:

### Pagination

```text
?page=1&limit=10
```

The API provides default pagination values and limits the maximum number of records returned per request.

### Category Filtering

```text
?category=electronics
```

### Price Filtering

```text
?min_price=1000&max_price=5000
```

### Search

Products can be searched by name.

```text
?search=watch
```

### Sorting

Products can be sorted by price.

```text
?sort=price_asc
```

---

## 🗄️ Database Indexing

MongoDB indexes were added to improve query performance for frequently searched or filtered fields.

Indexes allow MongoDB to locate matching documents more efficiently instead of scanning the entire collection.

Query execution was also checked using MongoDB query analysis tools such as `IXSCAN`.

---

## 📖 Swagger / OpenAPI Documentation

The API is documented using **Flasgger**.

Swagger provides an interactive interface where API endpoints can be viewed and tested.

**Swagger UI:**

https://flasapi-python-productcrudbackend.onrender.com/apidocs/

The documentation includes API endpoints, parameters, request bodies, authentication requirements, and responses.

---

## 🧪 Testing

Automated API tests were written using **Pytest**.

The tests cover areas such as:

* Login
* Authentication
* Protected routes
* Role-based access
* Product operations
* Invalid product IDs
* Non-existent products
* Refresh tokens
* Revoked refresh tokens
* Unauthorized requests

Tests help verify that the API behaves correctly and that protected functionality cannot be accessed improperly.

---

## 📝 Logging

Application logging was added to help monitor API activity and troubleshoot problems.

Logs can provide information about:

* Incoming requests
* Authentication-related events
* API activity
* Errors

This is useful when running the application in a production environment.

---

## 🔐 Security

The project includes several security-related practices:

* Password hashing with bcrypt
* JWT authentication
* Short-lived access tokens
* Refresh token mechanism
* Token revocation
* Role-based authorization
* Environment variables for sensitive configuration
* CORS configuration
* HTTP security headers
* Input validation
* ObjectId validation
* Error handling

Sensitive credentials such as the MongoDB connection string and secret keys are stored in environment variables rather than committed to GitHub.

---

## 🐳 Docker

The application is containerized using Docker.

Docker packages the application and its required runtime dependencies into a container.

### Why Docker?

Docker helps provide a consistent environment between development and deployment.

Instead of depending entirely on the host machine's Python setup, the application can run inside a controlled container environment.

The basic deployment flow is:

```text
Dockerfile
     ↓
Docker Image
     ↓
Docker Container
     ↓
Flask API
```

---

## ☁️ Deployment

The Dockerized Flask API is deployed on **Render**.

Deployment flow:

```text
GitHub
   ↓
Render
   ↓
Docker Image
   ↓
Docker Container
   ↓
Flask API
   ↓
MongoDB Atlas
```

### Why Render?

Render provides a cloud environment where the Flask API can run and be accessed through a public HTTPS URL.

### Why Docker + Render?

Docker handles the application's containerized runtime environment, while Render provides the cloud infrastructure where the container runs.

---

## ⚙️ Environment Variables

The application uses environment variables for sensitive configuration.

Example:

```env
MONGO_URI=your_mongodb_connection_string
SECRET_KEY=your_secret_key
```

These values should **not** be committed to GitHub.

For local development, create a `.env` file.

Example:

```env
MONGO_URI=...
SECRET_KEY=...
```

---

## 💻 Run Locally

### 1. Clone the repository

```bash
git clone <https://github.com/ritta87/FlasAPI-Python-productCRUDBackend.git>
```

### 2. Move into the project directory

```bash
cd <Python_API's>
```

### 3. Create a virtual environment

```bash
python -m venv venv
```

### 4. Activate the virtual environment

**Windows:**

```bash
venv\Scripts\activate
```

### 5. Install dependencies

```bash
pip install -r requirements.txt
```

### 6. Configure environment variables

Create a `.env` file:

```env
MONGO_URI=your_mongodb_connection_string
SECRET_KEY=your_secret_key
```

### 7. Run the application

```bash
python app.py
```

The API will be available locally at:

```text
http://127.0.0.1:5000
```

Swagger documentation:

```text
http://127.0.0.1:5000/apidocs/
```

---

## 🧪 Run Tests

Make sure the virtual environment is activated and run:

```bash
pytest
```

---

## 📂 Project Structure

A simplified project structure:

```text
flask-product-crud-api/
│
├── app.py
├── requirements.txt
├── Dockerfile
├── .env
├── .gitignore
├── tests/
│   └── test_api.py
└── README.md
```

> `.env` should be included in `.gitignore` and should never be pushed to GitHub.

---

## 🎯 What I Learned

Through this project, I practiced:

* Building REST APIs with Flask
* Connecting Flask with MongoDB Atlas
* Implementing JWT authentication
* Working with access and refresh tokens
* Implementing role-based authorization
* Secure password hashing
* Token revocation
* API input validation
* Pagination, filtering, searching and sorting
* MongoDB indexes and query optimization
* API testing with Pytest
* API documentation with Swagger/OpenAPI
* Application logging
* CORS and HTTP security headers
* Docker containerization
* Cloud deployment using Render
* Managing sensitive configuration using environment variables

---

## 👩‍💻 Author

**Ritta Ramachandran**

GitHub: https://github.com/ritta87
