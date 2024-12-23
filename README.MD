# Notes API

A simple RESTful API for managing user accounts and their personal notes. The API includes user authentication via JSON Web Tokens (JWT).

## Features
- User registration
- User login with token generation
- Middleware for token authentication
- CRUD operations for notes (Create, Read, Delete)

---

## Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   ```

2. Navigate to the project directory:
   ```bash
   cd <project-directory>
   ```

3. Install dependencies:
   ```bash
   npm install
   ```

4. Start the server:
   ```bash
   node app.js
   ```

The API will run at `http://localhost:3000` or on the port specified in the `PORT` environment variable.

---

## API Endpoints

### User Endpoints

#### Register User
**POST** `/register`

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "password123"
}
```

**Response:**
```json
{
  "success": true,
  "message": "User registered successfully."
}
```

---

#### Login User
**POST** `/login`

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "password123"
}
```

**Response:**
```json
{
  "success": true,
  "token": "<JWT_TOKEN>"
}
```

---

### Notes Endpoints

#### Get Notes
**GET** `/notes`

**Headers:**
```json
{
  "Authorization": "Bearer <JWT_TOKEN>"
}
```

**Response:**
```json
{
  "success": true,
  "data": [
    { "email": "user@example.com", "title": "Note Title", "content": "Note Content" }
  ]
}
```

---

#### Add Note
**POST** `/notes`

**Headers:**
```json
{
  "Authorization": "Bearer <JWT_TOKEN>"
}
```

**Request Body:**
```json
{
  "title": "Note Title",
  "content": "Note Content"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Note added successfully."
}
```

---

#### Delete Note
**DELETE** `/notes/:title`

**Headers:**
```json
{
  "Authorization": "Bearer <JWT_TOKEN>"
}
```

**Path Parameter:**
- `title`: The title of the note to be deleted.

**Response:**
```json
{
  "success": true,
  "message": "Note deleted successfully."
}
```

---

## Environment Variables
- `PORT`: The port on which the server runs. Default is `3000`.

## Dependencies
- `express`: Web framework for Node.js.
- `body-parser`: Middleware for parsing request bodies.
- `jsonwebtoken`: Library for generating and verifying JWTs.
- `bcryptjs`: Library for hashing passwords.

---

## Notes
- This project is for educational purposes and uses in-memory storage for simplicity. In a production environment, replace `users` and `notes` arrays with a database.
- Always use a strong secret key for signing JWTs.

---

## License
This project is licensed under the MIT License.
