# Modern Login & Registration Interface

A secure, professional, and responsive authentication system with modern UI design, secure password handling, and JWT-based backend API.

## Features

### Frontend
- Clean, modern UI with subtle shadows and rounded corners
- Responsive mobile-friendly design
- Input validation with real-time error messages
- Password visibility toggle
- "Remember Me" option
- "Forgot Password" link
- Accessible design (ARIA labels, proper contrast)
- Smooth transitions and hover effects

### Backend Security
- Bcrypt password hashing with salt rounds
- JWT token-based authentication
- Token refresh mechanism
- Rate limiting on login attempts (5 attempts per 15 minutes)
- Input sanitization and validation
- CSRF protection headers
- Secure HTTP-only cookie handling

### API Endpoints
- `POST /api/register` - User registration with validation
- `POST /api/login` - User login with JWT token
- `POST /api/refresh` - Refresh expired tokens
- `POST /api/logout` - User logout
- `GET /api/user` - Get current user info (protected)

## Installation & Setup

### Prerequisites
- Node.js (v14+)
- npm or yarn

### Backend Setup

1. Install dependencies:
```bash
npm install
```

2. Create a `.env` file:
```env
PORT=3000
JWT_SECRET=your_super_secret_jwt_key_change_this_in_production
JWT_EXPIRATION=1h
REFRESH_TOKEN_EXPIRATION=7d
NODE_ENV=development
```

3. Start the server:
```bash
npm start
```

The API will be available at `http://localhost:3000`

### Frontend Usage

1. Open `index.html` in a web browser (or serve via the Express static middleware)
2. Access the application at `http://localhost:3000`

## Project Structure

```
.
├── index.html           # Combined frontend & backend
├── package.json         # Dependencies
├── .env                 # Environment variables (create this)
└── README.md            # This file
```

## API Documentation

### Register User
```
POST /api/register
Content-Type: application/json

{
  "username": "john_doe",
  "email": "john@example.com",
  "password": "SecurePass123!"
}

Response: 201 Created
{
  "message": "User registered successfully",
  "user": {
    "id": "user_id",
    "username": "john_doe",
    "email": "john@example.com"
  }
}
```

### Login User
```
POST /api/login
Content-Type: application/json

{
  "email": "john@example.com",
  "password": "SecurePass123!",
  "rememberMe": true
}

Response: 200 OK
{
  "message": "Login successful",
  "accessToken": "jwt_token_here",
  "refreshToken": "refresh_token_here",
  "user": {
    "id": "user_id",
    "username": "john_doe",
    "email": "john@example.com"
  }
}
```

### Refresh Token
```
POST /api/refresh
Content-Type: application/json

{
  "refreshToken": "refresh_token_here"
}

Response: 200 OK
{
  "accessToken": "new_jwt_token_here"
}
```

## Security Features

✅ **Password Security**
- Bcrypt hashing with 10 salt rounds
- Passwords never stored in plain text
- Secure password comparison

✅ **Token Security**
- JWT tokens with expiration
- Refresh token rotation
- HTTP-only cookie option
- Token validation on protected routes

✅ **Input Security**
- Email validation
- Password strength requirements
- Username validation
- XSS protection headers
- Rate limiting (5 failed attempts per 15 minutes)

✅ **API Security**
- CORS protection
- CSRF prevention headers
- Content-Type validation
- Secure HTTP headers

## Browser Support

- Chrome/Edge (latest)
- Firefox (latest)
- Safari (latest)
- Mobile browsers (iOS Safari, Chrome Mobile)

## License

MIT

## Notes

- Change `JWT_SECRET` in production to a secure random string
- Implement database persistence for production use
- Add email verification for production
- Configure proper CORS settings for your domain
- Use HTTPS in production
- Implement rate limiting on your infrastructure/CDN

## Development Notes

Users are stored in memory during development. For production:
1. Integrate with MongoDB, PostgreSQL, or your preferred database
2. Add email verification
3. Implement password reset functionality
4. Add account lockout after failed attempts
5. Enable audit logging
