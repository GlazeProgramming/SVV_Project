# Travel Company Website - Registration & Authentication System

A secure user authentication system for a travel company website, featuring user registration with token-based email verification and login functionality.

## Features

- **User Registration**
  - Multi-field registration form (firstname, lastname, date of birth, phone number, username, email, password)
  - Client-side and server-side validation
  - Password strength requirements (uppercase, lowercase, digit, special character)
  - Data encryption for sensitive fields (firstname, lastname, phone number)
  - Email verification with OTP token
  - Token expiration (1 minute validity)

- **Email Verification**
  - Automated email delivery with verification token
  - Account activation page
  - Expired token handling with automatic account deletion

- **User Login**
  - Secure password hashing with bcrypt
  - Account verification check
  - Authentication validation

- **Data Management**
  - View registered users data
  - MySQL database integration
  - Encrypted storage of sensitive information
  - Unverified accounts are automatically deleted after token expiration

## Technology Stack

- **Frontend**: HTML5, CSS3, JavaScript (ES6+)
- **Backend**: Node.js, Express.js
- **Database**: MySQL
- **Security**: 
  - bcryptjs (password hashing)
  - crypto (AES-256-CBC encryption)
  - nodemailer (email verification)
- **Icons**: Ionicons

## Prerequisites

Before running this project, ensure you have the following installed:

- [Node.js](https://nodejs.org/) (v14 or higher recommended)
- [MySQL](https://www.mysql.com/) (v8.0 or higher recommended)
- MySQL Workbench (or any MySQL client)

## Installation & Setup

### 1. Download and Extract

Download the project zip file and extract it to your preferred location.

### 2. Environment Configuration

1. Locate the `.env` file in the project root
2. Update it with your MySQL credentials:
   ```env
   DB_HOST=localhost
   DB_USER=root
   DB_PASS=your_mysql_password
   DB_NAME=userdb

   # Application Configuration
   PORT=3000

   # Email Service (e.g., Gmail)
   EMAIL_USER=youremail@gmail.com
   EMAIL_PASS=your_gmail_app_password      # Crucial: Must be a Google App Password, not your account password.

   # Encryption Keys (Must be strong and unique)
   ENC_KEY=UltraSecureRandomKeyEncryptDataXYZ98765 # Must be exactly 32 bytes (32 characters)
   SECRET_KEY=AnotherStrongRandomKeyForIV
   ```

### 3. Install Dependencies

1. Navigate to the project directory in your terminal or Command Prompt.

2. Run the following command. This will read the package.json file and install all necessary packages, including server dependencies (like Express, MySQL2) and development tools (like Nodemon).

   ```installations
   npm install
   ```


### 4. Database Setup

use the dedicated setup script to build the database structure defined in database.sql:

   ```sql
   npm run db:setup
   ```

## Running the Application

1. In the Command Prompt (in project directory), run:
   ```bash
   npm start
   ```

2. The server will start (typically on port 3000)

3. Open your web browser and navigate to:
   ```
   http://localhost:3000/signup.html
   ```

## Project Structure

```
SVV_PROJECT/
├── .settings/
├── build/
│   └── classes/
├── node_modules/
├── public/
│   ├── css/
│   │   ├── background.jpg
│   │   └── styles.css
│   │   └── Travel.ico
│   ├── js/
│   │   ├── activate.js
│   │   ├── getdata.js
│   │   ├── login.js
│   │   └── signup.js
│   ├── activate.html
│   ├── getdata.html
│   ├── login.html
│   ├── pixel.png
│   └── signup.html
│   └── success.html
│   └── terms.html
├── routes/
│   ├── login.js
│   └── register.js
├── scripts/
│   ├── db_setup.js
├── src/
├── .classpath
├── .env
├── .gitignore
├── .project
├── database.sql
├── db.js
├── index.js
├── package-lock.json
└── package.json
└── pending_registrations_table.sql
```

## Usage Flow

1. **Registration** (`/signup.html`)
   - Fill in all required fields
   - Submit the form
   - Check your email for the verification token

2. **Activation** (`/activate.html`)
   - Enter your username
   - Enter the verification token from your email
   - Activate your account (within 1 minute of registration)

3. **Login** (`/login.html`)
   - Enter your username and password
   - Successfully log in after account activation

4. **View Users** (`/getdata.html`)
   - Click "Get Data" to view all verified users

## Validation Rules

### Registration Form:
- **First Name**: Minimum 3 letters, A-Z only
- **Phone Number**: Must start with `+` followed by 7-15 digits (e.g., +60123456789)
- **Email**: Valid email format
- **Password**: 
  - Minimum 6 characters
  - Must contain: uppercase letter, lowercase letter, digit, and special character
- **Confirm Password**: Must match password

## Security Features

- Password hashing using bcrypt (10 salt rounds)
- AES-256-CBC encryption for sensitive data (firstname, lastname, phone number)
- Token-based email verification
- Automatic deletion of unverified accounts after token expiration
- SQL injection prevention through parameterized queries

## Troubleshooting

### Database Connection Error
- Verify MySQL is running
- Check `.env` credentials
- Ensure `userdb` database exists

### Email Not Sending
- Check Gmail credentials in `register.js`
- Verify App Password is correct
- Check internet connection
- Ensure "Less secure app access" is disabled (use App Password instead)

### Token Expired
- Verification tokens expire after 1 minute
- Re-register if token has expired
- The system automatically deletes expired unverified accounts

### Port Already in Use
- Change the port in `server.js`
- Or stop the process using the port

## Development Notes

This project was developed as an assignment focusing on the registration and login functionality for a travel company website. 
