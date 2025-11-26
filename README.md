# Travel Company Website - Registration & Login System

A secure user authentication system for a travel company website, featuring user registration with email verification and login functionality.

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

### 2. Database Setup

1. Open MySQL Workbench
2. Connect to your MySQL server
3. Open the `database.sql` file from the project
4. Execute all lines to create the database and table:
   ```sql
   CREATE DATABASE userdb;
   USE userdb;
   CREATE TABLE users (...);
   ```

### 3. Environment Configuration

1. Locate the `.env` file in the project root
2. Update it with your MySQL credentials:
   ```env
   DB_HOST=localhost
   DB_USER=your_mysql_username
   DB_PASSWORD=your_mysql_password
   DB_NAME=userdb
   ENC_KEY=your_encryption_key
   SECRET_KEY=your_secret_key
   ```

### 4. Install Dependencies

1. Navigate to the project directory in File Explorer
2. Click on the address bar and type `cmd`, then press Enter
3. In the Command Prompt, run the following commands:

```bash
# Update npm to latest version
npm install -g npm@11.6.4

# Install required packages
npm install express mysql2 bcryptjs cors dotenv nodemailer

# Install development dependencies
npm install --save-dev nodemon
```

### 5. Email Configuration

If you want to use your own Gmail for sending verification emails:

1. Open `register.js` in the `routes` folder
2. Update the nodemailer configuration:
   ```javascript
   auth: {
       user: 'your_email@gmail.com',
       pass: 'your_app_password',
   }
   ```
3. **Note**: You need to generate an [App Password](https://support.google.com/accounts/answer/185833) from your Google Account settings

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
├── routes/
│   ├── login.js
│   └── register.js
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

This project was developed as an assignment focusing on the registration and login functionality for a travel company website. Future enhancements could include:

- Password reset functionality
- User profile management
- Session management with JWT
- Social media authentication
- Extended token validity period
- Admin dashboard

## Contributors

Developed as part of a web development assignment.

## License

This project is for educational purposes.