// --- CRITICAL FIX: Ensure project root is determined correctly for .env loading ---
const path = require('path');

// Determine the project root directory (two levels up from this script's location)
const projectRoot = path.join(__dirname, '..'); 

// Load environment variables from the .env file located in the project root
require('dotenv').config({ path: path.join(projectRoot, '.env') });
// -----------------------------------------------------------------------------------

// Corrected to use mysql2, which is listed in your package.json dependencies
const mysql = require('mysql2'); 
const fs = require('fs');

// --- Configuration ---
// Connection details for MySQL server (NOT the specific database yet)
const config = {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    multipleStatements: true // Allows running multiple SQL commands from the file
};

const DB_NAME = process.env.DB_NAME;
const SQL_SCHEMA_PATH = path.join(projectRoot, 'database.sql');
const PENDING_REG_SQL_PATH = path.join(projectRoot, 'pending_registrations_table.sql');

// --- Functions ---

// Function to set up the database by executing the SQL schema files.
async function setupDatabase() { 
    // === Configuration Validation Check ===
    if (!config.host || !config.user || !config.password || !DB_NAME) {
        console.error('\n❌ Configuration Error: One or more database environment variables are missing.');
        console.log('   Please ensure DB_HOST, DB_USER, DB_PASS, and DB_NAME are set correctly in your .env file.');
        // Display the values that were found (to aid debugging)
        console.log(`   Found: Host='${config.host}', User='${config.user}', Pass='${config.password ? '***' : ''}', DB='${DB_NAME}'`);
        return; 
    }
    // ============================================

    console.log(`Attempting to connect to MySQL host: ${config.host} with user: ${config.user}...`);

    // Use a connection without a specific database to allow CREATE DATABASE command
    const setupConnection = mysql.createConnection(config);

    try {
        await new Promise((resolve, reject) => {
            setupConnection.connect(err => {
                if (err) return reject(new Error(`MySQL Connection Failed: ${err.message}`));
                console.log('Successfully connected to MySQL server.');
                resolve();
            });
        });

        // 1. Create the database if it doesn't exist
        console.log(`Ensuring database '${DB_NAME}' exists...`);
        await setupConnection.promise().query(`CREATE DATABASE IF NOT EXISTS ${DB_NAME}`);
		
        console.log(`Database '${DB_NAME}' is ready.`);

		// 2. Switch to the database
		await setupConnection.promise().query(`USE ${DB_NAME}`);

		// 3. Read the main schema file
		console.log(`Reading schema from ${SQL_SCHEMA_PATH}...`);
		const mainSchemaSql = fs.readFileSync(SQL_SCHEMA_PATH, 'utf8');
		
		// Clean up the SQL - remove only CREATE DATABASE and USE commands (more specific patterns)
		const cleanedSql = mainSchemaSql
		    .replace(/CREATE\s+DATABASE\s+[^;]+;/gi, '')
		    .replace(/USE\s+[^;]+;/gi, '')
		    .trim();

		if (!cleanedSql) {
		    console.log('Warning: No SQL statements found in schema file after cleaning.');
		    return;
		}

		console.log(`Executing schema (${cleanedSql.length} characters)...`);
		
		// Execute the entire file at once (multipleStatements is enabled)
		await setupConnection.promise().query(cleanedSql);
		console.log('Main table (users) created/updated successfully.');

        
        // 3. Read and execute the pending registrations schema file
        if (fs.existsSync(PENDING_REG_SQL_PATH)) {
            const pendingRegSql = fs.readFileSync(PENDING_REG_SQL_PATH, 'utf8');
            console.log(`Executing schema from ${PENDING_REG_SQL_PATH}...`);
            await setupConnection.promise().query(pendingRegSql);
            console.log('Pending registrations table created/updated successfully.');
        } else {
            console.log('Note: pending_registrations_table.sql not found, skipping...');
        }

        console.log('\n✅ Database setup complete! You can now start the server with: npm start');

    } catch (error) {
        console.error(`\n❌ Database Setup Error: ${error.message}`);
        console.log('\n[Hint] Check if MySQL is running and your .env credentials (DB_USER, DB_PASS) are correct.');
        
        if (error.message.includes("Access denied")) {
            console.log("   [Action Needed] Ensure your MySQL server is running and the user/password combination in your .env file is valid for your local MySQL installation.");
        }

    } finally {
        setupConnection.end();
    }
}

// Check for required dependencies before running
if (!fs.existsSync(SQL_SCHEMA_PATH)) {
    console.error(`Error: SQL schema file not found at ${SQL_SCHEMA_PATH}`);
} else {
    setupDatabase();
}