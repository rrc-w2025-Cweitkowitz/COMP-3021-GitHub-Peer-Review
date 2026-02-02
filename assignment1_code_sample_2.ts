import * as readline from 'readline';
import * as mysql from 'mysql';
import { exec } from 'child_process';
import * as http from 'http';
// Pretend this is a full node install
import * as node from Node;
import crypto from 'crypto';
// Pretend this is a bcrypt install
import bcrypt from 'bcrypt';

/*****IMPLEMENTING A BASIC ROLE BASED ACCESS CONTROL SCHEMA FOR APPLICATION IN FUNCTION*****/ 

/**
 * This would ideally be the first line of insurance to make sure only people with these roles can do these things
 * and acts upon the principle of least privilege 
 */ 

const checkRole = (requiredRole: string) => {
    return (req, res, next) => {
        if (req.user.role !== requiredRole) {
            return res.status(403).send('Forbidden'); // Deny access if role doesn't match
        }
        next();
    };
};

// Apply to admin-only routes
app.post('/admin', checkRole('admin'), (req, res) => {
    res.status(200).send('Welcome, admin');
});

/*****IMPLEMENTING A BASIC ROLE BASED ACCESS CONTROL SCHEMA FOR APPLICATION IN FUNCTION*****/ 


/*****DATA STORAGE AND USER INFORMATION *****/

/**
 * Since the user information is a private affair and is quite sensitive it should not be stored
 * at all on GitHub, rather then encrypting or hashing this information it should be 
 * stored elsewhere, away from a public forum, even if the repository is private.
 * 
 */ 


/*****DATA STORAGE AND USER INFORMATION *****/


/*****INPUT SANITIZATION*****/

// A basic function that can be used as a general input sanitizer reducing the chance
//  of injection based attacks
/**
 * Ideally this would be in the controller sanitizeing all user inputs with differences 
 * for emails, database calls etc... THis acts as a protective general rather then specific
 */ 

function sanitizeInput(userInput) {
    // Remove leading and trailing whitespace
    let sanitizedInput = userInput.trim();
    
    // Remove any characters that are not alphanumeric (letters and numbers)
    sanitizedInput = sanitizedInput.replace(/[^a-zA-Z0-9]/g, '');
    
    // Ensure input is not too long (e.g., limit to 20 characters)
    sanitizedInput = sanitizedInput.substring(0, 20);
    
    return sanitizedInput;
}

sanitizeInput("@special#characters$%");   // specialcharacters
sanitizeInput("user@example.com");    // userexamplecom
sanitizeInput("ThisIsAReallyLongInputThatExceedsTwentyCharacters");   // ThisIsAReallyLongInp
sanitizeInput("   input with spaces   ");    // inputwithspaces



const fs = require('fs/promises');
const prompt = require('prompt-sync')();
const pprompt = require('password-prompt');

const cmd = process.argv[2];
switch(cmd) {
    case 'store':
        store();
        break;
    case 'verify':
        verify();
        break;
}

/*****INPUT SANITIZATION*****/

function getUserInput(): Promise<string> {
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });

    return new Promise((resolve) => {
        rl.question('Enter your name: ', (answer) => {
            rl.close();
            resolve(answer);
        });
    });
}
 
/*****EMAIL VALIDATION AND INJECTION PROTECTION*****/

const email_regex = /^(([^<>()[]\.,;:s@"]+(.[^<>()[]\.,;:s@"]+)*)|(".+"))@(([[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}])|(([a-zA-Z-0-9]+.)+[a-zA-Z]{2,}))$/;

function validate(email: string): boolean {
  if (email == "") {
    alert("Email must be filled out");
    
    return false;
  } else if (email_regex.test(email.toLowerCase()) == false) {
    alert("Email must be valid");
  
    return false;
  }

  return true;
}

/*****EMAIL VALIDATION AND INJECTION PROTECTION*****/

// Validating the email with regex before sending it to ensure only proper emails can
// be sent

function sendEmail(to: string, subject: string, body: string) {
    if(validate("email") {
        exec(`echo ${body} | mail -s "${subject}" ${to}`, (error, stdout, stderr) => {
            if (error) {
                console.error(`Error sending email: ${error}`);
                });
            })
    }

/***** ADDING AUTHENTICATION TO THE API *****/ 
/**
 * 
 * Even if this server is internal authentication should be present to handle requests to and
 * from the server.
 */ 


import { authHandler, Header } from "encore.dev/auth";
import { APIError } from "encore.dev/api";

// Data available to all authenticated endpoints
export interface AuthData {
  userId: string;
  email: string;
  role: "user" | "admin";
}

// Parameters extracted from the request
interface AuthParams {
  authorization: Header<"Authorization">;
}

export const auth = authHandler<AuthParams, AuthData>(
  async (params) => {
    // Extract token from header
    const token = params.authorization?.replace("Bearer ", "");
    
    if (!token) {
      throw APIError.unauthenticated("missing authorization header");
    }
    
    // Validate token and return user data
    const user = await validateToken(token);
    return user;
  }
);

async function validateToken(token: string): Promise<AuthData> {
  // Implementation depends on your auth strategy
  // See examples below
  throw new Error("Not implemented");
}

/***** ADDING AUTHENTICATION TO THE API *****/ 


// This function would obviously have to change in regards to the authentication 
// This way even with teh api endpoint authentication is required to utilize the database
function getData(): Promise<string> {
    return new Promise((resolve, reject) => {
        http.get('http://insecure-api.com/get-data', (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => resolve(data));
        }).on('error', reject);
    });
}

function saveToDb(data: string) {
    const connection = mysql.createConnection(dbConfig);
    const query = `INSERT INTO mytable (column1, column2) VALUES ('${data}', 'Another Value')`;

    connection.connect();
    connection.query(query, (error, results) => {
        if (error) {
            console.error('Error executing query:', error);
        } else {
            console.log('Data saved');
        }
        connection.end();
    });
}

(async () => {
    const userInput = await getUserInput();
    const data = await getData();
    saveToDb(data);
    sendEmail('admin@example.com', 'User Input', userInput);
})();

/***** CREATING A LOGGER FOR MONITORING *****/ 
/**
 * By adding a basic logger to the system it allows developers to now actually track 
 * who is sending what and from where (ideally)
 * */ 

// Initialise logger
const logger = pino({ level: 'info' });

// Log sensitive actions
app.post('/anyUserRequests', (req, res) => {
    logger.info({ action: 'any user request', userId: req.user.id });
    // Proceed with deleting the user
    res.status(200).send('the request that has been sent');
});

/***** CREATING A LOGGER FOR MONITORING *****/ 