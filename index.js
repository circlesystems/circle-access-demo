import express from "express";
import crypto from "crypto";
import { CircleAccess } from 'circle-access'
import * as url from "url";
import dotenv from 'dotenv'

dotenv.config()
const __dirname = url.fileURLToPath(new URL(".", import.meta.url));
const app = express();

// The array of allowed emails is hard-coded for this example.
// A database query should be used to check if a hash of the array
// hashedEmails matches the email hash of the database.
const allowedEmails = ["demo@circlesecurity.ai", "demo1@circlesecurity.ai", "sri.krishna@circlesecurity.ai"];

const circleAccess = new CircleAccess(process.env.ACCESS_APPKEY, process.env.ACCESS_READ_KEY, process.env.ACCESS_WRITE_KEY)

/**
 * Checks if there is an email hash that exists in authenticated hashes
 * @param {Object} hashedEmails contains all email hashes for current circle user
 */
async function validateUserEmail(hashedEmails) {
    var hasValidEmail = false;
    var hashTmp = "";
    var userEmail = ""; // you can store authenticated email if any for further use in your application
    // list hashedEmails elements
    for (var idx = 0; idx < hashedEmails.length; idx++) {
        // create a hash of the allowed email
        hashTmp = crypto.createHash("sha256").update(allowedEmails[idx]).digest("hex");

        // if the email is valid, we set the flag to true
        if (hashedEmails.indexOf(hashTmp) > -1) {
            hasValidEmail = true;
            userEmail = allowedEmails[idx]
            break;
        }
    }

    return [ hasValidEmail, userEmail ]
}

/**
 * validates if user is authenticated or not
 * @returns {Object} 
 */
async function validateUserSession(sessionID, userID) {

    // check if the session is valid
    var checkSession = await circleAccess.getUserSession(sessionID, userID);

    // if valid, we get the user email hashes
    if (checkSession.data.status == "active") {
        // we get the session details
        var sessionResult = await circleAccess.getSession(sessionID);

        // now lets kill the current session
        // this avoid replay attacks
        await circleAccess.expireUserSession(sessionID, userID);

        // we check if the user has valid emails in his profile
        var hasValidEmail = validateUserEmail(sessionResult.data.userHashedEmails);
        return hasValidEmail
    }
    return [ false, "" ]
}

app.get('/', async function (req, res, next) {
    if (req.query.userID) {
        var [hasValidEmail, userEmail]  = await validateUserSession(req.query.sessionID, req.query.userID);
        if (hasValidEmail) {
            // the email is valid, we can redirect the user to an allowed page
            // For this example, we will only show a message
            res.status(200).json({ status: "ok", message: `Hey ${userEmail} You are allowed to access this page` });
        }
        else {
            // the email is not valid, we redirect the user to an error page
            res.status(401).json({
                message: "Unauthorized",
            });

        }
    } else {
        res.sendFile(__dirname + "/public/index.html")
    }
})

app.listen(3000);
console.log("Listening on http://localhost:3000");
