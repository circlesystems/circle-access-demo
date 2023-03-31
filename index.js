import express from "express";
import crypto from "crypto";
import { CircleAccess } from 'circle-access'
import * as url from "url";
import dotenv from 'dotenv'

dotenv.config()
const __dirname = url.fileURLToPath(new URL(".", import.meta.url));
const app = express();
const allowedEmails = ["demo@gocircle.ai", "demo1@gocircle.ai","sri.krishna@circlesecurity.ai"];
const ca = new CircleAccess(process.env.ACCESS_APPKEY,process.env.ACCESS_READ_KEY,process.env.ACCESS_WRITE_KEY)

var encryptData = function(dataToEncrypt) {
    return crypto.createHmac('sha256', process.env.SECRET.trim()).update(dataToEncrypt).digest('base64');
}

async function getCircleToken(){
    let timeStamp = Math.floor(Date.now() / 1000);
    let urlParameters = `customerId=${process.env.CUSTOMER_ID}&appKey=${process.env.ACCESS_APPKEY}&endUserId=${process.env.END_USER_ID}`;
    urlParameters += '&nonce=' + timeStamp;

    let signature = encryptData(urlParameters);
    try {
        const ret = await axios.get("https://api.gocircle.ai/api/token?" + urlParameters + '&signature=' + signature);
        const cleaned = JSON.parse(ret.data.toString().replace(/\r\n/g, ""));
        return cleaned

    } catch (error) {
        console.log(error);
    }
}

async function validateUserEmail(req, res, next, hashedEmails) {
    var hasValidEmail = false;
    var hashTmp = "";

    // list hashedEmails elements
    for (var idx = 0; idx < hashedEmails.length; idx++) {
        // create a hash of the allowed email
        hashTmp = crypto.createHash("sha256").update(allowedEmails[idx]).digest("hex");

        // if the email is valid, we set the flag to true
        if (hashedEmails.indexOf(hashTmp) > -1) {
            hasValidEmail = true;
            break;
        }
    }

    if (hasValidEmail) {
        // the email is valid, we can redirect the user to an allowed page
        // For this example, we will only show a message
        res.status(200).json({ status: "ok", message: "You are allowed to access this page" });
    } else {
        // the email is not valid, we redirect the user to an error page
        res.status(401).json({
            message: "Unauthorized",
        });
    }
}

async function validateUserSession(req, res, next) {
    // get the sessionId and userID from callback
    var sessionID = req.query.sessionID;
    var userID = req.query.userID;

    // check if the session is valid
    var checkSession = await ca.getUserSession(sessionID, userID);

    // if valid, we get the user email hashes
    if (checkSession.data.status == "active") {
        // we get the session details
        var sessionResult = await ca.getSession(sessionID);

        // now lets kill the current session
        // this avoid replay attacks
        await ca.expireUserSession(sessionID, userID);

        // we check if the user has valid emails in his profile
        validateUserEmail(req, res, next, sessionResult.data.userHashedEmails);
    } else {
        res.status(401).json({
            message: "Unauthorized",
        });
    }
}

app.get('/tokengen', async function(req, res){
    var token = await getCircleToken()
    res.json(token)
})

app.get('/', async function(req, res, next){
    if(req.query.userID){
        validateUserSession(req, res, next);
    } else{
        res.sendFile(__dirname+"/public/index.html")
    }
})

app.listen(3000);
console.log("Listening on http://localhost:3000");