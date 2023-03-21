# Demo for Circle Access Mobile using Node JS

> In this tutorial, we will create an application that displays an HTML page for user interaction. When the user clicks on the button, they will be redirected to the authentication page.<br>
On scanning the code QR, the user will be authenticated and redirected to the previously registered callback page with the appropriate credentials. <br>
On the callback page, the user will scan the QR code using circle access mobile app after which the user email hash(sha256) will be matched with the database and redirected according to their permissions.

### Let´s go step by Step

- We will create a Node application using Express. To setup the app, start by typing ***npm init*** from the command line.

- We have to create a .env file in the root directory of the application. This file will contain keys that will be used to validate the user session. Add the following content to the .env file.

```env
CUSTOMER_ID='#customerID#'
ENDUSER_ID =  'userman'  // anythign, but should be different for every user
SECRET = '#secret#' 
API_URL = 'https://api.gocircle.ai/api/token' 
ACCESS_APPKEY = '#appKey#'
ACCESS_LOGIN_URL = '#loginUrl#'
ACCESS_READ_KEY = '#readKey#'
ACCESS_WRITE_KEY = '#writeKey#'
```

- Let's create the HTML page for user interaction. Please note that you need to replace any instance of **YOUR_APP_KEY_HERE** in the html.

```html
<!doctype html="">
<html>

<head>
    <title>Circle Access Mobile - Demo</title>
    <meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0" />
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css">

    <script src="https://code.jquery.com/jquery-3.6.0.min.js"> </script>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.min.js"></script>

    <script>
        var timestamp = new Date().getTime();
        document.write(`\x3Cscript src="https://cdn.circlesecurity.ai/circle/js/circlesecurity.ai-bundle.js?t=${timestamp}">\x3C/script>`);
        document.write(`\x3Cscript src="https://cdn.circlesecurity.ai/circle/js/circlesecurity.ai.js?t=${timestamp}">\x3C/script>`);
    </script>

</head>

<body>

    <nav class="navbar navbar-expand-lg navbar-light bg-light" style="margin-top:0px">
        <a class="navbar-brand" href="#"><img src="https://license.gocircle.ai/images/CircleLogoNoCompromise.svg"
                style="height:30px" /></a>
        <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarTogglerDemo02"
            aria-controls="navbarTogglerDemo02" aria-expanded="false" aria-label="Toggle navigation">
            <span class="navbar-toggler-icon"></span>
        </button>

        <div class="collapse navbar-collapse" id="navbarTogglerDemo02">

        </div>
    </nav>

    <div class="container-fluid main-cont">
        <div class="row">
            < <div class="col-12">
                <center>
                    <div id="btn_div" style="margin-top: 60px;">Loading the button async...</div>
                </center>
        </div>
    </div>
    </div>

    <script>
        async function init() {
            const btn = await Circle.getLoginButton();
            $("#btn_div").html(btn);
        }

        // this function is called by the circle button
        function circleButtonClicked() {
            callJsLoginBtn();
        }

        function callJsLoginBtn() {
            window.location.href = "https://circleauth.circlesecurity.ai/login/YOUR_APP_KEY_HERE";
        }

        init();
    </script>
</body>

</html>
```

- The second step is to build the server that will handle the callback.To build the server we have to add some additional NPM packages. Type the following command to install the packages:
```bash
npm install --save dotenv express @circlesystems/circleauth-wrapper
```

### Server side code step by step,
- Imports and constants used by the server:

```javascript
import express from "express";
import crypto from "crypto";
import { CircleAccess } from 'circle-access'
import * as url from "url";
import dotenv from 'dotenv'

dotenv.config()
const __dirname = url.fileURLToPath(new URL(".", import.meta.url));
const app = express();
const circleauthwrapper = new CircleAccess(process.env.ACCESS_APPKEY,process.env.ACCESS_READ_KEY,process.env.ACCESS_WRITE_KEY)

const allowedEmails = ["dropYourEmailHere@email.com"]; //remember this has to be the same email you registered on circle access mobile app
```

- Function that check if the hashedEmails array contains the hash of the user email.
```javascript
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
```

- Function that validates the user session.
```javascript
async function validateUserSession(req, res, next) {
    // get the sessionId and userID from callback
    var sessionID = req.query.sessionID;
    var userID = req.query.userID;

    // check if the session is valid
    var checkSession = await circleauthwrapper.getUserSession(sessionID, userID);

    // if valid, we get the user email hashes
    if (checkSession.data.status == "active") {
        // we get the session details
        var sessionResult = await circleauthwrapper.getSession(sessionID);

        // now lets kill the current session
        // this avoid replay attacks
        await circleauthwrapper.expireUserSession(sessionID, userID);

        // we check if the user has valid emails in his profile
        validateUserEmail(req, res, next, sessionResult.data.userHashedEmails);
    } else {
        res.status(401).json({
            message: "Unauthorized",
        });
    }
}
```

- Setup a base route and start the server using port 3000.
```javascript
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
```

- To start the server, execute the following line of code in the application folder:
***node < index or any server name that you set when performing npm init > eg: node index***

- After starting the server, navigate to http://localhost:3000 in a web browser.