# AutoDoorCtrlWebAPIPHP
AutoDoorCtrlWebAPIPHP is the API we use to connect our Angular web app to our MySQL database. The API is written in PHP, with some `.htaccess` files provided to make everything run smoothly. The repository for the website can be found [Here](https://github.com/AutomaticDoorControl/AutoDoorCtrlWeb)

## What to install
  * clone respository `https://github.com/AutomaticDoorControl/AutoDoorCtrlWebAPIPHP.git`
  * navigate to AutoDoorCtrlWebAPIPHP on your machine
  * in folder `api`, run `composer install` to install dependencies
  * copy `.htaccess` and the folder `api` to /var/www/html
## Notes  
  * This API will not work without the use of a properly setup MySQL database. Point the API to the db by changing `servername`, `username`, `password`, and `dbname` in `index.php`
  * This API will not have email functionality without a SMTP server from which it can send mail. Point the API to this SMTP server by changing `mailServer` and `mailPort`, and change mailer preferences with `mailUsername`, `mailPassword`, and `mailSender`
  * If you get permissions errors, it may be helpful to change ownership of files to `www-data` by running `sudo chown www-data:www-data /var/www/html/* /var/www/keys/*`, assuming you are using default paths
  * If an API call does not have an explicit return value, any data recieved should be ignored. Success or failure will be communicated through HTTP status codes

## API Calls
User objects returned by the API  are JSON objects in the form `{"rcsid": <rcsid>, "enabled": <boolean>}`

Requests with a star (\*) require admin authentication, otherwise they will return a `401 Unauthorized` error. Authentication is handled by sending the header `Authorization: Bearer <token>` as part of the request, where `<token>` is the token recieved during login. User tokens are not valid for admin authentication.

Requests with a plus (+) require user authentication. Authentication is handled in the same manner as for admin. 

### GET requests
* /api/get_users \*
    * Returns an array of all non-admin Users
* /api/add_all \*
    * Changes all Users' Status to `Active`
    * If email is enabled, sends an email to each User with changed status, informing them of the change and including a new temporary password
* /api/get_complaints \*
    * Returns an array of JSON items in the form `{"location": <location>, "message": <message>}`
* /api/get_doors
    * Returns an array of JSON items in the form `{"name": <name>, "location": <location>, "latitude": <latitude>, "longitude": <longitude>, "mac": <MACAdress>}`
* /api/renew_token \*/+
    * Extends the expiration deadline for the token used to authenticate
    * Note that tokens with `reason = "forgot_passwd"` cannot be renewed
* /api/forgot_password
    * Supply a GET parameter `token` containing a reset token (can be recovered from email sent by /api/forgot_password POST request)
    * If token is valid, resets user password to a new temporary password
    * If email is enabled, sends an email to the user indicated by the token informing them of the password reset and including a new temporary password
* /api/logout
    * If this request is made with a valid authentication token, the token is disabled and cannot be used for further requests

### POST requests
* /api/login
    * Supply a JSON object in the form `{"rcsid": <rcsid>, "password": <password>}`
    * Returns a JSON object in the form `{"SESSIONID": <token>}` where `<token>` is used to identify this user during future API interactions
    * If `<RCSid>` and `<password>` do not together represent a valid active user, `<token>` will be an empty string `""`
* /api/request_access
    * Supply a JSON object in the form `{"rcsid": <rcsid>}`
    * Adds a row to Users with the values `{"rcsid": <rcsid>, "password": "", "admin": FALSE, "enabled": FALSE}`
    * If email is enabled, sends an email to `<rcsid>`@rpi.edu informing them they have been added to the waitlist
* /api/add_to_active \*
    * Supply a JSON object in the form `{"rcsid": <rcsid>}`
    * Sets `enabled` to `TRUE` for the user with `rcsid` `<rcsid>`
    * If email is enabled, sends an email to `<rcsid>`@rpi.edu, informing them that their account is now active and including a new temporary password
* /api/remove \*
    * Supply a JSON object in the form `{"rcsid": <rcsid>}`
    * Deletes all non-admin users with rcsid `<rcsid>`
* /api/submit_complaint
    * Supply a JSON object in the form `{"location": <location>, "message": <message>}`
    * Stores the complaint in the server
* /api/open_door +
    * Supply a JSON object in the form `{"door": <name>}`
    * Returns a JSON object in the form `{"totp": <totp>}` where <totp> is a 6 digit one-time password which can be used to open the specified door.
 * /api/change_password
    * Supply a JSON object in the form `{"rcsid": <rcsid>, "password": <current password>, "newpass": <new password>}`
    * If supplied valid credentials, changes password for user `<rcsid>` from `<password>` to `<newPassword>`
    * If email is enabled, sends an email to `rcsid`@rpi.edu informing them that their password has been changed, and instructing them to notify an admin if they were not the party who changed their password
* /api/reset_password *
    * Supply a JSON object in the form `{"rcsid": <rcsid>, "newpass": <new password>}`
    * Changes the password of non-admin user `<rcsid>` to `<new password>`
* /api/forgot_password
    * Supply a JSON object in the form `{"rcsid": <rcsid>}`
    * If email is enabled and `rcsid` represents a valid active user, sends an email to `rcsid`@rpi.edu with a reset link containing an authentication token

### Database Setup
This API interfaces with a MySQL database called `ADC` with the following tables:
* `users`
    * `rcsid VARCHAR(255)` Holds the rcsid of the user, the portion of an RPI email before the `@`
    * `password VARCHAR(255)` Holds the bcrypt-ed password of the user
    * `admin BOOLEAN` Set to TRUE if this user is an admin, FALSE otherwise
    * `enabled BOOLEAN` Set to TRUE if this account is enabled, FALSE otherwise
* `complaints`
    * `location VARCHAR(255)` The location the complaint is regarding
    * `message TEXT` The complaint itself
* `doors`
    * `name VARCHAR(255)` The name of the door
    * `location VARCHAR(255)` The pretty name of the door. This should only be used for display purposes for the end user
    * `latitude DECIMAL(10,8)` The latitude of the door
    * `longitude DECIMAL(11,8)` The longitude of the door
    * `key VARCHAR(255)` The 256 bit HMAC key used for TOTP generation for this door
    * `mac VARCHAR(255)` The MAC address of the bluetooth module for this door
* `tokens`
    * `rcsid VARCHAR(255)` The RCSid this token can authenticate for
    * `reason VARCHAR(255)` The reason this token was issued (defined values are "login" and "forgot_passwd")
    * `expiration TIMESTAMP` The UTC timestamp after which this token is no longer valid
    * `value VARCHAR(255)` The actual token value
