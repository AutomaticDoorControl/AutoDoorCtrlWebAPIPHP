# AutoDoorCtrlWebAPIPHP
AutoDoorCtrlWebAPIPHP is the API we use to connect our Angular web app to our MySQL database. The API is written in PHP, with some `.htaccess` files provided to make everything run smoothly. The repository for the website can be found [Here](https://github.com/AutomaticDoorControl/AutoDoorCtrlWeb)

## What to install
  * clone respository `https://github.com/AutomaticDoorControl/AutoDoorCtrlWebAPIPHP.git`
  * navigate to AutoDoorCtrlWebAPIPHP on your machine
  * in folder `api`, run `composer install` to install dependencies
  * copy `.htaccess` and the folder `api` to /var/www/html
  * NOTE: This API will not work without the use of a properly setup MySQL database. Point the API to the db by changing `servername`, `username`, `password`, and `dbname` in `index.php`
  * NOTE: This API will not work without two public/private keypairs. Point the API to these keys by changing `adminPublic`, `adminPrivate`, `userPublic`, and `userPrivate` in `index.php`
  * NOTE: If you get permissions errors, it may be helpful to change ownership of files to `www-data` by running `sudo chown www-data:www-data /var/www/html/* /var/www/keys/*`, assuming you are using default paths

## API Calls
Users are JSON objects in the form `{"Status": "Active|Request", "RCSid": <RCSid>}`

Admins are JSON objects in the form `{"username": <username>, "password": <bcrypted password>}`

Requests with a star (\*) require admin authentication, otherwise they will return a `401 Unauthorized` error. Authentication is handled by sending the header `Authorization: Bearer <JWT>` as part of the request, where `<JWT>` is the Json Web Token recieved during login. User JWTs are not valid for admin authentication.

Requests with a plus (+) require user authentication. Authentication is handled in the same manner as for admin. 

### GET requests
* /api/active_user \*
    * Returns an array of all Users where Status is `Active`
* /api/inactive_user \*
    * Returns an array of all Users where Status is `Request`
* /api/addAll \*
    * Changes all Users' Status to `Active`
    * Returns a throwaway value
* /api/get-complaints \*
    * Returns an array of JSON items in the form `{"location": <location>, "message": <message>}`
* /api/get-doors
    * Returns an array of JSON items in the form `{"name": <name>, "location": <location>, "latitude": <latitude>, "longitude": <longitude>, "mac": <MACAdress>}`
* /api/renew-token \*/+
    * Returns a JSON object in the form `{"SESSIONID": <JWT>}` where `<JWT>` is a signed JSON web token with `sub` field matching `sub` field of token used to authenticate. Additionally, `<JWT>` will be signed with the same key as the token used to authenticate, so both users and admins can use this call. If authentication fails, `<JWT>` will be an empty string `""` 

### POST requests
* /api/login
    * Supply a JSON object in the form `{"RCSid": <RCSid>, "password": <password>}`
    * Returns a JSON object in the form `{"SESSIONID": <JWT>}` where `<JWT>` is a signed JSON web token with `sub` field matching `<RCSID>`
    * If `<RCSid>` and `<password>` do not together represent a valid active user, `<JWT>` will be an empty string `""`
* /api/admin/login
    * Supply a JSON object in the form `{"username": <username>, "password": <password>}`
    * Returns a JSON object in the form `{"SESSIONID": <JWT>}` where `<JWT>` is a signed JSON web token with `sub` field matching `<username>`
    * If `<username>` and `<password>` do not together represent a valid active user, `<JWT>` will be an empty string `""`
* /api/request-access
    * Supply a JSON object in the form `{"RCSid": <RCSid>}`
    * Adds a row to Users with the values `{"Status": Request, "RCSid": <RCSid>}`
    * Returns a throwaway value
* /api/addtoActive \*
    * Supply a JSON object in the form `{"RCSid": <RCSid>}`
    * Changes the status of User with RCSid `<RCSid>` to `Active`
    * Returns a throwaway value
* /api/remove \*
    * Supply a JSON object in the form `{"RCSid": <RCSid>}`
    * Deletes all Users with RCSid `<RCSid>`
    * Returns a throwaway value
* /api/submit-complaint
    * Supply a JSON object in the form `{"Location": <location>, "Message": <message>}`
    * Stores the complaint in the server
    * Returns a throwaway value
* /api/open-door +
    * Supply a JSON object in the form `{"door": <doorname>}`
    * Returns a JSON object in the form `{"TOTP": <TOTP>}` where <TOTP> is a one-time password which can be used to open the specified door.
* /api/change-password
    * Supply a JSON object in the form `{"RCSid": <RCSid>, "password": <password>, "newPassword": <newPassword>}`
    * If supplied valid credentials, changes password for user `<RCSid>` from `<password>` to `<newPassword>`
* /api/admin/change-password
    * Supply a JSON object in the form `{"username": <username>, "password": <password>, "newPassword": <newPassword>}`
    * If supplied valid credentials, changes password for admin `<username>` from `<password>` to `<newPassword>`
* /api/reset-password *
    * Supply a JSON object in the form `{"RCSid": <RCSid>, "newPassword": <newPassword>}`
    * Changes the password of user `<RCSid>` to `<newPassword>`
