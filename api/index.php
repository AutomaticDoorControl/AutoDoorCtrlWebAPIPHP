<?php
require __DIR__ . '/vendor/autoload.php';
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Parser;
use OTPHP\TOTP;

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

//Configuration variables
//Holds the database connection information
$servername = 'localhost';
$username = 'developer';
$password = 'developer';
$dbname = 'users';
//Holds the filesystem location of the four keys
$adminPublic = '/var/www/keys/adminPublic.key';
$adminPrivate = '/var/www/keys/adminPrivate.key';
$userPublic = '/var/www/keys/userPublic.key';
$userPrivate = '/var/www/keys/userPrivate.key';
//Holds the length of time in seconds for which a token is valid
$userDuration = 259200;
$adminDuration = 86400;
//Holds SMTP connection info
$mailServer = 'mail.rpiadc.com';
$mailUsername = 'mailer';
$mailPassword = 'password';
$mailPort = 465;
$mailSender = 'no-reply@rpiadc.com';

header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Headers: authorization, content-type");

//Checks if the current request is authenticated using $publicKey and JWT
function authenticate($publicKeyFile)
{
	$publicKey = new Key('file://' . $publicKeyFile);
	$headers = getallheaders();
	//If the request did not pass an Authorization header,
	//it is not authorized
	if(!array_key_exists('Authorization', $headers))
		return "";
	//Requests should be prefixed with 'Bearer', this removes that
	//to extract just the token
	$authHeader = $headers['Authorization'];
	$tokenString = substr($authHeader, 7);
	//Verify the token against the admin public key
	$signer = new Sha256();
	try
	{
		$token = (new Parser())->parse((string) $tokenString);
	}
	catch(InvalidArgumentException $e)
	{
		return "";
	}
	//If unauthorized, fail. Otherwise continue
	if(!$token->verify($signer, $publicKey))
		return "";
	return $token->getClaim('sub');
}

//Using an admin JWT
function adminAuthenticate()
{
	global $adminPublic;
	$admin = authenticate($adminPublic);
	if($admin == "")
	{
		header("HTTP/1.1 401 Unauthorized");
		echo "Unauthorized";
		exit;
	}
	return $admin;
}

//Using a user JWT
function userAuthenticate()
{
	global $userPublic;
	$user = authenticate($userPublic);
	if($user == "")
	{
		header("HTTP/1.1 401 Unauthorized");
		echo "Unauthorized";
		exit;
	}
	return $user;
}

//Generate JWT with subject $subject that expires after $duration signed by $privateKeyFile
function generateJWT($privateKeyFile, $subject, $duration)
{
	//We use RS256 for verification
	$signer = new Sha256();
	$time = time();
	//Sign the JWT using the private key
	$privateKey = new Key('file://' . $privateKeyFile);
	$token = (new Builder())
		->issuedAt($time) // Configures the time that the token was issue (iat claim)
		->expiresAt($time + $duration) // Configures the expiration time of the token (exp claim)
		->setSubject($subject) // Configures the subject of the token (sub claim)
		->getToken($signer,  $privateKey); // Retrieves the generated token
	error_log("Token generated for " . $subject . " with key " . $privateKeyFile);
	return $token;
}

function userLogin($RCSid, $password)
{
	global $conn;
	//Get the list of students with RCSid passed to us. List should
	//be of length 0 or 1
	$statement = $conn->prepare('SELECT * FROM students WHERE RCSid = ? AND STATUS = "Active"');
	$statement->bind_param('s', $RCSid);
	$statement->execute();
	$result = $statement->get_result();
	if($result)
	{
		if(mysqli_num_rows($result) > 0)
		{
			$user = $result->fetch_assoc();
			//Check the bcrypted password in DB against password passed to us
			if(password_verify($password, $user['Password']))
			{
				error_log("Successful login as user " . $RCSid);
				return true;
			}
			error_log("Failed login as user " . $RCSid . ": Bad password");
			return false;
		}
		else
		{
			error_log("Failed login as user " . $RCSid . ": Bad RCSid");
			return false;
		}
	}
	else
	{
		header("HTTP/1.1 500 Internal Server Error");
		error_log(mysqli_error($conn));
		echo "Database Error";
		exit;
	}
}

function adminLogin($username, $password)
{
	global $conn;
	//Get list of admin with username passed to us. List should be
	//of length 0 or 1
	$statement = $conn->prepare('SELECT * FROM admin WHERE username = ?');
	$statement->bind_param('s', $username);
	$statement->execute();
	$result = $statement->get_result();
	if($result)
	{
		if(mysqli_num_rows($result) > 0)
		{
			$admin = $result->fetch_assoc();
			//Check the bcrypted password in DB against password passed to us
			if(password_verify($password, $admin['password']))
			{
				error_log("Successful login as admin " . $username);
				return true;
			}
			else
			{
				error_log("Failed login as admin " . $username . ": Bad password");
				return false;
			}

		}
		else
		{
			error_log("Failed login as admin " . $username . ": Bad username");
			return false;
		}
	}
	else
	{
		header("HTTP/1.1 500 Internal Server Error");
		error_log(mysqli_error($conn));
		echo "Database Error";
		exit;
	}
}

function checkError()
{
	global $conn;
	//If we failed, tell them. Otherwise, success
	if(mysqli_errno($conn))
	{
		header("HTTP/1.1 500 Internal Server Error");
		error_log(mysqli_error($conn));
		echo "Database Error";
		exit;
	}
}

function genPassword()
{
	return bin2hex(random_bytes(16));
}

function confirmationEmail($RCSid)
{
	sendEmail($RCSid . "@rpi.edu", "Welcome to ADC!", "We're currently processing your request, and we'll reach out to you as soon as possible. If you have any questions, please direct them to adc@rpiadc.com");
}

function activatedEmail($RCSid, $tempPass)
{
	sendEmail($RCSid . "@rpi.edu", "Congratulations!", "Your RPI ADC account is now active. Your temporary password is " . $tempPass . ". You can use it to login at https://rpiadc.com, and don't forget to change it once you've logged in!");
}

function passwordChangeEmail($RCSid)
{
	sendEmail($RCSid . "@rpi.edu", "Password Change Notification", "Someone (hopefully you) just changed your password. If it wasn't you, please let us know right away at webmaster@rpiadc.com");
}

function sendEmail($recipient, $subject, $message)
{
	global $mailServer, $mailUsername, $mailPassword, $mailPort, $mailSender;

	$mail = new PHPMailer(true);
	try
	{
		//Server settings
		$mail->isSMTP();					// Send using SMTP
		$mail->Host       = $mailServer;			// Set the SMTP server to send through
		$mail->SMTPAuth   = true;				// Enable SMTP authentication
		$mail->Username   = $mailUsername;			// SMTP username
		$mail->Password   = $mailPassword;			// SMTP password
		$mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;	// Enable TLS encryption; `PHPMailer::ENCRYPTION_SMTPS` also accepted
		$mail->Port       = $mailPort ;				// TCP port to connect to

		//Recipients
		$mail->setFrom($mailSender);
		$mail->addAddress($recipient);				// Add a recipient

		// Content
		$mail->isHTML(true);					// Set email format to HTML
		$mail->Subject = $subject;
		$mail->Body    = $message;

		$mail->send();
	}
	catch (Exception $e)
	{
		header("HTTP/1.1 500 Internal Server Error");
		echo "Mailer error";
		error_log($mail->ErrorInfo);
	}
}

// Create connection
$conn = mysqli_connect($servername, $username, $password, $dbname);

// Check connection
if (!$conn)
{
	header("HTTP/1.1 500 Internal Server Error");
	error_log(mysqli_error($conn));
	echo "Database Error";
	exit;
}

//Server requests are differentiated by request method
if ($_SERVER['REQUEST_METHOD'] === 'GET')
{
	//Because all calls to /api/* are redirected here, we must
	//decide which call we're actually making
	$query = '';
	switch($_SERVER['REQUEST_URI'])
	{
	case '/api/active_user':
		adminAuthenticate();
		$query = 'SELECT RCSid, Status FROM students WHERE Status = "Active"';
		break;
	case '/api/inactive_user':
		adminAuthenticate();
		$query = 'SELECT RCSid, Status FROM students WHERE Status = "Request"';
		break;
	case '/api/addAll':
		$admin = adminAuthenticate();
		error_log("Admin " . $admin . " added all students to active");
		$query = 'UPDATE students SET Status = "Active" WHERE Status = "Request"';
		break;
	case '/api/get-complaints':
		adminAuthenticate();
		$query = 'SELECT * FROM complaints';
		break;
	case '/api/get-doors':
		$query = 'SELECT name, location, latitude, longitude, mac FROM doors';
		break;
	case '/api/renew-token':
		header('Content-Type: application/json');
		$admin = authenticate($adminPublic);
		$user = authenticate($userPublic);
		if($admin != "")
		{
			//Check if user exists in database
			$statement = $conn->prepare('SELECT username FROM admin WHERE username = ?');
			$statement->bind_param('s', $admin);
			$statement->execute();
			$result = $statement->get_result();
			if($result)
			{
				if(mysqli_num_rows($result) > 0)
				{
					error_log("Admin " . $admin . " renewed their token");
					$token = generateJWT($adminPrivate, $admin, $adminDuration);
					echo json_encode(["SESSIONID"=>strval($token)]);
					exit;
				}
			}
		}
		else if($user != "")
		{
			//Check if user exists in database
			$statement = $conn->prepare('SELECT Status FROM students WHERE Status = "Active" AND RCSid = ?');
			$statement->bind_param('s', $user);
			$statement->execute();
			$result = $statement->get_result();
			if($result)
			{
				if(mysqli_num_rows($result) > 0)
				{
					error_log("User " . $user . " renewed their token");
					$token = generateJWT($userPrivate, $user, $userDuration);
					echo json_encode(["SESSIONID"=>strval($token)]);
					exit;
				}
			}
		}
		checkError();
		//If no such user exists, send back an empty SESSIONID
		echo json_encode(["SESSIONID"=>""]);
		exit;
	//If we don't know this call, tell our client
	default:
		header("HTTP/1.1 400 Bad Request");
		echo "Unknown API call";
		error_log("Unknown API call: GET " . $_SERVER['REQUEST_URI']);
		exit;
	}
	//Make the request
	$result = mysqli_query($conn, $query);
	checkError();
	if($result)
	{
		//If we get back a boolean, we're done
		if (gettype($result) == 'boolean')
		{
			exit;
		}
		//If we have results, send them as a JSON array. Otherwise,
		//send back an empty array
		header('Content-Type: application/json');
		$resultArr = [];
		while($row = mysqli_fetch_assoc($result))
		{
			array_push($resultArr, $row);
		}
		echo json_encode($resultArr);
	}
	else
	{
		header("HTTP/1.1 500 Internal Server Error");
		error_log(mysqli_error($conn));
		echo "Database Error";
		exit;
	}
}
else if ($_SERVER['REQUEST_METHOD'] === 'POST')
{
	//Get all post data
	$postData = json_decode(file_get_contents('php://input'), true);
	switch($_SERVER['REQUEST_URI'])
	{
	case '/api/login':
		if(!userLogin($postData['RCSid'], $postData['password']))
		{
			//If no such user exists, send back an empty SESSIONID
			header('Content-Type: application/json');
			echo json_encode(["SESSIONID"=>""]);
			exit;
		}
		//If this user exists, generate a JWT for client
		$token = generateJWT($userPrivate, $postData['RCSid'], $userDuration);
		checkError();
		//Send the token to the client
		header('Content-Type: application/json');
		echo json_encode(["SESSIONID"=>strval($token)]);
		break;
	case '/api/admin/login':
		if(!adminLogin($postData['username'], $postData['password']))
		{
			//If no such admin exists, send back an empty SESSIONID
			header('Content-Type: application/json');
			echo json_encode(["SESSIONID"=>""]);
			exit;
		}
		//If this admin exists and the passwords match, generate a JWT
		$token = generateJWT($adminPrivate, $postData['username'], $adminDuration);
		checkError();
		//Send the token to the client
		header('Content-Type: application/json');
		echo json_encode(["SESSIONID"=>strval($token)]);
		break;
	case '/api/request-access':
		error_log("Access request with RCSid " . $postData['RCSid']);
		//Insert a new student with Status Request and RSCid passed to us
		$statement = $conn->prepare('INSERT INTO students (RCSid, Status, Password) VALUES (?, "Request", "")');
		$statement->bind_param('s', $postData['RCSid']);
		$statement->execute();
		checkError();
		confirmationEmail($postData['RCSid']);
		break;
	case '/api/addtoActive':
		//Check if user is an admin
		$admin = adminAuthenticate();
		error_log("Admin " . $admin . " added user " . $postData['RCSid'] . " to active");
		//If they are, change Status of user with RCSid passed to us to Active
		$tempPass = genPassword();
		$statement = $conn->prepare('UPDATE students SET Status = "Active", Password = "' . password_hash($tempPass, PASSWORD_BCRYPT) . '" WHERE RCSid = ?');
		$statement->bind_param('s', $postData['RCSid']);
		$statement->execute();
		checkError();
		activatedEmail($postData['RCSid'], $tempPass);
		break;
	case '/api/remove':
		//Check if user is an admin
		$admin = adminAuthenticate();
		error_log("Admin " . $admin . " removed user " . $postData['RCSid']);
		//If they are, remove user with RCSid passed to us from db
		$statement = $conn->prepare('DELETE FROM students WHERE RCSid = ?');
		$statement->bind_param('s', $postData['RCSid']);
		$statement->execute();
		checkError();
		break;
	case '/api/submit-complaint':
		//Insert a new complaint with location and message passed to us
		$statement = $conn->prepare('INSERT INTO complaints (location, message) VALUES (?, ?)');
		$statement->bind_param('ss', $postData['Location'], $postData['Message']);
		$statement->execute();
		checkError();
		break;
	case '/api/open-door':
		//Check if client is a user
		$user = userAuthenticate();
		error_log("User " . $user . " opened door " . $postData['door']);
		//If they are, get the private key from the door
		$statement = $conn->prepare('SELECT `key` FROM doors WHERE name = ?');
		$statement->bind_param('s', $postData['door']);
		$statement->execute();
		$result = $statement->get_result();
		checkError();
		if($result)
		{
			if(mysqli_num_rows($result) > 0)
			{
				//If we get the key, generate a TOTP from the key
				//and send it to the client
				$secret = mysqli_fetch_assoc($result)['key'];
				$otp = TOTP::create($secret, 30, 'sha1', 6);
				echo json_encode(['TOTP'=>strval($otp->now())]);
			}
			else
			{
				header("HTTP/1.1 400 Bad Request");
				error_log("No such door");
				echo "Door not found";
			}
		}
		else
		{
			header("HTTP/1.1 500 Internal Server Error");
			error_log(mysqli_error($conn));
			echo "Database Error";
		}
		break;
	case '/api/change-password':
		//Check if credentials are correct
		if(!userLogin($postData['RCSid'], $postData['password']))
		{
			echo "Bad credentials";
			exit;
		}
		//Create statement and hash password
		$statement = $conn->prepare('UPDATE students SET Password = ? WHERE RCSid = ?');
		$newPass = password_hash($postData['newPassword'], PASSWORD_BCRYPT);
		$statement->bind_param('ss', $newPass, $postData['RCSid']);
		$statement->execute();
		checkError();
		$result = $statement->get_result();
		error_log("Changed password for user " . $postData['RCSid']);
		//If we failed, tell them. Otherwise, success
		passwordChangeEmail($postData['RCSid']);
		break;
	case '/api/admin/change-password':
		//Check if credentials are correct
		if(!adminLogin($postData['username'], $postData['password']))
		{
			echo "Bad credentials";
			exit;
		}
		//Create statement and hash password
		$statement = $conn->prepare('UPDATE admin SET password = ? WHERE username = ?');
		$newPass = password_hash($postData['newPassword'], PASSWORD_BCRYPT);
		$statement->bind_param('ss', $newPass, $postData['username']);
		$statement->execute();
		checkError();
		$result = $statement->get_result();
		error_log("Changed password for admin " . $postData['username']);
		break;
	case '/api/reset-password':
		//Check if user is an admin
		$admin = adminAuthenticate();
		//If the are, create the statement and hash password
		error_log("Admin " . $admin . " reset password for user " . $postData['RCSid']);
		$statement = $conn->prepare('UPDATE students SET Password = ? WHERE RCSid = ?');
		$newPass = password_hash($postData['newPassword'], PASSWORD_BCRYPT);
		$statement->bind_param('ss', $newPass, $postData['RCSid']);
		$statement->execute();
		checkError();
		$result = $statement->get_result();
		break;
	default:
		header("HTTP/1.1 400 Bad Request");
		echo "Unknown API call";
		error_log("Unknown API call: POST " . $_SERVER['REQUEST_URI']);
		exit;
	}
}
else if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS')
{
	echo "good";
}
else
{
	//If we get a request that is neither POST nor GET, fail
	header("HTTP/1.1 400 Bad Request");
	echo $_SERVER['REQUEST_METHOD'] . " requests are not accepted by this API";
}
?>
