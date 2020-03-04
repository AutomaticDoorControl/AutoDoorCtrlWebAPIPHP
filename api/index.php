<?php
require __DIR__ . '/vendor/autoload.php';
use OTPHP\TOTP;

include 'constants.php';
include 'database.php';
include 'authentication.php';
include 'email.php';

header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Headers: authorization, content-type");

//Server requests are differentiated by request method
if ($_SERVER['REQUEST_METHOD'] === 'GET')
{
	//Because all calls to /api/* are redirected here, we must
	//decide which call we're actually making
	switch($_SERVER['REQUEST_URI'])
	{
	case '/api/get_users':
		adminAuthenticate();
		$query = '
		SELECT
			rcsid,
			enabled
		FROM
			users
		WHERE
			admin = 0';
		//Output the result
		dumpRequest($query);
		break;
	case '/api/addAll':
		$admin = adminAuthenticate();
		error_log("Admin " . $admin . " added all students to active");
		$query = '
		SELECT 
			rcsid
		FROM 
			users
		WHERE
			enabled = 0 AND
			admin = 0';
		$results = makeRequest($query);
		foreach($results as $name)
		{
			$tempPass = resetPassword($name);
			activatedEmail($name, $tempPass);
		}
		break;
	case '/api/get-complaints':
		adminAuthenticate();
		$query = 'SELECT * FROM complaints';
		//Output the result
		dumpRequest($query);
		break;
	case '/api/get-doors':
		$query = 'SELECT name, location, latitude, longitude, mac FROM doors';
		//Output the result
		dumpRequest($query);
		break;
	case '/api/renew-token':
		$token = getToken();
		$user = authenticate("login", $token);
		if($user == NULL)
		{
			header("HTTP/1.1 401 Unauthorized");
			echo "Unauthorized";
			break;
		}
		$query = 'UPDATE tokens SET expiration = ADDDATE(UTC_TIMESTAMP, INTERVAL ? SECOND) WHERE value = ?';
		$duration = $userDuration;
		if($user['admin'])
		{
			$duration = $adminDuration;
		}
		$statement = $conn->prepare($query);
		$statement->bind_param('is', $duration, $token);
		$statement->execute();
		error_log('Renewed token for ' . $user['rcsid']);
		checkError();
		break;
	case '/api/forgot-password':
		$token = $_GET['token'];
		$user = authenticate("forgot-passwd", $_GET['token']);
		if($user != NULL)
		{
			error_log("User " . $user['rcsid'] . " reset their password");
			$tempPass = resetPassword($user['rcsid']);
			resetPasswordEmail($user, $tempPass);
		}
		header("Location: https://rpiadc.com/");
		break;

	//If we don't know this call, tell our client
	default:
		header("HTTP/1.1 400 Bad Request");
		echo "Unknown API call";
		error_log("Unknown API call: GET " . $_SERVER['REQUEST_URI']);
	}
}
else if ($_SERVER['REQUEST_METHOD'] === 'POST')
{
	//Get all post data
	$postData = json_decode(file_get_contents('php://input'), true);
	switch($_SERVER['REQUEST_URI'])
	{
	case '/api/login':
		header('Content-Type: application/json');
		//If no such user exists, send back an empty SESSIONID
		$token = "";
		if(login($postData['rcsid'], $postData['password']))
		{
			//If this user exists, generate a JWT for client
			$token = generateToken($postData['rcsid'], "login", $userDuration);
		}
		//Send the token to the client
		echo json_encode(["SESSIONID"=>$token]);
		break;
	case '/api/request-access':
		error_log("Access request with rcsid " . $postData['rcsid']);
		//Insert a new student with Status Request and RSCid passed to us
		$statement = $conn->prepare('INSERT INTO users (rcsid, password, admin, enabled) VALUES (?, "", 0, 0)');
		$statement->bind_param('s', $postData['rcsid']);
		$statement->execute();
		checkError();
		confirmationEmail($postData['rcsid']);
		break;
	case '/api/addtoActive':
		//Check if user is an admin
		$admin = adminAuthenticate();
		error_log("Admin " . $admin . " added user " . $postData['rcsid'] . " to active");
		//If they are, change Status of user with RCSid passed to us to Active
		activate($postData['rcsid']);
		break;
	case '/api/remove':
		//Check if user is an admin
		$admin = adminAuthenticate();
		error_log("Admin " . $admin . " removed user " . $postData['rcsid']);
		//If they are, remove user with RCSid passed to us from db
		$statement = $conn->prepare('DELETE FROM students WHERE rcsid = ? AND admin = 0');
		$statement->bind_param('s', $postData['rcsid']);
		$statement->execute();
		checkError();
		break;
	case '/api/submit-complaint':
		//Insert a new complaint with location and message passed to us
		$statement = $conn->prepare('INSERT INTO complaints (location, message) VALUES (?, ?)');
		$statement->bind_param('ss', $postData['location'], $postData['message']);
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
		break;
	case '/api/change-password':
		//Check if credentials are correct
		if(!login($postData['rcsid'], $postData['password']))
		{
			echo "Bad credentials";
			exit;
		}
		//Create statement and hash password
		$statement = $conn->prepare('UPDATE users SET password = ? WHERE rcsid = ?');
		$newPass = password_hash($postData['newpass'], PASSWORD_BCRYPT);
		$statement->bind_param('ss', $newPass, $postData['rcsid']);
		$statement->execute();
		error_log("Changed password for " . $postData['rcsid']);
		checkError();
		//If we failed, tell them. Otherwise, success
		passwordChangeEmail($postData['rcsid']);
		break;
	case '/api/reset-password':
		//Check if user is an admin
		$admin = adminAuthenticate();
		//If they are, create the statement and hash password
		error_log("Admin " . $admin . " reset password for user " . $postData['rcsid']);
		$statement = $conn->prepare('UPDATE users SET password = ? WHERE rcsid = ? AND admin = 0');
		$newPass = password_hash($postData['newpass'], PASSWORD_BCRYPT);
		$statement->bind_param('ss', $newPass, $postData['rcsid']);
		$statement->execute();
		checkError();
		break;
	case '/api/forgot-password':
		error_log("User " . $postData['rcsid'] . " forgot their password");
		$statement = $conn->prepare('SELECT * FROM users WHERE rcsid = ? AND enabled = 1');
		$statement->bind_param('s', $postData['rcsid']);
		$statement->execute();
		checkError();
		$result = $statement->get_result();
		if($result && mysqli_num_rows($result) > 0)
		{
			forgotPasswordEmail($postData['RCSid']);
		}
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
