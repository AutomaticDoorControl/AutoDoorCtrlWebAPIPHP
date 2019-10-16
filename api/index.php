<?php
require __DIR__ . '/vendor/autoload.php';
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Parser;

//Checks if the current request is authenticated
//using an admin JWT
function adminAuthenticate()
{
	$headers = getallheaders();
	//If the request did not pass an Authorization header,
	//it is not authorized
	if(!array_key_exists('Authorization', $headers))
	{
		header("HTTP/1.1 401 Unauthorized");
		echo "Unauthorized";
		exit;
	}
	//Requests should be prefixed with 'bearer', this removes that
	//to extract just the token
	$authHeader = $headers['Authorization'];
	$tokenString = substr($authHeader, 7);
	//Verify the token against the admin public key
	$signer = new Sha256();
	global $keyStore;
	$adminPublicKey = new Key('file://' . $keyStore . '/adminPublic.key');
	$token = (new Parser())->parse((string) $tokenString);
	//If unauthorized, fail. Otherwise continue
	if(!$token->verify($signer, $adminPublicKey))
	{
		header("HTTP/1.1 401 Unauthorized");
		echo "Unauthorized";
		exit;
	}
}

//Holds the database connection information
$servername = 'localhost';
$username = 'developer';
$password = 'developer';
$dbname = 'users';
//Holds the filesystem location of the four keys
$keyStore = '/var/www/keys';

// Create connection
$conn = mysqli_connect($servername, $username, $password, $dbname);

// Check connection
if (!$conn)
{
	header("HTTP/1.1 500 Internal Server Error");
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
		$query = 'SELECT * FROM students WHERE Status = "Active"';
		break;
	case '/api/inactive_user':
		adminAuthenticate();
		$query = 'SELECT * FROM students WHERE Status = "Request"';
		break;
	case '/api/addAll':
		adminAuthenticate();
		$query = 'UPDATE students SET Status = "Active" WHERE Status = "Request"';
		break;
	case '/api/get-complaints':
		adminAuthenticate();
		$query = 'SELECT * FROM complaints';
		break;
	case '/api/get-doors':
		$query = 'SELECT * FROM doors';
		break;
	//If we don't know this call, tell our client
	default:
		header("HTTP/1.1 400 Bad Request");
		echo "Unknown API call";
		exit;
	}
	//Make the request
	$result = mysqli_query($conn, $query);
	if($result)
	{
		//If we have results, send them as a JSON array. Otherwise,
		//send back an empty array
		header('Content-Type: application/json');
		if (mysqli_num_rows($result) > 0) {
			$resultArr = [];
			while($row = mysqli_fetch_assoc($result)) {
				array_push($resultArr, $row);
			}
			echo json_encode($resultArr);
		}
		else
		{
			echo json_encode([]);
		}
	}
	else
	{
		header("HTTP/1.1 500 Internal Server Error");
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
		//Get the list of students with RCSid passed to us. List should
		//be of length 0 or 1
		$statement = $conn->prepare('SELECT * FROM students WHERE RCSid = ?');
		$statement->bind_param('s', $postData['RCSid']);
		$statement->execute();
		$result = $statement->get_result();
		if($result)
		{
			header('Content-Type: application/json');
			if(mysqli_num_rows($result) > 0)
			{
				//If this user exists, generate a JWT for client
				$signer = new Sha256();
				$time = time();
				//Sign the JWT using the user private key
				$userPrivateKey = new Key('file://' . $keyStore . '/userPrivate.key');
				$token = (new Builder())
					->issuedAt($time) // Configures the time that the token was issue (iat claim)
					->expiresAt($time + 3600) // Configures the expiration time of the token (exp claim)
					->setSubject($postData['RCSid']) // Configures the subject of the token (sub claim)
					->getToken($signer,  $userPrivateKey); // Retrieves the generated token
				//Send the token to the client
				echo json_encode(["SESSIONID"=>strval($token)]);
			}
			else
			{
				//If no such user exists, send back an empty SESSIONID
				echo json_encode(["SESSIONID"=>""]);
			}
		}
		else
		{
			header("HTTP/1.1 500 Internal Server Error");
			echo "Database Error";
			exit;
		}
		break;
	case '/api/admin/login':
		//Get list of admin with username passed to us. List should be
		//of length 0 or 1
		$statement = $conn->prepare('SELECT * FROM admin WHERE username = ?');
		$statement->bind_param('s', $postData['username']);
		$statement->execute();
		$result = $statement->get_result();
		if($result)
		{
			header('Content-Type: application/json');
			if(mysqli_num_rows($result) > 0)
			{
				$admin = $result->fetch_assoc();
				//Check the bcrypted password in DB against password passed to us
				if(password_verify($postData['password'], $admin['password']))
				{
					//If this admin exists and the passwords match, generate a JWT
					//signed with the admin private key
					$signer = new Sha256();
					$time = time();
					$adminPrivateKey = new Key('file://' . $keyStore . '/adminPrivate.key');
					$token = (new Builder())
						->issuedAt($time) // Configures the time that the token was issue (iat claim)
						->expiresAt($time + 3600) // Configures the expiration time of the token (exp claim)
						->setSubject($postData['username']) // Configures the subject of the token (sub claim)
						->getToken($signer,  $adminPrivateKey); // Retrieves the generated token
					//Send the token to the client
					echo json_encode(["SESSIONID"=>strval($token)]);
				}
				else
				{
					//If password is incorrect, send back an empty SESSIONID
					echo json_encode(["SESSIONID"=>""]);
				}

			}
			else
			{
				//If no such user exists, send back an empty SESSIONID
				echo json_encode(["SESSIONID"=>""]);
			}
		}
		else
		{
			header("HTTP/1.1 500 Internal Server Error");
			echo "Database Error";
			exit;
		}
		break;
	case '/api/request-access':
		//Insert a new student with Status Request and RSCid passed to us
		$statement = $conn->prepare('INSERT INTO students (RCSid, Status) VALUES (?, "Request")');
		$statement->bind_param('s', $postData['RCSid']);
		$statement->execute();
		//Return nothing
		echo "[]";
		break;
	case '/api/addtoActive':
		//Check if user is an admin
		adminAuthenticate();
		//If they are, change Status of user with RCSid passed to us to Active
		$statement = $conn->prepare('UPDATE students SET Status = "Active" WHERE RCSid = ?');
		$statement->bind_param('s', $postData['RCSid']);
		$statement->execute();
		//Return nothing
		echo "[]";
		break;
	case '/api/remove':
		//Check if user is an admin
		adminAuthenticate();
		//If they are, remove user with RCSid passed to us from db
		$statement = $conn->prepare('DELETE FROM students WHERE RCSid = ?');
		$statement->bind_param('s', $postData['RCSid']);
		$statement->execute();
		//Return nothing
		echo "[]";
		break;
	case '/api/submit-complaint':
		//Insert a new complaint with location and message passed to us
		$statement = $conn->prepare('INSERT INTO complaints (location, message) VALUES (?, ?)');
		$statement->bind_param('ss', $postData['Location'], $postData['Message']);
		$statement->execute();
		//Return nothing
		echo "[]";
		break;
	default:
		header("HTTP/1.1 400 Bad Request");
		echo "Unknown API call";
		exit;
	}
}
else
{
	//If we get a request that is neither POST nor GET, fail
	header("HTTP/1.1 500 Internal Server Error");
	echo $_SERVER['REQUEST_METHOD'] . " requests are not accepted by this API";
}
?>
