<?php
require __DIR__ . '/vendor/autoload.php';
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Parser;

function adminAuthenticate()
{
	$headers = getallheaders();
	if(!array_key_exists('Authorization', $headers))
	{
		header("HTTP/1.1 401 Unauthorized");
		echo "Unauthorized";
		exit;
	}
	$authHeader = $headers['Authorization'];
	$tokenString = substr($authHeader, 7);
	$signer = new Sha256();
	global $keyStore;
	$adminPublicKey = new Key('file://' . $keyStore . '/adminPublic.key');
	$token = (new Parser())->parse((string) $tokenString);
	if(!$token->verify($signer, $adminPublicKey))
	{
		header("HTTP/1.1 401 Unauthorized");
		echo "Unauthorized";
		exit;
	}
}

$servername = 'localhost';
$username = 'developer';
$password = 'developer';
$dbname = 'users';
$keyStore = '/var/www/keys';

// Create connection
$conn = mysqli_connect($servername, $username, $password, $dbname);

// Check connection
if (!$conn) {
	die('Connection failed: ' . mysqli_connect_error());
}

if ($_SERVER['REQUEST_METHOD'] === 'GET')
{
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
	default:
		echo "Unknown API call";
		exit;
	}
	$result = mysqli_query($conn, $query);
	if($result)
	{
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
		echo "Error: " . mysqli_error($conn);
	}
}
else if ($_SERVER['REQUEST_METHOD'] === 'POST')
{
	$query = '';
	$postData = json_decode(file_get_contents('php://input'), true);
	switch($_SERVER['REQUEST_URI'])
	{
	case '/api/login':
		$statement = $conn->prepare('SELECT * FROM students WHERE RCSid = ?');
		$statement->bind_param('s', $postData['RCSid']);
		$statement->execute();
		$result = $statement->get_result();
		if($result)
		{
			header('Content-Type: application/json');
			if(mysqli_num_rows($result) > 0)
			{
				$signer = new Sha256();
				$time = time();
				$userPrivateKey = new Key('file://' . $keyStore . '/userPrivate.key');
				$token = (new Builder())
					->issuedAt($time) // Configures the time that the token was issue (iat claim)
					->expiresAt($time + 3600) // Configures the expiration time of the token (exp claim)
					->setSubject($postData['RCSid'])
					->getToken($signer,  $userPrivateKey); // Retrieves the generated token
				echo json_encode(["SESSIONID"=>strval($token)]);
			}
			else
			{
				echo json_encode(["SESSIONID"=>""]);
			}
		}
		else
		{
			echo "Error: " . mysqli_error($conn);
		}
		break;
	case '/api/admin/login':
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
				if(password_verify($postData['password'], $admin['password']))
				{
					$signer = new Sha256();
					$time = time();
					$adminPrivateKey = new Key('file://' . $keyStore . '/adminPrivate.key');
					$token = (new Builder())
						->issuedAt($time) // Configures the time that the token was issue (iat claim)
						->expiresAt($time + 3600) // Configures the expiration time of the token (exp claim)
						->setSubject($postData['username'])
						->getToken($signer,  $adminPrivateKey); // Retrieves the generated token
					echo json_encode(["SESSIONID"=>strval($token)]);
				}
				else
				{
					echo json_encode(["SESSIONID"=>""]);
				}

			}
			else
			{
				echo json_encode(["SESSIONID"=>""]);
			}
		}
		else
		{
			echo "Error: " . mysqli_error($conn);
		}
		break;
	case '/api/request-access':
		$statement = $conn->prepare('INSERT INTO students (RCSid, Status) VALUES (?, "Request")');
		$statement->bind_param('s', $postData['RCSid']);
		$statement->execute();
		echo "[]";
		break;
	case '/api/addtoActive':
		adminAuthenticate();
		$statement = $conn->prepare('UPDATE students SET Status = "Active" WHERE RCSid = ?');
		$statement->bind_param('s', $postData['RCSid']);
		$statement->execute();
		echo "[]";
		break;
	case '/api/remove':
		adminAuthenticate();
		$statement = $conn->prepare('DELETE FROM students WHERE RCSid = ?');
		$statement->bind_param('s', $postData['RCSid']);
		$statement->execute();
		echo "[]";
		break;
	case '/api/submit-complaint':
		$statement = $conn->prepare('INSERT INTO complaints (location, message) VALUES (?, ?)');
		$statement->bind_param('ss', $postData['Location'], $postData['Message']);
		$statement->execute();
		echo "[]";
		break;
	default:
		echo "Unknown API call";
		exit;
	}
}
else
{
	echo $_SERVER['REQUEST_METHOD'] . " requests are not accepted by this API";
}
?>
