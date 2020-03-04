<?php
//This file holds all of the functions to authenticate a user and generate
//authentication material like tokens

//Generates 16 bytes of hex encoded randomness
function genRandom()
{
	return bin2hex(random_bytes(16));
}

//Checks if the current request is authenticated using a token
function getToken()
{
	$headers = getallheaders();
	//If the request did not pass an Authorization header,
	//it is not authorized
	if(!array_key_exists('Authorization', $headers))
		return "";
	//Requests should be prefixed with 'Bearer', this removes that
	//to extract just the token
	$authHeader = $headers['Authorization'];
	$tokenString = substr($authHeader, 7);
	return $tokenString;
}

function authenticate($reason, $tokenString)
{
	global $conn;

	//Get the rcsid and admin status of the user associated with
	//this token, checking that the account is enabled and the token
	//is not expired
	$query = '
	SELECT
		rcsid,
		admin
	FROM
		users
	WHERE
		enabled = 1 AND
		rcsid =
		(
			SELECT
				rcsid
			FROM
				tokens
			WHERE
				expiration > UTC_TIMESTAMP AND
				reason = ? AND
				value = ?
		);';

	//Run the query
	$statement = $conn->prepare($query);
	$statement->bind_param('ss', $reason, $tokenString);
	$statement->execute();
	checkError();
	$result = $statement->get_result();
	//If we have a result, return it. Otherwise give back NULL
	if($result && mysqli_num_rows($result) > 0)
	{
		return $result->fetch_assoc();
	}
	return NULL;
}

//Using an admin JWT
function adminAuthenticate()
{
	$token = getToken();
	//Try to authenticate the request, we succeed if the token is
	//valid and if the token is for an admin
	$userObj = authenticate("login", $token);
	if($userObj == NULL || $userObj['admin'] != 1)
	{
		header("HTTP/1.1 401 Unauthorized");
		echo "Unauthorized";
		exit;
	}
	return $userObj['rcsid'];
}

//Using a user JWT
function userAuthenticate()
{
	$token = getToken();
	//Try to authenticate the request, we succeed if the token is
	//valid for a user OR an admin
	$userObj = authenticate("login", $token);
	if($userObj == NULL)
	{
		header("HTTP/1.1 401 Unauthorized");
		echo "Unauthorized";
		exit;
	}
	return $userObj['rcsid'];
}

//Generate token for $user with duration $duration and upload it to the database
function generateToken($rcsid, $reason, $duration)
{
	global $conn;

	$token = genRandom();

	//Get the rcsid and admin status of the user associated with
	//this token, checking that the account is enabled and the token
	//is not expired
	$query = '
	INSERT INTO
		tokens
		(
			rcsid,
			reason,
			expiration,
			value
		)
	VALUES
	(
		?,
		?,
		ADDDATE(UTC_TIMESTAMP, INTERVAL ? SECOND),
		?
	)';

	//Run the query
	$statement = $conn->prepare($query);
	$statement->bind_param('ssis', $rcsid, $reason, $duration, $token);
	$statement->execute();
	checkError();
	error_log("Token generated for " . $rcsid);
	return $token;
}

function login($user, $password)
{
	global $conn;

	$query = '
	SELECT
		password
	FROM
		users
	WHERE
		enabled = 1 AND
		rcsid = ?';
	$statement = $conn->prepare($query);
	$statement->bind_param('s', $user);
	$statement->execute();
	checkError();
	$result = $statement->get_result();
	if(mysqli_num_rows($result) == 0)
	{
		error_log("Failed login as " . $user . ": Bad rcsid");
		return false;
	}
	$hash = $result->fetch_assoc()['password'];
	if(password_verify($password, $hash))
	{
		error_log("Successful login as " . $user);
		return true;
	}
	error_log("Failed login as " . $user . ": Bad password");
	return false;
}

function resetPassword($rcsid)
{
	global $conn;

	$tempPass = genRandom();
	$hash = password_hash($tempPass, PASSWORD_BCRYPT);
	$statement = $conn->prepare('UPDATE users SET enabled = 1, password = ? WHERE rcsid = ?');
	$statement->bind_param('ss', $hash, $rcsid);
	$statement->execute();
	checkError();
	return $tempPass;
}

