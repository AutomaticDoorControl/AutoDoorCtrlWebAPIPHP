<?php
//This file is used to initialize the database connection and provide
//a few database functions

//Check if the connection has generated an error
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

function makeRequest($query)
{
	global $conn;
	
	//Make the request
	$statement = $conn->prepare($query);
	$statement->execute();
	$result = $statement->get_result();
	checkError();

	//If we get back a boolean, we're done
	if (gettype($result) == 'boolean')
	{
		return "";
	}
	//If we have results, send them as a JSON array. Otherwise,
	//send back an empty array
	$resultArr = [];
	while($row = $result->fetch_assoc())
	{
		array_push($resultArr, $row);
	}
	return $resultArr;
}

function dumpRequest($query)
{
	//Output the result
	header('Content-Type: application/json');
	echo json_encode(makeRequest($query));
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
?>
