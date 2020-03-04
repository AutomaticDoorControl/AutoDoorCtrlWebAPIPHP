<?php
//Configuration variables that alter how the API integrates with the
//mailer and database
//
//Holds the database connection information
$servername = 'localhost';
$username = 'developer';
$password = 'developer';
$dbname = 'ADC';

//Holds the length of time in seconds for which a token is valid
$loginDuration = 259200; //72 hours
$forgotPasswordDuration = 1800; //30 minutes

//Holds SMTP connection info
$mailServer = 'mail.rpiadc.com';
$mailUsername = 'mailer';
$mailPassword = 'password';
$mailPort = 465;
$mailSender = 'no-reply@rpiadc.com';
?>
