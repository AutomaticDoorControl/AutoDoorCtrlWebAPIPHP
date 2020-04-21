<?php
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

//This file provides helper functions for sending notification emails to users

function confirmationEmail($rcsid)
{
	sendEmail($rcsid . "@rpi.edu", "Welcome to ADC!", "We're currently processing your request, and we'll reach out to you as soon as possible. If you have any questions, please direct them to adc@rpiadc.com");
	error_log("Sent confirmation email to " . $rcsid);
}

function activatedEmail($rcsid, $tempPass)
{
	sendEmail($rcsid . "@rpi.edu", "Congratulations!", "Your RPI ADC account is now active. Your temporary password is " . $tempPass . ". You can use it to login at https://rpiadc.com, and don't forget to change it once you've logged in!");
	error_log("Sent activation email to " . $rcsid);
}

function passwordChangeEmail($rcsid)
{
	sendEmail($rcsid . "@rpi.edu", "Password Change Notification", "Someone (hopefully you) just changed your password. If it wasn't you, please let us know right away at webmaster@rpiadc.com");
	error_log("Sent password change email to " . $rcsid);
}

function forgotPasswordEmail($rcsid)
{
	global $resetUserPrivate, $forgotPasswordDuration;

	$forgotToken = generateToken($rcsid, "forgot-passwd", $forgotPasswordDuration);
	sendEmail($rcsid . "@rpi.edu", "Password Reset", "Someone (hopefully you) just requested a new password on this account. If it was you, please click the following link: <a href='https://rpiadc.com/api/forgot_password?token=" . $forgotToken . "'>RESET PASSWORD</a>. If it wasn't you, please let us know right away at webmaster@rpiadc.com");
	error_log("Sent forgot password email to " . $rcsid);
}

function resetPasswordEmail($rcsid, $tempPass)
{
	sendEmail($rcsid . "@rpi.edu", "Your Temporary Password", "Your password has been reset. Your temporary password is " . $tempPass . ". Please log in at https://rpiadc.com and change it as soon as possible");
	error_log("Sent new password email to " . $rcsid);
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
?>
