<?php

/**
 * Improved Re-CAPTCHA implementation (for 1.0)
 */

require(dirname(__FILE__) . '/ReCaptcha.php');

// Type yours
$privateKey = '';
$publicKey = '';


$recaptcha = new ReCaptcha($publicKey, $privateKey, $_SERVER['REMOTE_ADDR']);

// Check if the form is submitted
if (!empty($_POST)) {
	
	if ($recaptcha->isValid($_POST['recaptcha_challenge_field'], $_POST['recaptcha_response_field'])) {
		die('Valid!');
	} else {
		die($recaptcha->getError());
	}
}

?>

<form method="POST">
	
	<?php $recaptcha->render(); ?>
	
	<br />
	
	<button type="submit">Submit</button>
	
</form>
