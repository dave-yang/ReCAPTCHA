<?php

/**
 * ReCAPTCHA Provider
 * 
 * Copyright (c) No Global State Lab
 * 
 * Licensed under BSD-3
 */

class ReCaptcha
{
	/**
	 * Last error message
	 * 
	 * @var string
	 */
	protected $error = null;

	/**
	 * User-provided public key
	 * 
	 * @var string
	 */
	protected $publicKey;

	/**
	 * User-provided private key
	 * 
	 * @var string
	 */
	protected $privateKey;

	/**
	 * Whether SSL is used or not
	 * 
	 * @var boolean
	 */
	protected $ssl;

	/**
	 * Client's IP address
	 * 
	 * @var string
	 */
	protected $ip;

	/**
	 * Additional parameters when asking a response from the server
	 * 
	 * @var array
	 */
	protected $extra = array();

	const RECAPTCHA_API_SECURE_SERVER = 'https://www.google.com/recaptcha/api';
	const RECAPTCHA_API_SERVER = 'http://www.google.com/recaptcha/api';
	const RECAPTCHA_HOST_SERVER = 'www.google.com';
	const RECAPTCHA_VERIFY_PATH = '/recaptcha/api/verify';

	/**
	 * State initialization
	 * 
	 * @param string $publicKey Public key is provided by the service
	 * @param string $privateKey Private key is provided by the service
	 * @param string $ip Client IP address
	 * @param boolean $ssl Whether to use secure connection. False by default
	 * @param array $extra Extra parameters to be added when making a request
	 * @return void
	 */
	public function __construct($publicKey, $privateKey, $ip, $ssl = false, array $extra = array())
	{
		$this->publicKey = $publicKey;
		$this->privateKey = $privateKey;
		$this->ip = $ip;
		$this->ssl = $ssl;
		$this->extra = $extra;
	}

	/**
	 * Renders a widget
	 * 
	 * @return void
	 */
	public function render()
	{
		require(dirname(__FILE__) . '/recaptcha-widget.phtml');
	}

	/**
	 * Returns last error message
	 * 
	 * @return string
	 */
	public function getError()
	{
		return $this->error;
	}

	/**
	 * Returns the path to a JavaScript script service
	 * 
	 * @return string
	 */
	public function getScriptUrl()
	{
		return $this->getServiceUrl('challenge');
	}

	/**
	 * Returns the path to IFRAME. Should be used when JS is not available
	 * 
	 * @return string
	 */
	public function getNoscriptUrl()
	{
		return $this->getServiceUrl('noscript');
	}

	/**
	 * Checks whether ReCapctha is valid
	 * 
	 * @param string $challenge
	 * @param string $target
	 * @return boolean
	 */
	public function isValid($challenge, $target)
	{
		if (empty($challenge) || empty($target)) {
			$this->error = 'incorrect-captcha-sol';
			return false;
		}
		
		$raw = $this->getServiceResponse($challenge, $target);
		
		$response = explode ("\n", $raw[1]);
		
		if (isset($response[0]) &&  trim($response[0] == 'true')) {
			return true;
			
		} else {
			
			$this->error = $response[1];
			return false;
		}
	}

	/**
	 * Makes request and returns the response from the server
	 * 
	 * @param string $challenge
	 * @param string $response
	 * @return array
	 */
	protected function getServiceResponse($challenge, $response)
	{
		$data = array(
			'privatekey' => $this->privateKey,
			'remoteip' => $this->ip,
			'challenge' => $challenge,
			'response' => $response
		);

		// In case we had optional parameters
		$data = array_merge($data, $this->extra);
		return $this->request(self::RECAPTCHA_HOST_SERVER, self::RECAPTCHA_VERIFY_PATH, $data);
	}

	/**
	 * Returns a server depending on SSL class option
	 * 
	 * @return string
	 */
	protected function getServer()
	{
		return $this->ssl !== false ? self::RECAPTCHA_API_SECURE_SERVER : self::RECAPTCHA_API_SERVER;
	}

	/**
	 * Returns service URL
	 * 
	 * @param string $type Either 'challenge' or 'noscript'
	 * @return string
	 */
	protected function getServiceUrl($type)
	{
		if ($this->error !== null) {
			$error = "&amp;error=" . $this->error;
		}

		return sprintf('%s/%s?k=%s', $this->getServer(), $type, $this->publicKey) . $error;
	}

	/**
	 * Makes a request to the service
	 * 
	 * @param string $host
	 * @param string $path
	 * @param array $data
	 * @param integer $port Default port when opening a socket
	 * @throws RuntimeException When connection isn't available
	 * @return array
	 */
	protected function request($host, $path, array $data, $port = 80)
	{
		$query = http_build_query($data);

		// Prepare headers for POST request
		$headers = array(
			sprintf('POST %s HTTP/1.0', $path),
			sprintf('Host: %s', $host),
			sprintf('Content-Type: application/x-www-form-urlencoded;'),
			sprintf('Content-Length: %s', strlen($query)),
			'User-Agent: reCAPTCHA/PHP',
			'',
			$query
		);

		$data = implode(PHP_EOL, $headers);

		//@ - intentionally
		$sock = @fsockopen($host, $port, $errno, $errstr, 10);

		if (false == $sock) {
			throw new RuntimeException('Could not open a socket. Make sure that the connection is available');
		}

		fwrite($sock, $data);

		$response = '';

		while (!feof($sock)) {
			$response .= fgets($sock, 1160);
		}

		fclose($sock);
		$response = explode("\r\n\r\n", $response, 2);

		return $response;
	}
}
