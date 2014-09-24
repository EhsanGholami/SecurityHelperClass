<?php
/*
 * Copyright 2014 Pouya Darabi Pouyyadarabi@gmail.com 
 * 
 * LICENSE: This source file is subject to version 3.01 of the PHP license
 * that is available through the world-wide-web at the following URI:
 * http://www.php.net/license/3_01.txt.  If you did not receive a copy of
 * the PHP License and are unable to obtain it through the web, please
 * send a note to license@php.net so we can mail you a copy immediately.
 */

/**
 *
 * @author Pouya Darabi <Pouyyadarabi@gmail.com>
 * @version 1
 * @category   Security
 * @copyright  Copyright (c) 2014, Pouya Darabi
 * @license    http://www.php.net/license/3_01.txt  PHP License 3.01
 *         
 */
class SecurityHelper {


	private static $_instance;

	private $badChars;

	public $Type_Integer  = 1;
	public $Type_String = 2;
	public $Type_Float = 3;
	public $Type_Date = 4;
	public $Type_Email = 5;
	public $Type_Array = 6;

	public $Request_POST = 1;
	public $Request_GET = 2;


	private $Blowfish_Pre = '$6$rounds=5000$';
	private $Blowfish_End = '$';

	private $salt_Pre = '%!@#*&%';
	private $salt_End = '/\<,>';
    
	public function __construct(){

		$this->badChars = array_merge ( array_map ( 'chr', range ( 0, 31 ) ), array ("<",">",":",'"',"/","\\","|","?","*" ), array ('CON','PRN','AUX','NUL','COM1','COM2','COM3','COM4','COM5','COM6','COM7','COM8','COM9','LPT1','LPT2','LPT3','LPT4','LPT5','LPT6','LPT7','LPT8','LPT9' ) );
	}
	/**
	 *
	 * @param string $str  <p>
	 * The Variable being checked.
	 * </p>
	 * @param number $Type   <p>
	 * Type of check using Type_ prefix in this class
	 * </p>
	 * @return boolean
	 *
	 */
	public function CheckType($str, $Type) {
		switch ($Type){
			case $this->Type_Date :
				return $this->TypeDate ( $str );
			case $this->Type_Integer :
				return $this->TypeInteger ( $str );
			case $this->Type_Email :
				return $this->TypeEmail ( $str );
			case $this->Type_Float :
				return $this->TypeFloat ( $str );
			case $this->Type_Array :
				return $this->TypeArray ( $str );
			case $this->Type_String :
				return $this->TypeString ( $str );
			default:
				return false;
		}

	}

	/**
	 *
	 * @param mixed $str <p>
	 * The Variable being cleaned.
	 * </p>   	      	
	 * @return mixed This function returns a string or an array with the cleaned values.
	 */
	public function CleanXss($str) {

		if (is_array ( $str )) {
			array_walk_recursive ( $str, array ($this,'CleanXssHelper') );
			return $str;
		}
		return strip_tags ( htmlentities ( $str, ENT_QUOTES, 'utf-8' ) );
	}

	/**
	 *
	 * @param mixed $badinput <p>
	 * The Variable being cleaned.
	 * </p>
	 * @return mixed This function returns a string or an array with the cleaned values.
	 */
	public function CleanFileChar($badinput) {
		if (is_array ( $badinput )) {			
			array_walk_recursive ( $badinput, array ($this,'CleanFileCharHelper') );
			return $badinput;
		}

		return str_replace ( $this->badChars, '', $badinput );

	}

	/**
	 *
	 * @param mixed $input <p>
	 * The Variable being decoded.
	 * </p>   	      	             	
	 * @return mixed This function returns a string or an array with the decoded values.
	 */
	public function HtmlDecode($input) {
		if (is_array ( $input )) {
			array_walk_recursive ( $input, array ($this,'HtmlDecodeHelper') );
			return $input;
		}
		return html_entity_decode ( $input );
	}

	/**
	 * 
	 * @return string This function generate safe token for csrf
	 */
	public function CsrfTokenGenerator() {
		return md5 ( base64_encode ( pack ( 'N6', mt_rand (), mt_rand (), mt_rand (), mt_rand (), mt_rand (), uniqid () ) ) );
	}

	/**
	 * 
	 * @param string $password <p>
	 * The Variable being crypted with bcrypt .
	 * </p>
	 * @return object contain two property { hash , salt }
	 */
	public function MyCrypt($password) {
		$Allowed_Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./';
		$salt = '';
		for($i = 0; $i < 21; $i ++) {
			$salt .= $Allowed_Chars [mt_rand ( 0, 63 )];
		}

		$bcrypt_salt = $this->Blowfish_Pre . $salt . $this->Blowfish_End;
		$Crypted = new stdClass;

		$Crypted->hash = crypt ( $password, $bcrypt_salt );
		$Crypted->salt = $salt;

		return $Crypted;
	}
	/**
	 * 
	 * @param string $password <p>
	 * The Variable being checked.
	 * </p>
	 * @param string $hash  <p>
	 * hashed string returned by MyCrypt function.
	 * </p>
	 * @param string $salt  <p>
	 * salt string returned by MyCrypt function.
	 * </p>
	 * @return boolean <p> 
	 * true if val matching with hash
	 * else false.
	 * </p>
	 */
	public function CheckMyCrypt($password , $hash , $salt) {

		$bcrypt_salt = $this->Blowfish_Pre . $salt . $this->Blowfish_End;
		return strcmp(crypt ( $password, $bcrypt_salt )  , $hash) == 0 ? TRUE : FALSE;
	}
	/**
	 * 
	 * @param string $password <p>
	 * The Variable being hashed with salted md5 .
	 * </p>
	 * @return string This function returns a hashed password.
	 */
	public function MyMD5($password) {
		$password = $this->salt_Pre . $password . $this->salt_End;
		return md5 ( $password );
	}
	/**
	 * 
	 * @param string $password <p>
	 * The Variable being checked.
	 * </p>
	 * @param string $hash  <p>
	 * hashed string.
	 * </p>
	 * @return boolean <p> 
	 * true if val matching with hash
	 * else false.
	 * </p>
	 */
	public function CheckMyMD5($password,$hash) {
		$password = $this->salt_Pre . $password . $this->salt_End;
		return strcmp(md5 ( $password ) ,$hash) == 0 ? true : false;
	}

	private function TypeDate($str) {
		try {
			$dt = new DateTime ( trim ( $str ) );
		} catch ( Exception $e ) {
			return false;
		}
		$month = $dt->format ( 'm' );
		$day = $dt->format ( 'd' );
		$year = $dt->format ( 'Y' );
		if (checkdate ( $month, $day, $year )) {
			return true;
		} else {
			return false;
		}
	}
	private function TypeEmail($str) {
		return filter_var ( $str, FILTER_VALIDATE_EMAIL ) == false ? false : true;
	}
	private function TypeFloat($fl) {
		return filter_var ( $fl, FILTER_VALIDATE_FLOAT ) == false ? false : true;
	}
	private function TypeArray($array) {
		if (count ( $array ) > 0 && is_array ( $array )) {
			return true;
		} else {
			return false;
		}
	}
	private function TypeInteger($id) {
		if (trim ( $id ) != '' && is_numeric ( $id )) {
			return true;
		} else {
			return false;
		}
	}
	private function TypeString($str) {
		if (trim ( $str ) != '' && is_string ( $str )) {
			return true;
		} else {
			return false;
		}
	}

	private function CleanFileCharHelper(&$badinput) {
		$str = str_replace ( $this->badChars, '', $badinput );
	}
	private function CleanXssHelper(&$str) {
		$str = strip_tags ( htmlentities ( $str, ENT_QUOTES, 'utf-8' ) );
	}
	private function HtmlDecodeHelper(&$str) {
		$str = html_entity_decode ( $str );
	}


	public static final function getInstance() {
		if (! self::$_instance) {
			self::$_instance = new self ();
		}

		return self::$_instance;
	}
}
