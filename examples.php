<?php 
// require class 
require_once 'SecurityHelper.php'; 
// get instance 
$sec = SecurityHelper::getInstance(); 

$endl = '<br />'; 
echo '<pre>'; 

echo $endl,'|--------      Xss Test     --------------|',$endl; 
// clean input from xss  
// input can be array or string 

$xss = 'hi <script>alert(1)</script>'; // before 

echo $sec->CleanXss($xss); // after 

$xssarray = array('hi <script>alert(1)</script>','hi <script>alert(1)</script>','hi <script>alert(1)</script>',132 => array('hi <script>alert(1)</script>')); // before 

print_r($sec->CleanXss($xssarray)); // after 

echo $endl,'|--------      Xss Test     --------------|',$endl; 



echo $endl,'|--------      File Upload Cleaner Test     --------------|',$endl; 
// clean un allowed char from upload file name  
// some one try to upload this file to replace site header 
// function remove special chars and safe it for use 
$replace_heder = '../../img/header.jpg'; // before 

echo $sec->CleanFileChar($replace_heder); // after 


echo $endl,'|--------      File Upload Cleaner Test     --------------|',$endl; 


echo $endl,'|--------      Csrf Generator Test     --------------|',$endl; 

// generate token for csrf check 
echo $sec->CsrfTokenGenerator(); // can be $_SESSION['token'] = $sec->CsrfTokenGenerator(); 


echo $endl,'|--------      Csrf Generator Test    --------------|',$endl; 


echo $endl,'|--------      Crypt Test     --------------|',$endl; 
// hash password and check password is correct 

$pass = '123456'; // before 
$wrongpass = '123'; 

// my seggest (more secure) bcrypt 
$obj = $sec->MyCrypt($pass); 

$hash = $obj->hash; 
$salt = $obj->salt; 

echo 'hash : '.$hash,' | salt :'.$salt , $endl; 
var_dump($sec->CheckMyCrypt($wrongpass, $hash, $salt)); // false 
var_dump($sec->CheckMyCrypt($pass, $hash, $salt)); // true 

// salted md5 (change salt in file if u want) 
$hashed = $sec->MyMD5($pass); 

echo 'MD5 : '.$hashed,$endl; 
var_dump($sec->CheckMyMD5($wrongpass, $hashed)); // false 
var_dump($sec->CheckMyMD5($pass, $hashed)); // true 

//$ = $sec->MyCrypt($pass); 


echo $endl,'|--------      Crypt Test     --------------|',$endl; 


echo $endl,'|--------      DataType Test     --------------|',$endl; 
// check data type 
$int = 11; 
$email  = 'a@mail.com'; 
$date = '2014-01-01 22:22:22'; 

var_dump($sec->CheckType($date, $sec->Type_Date)); 
var_dump($sec->CheckType($email, $sec->Type_Email)); 
var_dump($sec->CheckType($int, $sec->Type_Integer)); 

echo $endl,'|--------      DataType Test    --------------|',$endl; 


echo '</pre>';
