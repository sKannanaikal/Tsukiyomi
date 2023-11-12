<?php
	include("connect-db.php");
	session_start();

	if($_SERVER["REQUEST_METHOD"] == "POST"){
		$username = $_POST['username']; 
		$password = $_POST['password'];

		$sql = "SELECT id, username, password FROM credentials WHERE username = '" . $username . "' AND password = '" . sha1($password) . "';";

		$result = mysqli_query($connection, $sql);
		$row = mysqli_fetch_array($result, MYSQLI_ASSOC);
		$count = mysqli_num_rows($result);

		$storedUsername = $row['username'];
		$storedPassword = $row['password'];

		if($count != 0){
			header("Location: home.php");		}
		else{
			echo 'User Not Found';
		}
	}
?>

