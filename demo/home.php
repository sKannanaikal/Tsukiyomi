<!DOCTYPE html>
<html>
	<head>
	</head>
	<body>
		<h1>Logged In</h1>
		<form enctype="multipart/form-data" action="uploader.php" method="POST">
			Filename: <input type="text" name="filename">
		    <input type="hidden" name="MAX_FILE_SIZE" value="512000" />
		    Send this file: <input name="userfile" type="file" />
		    <input type="submit" value="Send File" />
		</form>
		<! -- Create upload functionality and can run php itesms but input upload filters and bypassing them -->
		<! -- create privliege esclattion via sudo permissions to run a command and sudo command to run gzip, edit path variable, to create root shell>
	</body>
</html>