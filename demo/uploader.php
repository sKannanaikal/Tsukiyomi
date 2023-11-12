<?php        
    $uploaddir = "/var/www/html/uploads/";
    $uploadfile = $uploaddir.$_POST["filename"];
    $extension = end(explode(".", $uploadfile));
    $uploadApproval = 1;

    $blacklist = array(
    	'php',
    	'phtml',
    	'php2',
    	'php3',
    	'php4',
    	'php5',
    	'php6',
    	'php7',
    	'phtm',
    	'pht'
    );
    
    if(in_array($extension, $blacklist)){
    	echo 'Sorry File Type is not supported!';
    	$uploadApproval = 0;
    }

    if($uploadApproval == 1){
    	if (move_uploaded_file($_FILES['userfile']['tmp_name'], $uploadfile)) {
	        echo "File is valid, and was successfully uploaded.\n";
	    } else {
	        echo "Upload failed";
	    }
	}
?>