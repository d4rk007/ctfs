// Coded by d4rkstat1c 
// usage php laravel_decrypt.php decrypt <encrypted_cookie> <APP_KEY>
// usage php laravel_decrypt.php encrypt <APP_KEY> <IV>
<?php
    if ($argc > 1) {    
        $key = base64_decode($argv[3]);
        
        if ($argv[1] == "encrypt") {
            $clear_data = readline('Enter a string to encrypt: ');
            $data = openssl_encrypt($clear_data,  'AES-256-CBC', $key, 0, base64_decode($argv[3]));
        }
        else if ($argv[1] == "decrypt") {
            $decoded_data = base64_decode(urldecode($argv[2]));
            echo "\nDecoded Data:\n" . $decoded_data. "\n";
 
            $json_data = json_decode($decoded_data, true);
            $iv = $json_data['iv'];
 
            $key = base64_decode($argv[3]);
            $encrypted_data = $json_data['value'];
 
            $data = openssl_decrypt($encrypted_data,  'AES-256-CBC', $key, 0, base64_decode($iv));
        }
        echo "\nResult:\n" . $data;
    }
    else {
        echo "Usage:\n";
        echo "php " . $argv[0] . " decrypt <data> <key>\n";
        echo "php " . $argv[0] . " encrypt <key> <iv>";
    }
?>
