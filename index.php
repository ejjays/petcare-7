<?php
ob_start();
session_start();
require_once('config/database.php');

if (isset($_SESSION['user_id'])) {
    if ($_SESSION['role'] === 'admin') {
        header('Location: admin/dashboard.php');
        exit();
    } else if ($_SESSION['role'] === 'user') {
        header('Location: user/dashboard.php');
        exit();
    }
}

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Pet Management System</title>
</head>
<body>
    <?php
    header('Location: views/login.php');
    exit();
    ?>

    <script>(function(){var js,fs,d=document,id="tars-widget-script",b="https://tars-file-upload.s3.amazonaws.com/bulb/";if(!d.getElementById(id)){js=d.createElement("script");js.id=id;js.type="text/javascript";js.src=b+"js/widget.js";fs=d.getElementsByTagName("script")[0];fs.parentNode.insertBefore(js,fs)}})();window.tarsSettings = {"convid": "JNG3R7", "href": "https://chatbot.hellotars.com/conv/JNG3R7"};</script>
</body>
</html>

<?php
ob_end_flush();
?>