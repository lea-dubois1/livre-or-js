<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <script src="script.js" defer></script>
    <title>Document</title>
</head>
<body>

    <?php if (session_status() == PHP_SESSION_NONE){ session_start();} ?>

    <button id="switchInscription">Signup</button>
    <button id="switchConnexion">Login</button><br><br>

    <div id="form">Bonjour <?php if($_SESSION){echo '&nbsp' . strtoupper($_SESSION['prenom']);}else{echo 'user';}?></div>

</body>
</html>