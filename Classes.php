<?php

if (session_status() == PHP_SESSION_NONE){ session_start();}

class User
{
    private $id;
    public $login;
    public $email;
    public $firstname;
    public $lastname;
    private $conn;

    public function __construct() {

        $db_username = 'root';
        $db_password = '';
        
        try{                            // try to connect to the db

            $this->conn = new PDO('mysql:host=localhost;dbname=utilisateurs;charset=utf8', $db_username, $db_password);

            // Define PDO error mode on Exception
            $this->conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

            // echo "You are connected to the database <br>";
        }

        catch(PDOException $e){         // Catch errors

            // Display errors infos
            echo "Error : " . $e->getMessage();

        }

    }

    public function Register($login, $password, $passwordConfirm, $email, $firstname, $lastname) {

        // List of messages : okReg, errorPassMatch, errorLogin, errorEmail, errorLastName, errorFirstName, errorLoginExist

        $messages = [];     // Create an array to stock messages

        $sql = "SELECT * FROM utilisateurs WHERE login=:login";
        
        // Check if a line with the same login exist in our Database.
        $req = $this->conn->prepare($sql);
        $req->execute(array(':login' => $login));
        $row = $req->rowCount();
        
        if($row <= 0) {     // If the login do not exist in the Database, we check the others

            if(strlen($login) >= 4 && !preg_match("[\W]", $login) && strlen($password) >= 5 && preg_match("/@/", $email) && preg_match("/\./", $email) && strlen($firstname) >= 2 && !preg_match("[\W]", $firstname) && strlen($lastname) >= 2 && !preg_match("[\W]", $lastname)) {

                if($password == $passwordConfirm) {     // If the password and the confirmation match
                    
                    $hash = password_hash($password, PASSWORD_DEFAULT);     // Cripting the password
                    
                    // Add data to the database 
                    $sql = "INSERT INTO `utilisateurs` (`login`, `password`, `email`, `firstname`, `lastname`) VALUES (:login, :pass, :email, :firstname, :lastname)";
                    $req = $this->conn->prepare($sql);
                    $req->execute(array(':login' => $login,
                                        ':pass' => $hash,
                                        ':email' => $email,
                                        ':firstname' => $firstname,
                                        ':lastname' => $lastname));

                    $messages['okReg'] = 'Your account is now created and you can login';

                }else{ $messages['errorPassMatch'] = 'The passwords do not match'; }

            }else{

                if(strlen($login) < 4 || preg_match("[\W]", $login)) {      // If the login is too short or contain special characters

                    $messages['errorLogin'] = 'Your login must contain at least 4 caracters and no specials caracters';
                }
                if(strlen($password) < 5) {     // If the password is too short

                    $messages['errorPassLong'] = 'Your password must contain at least 5 caracters';
                }
                if(!preg_match("/@/", $email) || !preg_match("/\./", $email)) {     // If the email does not contain "@" and "."

                    $messages['errorEmail'] = "Your email is not valid. It must contain '@' and '.'";
                }
                if(strlen($firstname) < 2 || preg_match("[\W]", $firstname)) {

                    $messages['errorFirstName'] = 'Your firstname must contain at least 2 caracters and no specials caracters';
                }
                if(strlen($lastname) < 2 || preg_match("[\W]", $lastname)) {

                    $messages['errorLastName'] = 'Your lastname must contain at least 2 caracters and no specials caracters';
                }
            }
            
        }else{ $messages['errorLoginExist'] = 'The login already exist. Please choose another one'; }

        $json = json_encode($messages, JSON_PRETTY_PRINT);
        echo $json;

    }

    public function Connect($login, $password) {

        // List of messages : okConn, errorPass, errorLogin

        $messages = [];         // Create an array to stock messages

        $sql = "SELECT * FROM utilisateurs WHERE login=:login";
        
        // Check if the username is already present or not in our Database.
        $req = $this->conn->prepare($sql);
        $req->execute(array(':login' => $login));
        $row = $req->rowCount();
        
        if($row == 1){    // If the login exist in the data base, continue

            $tab = $req->fetch(PDO::FETCH_ASSOC);
            $dataPass = $tab['password'];
            $id = $tab['id'];

            if(password_verify($password,$dataPass)){    // Check if the password existe in the database and decript it

                $_SESSION['id'] = $id;
                $_SESSION['login'] = $login;
                $_SESSION['password'] = $dataPass;
                $_SESSION['email'] = $tab['email'];
                $_SESSION['firstname'] = $tab['firstname'];
                $_SESSION['lastname'] = $tab['lastname'];

                $messages['okConn'] = 'You\'re connected';

            }else{    // If the password do not match, error
                $messages['errorPass'] = 'Wrong password';
            }
        }else{    // If the login do not exist, error
            $messages['errorLogin'] = 'The login do not exist. You don\'t have an account? <a href=\"inscription.php\">Signup</a>';
        }

        $json = json_encode($messages, JSON_PRETTY_PRINT);
        echo $json;

    }

    public function Disconnect() {

        session_destroy();
        exit('Vous avez bien été deconnecté');

    }

    public function Delete() {

        $messages = [];

        if($_SESSION){

            // Set variables to use in the following request.
            $sessionId = $_SESSION['id'];

            $sql = "DELETE FROM `utilisateurs` WHERE id = :sessionId";
        
            // Check if the username is already present or not in our Database.
            $req = $this->conn->prepare($sql);
            $req->execute(array(':sessionId' => $sessionId));

            session_destroy();
            exit('You have deleted your account');

        }else{
            $messages['errorDelete'] = 'You have to be connected to delete your account';
        }
        
        $json = json_encode($messages, JSON_PRETTY_PRINT);
        echo $json;
    }

    public function Update($login, $password, $passwordNew, $passwordNewConfirm, $email, $firstname, $lastname) {

        // List of success : okLoginEdit, okPassEdit, okEmailEdit, okFirstNameEdit, okLastNameEdit
        // List of errors : errorLoginExist, errorLogin, errorPassLong, errorPassConfirm, errorPassDiff, errorEmail, errorFirstName, errorLastName, errorPassWrong, errorNoLog

        $messages = [];

        if ($_SESSION){

            // Set variables to use in the following request.
            $sessionId = $_SESSION['id'];
            $passwordTrue = $_SESSION['password'];

            // Check if the username is already present or not in our Database.
            $sql = "SELECT * FROM utilisateurs WHERE id = :sessionId";
            $req = $this->conn->prepare($sql);
            $req->execute(array(':sessionId' => $sessionId));
            $row = $req->rowCount();

            if(password_verify($password,$passwordTrue)){

                if ($_SESSION['login'] != $login && strlen($login) >= 4 && !preg_match("[\W]", $login)){

                    if($row!=1){

                        $messages['errorLoginExist'] = 'The login already exist';

                    }else{

                        $sqlLog = "UPDATE utilisateurs SET login = :login WHERE id = :sessionId";
                
                        // Check if the username is already present or not in our Database.
                        $req = $this->conn->prepare($sqlLog);
                        $req->execute(array(':login' => $login, ':sessionId' => $sessionId));
                        
                        $_SESSION['login'] = $login;

                        $messages['okLoginEdit'] = 'Your login has been edited';

                    }

                }elseif(strlen($login) < 4 || preg_match("[\W]", $login)) {

                    $messages['errorLogin'] = "Your login must contain at least 4 caracters and no specials caracters";

                }

                if (!empty($passwordNew) && !empty($passwordNewConfirm && $passwordNew == $passwordNewConfirm && strlen($passwordNew) >= 5)){

                    $hash = password_hash($passwordNew, PASSWORD_DEFAULT);

                    $sqlPass = "UPDATE utilisateurs SET password = '$hash' WHERE id = '$sessionId'";
                    $rs = $this->conn->query($sqlPass);

                    $_SESSION['password'] = $hash;
                
                    $messages['okPassEdit'] = 'Your password has been edited';

                }elseif(strlen($passwordNew) < 5 and !empty($passwordNew)) {

                    $messages['errorPassLong'] = 'Your password must contain at least 5 caracters';

                }elseif (!empty($passwordNew) && empty($passwordNewConfirm)){
        
                    $$messges['errorPassConfirm'] = 'Please confirm password';
        
                }elseif(($passwordNew != $passwordNewConfirm)) {
    
                    $messages['errorPassDiff'] = 'The passwords are differents';

                }

                if ($_SESSION['email'] != $email && preg_match("/@/", $email) && preg_match("/\./", $email)){

                    $sqlMail = "UPDATE utilisateurs SET email = '$email' WHERE id = '$sessionId'";
                    $rs = $this->conn->query($sqlMail);
                    $_SESSION['email'] = $email;

                    $messages['okEmailEdit'] = 'Your email has been edited';

                }elseif(!preg_match("/@/", $email) || !preg_match("/\./", $email)) {

                    $messages['errorEmail'] = "Your email is not valid. It must contain '@' and '.'";

                }
                    
                if ($_SESSION['firstname'] != $firstname && strlen($firstname) >= 2 && !preg_match("[\W]", $firstname)){

                    $sqlFirstN = "UPDATE utilisateurs SET firstname = '$firstname' WHERE id = '$sessionId'";
                    $rs = $this->conn->query($sqlFirstN);
                    $_SESSION['firstname'] = $firstname;

                    $messages['okFirstNameEdit'] = 'Your first name has been edited';

                }elseif(strlen($firstname) < 2 || preg_match("[\W]", $firstname)) {

                    $messages['errorFirstName'] = 'Your first name must contain at least 2 caracters and no specials caracters';

                }
                    
                if ($_SESSION['lastname'] != $lastname && strlen($lastname) >= 2 && !preg_match("[\W]", $lastname)){

                    $sqlLastN = "UPDATE utilisateurs SET lastname = '$lastname' WHERE id = '$sessionId'";
                    $rs = $this->conn->query($sqlLastN);
                    $_SESSION['lastname'] = $lastname;
            
                    $messages['okLastNameEdit'] = 'Your last name has been edited';

                }elseif(strlen($lastname) < 2 || preg_match("[\W]", $lastname)) {

                    $messages['errorLastName'] = "Your last name must contain at least 2 caracters and no specials caracters";

                }

            }else{ $messages['errorPassWrong'] = 'Wrong password'; }

        }else{ $messages['errorNoLog'] = 'Please login to change your infos'; }

        $json = json_encode($messages, JSON_PRETTY_PRINT);
        echo $json;

    }

    public function IsConnected() {

        if($_SESSION){
            return true;
        }else{
            return false;
        }

    }

    public function GetAllInfos() {

        if($_SESSION){
            return $_SESSION;
        }else{
            echo 'Please login to view your infos';
        }

    }

    public function GetLogin() {

        if($_SESSION){
            return $_SESSION['login'];
        }else{
            echo 'Please login to view your login';
        }

    }

    public function GetEmail() {

        if($_SESSION){
            return $_SESSION['email'];
        }else{
            echo 'Please login to view your email';
        }

    }

    public function GetFirstname() {

        if($_SESSION){
            return $_SESSION['firstname'];
        }else{
            echo 'Please login to view your first name';
        }

    }

    public function GetLastname() {

        if($_SESSION){
            return $_SESSION['lastname'];
        }else{
            echo 'Please login to view your last name';
        }

    }

}

// $newUser = new User();
//echo $newUser->Register('juju', 'azerty', 'azerty', 'juju@gmail.com', 'Julie', 'Dubois');
//$newUser->Connect('juliedbs', 'azerty');
//echo $newUser->Update('juliedbs', 'azerty', '', '', 'julie@gmail.com', 'Julie', 'Dubois');
//$newUser->Update('lea', 'azerty', 'azer','azer', 'unemail@gmail.com', 'Lea', 'DuboiS');
//echo $newUser->GetLogin();
//$newUser->Disconnect();
//$newUser->Delete();
// var_dump($_SESSION);

?>