<?php 

    session_start();
    require_once 'db.php';

    if (isset($_POST['register'])) {
        $username = $_POST['username'];
        $email = $_POST['email'];
        $password = $_POST['password'];
        $confirm_password = $_POST['confirm_password'];

        $error = '';
        if (empty($username)) {
            $error = 'Username is required';
        } elseif (empty($email)) {
            $error = 'Email is required';
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $error = 'Invalid email format';
        } elseif (empty($password)) {
            $error = 'Password is required';
        } elseif ($password != $confirm_password) {
            $error = 'Passwords do not match';
        }

        if ($error) {
            $_SESSION['error'] = $error;
            header("location: register.php");
            return;
        }
        
        try {
            $check_email = $conn->prepare("SELECT * FROM users WHERE email = :email");
            $check_email->execute(['email' => $email]);
            if ($check_email->rowCount() > 0) {
                $_SESSION['error'] = 'Email already in use';
                header("location: register.php");
                return;
            }

            $password = password_hash($password, PASSWORD_DEFAULT);
            $sql = "INSERT INTO users (username, email, password) VALUES (:username, :email, :password)";
            $stmt = $conn->prepare($sql);
            $result = $stmt->execute(['username' => $username, 'email' => $email, 'password' => $password]);

            if ($result) {
                $_SESSION['success'] = 'User registered successfully';
                header("location: register.php");
            } else {
                $_SESSION['error'] = 'Error registering user';
                header("location: register.php");
            }
        } catch (PDOException $e) {
            $_SESSION['error'] = 'Error connecting to database: ' . $e->getMessage();
            header("location: register.php");
        }
    }
?>