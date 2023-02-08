<?php 
    session_start();

    require_once 'db.php';

    if (isset($_POST['login'])) {
        $email = $_POST['email'];
        $password = $_POST['password'];

        $error = '';
        if (empty($email)) {
            $error = 'Email is required';
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $error = 'Invalid email format';
        } elseif (empty($password)) {
            $error = 'Password is required';
        }

        if ($error) {
            $_SESSION['error'] = $error;
            header("location: login.php");
            return;
        }
        
        try {
            $stmt = $conn->prepare("SELECT * FROM users WHERE email = :email");
            $stmt->execute(['email' => $email]);
            if ($stmt->rowCount() == 0) {
                $_SESSION['error'] = 'Invalid email or password';
                header("location: login.php");
                return;
            }

            $user = $stmt->fetch();
            
            if (!password_verify($password, $user['password'])) {
                $_SESSION['error'] = 'Invalid email or password';
                header("location: login.php");
                return;
            }

            

            $_SESSION['user'] = $user;
            header("location: dashboard.php");
        } catch (PDOException $e) {
            $_SESSION['error'] = 'Error connecting to database: ' . $e->getMessage();
            header("location: login.php");
        }
    }
?>