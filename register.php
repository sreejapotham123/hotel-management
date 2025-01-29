<?php
session_start();
require_once "config.php";

// Redirect if user is already logged in
if(isset($_SESSION['username'])){
    if($_SESSION["admin"]=='YES'){
        header("location: dashboard.php");
    }
    else{
        header("location: home.php");
    }
    exit();
}

$fname = $lname = $email = $username = $password = $confirm_password = "";
$fname_err = $lname_err = $email_err = $username_err = $password_err = $confirm_password_err = "";

if($_SERVER['REQUEST_METHOD'] == "POST"){
    // Validate first name
    if(empty(trim($_POST['fname']))){
        $fname_err = "First Name cannot be blank";
    }
    else{
        $fname = trim($_POST['fname']);
    }

    // Validate last name
    if(empty(trim($_POST['lname']))){
        $lname_err = "Last Name cannot be blank";
    }
    else{
        $lname = trim($_POST['lname']);
    }

    // Validate email
    if(empty(trim($_POST['email']))){
        $email_err = "Email cannot be blank";
    }
    else{
        $email = trim($_POST['email']);
    }

    // Validate username
    if(empty(trim($_POST['username']))){
        $username_err = "Username cannot be blank";
    }
    else{
        $username = trim($_POST['username']);
    }

    // Validate password
    if(empty(trim($_POST['password']))){
        $password_err = "Password cannot be blank";
    }
    elseif(strlen(trim($_POST['password'])) < 8){
        $password_err = "Password cannot be less than 8 characters";
    }
    else{
        $password = trim($_POST['password']);
    }

    // Confirm Password validation
    if(trim($_POST['password']) != trim($_POST['confirm_password'])){
        $confirm_password_err = "Passwords should match";
    }

    // If there were no errors then insert the values into the database
    if(empty($username_err) && empty($password_err) && empty($confirm_password_err) && empty($email_err) && empty($fname_err) && empty($lname_err)){
        // Prepare SQL statement
        $sql = "INSERT INTO loginform (fname, lname, email, username, password) VALUES (?, ?, ?, ?, ?)";
        $stmt = mysqli_prepare($conn, $sql);

        if($stmt){
            // Bind parameters
            mysqli_stmt_bind_param($stmt, "sssss", $fname, $lname, $email, $username, $hashed_password);
            // Hash the password
            $hashed_password = password_hash($password, PASSWORD_DEFAULT);
            // Execute the statement
            if(mysqli_stmt_execute($stmt)){
                header("location: login.php");
                exit();
            }
            else{
                $error_message = "Something went wrong.. Cannot Redirect";
            }
            mysqli_stmt_close($stmt);
        }
        else{
            $error_message = "Something went wrong with the SQL statement";
        }
    }
}
mysqli_close($conn);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <!-- Required meta tags -->
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Hotel Booking Management</title>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.0-beta3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/font-awesome/4.7.0/css/font-awesome.min.css" />
    <link rel="stylesheet" href="style.css">
</head>
<body>

<nav class="navbar navbar-expand-lg navbar-dark bg-dark">
    <div class="container-fluid">
        <a class="navbar-brand" href="#">Hotel Booking Management</a>
        <ul class="navbar-nav">
            <li class="nav-item">
                <a class="nav-link active" aria-current="page" href="register.php">Register <i class="fa fa-user-plus" aria-hidden="true"></i></a>
            </li>
            <li class="nav-item">
                <a class="nav-link" href="login.php">Login <i class="fa fa-sign-in" aria-hidden="true"></i></a>
            </li>
            <li class="nav-item">
                <a class="nav-link" href="contact.php">Contact <i class="fa fa-envelope-o" aria-hidden="true"></i></a>
            </li>
        </ul>
    </div>
</nav>

<div class="container mt-4">
    <h2>Please Register</h2>
    <hr>
    <form action="" method="post">
        <div class="row">
            <div class="col-md-6">
                <label for="inputFName" class="form-label">First Name</label>
                <input type="text" class="form-control" name="fname" id="inputFName">
                <?php if(!empty($fname_err)) echo "<div class='alert alert-danger'>$fname_err</div>"; ?>
            </div>
            <div class="col-md-6">
                <label for="inputLName" class="form-label">Last Name</label>
                <input type="text" class="form-control" name="lname" id="inputLName">
                <?php if(!empty($lname_err)) echo "<div class='alert alert-danger'>$lname_err</div>"; ?>
            </div>
        </div>
        <br>
        <div class="row">
            <div class="col-md-6">
                <label for="inputEmail4" class="form-label">Email</label>
                <input type="email" class="form-control" name="email" id="inputEmail4">
                <?php if(!empty($email_err)) echo "<div class='alert alert-danger'>$email_err</div>"; ?>
            </div>
            <div class="col-md-6">
                <label for="inputUname" class="form-label">Username</label>
                <input type="text" class="form-control" name="username" id="inputUname">
                <?php if(!empty($username_err)) echo "<div class='alert alert-danger'>$username_err</div>"; ?>
            </div>
        </div>
        <br>
        <div class="row">
            <div class="col-md-6">
                <label for="inputPassword4" class="form-label">Password</label>
                <input type="password" class="form-control" name="password" id="inputPassword4">
                <?php if(!empty($password_err)) echo "<div class='alert alert-danger'>$password_err</div>"; ?>
            </div>
            <div class="col-md-6">
                <label for="inputPassword4" class="form-label">Confirm Password</label>
                <input type="password" class="form-control" name="confirm_password" id="inputPassword">
                <?php if(!empty($confirm_password_err)) echo "<div class='alert alert-danger'>$confirm_password_err</div>"; ?>
            </div>
        </div>
        <br>
        <div class="col-12">
            <button type="submit" class="btn btn-primary">Sign up</button>
        </div>
    </form>
    <?php if(isset($error_message)) echo "<div class='alert alert-danger'>$error_message</div>"; ?>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.0.0-beta3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>