# EncryptionObjectBackup
T-SQL stored procedure to back up keys and certs associated with column-level encryption

1) Create this stored procedure in your master database
2) Execute the proc and pass in the parameters as described
3) The result will be a script that can then be manually run to back up objects as needed

!!IMPORTANT!!
Please read, and be aware of, the "NEEDED TESTING" and "KNOWN ISSUES/CAVEATS" below - these sections descibe potential issues with the code that may, or may not, affect your use of it.
!!---------!!
