RapidMiner Cryptography Extension
===============================

A RapidMiner extension that adds operators for password-based file encryption and decryption and document encryption and decryption. It uses strong cryptography algorithms provided by the Bouncy Castle Crypto APIs (https://www.bouncycastle.org/).

In particular it adds four new operators:

 - Encrypt File (Password)
 - Decrypt File (Password)
 - Encrypt Document (Password)
 - Decrypt Document (Password)

For using strong algorithm strength the Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files have to be installed for the Java VM RapidMiner is started with. The files can be downloaded from here: http://www.oracle.com/technetwork/java/javase/downloads/jce-7-download-432124.html
To install the Unlimited Strength Jurisdiction Policy Files, extract the files from the downloaded archive and copy them to $PATH_TO_JRE/lib/security.
 
