# PMEA
C Implementation of a private message exchange application (PMEA).  
This application serves as a sample of client side encryption in C for PostgreSQL.  
The messages are stored encrypted in PostgreSQL and the intended recipient can decrypt and read them.  
The application uses symmetric as well as asymmetric encryption.  
Messages are encrypted and decrypted using a secret key.  
a) The public keys of both Alice and Bob are stored in database.  
b) When Alice makes Bob her friend, Alice generates a secret key (SK).  
c) The secret key (SK) is encrypted using Alice’s public key. This (MEK_S) will be used for message encryption.  
d) The secret key (SK) is also encrypted using Bob’s public key. This (MEK_R) will be used for message decryption.  
e) When Alice wants to send message to Bob, she first decrypts MEK_S using her private key to get SK.This makes sure that the sender is Alice, because only Alice can decrypt MEK_S using her private key.  
f) She then encrypts message using SK and saves cipher text in the database. This makes sure that only Bob can read them because only Bob can decrypt MEK_R using his private key.  
g) When Bob wants to read messages from Alice, he first decrypts MEK_R using his private key, to get SK.  
h) Bob then decrypts message sent by Alice using SK.  
  
The PostgreSQL schema is as follows:  
  
  CREATE SCHEMA pmea;  
  CREATE TABLE pmea.tbl_users(  
      u_id INT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,  
      u_name VARCHAR(255) NOT NULL UNIQUE,  
      u_public_key VARCHAR NOT NULL);  
  CREATE TABLE pmea.tbl_friends(  
      f_id INT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,  
      f_from_u_id INT REFERENCES pmea.tbl_users(u_id),  
      f_to_u_id INT REFERENCES pmea.tbl_users(u_id),  
      f_mek_for_sending BYTEA NOT NULL,  
      f_mek_for_reading BYTEA NOT NULL,  
      UNIQUE (f_from_u_id, f_to_u_id));  
  CREATE TABLE pmea.tbl_messages(  
      m_id INT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,  
      m_f_id INT REFERENCES pmea.tbl_friends(f_id),  
      m_message VARCHAR NOT NULL,  
      m_sent_on timestamp with time zone NOT NULL);  
    
    
  CREATE OR REPLACE FUNCTION pmea.getSenderID(m_f_id integer) RETURNS varchar AS $$  
  DECLARE uid VARCHAR(255);  
  BEGIN  
    SELECT u_id INTO uid FROM pmea.tbl_users, pmea.tbl_friends WHERE f_id = m_f_id AND f_from_u_id = u_id;  
    RETURn uid;  
  END; $$  
  LANGUAGE PLPGSQL;  
    
  CREATE OR REPLACE FUNCTION pmea.getSenderName(m_f_id integer) RETURNS varchar AS $$  
  DECLARE uname VARCHAR(255);  
  BEGIN  
    SELECT u_name INTO uname FROM pmea.tbl_users, pmea.tbl_friends WHERE f_id = m_f_id AND f_from_u_id = u_id;  
    RETURn uname;  
  END; $$  
  LANGUAGE PLPGSQL;  
  
Build Command:  
  make  
  
Run Command:  
  ./pmea add-user  
  
Commands supported by the application  
  add-user  
  add-friend  
  send-messages  
  read-messages  

