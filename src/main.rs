extern crate openssl;

use openssl::pkey::{Private, Public};
use openssl::rsa::{Rsa,Padding};
use openssl::sha::sha256;
use std::collections::HashMap;
use std::io::{self,Write};
use std::fs::File;

fn main() {
   //create hashmap to store encrypted password
   let mut password_map: HashMap<String,String>=HashMap::new();    
   //Generate an RSA key pair with a 2048-bit key size    
   let rsa = Rsa::generate(2048).unwrap();         

   loop{

    println!("\n *************************************");
    println!("\n Enter your choice");
    println!("\n 1. Save your account number");
    println!("\n 2.Retrieve your account number");
    println!("\n 3.Exit");

    io::stdout().flush().unwrap();

    let mut choice= String::new();
    io::stdin().read_line(&mut choice).unwrap();

    match choice.trim(){
    "1" => {
        println!("\n Enter your name");                                //user data

        io::stdout().flush().unwrap();
        let mut name = String::new();                                  // user name
        io::stdin().read_line(&mut name).unwrap();
        let name = name.trim().to_string();

        println!("\n Enter your account number");                      //account number

        io::stdout().flush().unwrap();
        let mut accno = String::new();
        io::stdin().read_line(&mut accno).unwrap();

        //Encrypt the account number and store it in the HashMap                                                               
        let encrypted_password =encrypt(&accno,&rsa);                  
        password_map.insert(name,encrypted_password);
    },
    "2" => {
        print!("\nEnter your name: ");   
                            // user name
        io::stdout().flush().unwrap();
        let mut name = String::new();
        io::stdin().read_line(&mut name).unwrap();
        let name = name.trim().to_string();

        if let Some(encrypted_password) = password_map.get(&name) {    
            // Decrypt the stored password and print the result       
            decrypt(&encrypted_password,&rsa)                  
        }
        else{
            println!("No password saved for {}",name);
        }
    },
    "3" => break,
    _ => println!("Invalid choice"),
    }  
   }



}

// Encrypts the account number using the RSA public key and returns the encrypted password
fn encrypt(accno: &str, rsa: &Rsa<Private>) -> String {             

    let mut enc_data = vec![0; rsa.size() as usize];             
    let len = rsa.public_encrypt(&sha256(accno.as_bytes()), &mut enc_data, Padding::PKCS1).unwrap();       
    enc_data.truncate(len);
    let encrypted_password = base64::encode(&enc_data);
   
   // Create a file and write the encrypted password to it
    let mut encrypted_file = File::create("encrypt.txt").expect("creation failed");    
    encrypted_file.write(encrypted_password.as_bytes()).expect("write failed");        

   // Return the encrypted password
    return encrypted_password;
    
}
// Decrypts the encrypted password using the RSA private key and prints the result
fn decrypt(encrypted_password: &str,rsa: &Rsa<Private>) {

 // Decode the base64-encoded encrypted password
    let encrypted_password_bytes= base64::decode(&encrypted_password).unwrap();
    let mut decrypted_data_buf = vec![0; rsa.size() as usize];
    let decrypted_data = rsa.private_decrypt(&encrypted_password_bytes, &mut decrypted_data_buf, Padding::PKCS1).unwrap();
    decrypted_data_buf.truncate(decrypted_data);    
    
    let base_64_decrypted_data= base64::encode(decrypted_data_buf);
    println!("base64 Decrypted data: {:?}", base_64_decrypted_data);

}

