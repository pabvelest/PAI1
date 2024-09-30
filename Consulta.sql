USE users;

CREATE TABLE usuarios (
    id INT AUTO_INCREMENT PRIMARY KEY, 
    nombre_usuario VARCHAR(50) NOT NULL, 
    contrasena VARCHAR(255) NOT NULL
);

