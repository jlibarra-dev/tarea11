let jwt = require('jsonwebtoken');
let config = require('./config');
let dbconn = require('./lib/mongoUtils.js')
const bcrypt = require('bcrypt');
const saltRounds = 10;
let token = "";

// Clase encargada de la creación del token
class HandlerGenerator {

    login(req, res1) {

        // Extrae el usuario y la contraseña especificados en el cuerpo de la solicitud
        let username = req.body.username;
        let password = req.body.password;
        let hashPassword = "";

        // Encripta la contraseña enviada por el cliente en el request
        bcrypt.genSalt(saltRounds, function (err, salt) {
            bcrypt.hash(password, salt, function (err, hash) {
                // Store hash in your password DB.
                hashPassword = hash;
            });
        });

        // Realiza la conexion con la base de datos para encontrar al usuario
        dbconn.conn().then((client) => {
            return client.db("usuarios")
                .collection("usuarios")
                .aggregate([
                    { $match: { username: username } }
                ])
                .toArray();
        }).then((res) => {
            console.log(res);
            // Si se especifico un usuario y contraseña, proceda con la validación
            // de lo contrario, un mensaje de error es retornado
            if (username != undefined && password != undefined && res[0] != undefined) {
                let mockedUsername = res[0].username;
                let mockedPassword = res[0].password;
                let mockedRole = res[0].role;

                let serverRcvPassword = "";
                // Encripta la contraseña recibida por el server
                bcrypt.genSalt(saltRounds, function (err, salt) {
                    bcrypt.hash(mockedPassword, salt, function (err, hash) {
                        // Store hash in your password DB.
                        serverRcvPassword = hash;
                    });
                });

                console.log("Hasta aca todo en orden");
                // Si el usuario coincide procede el metodo
                if (username === mockedUsername) {

                    // Compara el hash de las contraseñas
                    bcrypt.compare(serverRcvPassword, hashPassword, function (err, result) {
                        if (result == true) {
                            // Si el usuario tiene el rol de admin genera un token con la llave secreta de admin
                            if (mockedRole == "admin") {
                                token = jwt.sign({ password: mockedPassword, role: mockedRole },
                                    config.secretAdmin, { expiresIn: '24h' });
                            }
                            else {
                                // Se genera un nuevo token para el nombre de usuario el cuál expira en 24 horas con la llave de usuario
                                token = jwt.sign({ password: mockedPassword, role: mockedRole },
                                    config.secret, { expiresIn: '24h' });
                            }
                            // Retorna el token el cuál debe ser usado durante las siguientes solicitudes
                            res1.json({
                                success: true,
                                message: 'Authentication successful!',
                                token: token
                            });
                        }
                        else {

                            // El error 403 corresponde a Forbidden (Prohibido) de acuerdo al estándar HTTP
                            res1.send(403).json({
                                success: false,
                                message: 'Incorrect username or password'
                            });

                        }
                    });

                } else {

                    // El error 403 corresponde a Forbidden (Prohibido) de acuerdo al estándar HTTP
                    res1.send(403).json({
                        success: false,
                        message: 'Incorrect username or password'
                    });

                }

            } else {

                // El error 400 corresponde a Bad Request de acuerdo al estándar HTTP
                res1.send(400).json({
                    success: false,
                    message: 'Authentication failed! Please check the request'
                });

            }
        })

        // Este usuario y contraseña, en un ambiente real, deben ser traidos de la BD

    }

    index(req, res) {

        // Retorna una respuesta exitosa con previa validación del token
        res.json({
            success: true,
            message: 'Index page'
        });

    }

    register(req, res) {
        dbconn.conn().then((client) => {
            client.db("usuarios")
                .collection("usuarios")
                .insertOne({ username: req.body.username, password: req.body.password, role: req.body.role }) // Si no se provee un ID, este será generado automáticamente.
        });

        res.json({
            success: true,
            message: 'Usuario registrado exitosamente.'
        });
    }
}

module.exports = HandlerGenerator;