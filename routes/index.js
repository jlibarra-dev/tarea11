var express = require('express');
var router = express.Router();

var HandlerGenerator = require("../handlegenerator.js");
var middleware = require("../middleware.js");

HandlerGenerator = new HandlerGenerator();

// Metodo para recibir el index page. Admitido solo para usuarios logueados.
router.get('/', middleware.checkToken, HandlerGenerator.index);

// Metodo para hacer login. Accesible para todos los usuarios
router.post('/login', HandlerGenerator.login);

// Metodo para registrar usuarios. SOLO accesible por usuarios con el rol admin.
router.post('/register', middleware.checkTokenAdmin, HandlerGenerator.register);

module.exports = router;
