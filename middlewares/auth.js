const jwt = require('jsonwebtoken')

async function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization']     // variable for authorization
    const token = authHeader && authHeader.split(' ')[1]

    if (token == null) return res.sendStatus(401)

    jwt.verify(token, "Snippet_SecretKey", (err, user) => {
        if (err) return res.sendStatus(403)
        req.user = user;
        next();
    })
}

async function generateAccessToken(username) {
    return jwt.sign({ data: username }, "Snippet_SecretKey", {
        expireIn: "1h",
    })
}

module.exports = {
    authenticateToken,
    generateAccessToken
}