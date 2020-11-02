const jwt = require('jsonwebtoken');

require('dotenv').config();

const isLoggedin = async (req, res, next) => {
    const token = req.headers.authorization;
    try {
        const user = jwt.vertify(token, process.env.JWT_SECRET);
        req.userId = user.id;
        next();
    } catch (err) {
        return res.json( { status: 401, msg: '로그인도 안된 사람이 어딜!' } )
    }
}

module.exports = isLoggedin