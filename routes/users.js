var express = require('express');
var router = express.Router();


const pool = require('../utils/mysql');

const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const isLoggedin = require('../utils/isLoggedin')


/* GET users listing. */
/*
router.get('/', function(req, res, next) {
  res.json({ status: 200, msg: 'hello!!!!!' });
});
*/

router.get('/', async function(req, res, next) {
  try{
    const connection = await pool.getConnection();
    const [results] = await connection.query('SELECT * FROM moim_created');
    connection.release();
    res.json({ status: 200, arr: results });
  } catch (err) {
    console.log(err);
    res.json({ status: 500, msg: '테이블명 오타로 인한 서버 에러입니다!' });
  }
});

router.post('/', async function(req, res, next) {
  try{
    const { title } = req.body;
    const connection = await pool.getConnection();
    await connection.query('INSERT INTO moim_created(title) VALUES(?)', [title]);
    connection.release();
    res.json({ status: 201, msg: '모임이 생성되었습니다!' });
  } catch (err) {
    console.log(err);
    res.json({ status: 500, msg: '알 수 없는 문제' });
  }
});

router.post('/join', async function(req, res, next) {
  try{
    const { email, pwd, name } = req.body;
    const connection = await pool.getConnection();
    const pwdSalt = (await crypto.randomBytes(64)).toString('base64');
    const hashedPwd = (crypto.pbkdf2Sync(pwd, pwdSalt, 100000, 64, 'SHA512')).toString('base64')
    await connection.query('INSERT INTO moim_users(email, name, hashed_pwd, pwd_salt) VALUES(?, ?, ?, ?)', [email, name, hashedPwd, pwdSalt]);
    connection.release();
    res.json({ status: 201, msg: '저장 성공!' });
  } catch (err) {
    console.log(err);
    res.json({ status: 500, msg: '알 수 없는 문제!' });
  }
});

/*
router.post('/join', async function(req, res, next) {
  try{
    const { email, name } = req.body;
    const connection = await pool.getConnection();
    await connection.query('INSERT INTO moim_users(email, name) VALUES(?, ?)', [email, name]);
    connection.release();
    res.json({ status: 201, msg: '저장 성공!' });
  } catch (err) {
    console.log(err);
    res.json({ status: 500, msg: '알 수 없는 문제!' });
  }
});
*/
router.post('/login', async function(req, res, next) {
  try{
    const { email, pwd } = req.body;
    const connection = await pool.getConnection();
    const [users] = await connection.query('SELECT * FROM moim_users WHERE email = ?', [email]);
    if (users.length === 0) {
      return res.json({ status: 401, msg: '없는 이메일입니다!' })
    }
    const user = users[0];
    const hashedPwd = (crypto.pbkdf2Sync(pwd, user.pwd_salt, 100000, 64, 'SHA512')).toString('base64');
    if (user.hashed_pwd !== hashedPwd) {
      return res.json({ status: 401, msg: '일치하는 않는 비밀번호에요!' });
    }
    connection.release();
    const token = jwt.sign( { id: user.id }, process.env.JWT_SECRET, { expiresIn: '30d' });
    res.cookie('token', token);
    res.json({ status: 200, token: token });
  } catch (err) {
    console.log(err);
    res.json({ status: 500, msg: '알 수 없는 문제!' });
  }
});

module.exports = router;
