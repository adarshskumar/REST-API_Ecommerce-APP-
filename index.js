const express = require('express')
const mongoose = require('mongoose')
const dbConfig = require('./config/db.config')

const auth = require('./middlewares/auth')
const errors=require('./middlewares/errors')

const unless = require('express-unless')

const app = express()

mongoose.Promise = global.Promise // we need to set mongoose a global mode to use it in different positions
mongoose.connect(dbConfig.db,{
    useNewUrlParser:true,
    useUnifiedTopology:true
}).then(()=>{
    console.log('Database Connected')
},(error)=>{
    console.log('Database cant be connected: '+error)
});

auth.authenticateToken.unless=unless;
app.use(
    auth.authenticateToken.unless({
        path: [
            { url: '/users/login', methods:["POST"]},
            { url: '/users/register', methods: ["POST"]},
        ],
    })
);

app.use(express.json())

app.use('/users',require('./routes/user.routes'))

app.use(errors.errorHandler)

app.listen(process.env.port || 4000, ()=>{
    console.log("Ready to Go!")
})