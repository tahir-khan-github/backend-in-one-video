backend = server , api, database

everything in node js is module
1)built in module hhtp,fs
2)third party module
3)file base module - features.js

express is node framework used to make routing/code syntactically easy, also routing can be done seperately

JSON stands for JavaScript Object Notation lightweight format for storing and transporting data

To send dynamic data use res.render, views  
res.render, res.redirect after task is completed

To send/access/use static data/file use express.static(absolute path) as a middlware using app.use()

Middleware is a function that can be used to modify requests and responses in an Express application. 

mongodb compass, mongoose package to create connectivity, schema as datatype and modal as collection

authentication :-
if cookies stored that means user is logged in. Once data is removed it will logged out

storage: 
local store till manually delete , session till browser doesn't close and cookies with expire time with cookie-parser package

Next will call the next handler (req,res)=>{} once the current handler gets completed

JWT to secure the userid token
