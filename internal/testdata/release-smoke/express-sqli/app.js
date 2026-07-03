const express = require('express');
const app = express();

app.get('/users', (req, res) => {
    const name = req.query.name;
    const query = "SELECT * FROM users WHERE name = '" + name + "'";
    db.query(query);
    res.send('ok');
});

app.listen(3000);
