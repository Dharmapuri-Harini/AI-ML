const path = require('path');

module.exports = function(app, db, bcrypt) {
    app.get('/signup', (req, res) => {
        res.sendFile(path.join(__dirname, 'views', 'signup.html'));
    });

    app.get('/login', (req, res) => {
        res.sendFile(path.join(__dirname, 'views', 'login.html'));
    });

    app.get('/index', (req, res) => {
        res.sendFile(path.join(__dirname, 'views', 'index.html'));
    });

    app.post('/signup', (req, res) => {
        const { fullname, email, password, password2 } = req.body;

        if (password !== password2) {
            res.send('<script>alert("Passwords do not match"); window.location.href="/signup";</script>');
        } else {
            bcrypt.hash(password, 10, (err, hash) => {
                if (err) throw err;
                const sql = 'INSERT INTO Signup (fullname, email, password) VALUES (?, ?, ?)';
                db.query(sql, [fullname, email, hash], (err, result) => {
                    if (err) throw err;
                    res.redirect("/index");
                });
            });
        }
    });

    app.post('/login', (req, res) => {
        const { email, password } = req.body;
        const sql = 'SELECT * FROM Signup WHERE email=?';
        
        db.query(sql, [email], (err, results) => {
            if (err) throw err;
            
            if (results.length === 0) {
                res.send('<script>alert("Invalid username or password"); window.location.href="/login";</script>');
            } else {
                const user = results[0];
                bcrypt.compare(password, user.password, (err, isMatch) => {
                    if (err) throw err;
                    if (isMatch) {
                        res.redirect("/index");
                    } else {
                        res.send('<script>alert("Invalid username or password"); window.location.href="/login";</script>');
                    }
                });
            }
        });
    });
};
