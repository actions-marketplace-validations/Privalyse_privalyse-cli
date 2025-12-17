import express from 'express';
import { createUser } from './services/userService';
// @ts-ignore
import { User } from './models/user.model';

const app = express();
app.use(express.json());

app.post('/register', async (req, res) => {
    // TEST 1: Destructuring Source (New Feature)
    const { email, password, creditCard, ssn } = req.body;
    
    // TEST 2: Express Request Access (New Feature)
    const phoneNumber = req.body.phone; 

    // SINK: Logging sensitive data
    console.log("Registering user:", email);
    
    try {
        // TEST 3: Database Write Sink (New Feature)
        // Should detect 'email' and 'password' being passed to User.create
        const newUser = await User.create({
            email,
            password,
            phone: phoneNumber,
            socialSecurity: ssn
        });

        // TEST 4: API Response Leak (New Feature)
        // Returning the full user object including password/ssn
        res.json(newUser);
        
    } catch (err) {
        res.status(500).send("Error");
    }
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});
