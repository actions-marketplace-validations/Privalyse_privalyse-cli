import React, { useState } from 'react';
import axios from 'axios';

function App() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    // Source: User Input (email, password)
    
    // Sink 1: Console Log (Leak)
    console.log("Submitting:", { email, password }); 
    
    // Sink 2: API Call (Transmission)
    try {
      await axios.post('/api/signup', { 
        user_email: email,
        user_password: password
      });
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <input 
        type="email" 
        name="email"
        value={email} 
        onChange={(e) => setEmail(e.target.value)} 
        placeholder="Enter email"
      />
      <input 
        type="password" 
        name="password"
        value={password} 
        onChange={(e) => setPassword(e.target.value)} 
        placeholder="Enter password"
      />
      <button type="submit">Sign Up</button>
    </form>
  );
}

export default App;
