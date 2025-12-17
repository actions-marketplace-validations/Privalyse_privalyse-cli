import React, { useState } from 'react';
import { saveToken } from '../api/userApi';

export const RegistrationForm = () => {
  const [formData, setFormData] = useState({
    firstName: '',
    lastName: '',
    email: '',
    password: '',
    phoneNumber: '',
    birthDate: ''
  });

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    // BAD PRACTICE: Storing sensitive data in localStorage
    localStorage.setItem('userEmail', formData.email);
    localStorage.setItem('tempPassword', formData.password); 
    
    // BAD PRACTICE: Logging PII to console
    console.log("Submitting user data:", formData);
    
    try {
      const response = await fetch('http://api.example.com/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData)
      });
      
      const data = await response.json();
      if (data.token) {
        saveToken(data.token);
      }
    } catch (error) {
      console.error("Registration failed", error);
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <div>
        <label>First Name</label>
        <input 
          type="text" 
          name="firstName" 
          value={formData.firstName} 
          onChange={handleChange} 
        />
      </div>
      <div>
        <label>Last Name</label>
        <input 
          type="text" 
          name="lastName" 
          value={formData.lastName} 
          onChange={handleChange} 
        />
      </div>
      <div>
        <label>Email</label>
        <input 
          type="email" 
          name="email" 
          value={formData.email} 
          onChange={handleChange} 
        />
      </div>
      <div>
        <label>Password</label>
        <input 
          type="password" 
          name="password" 
          value={formData.password} 
          onChange={handleChange} 
        />
      </div>
      <div>
        <label>Phone</label>
        <input 
          type="tel" 
          name="phoneNumber" 
          value={formData.phoneNumber} 
          onChange={handleChange} 
        />
      </div>
      <div>
        <label>Date of Birth</label>
        <input 
          type="date" 
          name="birthDate" 
          value={formData.birthDate} 
          onChange={handleChange} 
        />
      </div>
      <button type="submit">Register</button>
    </form>
  );
};
