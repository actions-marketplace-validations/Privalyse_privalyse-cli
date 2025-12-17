import axios from 'axios';

// BAD PRACTICE: Insecure HTTP endpoint
const API_URL = 'http://api.insecure-backend.com';

export const saveToken = (token: string) => {
    // BAD PRACTICE: Storing auth token in localStorage
    localStorage.setItem('authToken', token);
    sessionStorage.setItem('jwt_secret', token);
};

export const getUserProfile = async (userId: string) => {
    // BAD PRACTICE: Passing ID in URL (minor issue, but good for tracking)
    const response = await axios.get(`${API_URL}/users/${userId}`);
    return response.data;
};

export const updateUser = async (userData: any) => {
    // BAD PRACTICE: Logging full user object
    console.log("Updating user:", userData);
    
    const response = await fetch(`${API_URL}/users/update`, {
        method: 'POST',
        body: JSON.stringify(userData)
    });
    return response.json();
};
