import React, { useState } from 'react';

export default function RegisterForm() {
  const [formData, setFormData] = useState({});

  return (
    <form>
      {/* 1. Email Detection via Placeholder (Variable name is obscure) */}
      <div>
        <label>Contact Info</label>
        <input 
          type="text" 
          name="field_1" 
          placeholder="Enter your email address" 
          onChange={(e) => setFormData({...formData, field1: e.target.value})}
        />
      </div>

      {/* 2. Password Detection via Aria-Label */}
      <div>
        <input 
          type="text" 
          name="field_2" 
          aria-label="Password Input"
          onChange={(e) => setFormData({...formData, field2: e.target.value})}
        />
      </div>

      {/* 3. SSN Detection via Label */}
      <div>
        <label htmlFor="field_3">Please provide your SSN for tax purposes</label>
        <input 
          id="field_3"
          type="text" 
          name="field_3" 
          label="SSN"
        />
      </div>

      {/* 4. Credit Card via Placeholder */}
      <div>
        <input 
          type="text" 
          name="payment_info" 
          placeholder="XXXX-XXXX-XXXX-XXXX (Credit Card)" 
        />
      </div>

      {/* 5. Phone Number via Name attribute regex */}
      <div>
        <input 
          type="tel" 
          name="user_mobile" 
        />
      </div>

      {/* 6. Date of Birth via Placeholder */}
      <div>
        <input 
          type="date" 
          placeholder="Date of Birth (DD/MM/YYYY)" 
        />
      </div>
      
      {/* 7. Address via Label attribute (e.g. Material UI style) */}
      <TextField 
        label="Street Address"
        name="addr"
      />
    </form>
  );
}
