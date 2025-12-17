
export const createUser = async (email: string, pass: string) => {
    // PROPAGATION: Function arguments are harder to track with Regex Lite Taint,
    // but let's simulate local assignment which IS tracked.
    
    const dbEmail = email;
    const dbPassword = pass;
    
    // SINK: Logging inside service
    console.log(`Saving to DB: ${dbEmail} / ${dbPassword}`);
    
    // Simulate DB save
    return { id: "123", status: "created" };
};

export const processPayment = (ccn: string, cvv: string) => {
    const cardNum = ccn;
    const securityCode = cvv;
    
    // BAD PRACTICE: Logging financial data
    console.log(`Charging card ${cardNum} with CVV ${securityCode}`);
    
    return true;
};
