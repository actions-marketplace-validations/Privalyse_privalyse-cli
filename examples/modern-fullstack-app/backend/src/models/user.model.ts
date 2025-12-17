import mongoose from 'mongoose';

// TEST 5: Mongoose Schema Definition (New Feature)
const UserSchema = new mongoose.Schema({
    email: { type: String, required: true },
    password: { type: String, required: true }, // Should be detected as stored credential
    firstName: String,
    lastName: String,
    ssn: { type: String, unique: true }, // Should be detected as ID
    creditCard: String // Should be detected as Financial
});

export const User = mongoose.model('User', UserSchema);
