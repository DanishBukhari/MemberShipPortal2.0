const UserSchema = new mongoose.Schema({
  name: String,
  email: String,
  phone: String,
  tier: String,
  paymentStatus: { type: String, default: 'pending' },
  expiry: Date,
  visitsLeft: Number,
  photo: String,
  address: String,
  family: [{ name: String, email: String, phone: String, tier: String }],
});

const User = mongoose.model('User', UserSchema);