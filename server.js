require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const axios = require("axios");
const nodemailer = require("nodemailer");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cloudinary = require("cloudinary").v2;
const multer = require("multer");
const upload = multer({ dest: "uploads/" });
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
const crypto = require("crypto");
const bodyParser = require("body-parser");
// const cron = require("node-cron");


const app = express();
app.use(cors());
app.use(express.json());

mongoose.connect(process.env.MONGODB_URI, {});

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const UserSchema = new mongoose.Schema({
  name: String,
  email: String,
  phone: String,
  password: String,
  paymentStatus: { type: String, default: "pending" },
  memberships: [
    {
      _id: {
        type: mongoose.Schema.Types.ObjectId,
        default: () => new mongoose.Types.ObjectId(),
      },
      tier: String,
      expiry: Date,
      visitsLeft: Number,
      paymentStatus: { type: String, default: "pending" },
      lastCheck: Date,
      createdAt: { type: Date, default: Date.now },
      stripeItemId: String,
      numHours: { type: Number, default: 1 }, // Changed from numAdults
      numParticipants: { type: Number, default: 1 }, // Changed from numChildren
      numNonParticipatingAdults: { type: Number, default: 0 }, // New field
      hoursLeft: Number, // New for hourly deduction in walk-in

      sessionStart: Date,
      sessionEnd: Date,
    },
  ],
  photo: String,
  address: String,
  age: Number,
  family: [
    {
      _id: {
        type: mongoose.Schema.Types.ObjectId,
        default: () => new mongoose.Types.ObjectId(),
      },
      name: String,
      age: Number,
      relationship: String,
      photo: String,
      tier: String,
      expiry: Date,
      visitsLeft: Number,
      paymentStatus: { type: String, default: "pending" },
      lastCheck: Date,
      createdAt: { type: Date, default: Date.now },
      stripeItemId: String,

      sessionStart: Date,
      sessionEnd: Date,
    },
  ],
  familyTiers: [String],
  numHours: { type: Number, default: 1 }, // Changed
  numParticipants: { type: Number, default: 1 }, // Changed
  profileComplete: { type: Boolean, default: false },
  resetPasswordToken: String,
  resetPasswordExpires: Date,
  stripeCustomerId: String,
  stripeSubscriptionId: String,
  familyItemIds: [String],
});
const User = mongoose.model("Users", UserSchema);

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
});

const formatDateForGHL = (date) => {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");
  return `${year}-${month}-${day}`;
};

const createGHLContact = async (name, email, phone, tier, expiry) => {
  try {
    const emailLower = email.toLowerCase();
    const response = await axios.get(
      `https://rest.gohighlevel.com/v1/contacts?email=${encodeURIComponent(
        emailLower,
      )}`,
      { headers: { Authorization: `Bearer ${process.env.GHL_API_TOKEN}` } },
    );
    const dateString = expiry ? formatDateForGHL(expiry) : null;
    const tags = [`member-${tier}`, "gokollab"];
    const customFieldId = "dIg1gNeOG3xsWTE2lKEr";
    const customFields = dateString
      ? [{ id: customFieldId, value: dateString }]
      : [];

    const existingContact = response.data.contacts.find(
      (c) => c.email === emailLower,
    );
    if (existingContact) {
      await axios.put(
        `https://rest.gohighlevel.com/v1/contacts/${existingContact.id}`,
        { customField: customFields },
        { headers: { Authorization: `Bearer ${process.env.GHL_API_TOKEN}` } },
      );
      return existingContact.id;
    } else {
      const createResponse = await axios.post(
        "https://rest.gohighlevel.com/v1/contacts/",
        { name, email: emailLower, phone, tags, customField: customFields },
        { headers: { Authorization: `Bearer ${process.env.GHL_API_TOKEN}` } },
      );
      return createResponse.data.contact.id;
    }
  } catch (error) {
    console.error("GHL Error:", error.response?.data || error.message);
    throw error;
  }
};

const updateGHLContactTag = async (contactId, tag) => {
  try {
    await axios.post(
      `https://rest.gohighlevel.com/v1/contacts/${contactId}/tags`,
      { tags: [tag] },
      { headers: { Authorization: `Bearer ${process.env.GHL_API_TOKEN}` } },
    );
  } catch (error) {
    console.error("Error updating GHL tag:", error);
    throw error;
  }
};

const getStripePriceId = (tier, isDiscounted = false) => {
  // const priceMap = {
  //   "legacy-maker": {
  //     full: "price_1ReTLmBQRG3WrNBRzfsYqcLa",
  //     discounted: "price_1ReTaABQRG3WrNBRYO5r0WXb",
  //   },
  //   leader: {
  //     full: "price_1ReTN8BQRG3WrNBRrarZEwBU",
  //     discounted: "price_1ReTYtBQRG3WrNBRmHQ5uhM7",
  //   },
  //   supporter: {
  //     full: "price_1ReTPxBQRG3WrNBRVtCCZMwX",
  //     discounted: "price_1ReTXSBQRG3WrNBRDsi504MZ",
  //   },
  // };

  const priceMap = {
     "legacy-maker": {
       full: "price_1RfpatJqz3pkKu5cpxDdOKTy",
       discounted: "price_1RfpbyJqz3pkKu5cE2LLL9Jr",
     },
     leader: {
       full: "price_1RfpaXJqz3pkKu5c7xnLsO48",
       discounted: "price_1RfpdnJqz3pkKu5cQgQN7Nk7",
     },
     supporter: {
       full: "price_1RfpaFJqz3pkKu5cW4cZKkUa",
       discounted: "price_1RfpeuJqz3pkKu5cc6lou0FU",
     },
   };
  return isDiscounted ? priceMap[tier].discounted : priceMap[tier].full;
};

// New endpoint to get all walk-in bookings
app.get("/api/admin/walk-ins", async (req, res) => {
  try {
    // Get start and end of current day in UTC
    const now = new Date();
    const startOfToday = new Date(
      Date.UTC(
        now.getUTCFullYear(),
        now.getUTCMonth(),
        now.getUTCDate(),
        0,
        0,
        0,
        0,
      ),
    );
    const endOfToday = new Date(
      Date.UTC(
        now.getUTCFullYear(),
        now.getUTCMonth(),
        now.getUTCDate(),
        23,
        59,
        59,
        999,
      ),
    );

    const users = await User.find({
      "memberships.tier": "walk-in",
      "memberships.expiry": {
        $gte: startOfToday,
        $lte: endOfToday,
      },
    });

    const bookings = [];

    users.forEach((user) => {
      user.memberships
        .filter(
          (m) =>
            m.tier === "walk-in" &&
            m.expiry >= startOfToday &&
            m.expiry <= endOfToday,
        )
        .forEach((membership) => {
          // Inside the forEach loop for bookings.push
          bookings.push({
            _id: membership._id,
            membership: {
              ...membership.toObject(),
              amountDue: (
                membership.numHours * 7 +  // First participant
                membership.numHours * 3.5 * (membership.numParticipants - 1) +  // Additional participants
                2.5 * (membership.numNonParticipatingAdults >= 1 ? 1 : 0) +  // First non-part
                1 * (membership.numNonParticipatingAdults - 1 > 0 ? membership.numNonParticipatingAdults - 1 : 0)  // Additional non-part
              ).toFixed(2),
            },
            user: {
              _id: user._id,
              name: user.name,
              phone: user.phone,
              photo: user.photo,
            },
          });
        });
    });

    res.send(bookings);
  } catch (error) {
    console.error("Error fetching walk-ins:", error);
    res.status(500).send({ error: "Failed to fetch walk-in bookings" });
  }
});

app.post(
  "/api/stripe-webhook",
  bodyParser.raw({ type: "application/json" }),
  async (req, res) => {
    const sig = req.headers["stripe-signature"];
    let event;

    try {
      event = stripe.webhooks.constructEvent(
        req.body,
        sig,
        process.env.STRIPE_WEBHOOK_SECRET,
      );
    } catch (err) {
      console.error("Webhook signature verification failed:", err.message);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    if (event.type === "invoice.payment_succeeded") {
      const invoice = event.data.object;
      const subscriptionId = invoice.subscription;
      const user = await User.findOne({ stripeSubscriptionId: subscriptionId });
      if (user) {
        user.memberships.forEach((m) => {
          m.visitsLeft =
            m.tier === "legacy-maker"
              ? Number.MAX_SAFE_INTEGER
              : m.tier === "leader"
                ? 5
                : m.tier === "supporter"
                  ? 2
                  : 1;
          m.lastCheck = null;
        });
        user.family.forEach((f) => {
          f.visitsLeft =
            f.tier === "legacy-maker"
              ? Number.MAX_SAFE_INTEGER
              : f.tier === "leader"
                ? 5
                : f.tier === "supporter"
                  ? 2
                  : 1;
          f.lastCheck = null;
        });
        await user.save();
      }
    }

    res.json({ received: true });
  },
);

app.post("/api/users", async (req, res) => {
  const { name, email, phone, memberships } = req.body;
  const emailLower = email.toLowerCase();

  try {
    // 1. Check for existing user with matching email AND phone
    let user = await User.findOne({
      email: emailLower,
      phone: phone,
    });

    const primaryMembership = {
      _id: new mongoose.Types.ObjectId(),
      tier: memberships[0],
      visitsLeft:
        memberships[0] === "legacy-maker"
          ? Number.MAX_SAFE_INTEGER
          : memberships[0] === "leader"
            ? 5
            : memberships[0] === "supporter"
              ? 2
              : 1,
      paymentStatus: "pending",
    };

    const familyTiers = memberships.slice(1);

    if (user) {
      // 2. Found matching user - add membership
      user.memberships.push(primaryMembership);

      // MERGE family tiers instead of replacing
      user.familyTiers = [...(user.familyTiers || []), ...familyTiers];
    } else {
      // 3. No matching user - check for conflicts
      const existingEmail = await User.findOne({ email: emailLower });
      const existingPhone = await User.findOne({ phone });

      if (existingEmail || existingPhone) {
        let errorMessage = "";
        if (existingEmail && existingPhone) {
          errorMessage =
            "Both email and phone already exist with different accounts";
        } else if (existingEmail) {
          errorMessage = "Email already exists with a different phone";
        } else {
          errorMessage = "Phone number already exists with a different email";
        }
        return res.status(400).send({ error: errorMessage });
      }

      // 4. Create new user since no conflicts
      user = new User({
        name,
        email: emailLower,
        phone,
        memberships: [primaryMembership],
        familyTiers,
      });
    }

    // 5. GHL contact handling
    let contactId = user?.ghlContactId;
    if (!contactId) {
      contactId = await createGHLContact(
        name,
        emailLower,
        phone,
        memberships[0],
        null,
      );
      user.ghlContactId = contactId;
    }

    await user.save();
    res.status(201).json(user);
  } catch (error) {
    // Handle duplicate key errors
    if (error.code === 11000) {
      const key = Object.keys(error.keyPattern)[0];
      return res.status(400).send({
        error: `${key.replace(/^\$/, "")} already exists`,
      });
    }
    console.error("Error in /api/users:", error);
    res.status(500).json({ error: "Server error" });
  }
});

const updateGHLContactAfterPayment = async (
  contactId,
  email,
  expiry,
  password,
) => {
  try {
    const dateString = expiry ? formatDateForGHL(expiry) : null;
    const customFields = [
      { id: "AWEGVmYcODJ9AKt25LUW", value: email },
      { id: "UsNxm6CgF2G6VtXoVDGN", value: password },
    ];
    if (dateString) {
      customFields.push({ id: "dIg1gNeOG3xsWTE2lKEr", value: dateString });
    }
    await axios.put(
      `https://rest.gohighlevel.com/v1/contacts/${contactId}`,
      { customField: customFields },
      { headers: { Authorization: `Bearer ${process.env.GHL_API_TOKEN}` } },
    );
    if (!expiry) {
      // Only for non-walk-ins
      await axios.post(
        `https://rest.gohighlevel.com/v1/contacts/${contactId}/tags`,
        { tags: ["first-time-payment"] },
        { headers: { Authorization: `Bearer ${process.env.GHL_API_TOKEN}` } },
      );
    }
  } catch (error) {
    console.error("Error updating GHL contact:", error);
    throw error;
  }
};

app.post("/api/payment", async (req, res) => {
  const {
    paymentMethodId,
    memberships,
    name,
    email,
    phone,
    totalAmountInCents,
    selectedDate, // Added for walk-in creation
    numAdults = 1, // Added with default
    numChildren = 0, // Added with default
  } = req.body;
  const hasWalkIn = memberships.some((m) => m === "walk-in");
  const emailLower = email.toLowerCase();

  try {
    let user = await User.findOne({ email: emailLower });
    console.log("user kk", user);
    const password = crypto.randomBytes(8).toString("hex");
    const hashedPassword = await bcrypt.hash(password, 10);

    if (hasWalkIn) {
      // Create walk-in record if missing
      if (
        !user ||
        !user.memberships.some(
          (m) => m.tier === "walk-in" && m.paymentStatus === "pending",
        )
      ) {
        const expiryDate = new Date(selectedDate);
        expiryDate.setUTCHours(23, 59, 59, 999);

        if (!user) {
          user = new User({
            name,
            email: emailLower,
            phone,
            memberships: [
              {
                tier: "walk-in",
                visitsLeft: 1,
                expiry: expiryDate,
                paymentStatus: "pending",
                numAdults,
                numChildren,
              },
            ],
          });
        } else {
          user.memberships.push({
            tier: "walk-in",
            visitsLeft: 1,
            expiry: expiryDate,
            paymentStatus: "pending",
            numAdults,
            numChildren,
          });
        }
        await user.save();
      }

      // Process payment
      const paymentIntent = await stripe.paymentIntents.create({
        amount: totalAmountInCents || 700,
        currency: "aud",
        payment_method: paymentMethodId,
        payment_method_types: ["card"],
        confirm: true,
      });

      if (paymentIntent.status === "succeeded") {
        // Find the most recent pending walk-in
        const walkInMembership = user.memberships
          .slice()
          .reverse()
          .find((m) => m.tier === "walk-in" && m.paymentStatus === "pending");

        if (!walkInMembership) {
          console.error("Walk-in not found after creation", {
            userId: user._id,
            memberships: user.memberships,
          });
          throw new Error("Walk-in membership processing failed");
        }

        walkInMembership.paymentStatus = "active";
        // if (!user.password) user.password = hashedPassword;

        let contactId = user?.ghlContactId;
        if (!contactId) {
          contactId = await createGHLContact(
            name,
            emailLower,
            phone,
            "walk-in",
            walkInMembership.expiry,
          );
          user.ghlContactId = contactId;
        }

        await updateGHLContactAfterPayment(
          contactId,
          emailLower,
          walkInMembership.expiry,
          // password,
        );

        await axios.post(
          `https://rest.gohighlevel.com/v1/contacts/${contactId}/tags`,
          { tags: ["welcome walkin"] },
          { headers: { Authorization: `Bearer ${process.env.GHL_API_TOKEN}` } },
        );

        await user.save();
        return res
          .status(200)
          .send({ message: "Payment processed successfully" });
      }
    } else {
      const customer = await stripe.customers.create({
        email: email.toLowerCase(),
        payment_method: paymentMethodId,
        invoice_settings: { default_payment_method: paymentMethodId },
      });

      const subscriptionItems = memberships.map((tier, index) => ({
        price:
          index === 0 ? getStripePriceId(tier) : getStripePriceId(tier, true),
        quantity: 1,
      }));

      const subscription = await stripe.subscriptions.create({
        customer: customer.id,
        items: subscriptionItems,
        default_payment_method: paymentMethodId,
        collection_method: "charge_automatically",
      });

      if (subscription.status === "active") {
        const primaryMembership = {
          _id: new mongoose.Types.ObjectId(),
          tier: memberships[0],
          visitsLeft:
            memberships[0] === "legacy-maker"
              ? Number.MAX_SAFE_INTEGER
              : memberships[0] === "leader"
                ? 5
                : memberships[0] === "supporter"
                  ? 2
                  : 1,
          paymentStatus: "active",
          stripeItemId: subscription.items.data[0].id,
        };
        const familyItemIds = subscription.items.data
          .slice(1)
          .map((item) => item.id);

        // Handle user creation/update
        if (user) {
          user.memberships = user.memberships.filter(
            (m) =>
              !(m.tier === memberships[0] && m.paymentStatus === "pending"),
          );
          // Preserve existing memberships while adding the new one
          console.log("user membership ache? 1", user.memberships);

          user.memberships.push(primaryMembership);
          console.log("user ache?", user);
          console.log("user membership ache? 2", user.memberships);
        } else {
          // Create new user with initial membership
          user = new User({
            name,
            email: email.toLowerCase(),
            phone,
            paymentStatus: "active",
            password: hashedPassword,
            profileComplete: false,
            memberships: [primaryMembership],
          });
        }

        // Update user properties
        user.familyTiers = memberships.slice(1);
        user.stripeCustomerId = customer.id;
        user.stripeSubscriptionId = subscription.id;

        // Preserve existing familyItemIds and add new ones
        user.familyItemIds = [...(user.familyItemIds || []), ...familyItemIds];

        if (!user.password) user.password = hashedPassword;

        let contactId = user?.ghlContactId;
        if (!contactId) {
          contactId = await createGHLContact(
            name,
            email.toLowerCase(),
            phone,
            memberships[0],
            null,
          );
          user.ghlContactId = contactId;
        }

        await updateGHLContactAfterPayment(
          contactId,
          email.toLowerCase(),
          null,
          password,
        );

        await user.save();
        return res
          .status(200)
          .send({ message: "Subscription created successfully" });
      }
    }
  } catch (error) {
    console.error("Payment error:", {
      endpoint: "/api/payment",
      error: error.message,
      email,
      memberships,
      hasWalkIn,
    });
    return res.status(500).send({
      error: "Payment processing failed: " + error.message,
    });
  }
});

app.post("/api/confirm-cash-payment", async (req, res) => {
  const { userId, membershipId, isFamily } = req.body;
  try {
    const user = await User.findById(userId);
    if (!user) {
      return res.status(400).send({ error: "User not found" });
    }
    if (isFamily) {
      const familyMember = user.family.find(
        (f) => f._id.toString() === membershipId,
      );
      if (!familyMember || familyMember.tier !== "walk-in") {
        return res.status(400).send({ error: "Invalid family member request" });
      }
      familyMember.paymentStatus = "active";
    } else {
      const membership = user.memberships.find(
        (m) => m._id.toString() === membershipId,
      );
      if (!membership || membership.tier !== "walk-in") {
        return res.status(400).send({ error: "Invalid membership request" });
      }
      membership.paymentStatus = "active";
      user.paymentStatus = "active";
    }
    await user.save();
    res.send({ success: true });
  } catch (error) {
    console.error("Error in /api/confirm-cash-payment:", error);
    res.status(500).send({ error: "Failed to confirm cash payment" });
  }
});

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      return res.status(401).send({ error: "Invalid credentials" });
    }
    console.log("check user mail", user);
    const isMatch = await bcrypt.compare(password, user.password);
    console.log("check match", isMatch);

    if (!isMatch) {
      return res.status(401).send({ error: "Invalid credentials" });
    }
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });
    res.send({ token });
  } catch (error) {
    console.error("Error in /api/login:", error);
    res.status(500).send({ error: "Login failed" });
  }
});
app.post("/api/forgot-password", async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).send({ error: "User not found" });
    }
    const newPassword = crypto.randomBytes(8).toString("hex");
    console.log("newPassword", newPassword);
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    console.log("hashedPassword", hashedPassword);
    user.password = hashedPassword;
    console.log("user password", user.password);
    await user.save();

    const response = await axios.get(
      `https://rest.gohighlevel.com/v1/contacts?email=${encodeURIComponent(
        email,
      )}`,
      { headers: { Authorization: `Bearer ${process.env.GHL_API_TOKEN}` } },
    );
    const contact = response.data.contacts.find(
      (c) => c.email.toLowerCase() === email.toLowerCase(),
    );
    if (!contact) {
      throw new Error("Contact not found in GHL");
    }

    const customFieldId = "UsNxm6CgF2G6VtXoVDGN";
    const customFields = [{ id: customFieldId, value: newPassword }];
    await axios.put(
      `https://rest.gohighlevel.com/v1/contacts/${contact.id}`,
      { customField: customFields },
      { headers: { Authorization: `Bearer ${process.env.GHL_API_TOKEN}` } },
    );

    await axios.post(
      `https://rest.gohighlevel.com/v1/contacts/${contact.id}/tags`,
      { tags: ["password reset requested"] },
      { headers: { Authorization: `Bearer ${process.env.GHL_API_TOKEN}` } },
    );

    res.send({
      success: true,
      message: "Password reset initiated. Check your email.",
    });
  } catch (error) {
    console.error("Error in /api/forgot-password:", error.message);
    res.status(500).send({ error: "Failed to process password reset" });
  }
});

app.post("/api/reset-password", async (req, res) => {
  const { token, newPassword } = req.body;
  try {
    const user = await User.findOne({
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() },
    });
    if (!user) {
      return res.status(400).send({ error: "Invalid or expired token" });
    }
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();
    res.send({ success: true });
  } catch (error) {
    console.error("Error in /api/reset-password:", error);
    res.status(500).send({ error: "Failed to reset password" });
  }
});

app.post("/api/change-password", async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) {
    return res.status(401).send({ error: "Unauthorized" });
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user) {
      return res.status(404).send({ error: "User not found" });
    }
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res.status(401).send({ error: "Current password is incorrect" });
    }
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();
    res.send({ success: true });
  } catch (error) {
    console.error("Error in /api/change-password:", error);
    res.status(500).send({ error: "Failed to change password" });
  }
});

app.post("/api/subscription/set-tier-quantity", async (req, res) => {
  const { tier, quantity } = req.body;
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) {
    return res.status(401).send({ error: "Unauthorized" });
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user || !user.stripeSubscriptionId) {
      return res.status(404).send({ error: "Subscription not found" });
    }
    const priceId = getStripePriceId(tier);
    const subscription = await stripe.subscriptions.retrieve(
      user.stripeSubscriptionId,
    );
    const item = subscription.items.data.find(
      (item) => item.price.id === priceId,
    );
    if (quantity > 0) {
      if (item) {
        await stripe.subscriptions.update(user.stripeSubscriptionId, {
          items: [{ id: item.id, quantity }],
        });
      } else {
        await stripe.subscriptions.update(user.stripeSubscriptionId, {
          items: [{ price: priceId, quantity }],
        });
      }
    } else if (item) {
      await stripe.subscriptions.update(user.stripeSubscriptionId, {
        items: [{ id: item.id, deleted: true }],
      });
    }
    const updatedSubscription = await stripe.subscriptions.retrieve(
      user.stripeSubscriptionId,
    );
    user.memberships = updatedSubscription.items.data.map((item) => ({
      _id: new mongoose.Types.ObjectId(),
      tier: Object.keys({ "legacy-maker": "", leader: "", supporter: "" }).find(
        (key) => getStripePriceId(key) === item.price.id,
      ),
      visitsLeft:
        item.price.id === getStripePriceId("legacy-maker")
          ? Number.MAX_SAFE_INTEGER
          : item.price.id === getStripePriceId("leader")
            ? 5
            : 2,
    }));
    await user.save();
    res.send({ success: true });
  } catch (error) {
    console.error("Error in /api/subscription/set-tier-quantity:", error);
    res.status(500).send({ error: "Failed to update subscription" });
  }
});

app.get("/api/subscription", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) {
    return res.status(401).send({ error: "Unauthorized" });
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user || !user.stripeSubscriptionId) {
      return res.status(404).send({ error: "Subscription not found" });
    }
    const subscription = await stripe.subscriptions.retrieve(
      user.stripeSubscriptionId,
    );
    res.send(subscription);
  } catch (error) {
    console.error("Error in /api/subscription:", error);
    res.status(500).send({ error: "Failed to retrieve subscription" });
  }
});

const removeGHLContactTag = async (contactId, tag) => {
  try {
    await axios.delete(
      `https://rest.gohighlevel.com/v1/contacts/${contactId}/tags`,
      {
        data: { tags: [tag] },
        headers: { Authorization: `Bearer ${process.env.GHL_API_TOKEN}` }
      }
    );
  } catch (error) {
    console.error("Error removing GHL tag:", error);
    throw error;
  }
};

app.post("/api/subscription/change-tier", async (req, res) => {
  const { currentTier, newTier, memberId } = req.body;
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) {
    return res.status(401).send({ error: "Unauthorized" });
  }
  try {
    console.log("Received request to change tier:", {
      currentTier,
      newTier,
      memberId,
    });
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user) {
      return res.status(404).send({ error: "User not found" });
    }
    if (!user.stripeSubscriptionId) {
      return res.status(404).send({ error: "Subscription not found" });
    }

    let membershipToUpdate;
    let stripeItemId;
    if (memberId) {
      membershipToUpdate = user.family.find(
        (f) => f._id.toString() === memberId,
      );
      if (!membershipToUpdate) {
        return res.status(404).send({ error: "Family member not found" });
      }
      stripeItemId = membershipToUpdate.stripeItemId;
    } else {
      if (user.memberships.length === 0) {
        return res
          .status(400)
          .send({ error: "Primary user has no membership" });
      }
      membershipToUpdate = user.memberships[0];
      stripeItemId = membershipToUpdate.stripeItemId;
    }

    if (membershipToUpdate.tier !== currentTier) {
      return res.status(400).send({ error: "Current tier does not match" });
    }

    if (!stripeItemId) {
      return res
        .status(400)
        .send({ error: "Stripe subscription item ID not found" });
    }

    await stripe.subscriptionItems.update(stripeItemId, {
      price: getStripePriceId(newTier, memberId ? true : false),
    });

    membershipToUpdate.tier = newTier;
    membershipToUpdate.visitsLeft =
      newTier === "legacy-maker"
        ? Number.MAX_SAFE_INTEGER
        : newTier === "leader"
          ? 5
          : newTier === "supporter"
            ? 2
            : 1;

    // Update GHL tag for primary membership only
    if (user.ghlContactId && !memberId) {
      await removeGHLContactTag(user.ghlContactId, `member-${currentTier}`);
      await updateGHLContactTag(user.ghlContactId, `member-${newTier}`);
    }

    await user.save();
    res.send({ success: true });
  } catch (error) {
    console.error("Error in /api/subscription/change-tier:", error);
    res.status(500).send({ error: "Failed to change tier: " + error.message });
  }
});
app.post("/api/subscription/cancel-member", async (req, res) => {
  const { memberId } = req.body;
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) {
    return res.status(401).send({ error: "Unauthorized" });
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user) {
      return res.status(404).send({ error: "User not found" });
    }
    if (!user.stripeSubscriptionId) {
      return res.status(404).send({ error: "Subscription not found" });
    }

    if (memberId) {
      const familyMember = user.family.find(
        (f) => f._id.toString() === memberId,
      );
      if (!familyMember) {
        return res.status(404).send({ error: "Family member not found" });
      }

      const subscription = await stripe.subscriptions.retrieve(
        user.stripeSubscriptionId,
      );
      const item = subscription.items.data.find(
        (item) => item.id === familyMember.stripeItemId,
      );
      if (item) {
        await stripe.subscriptionItems.del(item.id);
      }

      user.family = user.family.filter((f) => f._id.toString() !== memberId);
    } else {
      await stripe.subscriptions.cancel(user.stripeSubscriptionId);
      user.paymentStatus = "cancelled";
      user.memberships = [];
      user.family = [];

      // Update GHL tag for cancellation
      if (user.ghlContactId) {
        const currentTier = user.memberships[0]?.tier;
        if (currentTier) {
          await removeGHLContactTag(user.ghlContactId, `member-${currentTier}`);
        }
        await updateGHLContactTag(user.ghlContactId, "membership-cancelled");
      }
    }

    await user.save();
    res.send({ success: true });
  } catch (error) {
    console.error("Error in /api/subscription/cancel-member:", error);
    res.status(500).send({ error: "Failed to cancel member subscription" });
  }
});
app.get("/api/invoices", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) {
    return res.status(401).send({ error: "Unauthorized" });
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user || !user.stripeCustomerId) {
      return res.status(404).send({ error: "Customer not found" });
    }
    const invoices = await stripe.invoices.list({
      customer: user.stripeCustomerId,
    });
    res.send(invoices);
  } catch (error) {
    console.error("Error in /api/invoices:", error);
    res.status(500).send({ error: "Failed to retrieve invoices" });
  }
});

app.get("/api/user", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) {
    return res.status(401).send({ error: "Unauthorized" });
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);
    console.log("user", user);
    if (!user) {
      return res.status(404).send({ error: "User not found" });
    }
    res.send(user);
  } catch (error) {
    console.error("Error in /api/user:", error);
    res.status(401).send({ error: "Invalid token" });
  }
});

app.post("/api/upload-photo", upload.single("photo"), async (req, res) => {
  try {
    const result = await cloudinary.uploader.upload(req.file.path);
    res.send({ photoUrl: result.secure_url });
  } catch (error) {
    console.error("Error in /api/upload-photo:", error);
    res.status(500).send({ error: "Photo upload failed" });
  }
});

app.put("/api/user", async (req, res) => {
  const { email, photo, address, age, profileComplete } = req.body;
  try {
    await User.updateOne({ email }, { photo, address, age, profileComplete });
    res.status(200).send({ success: true });
  } catch (error) {
    console.error("Error in /api/user (PUT):", error);
    res.status(500).send({ error: "Failed to update user" });
  }
});

app.post("/api/family", async (req, res) => {
  const { name, age, relationship, photo, tier, userId } = req.body;
  try {
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).send({ error: "User not found" });
    }
    if (user.familyItemIds.length === 0) {
      return res
        .status(400)
        .send({ error: "No available subscription items for family members" });
    }
    const stripeItemId = user.familyItemIds.shift();
    const visitsLeft =
      tier === "legacy-maker"
        ? Number.MAX_SAFE_INTEGER
        : tier === "leader"
          ? 5
          : tier === "supporter"
            ? 2
            : 1;

    const familyMember = {
      _id: new mongoose.Types.ObjectId(),
      name,
      age,
      relationship,
      photo,
      tier,
      visitsLeft,
      paymentStatus: "active",
      stripeItemId,
    };

    if (user.family.some((f) => f.name === name)) {
      return res.status(400).send({ error: "Family member already exists" });
    }

    await User.updateOne(
      { _id: userId },
      {
        $push: { family: familyMember },
        $set: { familyItemIds: user.familyItemIds },
      },
    );
    res.status(201).send(familyMember);
  } catch (error) {
    console.error("Error in /api/family:", error);
    res.status(500).send({ error: "Failed to add family member" });
  }
});

app.put("/api/family", async (req, res) => {
  const { name, relationship, photo, tier, userId } = req.body;
  try {
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).send({ error: "User not found" });
    }
    const familyMember = user.family.find((f) => f.name === name);
    if (!familyMember) {
      return res.status(404).send({ error: "Family member not found" });
    }
    familyMember.relationship = relationship;
    familyMember.photo = photo;
    familyMember.tier = tier;
    await user.save();
    res.send(familyMember);
  } catch (error) {
    console.error("Error in /api/family (PUT):", error);
    res.status(500).send({ error: "Failed to update family member" });
  }
});

app.post("/api/walk-in", async (req, res) => {
  const {
    name,
    email,
    phone,
    tier,
    paymentMethod,
    numHours = 1,
    numParticipants = 1,
    numNonParticipatingAdults = 0,
    selectedDate,
  } = req.body;

  if (numParticipants < 1) {
    return res.status(400).send({ error: "Number of participants must be at least 1" });
  }

  const emailLower = email.toLowerCase();

  try {
    let user = await User.findOne({
      email: emailLower,
      phone,
    });

    const expiryDate = new Date(
      Date.UTC(
        new Date(selectedDate).getUTCFullYear(),
        new Date(selectedDate).getUTCMonth(),
        new Date(selectedDate).getUTCDate(),
        23,
        59,
        59,
        999,
      ),
    );

    const membership = {
      _id: new mongoose.Types.ObjectId(),
      tier,
      visitsLeft: 1,
      expiry: expiryDate,
      paymentStatus: "pending",
      createdAt: new Date(),
      numHours,
      numParticipants,
      numNonParticipatingAdults,
      hoursLeft: numHours,  // New: for hourly deduction
    };

    if (user) {
      user.memberships.push(membership);
      user.numHours = numHours;
      user.numParticipants = numParticipants;
    } else {
      // 3. No matching user - check for conflicts
      const existingEmail = await User.findOne({ email: emailLower });
      const existingPhone = await User.findOne({ phone });

      if (existingEmail || existingPhone) {
        let errorMessage = "";
        if (existingEmail && existingPhone) {
          errorMessage =
            "Both email and phone already exist with different accounts";
        } else if (existingEmail) {
          errorMessage = "Email already exists with a different phone";
        } else {
          errorMessage = "Phone number already exists with a different email";
        }
        return res.status(400).send({ error: errorMessage });
      }

      // 4. Create new user since no conflicts
      user = new User({
        name,
        email: emailLower,
        phone,
        memberships: [membership],
        numHours,
        numParticipants,
      });
    }

    // 5. GHL contact handling
    let contactId = user?.ghlContactId;
    if (!contactId) {
      contactId = await createGHLContact(
        name,
        emailLower,
        phone,
        tier,
        expiryDate,
      );
      user.ghlContactId = contactId;
    }

    // 6. Add tag in GHL
    await axios.post(
      `https://rest.gohighlevel.com/v1/contacts/${contactId}/tags`,
      { tags: ["welcome walkin"] },
      { headers: { Authorization: `Bearer ${process.env.GHL_API_TOKEN}` } },
    );

    // 7. Save user and respond
    await user.save();
    res.status(201).send(user);
  } catch (error) {
    // Handle duplicate key errors
    if (error.code === 11000) {
      const key = Object.keys(error.keyPattern)[0];
      return res.status(400).send({
        error: `${key.replace(/^\$/, "")} already exists`,
      });
    }
    console.error("Error in /api/walk-in:", error);
    res.status(500).send({ error: "Failed to process walk-in request" });
  }
});

// app.post("/api/check-visit", async (req, res) => {
//   const { userId } = req.body;
//   try {
//     const user = await User.findById(userId);
//     if (!user) return res.status(404).send({ error: "User not found" });
//     const now = new Date();

//     // Define cooldown function for visit deduction
//     const getCooldown = (tier) => {
//       if (tier === "walk-in") {
//         return 60 * 60 * 1000; // 1 hour for walk-ins
//         // return 20 * 1000; // 1 hour for walk-ins
//       } else {
//         return 24 * 60 * 60 * 1000; // 24 hours for other tiers, adjust as needed
//         // return 20 * 1000; // 24 hours for other tiers, adjust as needed
//       }
//     };

//     // Process memberships
//     user.memberships.forEach((m) => {
//       if (m.paymentStatus === "active" && m.visitsLeft > 0) {
//         const cooldown = getCooldown(m.tier);
//         if (!m.lastCheck || now - new Date(m.lastCheck) > cooldown) {
//           m.visitsLeft -= 1; // Deduct visit only after cooldown period
//           m.lastCheck = now;
//           if (m.visitsLeft === 0) {
//             m.paymentStatus = "expired";
//           }
//         } // Else, retain visitsLeft if within cooldown
//       }
//     });

//     // Process family members
//     user.family.forEach((f) => {
//       if (f.paymentStatus === "active" && f.visitsLeft > 0) {
//         const cooldown = getCooldown(f.tier);
//         if (!f.lastCheck || now - new Date(f.lastCheck) > cooldown) {
//           f.visitsLeft -= 1; // Deduct visit only after cooldown period
//           f.lastCheck = now;
//           if (f.visitsLeft === 0) {
//             f.paymentStatus = "expired";
//           }
//         } // Else, retain visitsLeft if within cooldown
//       }
//     });

//     await user.save();
//     res.send({ success: true });
//   } catch (error) {
//     console.error("Error in /api/check-visit:", error);
//     res.status(500).send({ error: "Failed to check visit" });
//   }
// });

app.post("/api/check-visit", async (req, res) => {
  const { userId, membershipIds = [], familyIds = [] } = req.body;
  try {
    const user = await User.findById(userId);
    if (!user) return res.status(404).send({ error: "User not found" });
    const now = new Date();
    const errors = [];

    // Process selected memberships
    user.memberships.forEach((m) => {
      if (membershipIds.includes(m._id.toString())) {
        // Check if membership is active and has visits left
        if (m.paymentStatus !== "active" || m.visitsLeft <= 0) {
          errors.push(
            `Membership ${m.tier} is not active or has no visits left`,
          );
          return;
        }

        // Check cooldown - minimum 5 minutes between check-ins
        if (m.lastCheck && now - new Date(m.lastCheck) < 300000) {
          errors.push(`Membership ${m.tier} was checked in too recently`);
          return;
        }

        // Check if session is already active
        if (m.sessionStart) {
          const sessionDuration =
            m.tier === "walk-in"
              ? 3600000
              : m.tier === "legacy-maker"
              ? 3600000
              : 86400000;
          const sessionEnd = new Date(
            m.sessionStart.getTime() + sessionDuration,
          );

          if (now < sessionEnd) {
            errors.push(`Membership ${m.tier} has an active session`);
            return;
          }
        }

        // Set sessionStart and sessionEnd
        m.sessionStart = now;
        m.lastCheck = now; // Update last check time

        if (m.tier === "walk-in") {
          m.sessionEnd = new Date(now.getTime() + 3600000); // 1 hour
        } else if (m.tier === "legacy-maker") {
          m.sessionEnd = new Date(now.getTime() + 3600000); // 1 hour
        } else {
          m.sessionEnd = new Date(now.getTime() + 86400000); // 24 hours
        }
      }
    });

    // Process selected family members
    user.family.forEach((f) => {
      if (familyIds.includes(f._id.toString())) {
        // Check if family member is active and has visits left
        if (f.paymentStatus !== "active" || f.visitsLeft <= 0) {
          errors.push(
            `Family member ${f.name} is not active or has no visits left`,
          );
          return;
        }

        // Check cooldown - minimum 5 minutes between check-ins
        if (f.lastCheck && now - new Date(f.lastCheck) < 300000) {
          errors.push(`Family member ${f.name} was checked in too recently`);
          return;
        }

        // Check if session is already active
        if (f.sessionStart) {
          const sessionDuration =
            f.tier === "walk-in"
              ? 3600000
              : f.tier === "legacy-maker"
              ? 3600000
              : 86400000;
          const sessionEnd = new Date(
            f.sessionStart.getTime() + sessionDuration,
          );

          if (now < sessionEnd) {
            errors.push(`Family member ${f.name} has an active session`);
            return;
          }
        }

        // Set sessionStart and sessionEnd
        f.sessionStart = now;
        f.lastCheck = now; // Update last check time

        if (f.tier === "walk-in") {
          f.sessionEnd = new Date(now.getTime() + 3600000); // 1 hour
        } else if (f.tier === "legacy-maker") {
          f.sessionEnd = new Date(now.getTime() + 3600000); // 1 hour
        } else {
          f.sessionEnd = new Date(now.getTime() + 86400000); // 24 hours
        }
      }
    });

    if (errors.length > 0) {
      return res.status(400).send({
        success: false,
        message: "Some check-ins failed",
        errors,
      });
    }

    await user.save();
    res.send({ success: true });
  } catch (error) {
    console.error("Error in /api/check-visit:", error);
    res.status(500).send({ error: "Failed to check visit" });
  }
});
app.get("/api/admin/user", async (req, res) => {
  const { phone } = req.query;
  try {
    const user = await User.findOne({ phone });
    if (!user) return res.status(404).send({ error: "User not found" });

    const now = new Date();
    let modified = false;

    // Process memberships
    user.memberships.forEach((m) => {
      if (m.paymentStatus === "active" && m.sessionStart) {
        let sessionDuration = 0;

        // Determine session duration based on tier
        if (m.tier === "walk-in") {
          sessionDuration = 3600000; // 1 hour
        } else if (m.tier === "legacy-maker") {
          sessionDuration = 3600000; // 1 hour (no deduction)
        } else {
          sessionDuration = 86400000; // 24 hours
        }

        const timePassed = now - new Date(m.sessionStart);
        const hoursPassed = Math.floor(timePassed / 3600000);

        if (hoursPassed > 0) {
          if (m.tier === "walk-in") {
            m.hoursLeft -= hoursPassed;
            if (m.hoursLeft < 0) m.hoursLeft = 0;
          } else if (m.tier !== "legacy-maker") {
            m.visitsLeft -= hoursPassed;
            if (m.visitsLeft < 0) m.visitsLeft = 0;
          }

          // Adjust sessionStart forward
          m.sessionStart = new Date(m.sessionStart.getTime() + hoursPassed * 3600000);

          // Calculate new sessionEnd
          const newSessionEnd = new Date(m.sessionStart.getTime() + sessionDuration);

          // If last hour or expired
          if (now > newSessionEnd || (m.tier === "walk-in" && m.hoursLeft <= 0) || (m.tier !== "legacy-maker" && m.visitsLeft <= 0)) {
            m.sessionStart = null;
            m.paymentStatus = "expired";
          }

          modified = true;
        }
      }

      // Old walk-in expiry check (keep this for backward compatibility)
      if (m.tier === "walk-in" && now > new Date(m.expiry)) {
        m.paymentStatus = "expired";
        m.visitsLeft = 0;
        modified = true;
      }
    });

    // Process family members
    user.family.forEach((f) => {
      if (f.paymentStatus === "active" && f.sessionStart) {
        let sessionDuration = 0;

        if (f.tier === "walk-in") {
          sessionDuration = 3600000; // 1 hour
        } else if (f.tier === "legacy-maker") {
          sessionDuration = 3600000; // 1 hour (no deduction)
        } else {
          sessionDuration = 86400000; // 24 hours
        }

        const timePassed = now - new Date(f.sessionStart);
        const hoursPassed = Math.floor(timePassed / 3600000);

        if (hoursPassed > 0) {
          if (f.tier === "walk-in") {
            f.hoursLeft -= hoursPassed;
            if (f.hoursLeft < 0) f.hoursLeft = 0;
          } else if (f.tier !== "legacy-maker") {
            f.visitsLeft -= hoursPassed;
            if (f.visitsLeft < 0) f.visitsLeft = 0;
          }

          f.sessionStart = new Date(f.sessionStart.getTime() + hoursPassed * 3600000);

          const newSessionEnd = new Date(f.sessionStart.getTime() + sessionDuration);

          if (now > newSessionEnd || (f.tier === "walk-in" && f.hoursLeft <= 0) || (f.tier !== "legacy-maker" && f.visitsLeft <= 0)) {
            f.sessionStart = null;
            f.paymentStatus = "expired";
          }

          modified = true;
        }
      }

      // Old walk-in expiry check
      if (f.tier === "walk-in" && now > new Date(f.expiry)) {
        f.paymentStatus = "expired";
        f.visitsLeft = 0;
        modified = true;
      }
    });

    // Save if any modifications were made
    if (modified) {
      await user.save();
    }

    const responseData = {
      _id: user._id,
      name: user.name,
      phone: user.phone,
      photo: user.photo,
      memberships: user.memberships.map((m) => ({
        _id: m._id,
        tier: m.tier,
        visitsLeft: m.visitsLeft,
        expiry: m.expiry,
        paymentStatus: m.paymentStatus,
        createdAt: m.createdAt,
        numHours: m.numHours,
        numParticipants: m.numParticipants,
        numNonParticipatingAdults: m.numNonParticipatingAdults,
        hoursLeft: m.hoursLeft,
        sessionStart: m.sessionStart, // Include session info in response
      })),
      paymentStatus: user.paymentStatus,
      family: user.family.map((f) => ({
        _id: f._id,
        name: f.name,
        age: f.age,
        relationship: f.relationship,
        photo: f.photo,
        tier: f.tier,
        visitsLeft: f.visitsLeft,
        expiry: f.expiry,
        paymentStatus: f.paymentStatus,
        createdAt: f.createdAt,
        sessionStart: f.sessionStart, // Include session info in response
      })),
      numHours: user.numHours,
      numParticipants: user.numParticipants,
      stripeCustomerId: user.stripeCustomerId,
      stripeSubscriptionId: user.stripeSubscriptionId,
    };

    res.send(responseData);
  } catch (error) {
    console.error("Error in /api/admin/user:", error);
    res.status(500).send({ error: "Failed to retrieve user" });
  }
});
app.delete("/api/admin/delete-user", async (req, res) => {
  const { userId } = req.body;
  try {
    const user = await User.findById(userId);
    if (user && user.stripeSubscriptionId) {
      await stripe.subscriptions.del(user.stripeSubscriptionId);
    }
    await User.deleteOne({ _id: userId });
    res.status(200).send({
      success: true,
      message: "User deleted and subscription cancelled",
    });
  } catch (error) {
    console.error("Error deleting user:", error);
    res.status(500).send({ error: "Failed to delete user" });
  }
});

app.post("/api/ghl/contact-delete", async (req, res) => {
  const { email, phone } = req.body;
  try {
    const result = await User.deleteMany({ $or: [{ email }, { phone }] });
    if (result.deletedCount > 0) {
      res
        .status(200)
        .send({ success: true, message: "Contact(s) deleted from MongoDB" });
    } else {
      res.status(404).send({ error: "No matching contact found in MongoDB" });
    }
  } catch (error) {
    console.error("Error deleting contact:", error);
    res.status(500).send({ error: "Failed to delete contact" });
  }
});

// API endpoint for GHL to update user data
// API endpoint for GHL to update user data
app.post("/api/ghl/update-user", async (req, res) => {
  const contact = req.body;
  if (!contact) return res.status(400).send("Missing contact data");

  try {
    const email = contact.email?.toLowerCase();
    const phone = contact.phone?.replace(/\D/g, ""); // Normalize phone number
    const name = contact.name || "";

    // Validate required fields
    if (!email && !phone) {
      return res.status(400).send("Email or phone required");
    }

    // Find user by email or phone
    const user = await User.findOne({
      $or: [{ email: email }, { phone: phone }],
    });

    if (!user) return res.status(404).send("User not found");

    // Update fields from GHL
    const updates = {};
    if (name) updates.name = name;
    if (email && email !== user.email) {
      // Verify email doesn't exist elsewhere
      const emailExists = await User.exists({ email, _id: { $ne: user._id } });
      if (emailExists) return res.status(400).send("Email already in use");
      updates.email = email;
    }
    if (phone && phone !== user.phone) {
      // Verify phone doesn't exist elsewhere
      const phoneExists = await User.exists({ phone, _id: { $ne: user._id } });
      if (phoneExists) return res.status(400).send("Phone already in use");
      updates.phone = phone;
    }

    // Update custom fields
    if (contact.customField) {
      const expiryFieldId = "dIg1gNeOG3xsWTE2lKEr"; // Your GHL expiry field ID
      const expiryDate = contact.customField[expiryFieldId];

      if (expiryDate) {
        // Update most recent walk-in membership expiry
        const walkIns = user.memberships
          .filter((m) => m.tier === "walk-in")
          .sort((a, b) => b.createdAt - a.createdAt);

        if (walkIns.length > 0) {
          walkIns[0].expiry = new Date(expiryDate);
        }
      }
    }

    // Apply updates
    await User.updateOne({ _id: user._id }, { $set: updates });

    // Check for "delete" tag
    if (contact.tags && contact.tags.includes("delete")) {
      // Cancel Stripe subscription if exists
      if (user.stripeSubscriptionId) {
        await stripe.subscriptions.del(user.stripeSubscriptionId);
      }

      // Cancel access to membership
      user.paymentStatus = "cancelled";
      user.memberships = [];
      user.family = [];

      const contactId = contact.id || user.ghlContactId;
      if (!contactId) {
        throw new Error("No GHL contact ID available");
      }

      // Set if not present
      if (!user.ghlContactId) {
        user.ghlContactId = contactId;
      }

      // Remove current member tag if exists
      const currentTier = user.memberships.length > 0 ? user.memberships[0].tier : null;
      if (currentTier && contact.tags.includes(`member-${currentTier}`)) {
        await removeGHLContactTag(contactId, `member-${currentTier}`);
      }

      // Add cancelled tag
      await updateGHLContactTag(contactId, "membership-cancelled");

      await user.save();
    }

    res.status(200).send("User updated successfully");
  } catch (error) {
    console.error("GHL update error:", error);
    res.status(500).send("Server error");
  }
});
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));