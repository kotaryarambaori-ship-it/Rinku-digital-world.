const express = require("express");
const admin = require("firebase-admin");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: "1mb" }));

// Firebase setup
let firebaseReady = false;

try {
  const serviceAccountJson =
    process.env.FIREBASE_SERVICE_ACCOUNT_JSON;

  if (serviceAccountJson) {
    const serviceAccount = JSON.parse(serviceAccountJson);

    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount)
    });

    firebaseReady = true;
    console.log("Firebase connected successfully");
  } else {
    console.log("Firebase setup pending");
  }
} catch (error) {
  console.error("Firebase setup error:", error.message);
}

// Website homepage
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// Health check
app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    message: "Rinku Digital World server is running",
    firebase: firebaseReady
  });
});

// Verify Firebase login token
async function verifyUser(req, res, next) {
  try {
    if (!firebaseReady) {
      return res.status(503).json({
        success: false,
        message: "Firebase setup is pending"
      });
    }

    const authHeader = req.headers.authorization || "";
    const match = authHeader.match(/^Bearer\s+(.+)$/i);

    if (!match) {
      return res.status(401).json({
        success: false,
        message: "Firebase login token is required"
      });
    }

    const decodedToken = await admin
      .auth()
      .verifyIdToken(match[1]);

    req.user = decodedToken;
    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: "Invalid or expired login token"
    });
  }
}

// Get logged-in user's profile
app.get("/api/profile", verifyUser, async (req, res) => {
  try {
    const db = admin.firestore();

    const doc = await db
      .collection("profiles")
      .doc(req.user.uid)
      .get();

    res.json({
      success: true,
      uid: req.user.uid,
      profile: doc.exists ? doc.data() : {}
    });
  } catch (error) {
    console.error("Profile read error:", error.message);

    res.status(500).json({
      success: false,
      message: "Could not load profile"
    });
  }
});

// Save logged-in user's profile
app.put("/api/profile", verifyUser, async (req, res) => {
  try {
    const allowedFields = ["name", "photoURL", "bio"];
    const profile = {};

    for (const field of allowedFields) {
      if (typeof req.body[field] === "string") {
        profile[field] = req.body[field].slice(0, 500);
      }
    }

    const db = admin.firestore();

    await db
      .collection("profiles")
      .doc(req.user.uid)
      .set(profile, { merge: true });

    res.json({
      success: true,
      message: "Profile saved successfully"
    });
  } catch (error) {
    console.error("Profile save error:", error.message);

    res.status(500).json({
      success: false,
      message: "Could not save profile"
    });
  }
});

// Start server
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
});
