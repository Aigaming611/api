import express from 'express';
import dotenv from 'dotenv';
import { genSaltSync, hashSync } from 'bcrypt';
import firebase from "firebase/compat/app"; // Import only the 'app' module
import { getAuth, createUserWithEmailAndPassword, signInWithEmailAndPassword, getIdToken } from 'firebase/auth';
import { getFirestore, collection, doc, setDoc } from 'firebase/firestore';
import { json } from 'stream/consumers';

dotenv.config();


const { PORT, FIREBASE_API_KEY, FIREBASE_AUTH_DOMAIN, FIREBASE_PROJECT_ID, FIREBASE_STORAGE_BUCKET, FIREBASE_MESSAGING_SENDER_ID, FIREBASE_APP_ID } = process.env;
const firebaseConfig = {
  apiKey: FIREBASE_API_KEY,
  authDomain: FIREBASE_AUTH_DOMAIN,
  projectId: FIREBASE_PROJECT_ID,
  storageBucket: FIREBASE_STORAGE_BUCKET,
  messagingSenderId: FIREBASE_MESSAGING_SENDER_ID,
  appId: FIREBASE_APP_ID,
};
firebase.initializeApp(firebaseConfig);
const db = getFirestore();
const auth = getAuth();


const app = express();
app.use(express.json());
const salt = genSaltSync(10);
interface User {
  id: string;
  email: string;
  hashed_password: string;
}
const USERS: User[] = [];

app.post('/register', async (req, res) => {
  const { email, password } = req.body;

  try {
    if (!email || !password) {
      return res.status(400).json({
        message: 'Email and password are required.',
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        message: 'Password must be at least 8 characters.',
      });
    }

    const existingUser = USERS.find((user) => user.email === email);

    if (existingUser) {
      return res.status(400).json({
        message: 'User already exists.',
      });
    }

    const hashed_password = hashSync(password, salt);
    const id = Math.random().toString(36).slice(2);

    const newUser = {
      id,
      email,
      hashed_password,
    };

    USERS.push(newUser);

    await setDoc(doc(db, 'users', id), {
      id,
      email,
      name: email,
    });

    // Here, we use auth.createUserWithEmailAndPassword for server-side authentication
    const userCredential = await createUserWithEmailAndPassword(auth, email, password);

    // Now, you can access userCredential.user.uid, userCredential.user.email, etc.
    const { uid, email: userEmail } = userCredential.user;

    return res.status(200).json({
      user:{
      userId: uid,
      email: userEmail,
      name: email,
      password
      }      // Add any other user details you want to include in the response
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error during registration. Please try again.' });
  }
});
app.post('/login', async (req,res) => {
  const { email, password } = req.body;
  const user = USERS.find((user) => user.email === email);
  const hashed_password = hashSync(password, salt);
  if (!user || user.hashed_password !== hashed_password) {
    return res.status(400).json({
      message: 'Invalid credentials.',
    })
  }
  const userCredential = await signInWithEmailAndPassword(auth, email, password);

  const { uid, email: userEmail } = userCredential.user;

   const token = await getIdToken(userCredential.user);

   console.log('User logged in successfully. Token:', token);

   res.status(200).json({
    
    token,
    user: {
      userId: uid,
      email: userEmail,
      name: email,
      password,
    },
    // Add any other user details you want to include in the response
  });
});

app.listen(PORT, () => {
  console.log(`Server is listening on port ${PORT}`);
});