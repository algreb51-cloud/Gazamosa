import { initializeApp } from "https://www.gstatic.com/firebasejs/11.1.0/firebase-app.js";
import { getFirestore, collection, addDoc, onSnapshot, doc, updateDoc, deleteDoc, query, orderBy, where, getDocs, setDoc, getDoc } from "https://www.gstatic.com/firebasejs/11.1.0/firebase-firestore.js";
import { getAuth, signInWithEmailAndPassword, signOut, onAuthStateChanged } from "https://www.gstatic.com/firebasejs/11.1.0/firebase-auth.js";

// ===========================================
//       نظام الحماية (Security Layer)
// ===========================================
const allowedDomains = ["algreb51-cloud.github.io", "mosadata-18521.firebaseapp.com", "mosadata-18521.web.app", "localhost", "127.0.0.1"];
if (!allowedDomains.includes(window.location.hostname)) {
    document.documentElement.innerHTML = "<div style='height:100vh;background:#000;color:red;display:flex;justify-content:center;align-items:center;font-family:sans-serif;font-weight:bold;font-size:24px;direction:rtl;'>غير مصرح بتشغيل النظام خارج النطاق الرسمي<br><span style='font-size:16px;color:#ccc;margin-top:10px;'>Unauthorized Domain Access</span></div>";
    // إيقاف التنفيذ فوراً
    throw new Error("Security Alert: Unauthorized Domain Access");
}

const firebaseConfig = {
    apiKey: "AIzaSyCxI5hPvlddgn9aZUrewesDbg8YSD7bEnk",
    authDomain: "mosadata-18521.firebaseapp.com",
    projectId: "mosadata-18521",
    storageBucket: "mosadata-18521.firebasestorage.app",
    messagingSenderId: "517965913092",
    appId: "1:517965913092:web:39db81b21739cef58e6951",
    measurementId: "G-C00LHCKEG7"
};

Object.freeze(firebaseConfig); // حماية الإعدادات من التعديل
const app = initializeApp(firebaseConfig);

export const db = getFirestore(app);
export const auth = getAuth(app);
export const appId = "mosadata-18521";
export const fs = { collection, addDoc, onSnapshot, doc, updateDoc, deleteDoc, query, orderBy, where, getDocs, setDoc, getDoc };

window.db = db;
window.fs = fs;
window.appId = appId;
window.auth = auth;

export { signInWithEmailAndPassword, signOut, onAuthStateChanged };
