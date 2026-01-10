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
const db = getFirestore(app);
const auth = getAuth(app);
const appId = "mosadata-18521";

window.db = db;
window.fs = { collection, addDoc, onSnapshot, doc, updateDoc, deleteDoc, query, orderBy, where, getDocs, setDoc, getDoc };
window.appId = appId;
window.auth = auth;

window.currentUserData = null;

// ===========================================
//       نظام المصادقة
// ===========================================

async function checkPersistentLogin() {
    const sessionString = localStorage.getItem('dbUserSession');
    if (!sessionString) {
        return false;
    }

    const { userId, expiry } = JSON.parse(sessionString);

    if (Date.now() > expiry) {
        localStorage.removeItem('dbUserSession');
        return false;
    }

    try {
        const userDocRef = window.fs.doc(window.db, "app_users", userId);
        const userDoc = await window.fs.getDoc(userDocRef);

        if (!userDoc.exists() || userDoc.data().isDisabled) {
            localStorage.removeItem('dbUserSession');
            return false;
        }
        
        const newExpiry = Date.now() + (60 * 60 * 1000); // 1 hour sliding expiry
        localStorage.setItem('dbUserSession', JSON.stringify({ userId, expiry: newExpiry }));
        
        await window.fs.updateDoc(userDocRef, {
            lastLogin: new Date().toISOString(),
            isOnline: true
        });

        const userData = userDoc.data();
        window.currentUserData = {
            id: userId,
            name: userData.name,
            username: userData.username,
            role: userData.role,
            permissions: userData.permissions || [],
            type: "db_user"
        };
        Object.freeze(window.currentUserData); // حماية بيانات المستخدم
        handleLoginSuccess();
        return true;
    } catch (e) {
        console.error("Persistent login check failed", e);
        localStorage.removeItem('dbUserSession');
        return false;
    }
}

onAuthStateChanged(auth, async (user) => { // This handles Google Auth persistence
    if (user) {
        window.currentUserData = {
            name: "المدير الرئيسي",
            username: user.email,
            role: "super_admin",
            permissions: ["add", "edit", "remove", "view", "manage_users", "export", "view_all"],
            type: "google_auth"
        };
        Object.freeze(window.currentUserData); // حماية بيانات المستخدم
        handleLoginSuccess();
    } else {
        // If no Google user, check for our custom persistent session
        const customSessionActive = await checkPersistentLogin();
        if (!customSessionActive) {
            document.getElementById('authOverlay').classList.remove('hidden');
        }
    }
});

window.unifiedLogin = async function() {
    const userOrEmail = document.getElementById('loginUser').value.trim();
    const pass = document.getElementById('loginPass').value;
    const errorDiv = document.getElementById('loginError');
    errorDiv.classList.add('hidden');

    if(!userOrEmail || !pass) {
        errorDiv.innerText = "يرجى تعبئة جميع الحقول";
        errorDiv.classList.remove('hidden');
        return;
    }

    try {
        if(userOrEmail.includes('@')) {
            await signInWithEmailAndPassword(auth, userOrEmail, pass);
            return;
        }

        const q = query(collection(db, "app_users"), where("username", "==", userOrEmail));
        const querySnapshot = await getDocs(q);

        if (querySnapshot.empty) {
            throw new Error("User not found");
        }

        let userData = null;
        let docId = null;
        
        querySnapshot.forEach((doc) => {
            if (doc.data().password === pass) {
                userData = doc.data();
                docId = doc.id;
            }
        });

        if (!userData) {
            throw new Error("Wrong password");
        }

        if (userData.isDisabled) {
            errorDiv.innerText = "هذا الحساب معطل، يرجى مراجعة المسؤول";
            errorDiv.classList.remove('hidden');
            return;
        }

        await updateDoc(doc(db, "app_users", docId), {
            lastLogin: new Date().toISOString(),
            isOnline: true
        });

        window.currentUserData = {
            id: docId,
            name: userData.name,
            username: userData.username,
            role: userData.role,
            permissions: userData.permissions || [],
            type: "db_user"
        };
        Object.freeze(window.currentUserData); // حماية بيانات المستخدم

        // حفظ الجلسة في localStorage لمدة ساعة
        const session = {
            userId: docId,
            expiry: Date.now() + (60 * 60 * 1000) // 1 hour
        };
        localStorage.setItem('dbUserSession', JSON.stringify(session));

        handleLoginSuccess();

    } catch (error) {
        // محاولة تسجيل الدخول كمستفيد (فرد)
        try {
            const benQ = query(collection(db, "artifacts", appId, "public", "data", "families"), where("pId", "==", userOrEmail));
            const benSnap = await getDocs(benQ);
            
            let benData = null;
            let benId = null;

            benSnap.forEach((doc) => {
                // التحقق من رقم الجوال ككلمة مرور
                if (doc.data().pPhone === pass) {
                    benData = doc.data();
                    benId = doc.id;
                }
            });

            if (!benData) throw new Error("Beneficiary not found or wrong phone");

            window.currentUserData = {
                id: benId,
                name: benData.pName,
                username: benData.pId,
                role: "beneficiary", // دور جديد
                permissions: ["edit_self"],
                type: "beneficiary_auth"
            };
            Object.freeze(window.currentUserData); // حماية بيانات المستخدم
            handleLoginSuccess();

        } catch (benError) {
            console.error("Login Error:", error, benError);
            errorDiv.innerText = "بيانات الدخول غير صحيحة (تأكد من الهوية والجوال)";
            errorDiv.classList.remove('hidden');
        }
    }
};

function handleLoginSuccess() {
    document.getElementById('authOverlay').classList.add('hidden');
    document.getElementById('mainUI').classList.remove('hidden');
    setupUIBasedOnRole();
    initDataListener();
}

function setupUIBasedOnRole() {
    const u = window.currentUserData;
    document.getElementById('roleTitle').innerText = `أهلاً بك، ${u.name}`;

    const settingsBtn = document.getElementById('navSettingsBtn');
    const homeBtn = document.getElementById('navHomeBtn');
    const benBtn = document.getElementById('navBeneficiariesBtn');
    
    // إخفاء/إظهار واجهة المستفيد الخاصة
    if (u.role === 'beneficiary') {
        document.querySelector('nav').classList.add('hidden'); // إخفاء القائمة الجانبية
        document.getElementById('adminDashboard').classList.add('hidden'); // إخفاء لوحة التحكم الرئيسية
        document.getElementById('beneficiaryDashboard').classList.remove('hidden'); // إظهار لوحة المستفيد
        renderBeneficiaryView();
        return; // توقف هنا للمستفيد
    }

    // الوضع الطبيعي للموظفين والمدراء
    document.querySelector('nav').classList.remove('hidden');
    document.getElementById('adminDashboard').classList.remove('hidden');
    document.getElementById('beneficiaryDashboard').classList.add('hidden');

    if (u.role === 'super_admin') {
        settingsBtn.classList.remove('hidden');
        homeBtn.classList.add('hidden');
    } else {
        settingsBtn.classList.add('hidden');
        homeBtn.classList.remove('hidden');
    }

    if (u.role === 'super_admin' || u.role === 'admin' || u.role === 'employee') {
        benBtn.classList.remove('hidden');
    } else {
        benBtn.classList.add('hidden');
    }

    const canAdd = u.permissions.includes('add');
    // التعديل هنا: تمكين التصدير إذا كان المدير الرئيسي أو لديه صلاحية export
    const canExport = u.role === 'super_admin' || u.role === 'admin' || u.permissions.includes('export');
    const actionsGroup = document.getElementById('navActionsGroup');
    
    if(canAdd) document.getElementById('adminAddBtn').classList.remove('hidden');
    else document.getElementById('adminAddBtn').classList.add('hidden');

    // التحكم في ظهور زر التصدير في القائمة الجانبية
    if(canExport) document.getElementById('navExportBtn').classList.remove('hidden');
    else document.getElementById('navExportBtn').classList.add('hidden');

    if(canAdd || canExport) actionsGroup.classList.remove('hidden');
    else actionsGroup.classList.add('hidden');

    // التحكم في ظهور أزرار الإجراءات الإدارية (قالب، استيراد، تصدير الفرز)
    if(canExport) {
        document.getElementById('adminActions').classList.remove('hidden');
        document.getElementById('adminActions').classList.add('flex'); // التأكد من تفعيل ال flex
    } else {
        document.getElementById('adminActions').classList.add('hidden');
        document.getElementById('adminActions').classList.remove('flex');
    }
    
    // الفلاتر تظهر للجميع
    document.getElementById('sensitiveFilters').classList.remove('hidden');
    document.getElementById('socialFilterDiv').classList.remove('hidden');
}

window.logout = async function() {
    try {
        if (window.currentUserData && window.currentUserData.type === 'db_user') {
            await updateDoc(doc(db, "app_users", window.currentUserData.id), {
                isOnline: false
            });
        }
        localStorage.removeItem('dbUserSession');
        await signOut(auth);
        window.currentUserData = null;
        location.reload();
    } catch (error) {
        console.error("Logout Error", error);
        location.reload();
    }
}

function initDataListener() {
    if (window.currentUserData && window.currentUserData.role === 'beneficiary') {
        // للمستفيد: استمع فقط لملفه الشخصي
        onSnapshot(doc(db, "artifacts", appId, "public", "data", "families", window.currentUserData.id), (doc) => {
            if (doc.exists()) {
                window.families = [{ id: doc.id, ...doc.data() }];
                renderBeneficiaryView(); // تحديث العرض عند تغير البيانات
            } else {
                alert("لم يعد الملف موجوداً");
                logout();
            }
        });
    } else {
        // للمدراء: استمع للكل
        const q = query(
            collection(db, "artifacts", appId, "public", "data", "families"),
            orderBy("updatedAt", "desc")
        );
        onSnapshot(q, (snapshot) => {
            window.families = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
            updateDelegateFilterOptions();
            updateSocialFilterOptions();
            runFilters();
        }, (err) => console.error("Firebase Snapshot Error", err));
    }
}

// منع القائمة المنبثقة (Right Click)
document.addEventListener('contextmenu', event => event.preventDefault());

// منع اختصارات المطورين (F12, Ctrl+Shift+I, etc)
document.addEventListener('keydown', function(e) {
    if(e.key === 'F12' || (e.ctrlKey && e.shiftKey && e.key === 'I') || (e.ctrlKey && e.key === 'u')) {
        e.preventDefault();
    }
});

window.families = [];
let activeViewTab = 'family'; // 'family', 'individual', 'health'
let deleteTimer = null;
let pendingDeleteId = null;
let showDupsOnly = false;
let currentViewData = []; 
let currentViewMode = 'family'; 
let matchedIdsForArchive = []; // To store IDs from match import

let visibleColumnsMap = {
    family: ['pName', 'pId', 'pDob', 'age', 'wifeName', 'wifeId', 'pPhone', 'pDelegate', 'pSocial', 'totalCount'],
    individual: ['targetName', 'targetId', 'targetAge', 'targetDob', 'relation', 'pName', 'pId', 'pPhone'],
    health: ['patientName', 'patientId', 'patientAge', 'patientDob', 'diseaseType', 'diseaseDesc', 'pName', 'pId', 'pPhone']
};

// تعريف الأعمدة المتاحة للجدول الرئيسي
const columnDefinitions = [
    // Individual Specific
    { id: 'targetName', label: 'اسم الفرد', group: 'بيانات الفرد (للفرز)' },
    { id: 'targetId', label: 'هوية الفرد', group: 'بيانات الفرد (للفرز)' },
    { id: 'targetDob', label: 'تاريخ ميلاد الفرد', group: 'بيانات الفرد (للفرز)' },
    { id: 'targetAge', label: 'عمر الفرد', group: 'بيانات الفرد (للفرز)' },
    { id: 'relation', label: 'الصلة', group: 'بيانات الفرد (للفرز)' },

    // Health Specific
    { id: 'patientName', label: 'اسم المريض', group: 'بيانات صحية (للفرز)' },
    { id: 'patientId', label: 'هوية المريض', group: 'بيانات صحية (للفرز)' },
    { id: 'patientDob', label: 'تاريخ ميلاد المريض', group: 'بيانات صحية (للفرز)' },
    { id: 'patientAge', label: 'عمر المريض', group: 'بيانات صحية (للفرز)' },
    { id: 'diseaseType', label: 'نوع المرض', group: 'بيانات صحية (للفرز)' },
    { id: 'diseaseDesc', label: 'تفاصيل المرض', group: 'بيانات صحية (للفرز)' },

    { id: 'pName', label: 'اسم رب الأسرة', group: 'بيانات رب الأسرة' },
    { id: 'pId', label: 'هوية رب الأسرة', group: 'بيانات رب الأسرة' },
    { id: 'pIdIssue', label: 'اصدار الهوية', group: 'بيانات رب الأسرة' },
    { id: 'pDob', label: 'تاريخ الميلاد', group: 'بيانات رب الأسرة' },
    { id: 'age', label: 'عمر رب الأسرة', group: 'بيانات رب الأسرة' },
    { id: 'pSocial', label: 'الحالة الاجتماعية', group: 'بيانات رب الأسرة' },
    { id: 'wifeName', label: 'اسم الزوجة', group: 'بيانات الزوجة' },
    { id: 'wifeId', label: 'هوية الزوجة', group: 'بيانات الزوجة' },
    { id: 'wifeDob', label: 'تاريخ ميلاد الزوجة', group: 'بيانات الزوجة' },
    { id: 'wifeStatus', label: 'حالة الزوجة', group: 'بيانات الزوجة' },
    { id: 'pPhone', label: 'رقم الجوال', group: 'بيانات الاتصال' },
    { id: 'pAltPhone', label: 'جوال بديل', group: 'بيانات الاتصال' },
    { id: 'pDelegate', label: 'المندوب', group: 'بيانات الاتصال' },
    { id: 'originArea', label: 'السكن الأصلي', group: 'بيانات الاتصال' },
    { id: 'displaceArea', label: 'منطقة النزوح', group: 'بيانات الاتصال' },
    { id: 'totalCount', label: 'العدد الكلي', group: 'الإحصائيات' },
    { id: 'maleCount', label: 'عدد الذكور', group: 'الإحصائيات' },
    { id: 'femaleCount', label: 'عدد الإناث', group: 'الإحصائيات' },
    { id: 'walletOwner', label: 'مالك المحفظة', group: 'المحفظة الإلكترونية' },
    { id: 'walletId', label: 'هوية المحفظة', group: 'المحفظة الإلكترونية' },
    { id: 'walletPhone', label: 'جوال المحفظة', group: 'المحفظة الإلكترونية' },
    { id: 'shelterType', label: 'طبيعة المأوى', group: 'بيانات السكن' },
    { id: 'displacementPeriod', label: 'فترة النزوح', group: 'بيانات السكن' },
    { id: 'citizenStatus', label: 'طبيعة المواطن', group: 'بيانات السكن' }
];

// تعريف المجموعات (Macros) للقائمة المنسدلة
const macroDefinitions = [
    { id: 'macro_mNames', label: 'أسماء الأفراد (الكل)', group: 'بيانات الأفراد (مجمع)', targets: [] },
    { id: 'macro_mRels', label: 'صلات القرابة (الكل)', group: 'بيانات الأفراد (مجمع)', targets: [] },
    { id: 'macro_mDobs', label: 'تواريخ ميلاد الأفراد (الكل)', group: 'بيانات الأفراد (مجمع)', targets: [] },
    { id: 'macro_mIds', label: 'هويات الأفراد (الكل)', group: 'بيانات الأفراد (مجمع)', targets: [] },
    { id: 'macro_hNames', label: 'أسماء المرضى (الكل)', group: 'بيانات المرضى (مجمع)', targets: [] },
    { id: 'macro_hTypes', label: 'أنواع الأمراض (الكل)', group: 'بيانات المرضى (مجمع)', targets: [] },
    { id: 'macro_hIds', label: 'هويات المرضى (الكل)', group: 'بيانات المرضى (مجمع)', targets: [] }
];

// إضافة المجموعات لتعريفات الأعمدة (ستظهر في القائمة)
columnDefinitions.push(...macroDefinitions);

// إضافة أعمدة الأفراد (1-10) ديناميكياً
for (let i = 1; i <= 10; i++) {
    columnDefinitions.push(
        { id: `m${i}Name`, label: `اسم الفرد ${i}`, group: 'بيانات الأفراد (تفصيلي)', hidden: true },
        { id: `m${i}Rel`, label: `صلة القرابة ${i}`, group: 'بيانات الأفراد (تفصيلي)', hidden: true },
        { id: `m${i}Dob`, label: `تاريخ ميلاد الفرد ${i}`, group: 'بيانات الأفراد (تفصيلي)', hidden: true },
        { id: `m${i}Id`, label: `هوية الفرد ${i}`, group: 'بيانات الأفراد (تفصيلي)', hidden: true }
    );
    macroDefinitions[0].targets.push(`m${i}Name`);
    macroDefinitions[1].targets.push(`m${i}Rel`);
    macroDefinitions[2].targets.push(`m${i}Dob`);
    macroDefinitions[3].targets.push(`m${i}Id`);
}

// إضافة أعمدة الحالات الصحية (1-5) ديناميكياً
for (let i = 1; i <= 5; i++) {
    columnDefinitions.push(
        { id: `h${i}Name`, label: `اسم المريض ${i}`, group: 'بيانات المرضى (تفصيلي)', hidden: true },
        { id: `h${i}Type`, label: `نوع المرض ${i}`, group: 'بيانات المرضى (تفصيلي)', hidden: true },
        { id: `h${i}Id`, label: `هوية المريض ${i}`, group: 'بيانات المرضى (تفصيلي)', hidden: true }
    );
    macroDefinitions[4].targets.push(`h${i}Name`);
    macroDefinitions[5].targets.push(`h${i}Type`);
    macroDefinitions[6].targets.push(`h${i}Id`);
}

window.setViewMode = function(mode) {
    activeViewTab = mode;
    
    // Update UI Buttons
    ['family', 'individual', 'health'].forEach(m => {
        const btn = document.getElementById('viewBtn-' + m);
        if(m === mode) {
            btn.className = "px-6 py-3 rounded-xl text-sm font-bold bg-slate-800 text-white shadow-lg transition-all";
        } else {
            btn.className = "px-6 py-3 rounded-xl text-sm font-bold bg-white text-slate-500 hover:bg-slate-100 transition-all";
        }
    });

    runFilters();
};

const FIELD_MAP = {
    pName: "اسم رب الأسرة",
    pId: "هوية رب الأسرة",
    pIdIssue: "اصدار الهوية",
    pDob: "تاريخ ميلاد رب الأسرة",
    pPhone: "رقم الجوال",
    wifeName: "اسم الزوجة",
    wifeId: "هوية الزوجة",
    wifeDob: "تاريخ ميلاد الزوجة",
    wifeStatus: "حالة الزوجة",
    pSocial: "الحالة الاجتماعية",
    pDelegate: "اسم المندوب",
    pAltPhone: "جوال بديل",
    originArea: "منطقة السكن الأصلية",
    displaceArea: "منطقة النزوح الحالية",
    totalCount: "عدد الأفراد الكلي",
    femaleCount: "عدد الإناث",
    maleCount: "عدد الذكور",
    walletOwner: "مالك المحفظة",
    walletId: "هوية المحفظة",
    walletPhone: "جوال المحفظة",
    shelterType: "طبيعة المأوى",
    displacementPeriod: "فترة النزوح",
    citizenStatus: "طبيعة المواطن"
};

function only9Numbers(input) { input.value = input.value.replace(/\D/g, '').substring(0, 9); }
function closeModal(id) { document.getElementById(id).classList.add('hidden'); }

function getAge(dob) {
    if (!dob) return { y: 0, m: 0 };
    const birth = new Date(dob);
    const now = new Date();
    let y = now.getFullYear() - birth.getFullYear();
    let m = now.getMonth() - birth.getMonth();
    if (m < 0) { y--; m += 12; }
    return { y, m };
}

// ===========================================
//       Network & Security Logic
// ===========================================

function updateNetworkStatus() {
    const offlineOverlay = document.getElementById('offlineOverlay');
    const authOverlay = document.getElementById('authOverlay');
    const mainUI = document.getElementById('mainUI');
    
    if (!navigator.onLine) {
        offlineOverlay.classList.remove('hidden');
        authOverlay.classList.add('hidden');
        mainUI.classList.add('hidden');
        document.querySelectorAll('[id$="Modal"]').forEach(el => el.classList.add('hidden'));
    } else {
        offlineOverlay.classList.add('hidden');
        if (!window.currentUserData) authOverlay.classList.remove('hidden');
        else mainUI.classList.remove('hidden');
    }
}
window.addEventListener('online', updateNetworkStatus);
window.addEventListener('offline', updateNetworkStatus);
setTimeout(updateNetworkStatus, 500);

// ===========================================
//       Column Selection Logic
// ===========================================

window.toggleColumnMenu = function(event) {
    event.stopPropagation();
    const menu = document.getElementById('columnSelectionMenu');
    const btn = event.currentTarget;
    const rect = btn.getBoundingClientRect();
    
    if (menu.classList.contains('hidden')) {
        renderColumnOptions();
        menu.style.top = `${window.scrollY + rect.bottom + 5}px`;
        menu.style.left = 'auto';
        menu.style.right = `${document.documentElement.clientWidth - rect.right}px`;
        menu.classList.remove('hidden');
    } else {
        menu.classList.add('hidden');
    }
};

function renderColumnOptions() {
    const container = document.getElementById('columnOptionsList');
    container.innerHTML = '';
    const currentCols = visibleColumnsMap[currentViewMode];
    
    const groups = {};
    columnDefinitions.forEach(col => {
        if (col.hidden) return; // إخفاء الأعمدة التفصيلية من القائمة
        if(!groups[col.group]) groups[col.group] = [];
        groups[col.group].push(col);
    });

    for (const [groupName, cols] of Object.entries(groups)) {
        let groupHTML = `<div class="mb-2"><h5 class="text-xs font-black text-slate-400 mb-2 sticky top-0 bg-white py-1">${groupName}</h5><div class="space-y-1">`;
        cols.forEach(col => {
            let isChecked = '';
            if (col.targets) {
                // Check if all targets are selected
                const allSelected = col.targets.every(t => currentCols.includes(t));
                isChecked = allSelected ? 'checked' : '';
            } else {
                isChecked = currentCols.includes(col.id) ? 'checked' : '';
            }
            
            groupHTML += `
                <label class="flex items-center gap-3 cursor-pointer hover:bg-slate-50 p-2 rounded-lg transition-colors border border-transparent hover:border-slate-100">
                    <div class="relative flex items-center"><input type="checkbox" value="${col.id}" ${isChecked} onchange="toggleColumn('${col.id}')" class="peer w-4 h-4 rounded text-indigo-600 focus:ring-indigo-500 border-slate-300"></div>
                    <span class="text-xs font-bold text-slate-700 select-none">${col.label}</span>
                </label>`;
        });
        groupHTML += `</div></div>`;
        container.innerHTML += groupHTML;
    }
}

window.toggleColumn = function(colId) {
    let cols = visibleColumnsMap[currentViewMode];
    const colDef = columnDefinitions.find(c => c.id === colId);
    
    if (colDef && colDef.targets) {
        // Handle Macro Toggle
        const allSelected = colDef.targets.every(t => cols.includes(t));
        if (allSelected) {
            // Deselect all
            visibleColumnsMap[currentViewMode] = cols.filter(c => !colDef.targets.includes(c));
        } else {
            // Select all missing
            const toAdd = colDef.targets.filter(t => !cols.includes(t));
            visibleColumnsMap[currentViewMode] = [...cols, ...toAdd];
        }
    } else {
        // Handle Single Column Toggle
        if (cols.includes(colId)) {
            visibleColumnsMap[currentViewMode] = cols.filter(c => c !== colId);
        } else {
            visibleColumnsMap[currentViewMode].push(colId);
        }
    }
    
    // Sort columns to maintain interleaved order (Name, Rel, Dob, Id...)
    const orderMap = columnDefinitions.reduce((acc, col, idx) => { acc[col.id] = idx; return acc; }, {});
    visibleColumnsMap[currentViewMode].sort((a, b) => (orderMap[a] || 9999) - (orderMap[b] || 9999));

    runFilters(); // إعادة رسم الجدول
};

window.selectAllColumns = function(select) {
    if(select) {
        // Select all non-macro columns
        visibleColumnsMap[currentViewMode] = columnDefinitions.filter(c => !c.targets).map(c => c.id);
    } else {
        visibleColumnsMap[currentViewMode] = [];
    }
    renderColumnOptions();
    runFilters();
};

// إغلاق القائمة عند النقر خارجها
window.addEventListener('click', function(e) {
    const menu = document.getElementById('columnSelectionMenu');
    if (!menu.classList.contains('hidden') && !e.target.closest('#columnSelectionMenu') && !e.target.closest('button[onclick="toggleColumnMenu(event)"]')) {
        menu.classList.add('hidden');
    }
});

// ===========================================
//       Multi-select Dropdown Logic
// ===========================================

window.toggleMultiSelect = function(id) {
    const optionsDiv = document.getElementById(id + '-options');
    const allOptions = document.querySelectorAll('.multiselect-options');
    allOptions.forEach(div => {
        if(div.id !== id + '-options') div.classList.remove('show');
    });
    optionsDiv.classList.toggle('show');
};

window.onclick = function(event) {
    if (!event.target.closest('.multiselect-container')) {
        document.querySelectorAll('.multiselect-options').forEach(div => div.classList.remove('show'));
    }
};

function getCheckedValues(containerId) {
    const container = document.getElementById(containerId + '-container');
    if(!container) return [];
    const checkboxes = container.querySelectorAll('input[type="checkbox"]:checked');
    return Array.from(checkboxes).map(cb => cb.value);
}

// ===========================================
//       User Management Logic
// ===========================================

function openUserManagement() {
    if(window.currentUserData.role !== 'super_admin') {
        alert("غير مصرح لك");
        return;
    }
    document.getElementById('userParamsModal').classList.remove('hidden');
    switchUserTab('create');
}

function switchUserTab(tabName) {
    document.querySelectorAll('.user-tab-content').forEach(el => el.classList.add('hidden'));
    document.querySelectorAll('[id^="tabBtn-"]').forEach(el => el.className = "w-full text-right p-4 rounded-xl font-bold text-slate-500 hover:bg-white hover:shadow-sm transition-all");
    document.getElementById(`tab-${tabName}`).classList.remove('hidden');
    document.getElementById(`tabBtn-${tabName}`).className = "w-full text-right p-4 rounded-xl font-bold text-slate-800 bg-white shadow-md transition-all";

    if(tabName === 'list' || tabName === 'trash') {
        fetchUsersList(tabName === 'trash');
    }
}

async function handleCreateUser(e) {
    e.preventDefault();
    const name = document.getElementById('newUserName').value;
    const user = document.getElementById('newUserUser').value;
    const pass = document.getElementById('newUserPass').value;
    const role = document.getElementById('newUserRole').value;
    
    const perms = Array.from(document.querySelectorAll('input[name="perms"]:checked')).map(cb => cb.value);
    if(!perms.includes('view')) perms.push('view');

    // التحقق الأمني: طلب كلمة المرور
    if (window.currentUserData.type === 'db_user') {
        const confirmPass = prompt("لأغراض أمنية، يرجى إدخال كلمة المرور الخاصة بك لتأكيد إنشاء المستخدم:");
        if (confirmPass === null) return;

        try {
            const myDoc = await window.fs.getDoc(window.fs.doc(window.db, "app_users", window.currentUserData.id));
            if (!myDoc.exists() || myDoc.data().password !== confirmPass) {
                alert("كلمة المرور غير صحيحة. تم إلغاء العملية.");
                return;
            }
        } catch (err) {
            console.error(err);
            alert("حدث خطأ أثناء التحقق الأمني.");
            return;
        }
    } else if (window.currentUserData.type === 'google_auth') {
        if(!confirm("هل أنت متأكد من إنشاء هذا المستخدم؟")) return;
    }

    try {
        const q = window.fs.query(window.fs.collection(window.db, "app_users"), window.fs.where("username", "==", user));
        const snap = await window.fs.getDocs(q);
        if(!snap.empty) {
            alert("اسم المستخدم هذا موجود مسبقاً");
            return;
        }

        await window.fs.addDoc(window.fs.collection(window.db, "app_users"), {
            name, username: user, password: pass, role, permissions: perms,
            createdAt: new Date().toISOString(),
            isDisabled: false,
            isOnline: false,
            lastLogin: null
        });
        alert("تم إنشاء المستخدم بنجاح");
        document.getElementById('createUserForm').reset();
    } catch(err) {
        console.error(err);
        alert("خطأ أثناء الإنشاء");
    }
}

async function fetchUsersList(showDisabled) {
    const tbody = showDisabled ? document.getElementById('trashUsersBody') : document.getElementById('usersListBody');
    tbody.innerHTML = '<tr><td colspan="7" class="p-4 text-center">جاري التحميل...</td></tr>';

    try {
        const q = window.fs.query(window.fs.collection(window.db, "app_users"), window.fs.orderBy("createdAt", "desc"));
        const snap = await window.fs.getDocs(q);
        
        tbody.innerHTML = '';
        
        snap.forEach(doc => {
            const data = doc.data();
            if(data.isDisabled !== showDisabled) return; 

            const tr = document.createElement('tr');
            tr.className = "border-b border-slate-50 hover:bg-slate-50 transition-all";
            
            if(!showDisabled) {
                const isOnline = data.isOnline ? '<span class="text-emerald-500">نشط الآن</span>' : '<span class="text-slate-400">غير متاح</span>';
                const lastLogin = data.lastLogin ? new Date(data.lastLogin).toLocaleString('ar-EG') : 'لم يدخل بعد';
                const permsString = (data.permissions || []).join(',');
                
                tr.innerHTML = `
                    <td class="p-4">${data.name}</td>
                    <td class="p-4 font-mono">${data.username}</td>
                    <td class="p-4"><span class="bg-indigo-50 text-indigo-600 px-2 py-1 rounded text-xs">${data.role}</span></td>
                    <td class="p-4 text-xs font-mono">${lastLogin}</td>
                    <td class="p-4 text-xs font-bold">${isOnline}</td>
                    <td class="p-4 flex justify-center">
                        <button onclick="toggleUserStatus('${doc.id}', true)" class="text-red-400 hover:text-red-600 font-bold text-xs border border-red-200 px-3 py-1 rounded-lg">تعطيل</button>
                    </td>
                    <td class="p-4 flex justify-center">
                        <button onclick="openEditCreds('${doc.id}', '${data.username}', '${data.password}', '${permsString}')" class="text-blue-500 hover:text-blue-700 bg-blue-50 px-3 py-1 rounded-lg text-xs font-bold">تعديل</button>
                    </td>
                `;
            } else {
                tr.innerHTML = `
                    <td class="p-4 opacity-50">${data.name}</td>
                    <td class="p-4 font-mono opacity-50">${data.username}</td>
                    <td class="p-4 opacity-50">${data.role}</td>
                    <td class="p-4 flex justify-center gap-2">
                        <button onclick="toggleUserStatus('${doc.id}', false)" class="bg-emerald-50 text-emerald-600 font-bold text-xs px-3 py-1 rounded-lg">استعادة</button>
                        <button onclick="deleteUserPermanently('${doc.id}')" class="bg-red-600 text-white font-bold text-xs px-3 py-1 rounded-lg">حذف نهائي</button>
                    </td>
                `;
            }
            tbody.appendChild(tr);
        });
        
        if(tbody.innerHTML === '') tbody.innerHTML = '<tr><td colspan="7" class="p-4 text-center text-slate-400">لا يوجد بيانات</td></tr>';

    } catch(err) {
        console.error(err);
        tbody.innerHTML = '<tr><td colspan="7" class="p-4 text-center text-red-400">خطأ في التحميل</td></tr>';
    }
}

window.toggleUserStatus = async function(id, disable) {
    if(!confirm(disable ? "هل أنت متأكد من تعطيل الحساب؟" : "استعادة الحساب؟")) return;
    try {
        await window.fs.updateDoc(window.fs.doc(window.db, "app_users", id), { isDisabled: disable });
        fetchUsersList(disable ? false : true); 
    } catch(err) { alert(err.message); }
};

window.deleteUserPermanently = async function(id) {
    if(!confirm("حذف نهائي؟ لا يمكن التراجع!")) return;
    try {
        await window.fs.deleteDoc(window.fs.doc(window.db, "app_users", id));
        fetchUsersList(true);
    } catch(err) { alert(err.message); }
};

// ===========================================
//       Credentials Editing Logic
// ===========================================

window.openEditCreds = function(id, user, pass, permsString) {
    document.getElementById('editCredsId').value = id;
    document.getElementById('editCredsUser').value = user;
    document.getElementById('editCredsPass').value = ""; // Don't show old pass for security in UI usually, but user asked for it in prev versions. Let's keep it blank for "Change" logic or leave it as placeholder. Code above had `value = pass`.
    document.getElementById('editCredsPass').placeholder = "أدخل كلمة جديدة للتغيير";
    
    // If editing own profile as non-admin, disable username and permissions
    if(window.currentUserData.role !== 'super_admin') {
        document.getElementById('editCredsUser').disabled = true;
        document.getElementById('usernameEditField').classList.add('opacity-50');
        document.getElementById('editPermsContainer').classList.add('hidden');
    } else {
        document.getElementById('editCredsUser').disabled = false;
        document.getElementById('usernameEditField').classList.remove('opacity-50');
        document.getElementById('editPermsContainer').classList.remove('hidden');
        
        // Populate permissions
        const perms = permsString ? permsString.split(',') : [];
        document.querySelectorAll('input[name="editPerms"]').forEach(cb => {
            cb.checked = perms.includes(cb.value);
        });
    }
    
    document.getElementById('editCredsModal').classList.remove('hidden');
};

window.openMyProfile = function() {
    if(!window.currentUserData || window.currentUserData.type === 'google_auth') {
        alert("لا يمكن تغيير كلمة المرور للحساب الرئيسي من هنا");
        return;
    }
    const id = window.currentUserData.id;
    const user = window.currentUserData.username;
    openEditCreds(id, user, '', '');
};

window.handleSaveCreds = async function(e) {
    e.preventDefault();
    const id = document.getElementById('editCredsId').value;
    const newUser = document.getElementById('editCredsUser').value;
    const newPass = document.getElementById('editCredsPass').value;
    
    let updatePayload = { username: newUser };
    if(newPass && newPass.trim() !== "") {
        updatePayload.password = newPass;
    }

    // Only update permissions if super_admin
    if(window.currentUserData.role === 'super_admin') {
        const newPerms = Array.from(document.querySelectorAll('input[name="editPerms"]:checked')).map(cb => cb.value);
        if(!newPerms.includes('view')) newPerms.push('view');
        updatePayload.permissions = newPerms;
    }

    try {
        await window.fs.updateDoc(window.fs.doc(window.db, "app_users", id), updatePayload);
        alert("تم تحديث البيانات بنجاح");
        closeModal('editCredsModal');
        
        // Refresh list if open
        if(!document.getElementById('userParamsModal').classList.contains('hidden')) {
            fetchUsersList(false);
        }

    } catch(err) {
        console.error(err);
        alert("خطأ أثناء التحديث");
    }
};


// ===========================================
//       Existing Data Logic 
// ===========================================

function hasPerm(p) {
    if (!window.currentUserData) return false;
    if (window.currentUserData.role === 'beneficiary' && p === 'edit') return true; // السماح للمستفيد بالتعديل
    return window.currentUserData.permissions.includes(p) || window.currentUserData.permissions.includes('all');
}

function updateDelegateFilterOptions() {
    const container = document.getElementById('filterDelegate-options');
    if (!container) return;
    
    const currentChecked = Array.from(container.querySelectorAll('input[type="checkbox"]:checked')).map(cb => cb.value);
    const delegates = [...new Set(window.families.map(f => f.pDelegate ? f.pDelegate.trim() : "").filter(d => d !== ""))].sort();
    
    let html = '';
    delegates.forEach(d => {
        const isChecked = currentChecked.includes(d) ? 'checked' : '';
        html += `<label class="multiselect-option"><input type="checkbox" onchange="runFilters()" value="${d}" ${isChecked}> ${d}</label>`;
    });
    
    if(delegates.length === 0) html = '<div class="p-2 text-xs text-slate-400 text-center">لا يوجد مناديب</div>';
    container.innerHTML = html;
}

function updateSocialFilterOptions() {
    const container = document.getElementById('filterSocial-options');
    if (!container) return;
    
    const currentChecked = Array.from(container.querySelectorAll('input[type="checkbox"]:checked')).map(cb => cb.value);
    const socials = [...new Set(window.families.map(f => f.pSocial ? f.pSocial.trim() : "").filter(s => s !== ""))].sort();
    
    let html = '';
    socials.forEach(s => {
        const isChecked = currentChecked.includes(s) ? 'checked' : '';
        html += `<label class="multiselect-option"><input type="checkbox" onchange="runFilters()" value="${s}" ${isChecked}> ${s}</label>`;
    });
    
    if(socials.length === 0) html = '<div class="p-2 text-xs text-slate-400 text-center">لا يوجد بيانات</div>';
    container.innerHTML = html;
}

function runFilters() {
    const search = document.getElementById('searchInput').value.toLowerCase();
    
    // Collect multi-select values
    const ageFilters = getCheckedValues('filterAge');
    const diseaseFilters = getCheckedValues('filterDisease');
    const delegateFilters = getCheckedValues('filterDelegate');
    const socialFilters = getCheckedValues('filterSocial');
    const countFilters = getCheckedValues('filterCount');
    const wifeStatusFilters = getCheckedValues('filterWifeStatus');

    // Update Labels (Optional UX improvement)
    document.getElementById('filterAge-label').innerText = ageFilters.length > 0 ? `تم اختيار ${ageFilters.length}` : 'اختيار الفئات العمرية...';
    document.getElementById('filterDisease-label').innerText = diseaseFilters.length > 0 ? `تم اختيار ${diseaseFilters.length}` : 'اختيار الحالات...';
    document.getElementById('filterDelegate-label').innerText = delegateFilters.length > 0 ? `تم اختيار ${delegateFilters.length}` : 'كل المناديب';
    document.getElementById('filterSocial-label').innerText = socialFilters.length > 0 ? `تم اختيار ${socialFilters.length}` : 'كل الحالات';
    document.getElementById('filterCount-label').innerText = countFilters.length > 0 ? `تم اختيار ${countFilters.length}` : 'اختيار العدد...';
    document.getElementById('filterWifeStatus-label').innerText = wifeStatusFilters.length > 0 ? `تم اختيار ${wifeStatusFilters.length}` : 'اختيار الحالة...';


    let resultData = [];
    
    // Determine View Mode based on Filters OR Active Tab
    if (ageFilters.length > 0 && !ageFilters.includes('all')) currentViewMode = 'individual';
    else if (wifeStatusFilters.length > 0 && !wifeStatusFilters.includes('all')) currentViewMode = 'individual';
    else if (diseaseFilters.length > 0 && !diseaseFilters.includes('all')) currentViewMode = 'health';
    else currentViewMode = activeViewTab;

    const matchesSearch = (f) => (f.pName || "").toLowerCase().includes(search) || 
                                 (f.pId || "").includes(search) || 
                                 (f.pDelegate || "").toLowerCase().includes(search) ||
                                 (f.totalCount || "").toString().includes(search);
    
    const isRestricted = window.currentUserData?.role === 'viewer' && !hasPerm('view_all');

    // Logic adapted for multiple selections
    if (currentViewMode === 'individual') {
            window.families.forEach(f => {
                if (!matchesSearch(f)) return;
                
                // Check if we are filtering or showing all
                const hasAgeFilter = ageFilters.length > 0 && !ageFilters.includes('all');
                const hasWifeFilter = wifeStatusFilters.length > 0 && !wifeStatusFilters.includes('all');
                const showAll = !hasAgeFilter && !hasWifeFilter;

                (f.members || []).forEach(m => {
                    if (!m.dob || m.dob.trim() === '') return;
                    const age = getAge(m.dob);
                    let match = false;
                    
                    if (showAll) match = true;
                    else if (hasAgeFilter) {
                        ageFilters.forEach(ageF => {
                            if (ageF === '0-1' && age.y === 0) match = true;
                            if (ageF === '1-2' && age.y === 1) match = true;
                            if (ageF === '2-5' && age.y >= 2 && age.y <= 5) match = true;
                            if (ageF === '5-10' && age.y > 5 && age.y <= 10) match = true;
                            if (ageF === '10-17' && age.y > 10 && age.y <= 17) match = true;
                            if (ageF === '18-25' && age.y > 17 && age.y <= 25) match = true;
                            if (ageF === '26-40' && age.y > 25 && age.y <= 40) match = true;
                            if (ageF === '41-80' && age.y > 40 && age.y <= 80) match = true;
                        });
                    }

                    if (match) {
                        resultData.push({
                            ...f,
                            type: 'individual',
                            familyId: f.id,
                            targetName: m.name,
                            targetId: m.idNum,
                            targetAge: `${age.y} سنة`,
                            targetDob: m.dob,
                            relation: m.relation
                        });
                    }
                });
                [ {name: f.pName, dob: f.pDob, id: f.pId, role: 'أب'}, {name: f.wifeName, dob: f.wifeDob, id: f.wifeId, role: 'زوجة'} ]
                .filter(p => p.name && p.dob && p.dob.trim() !== '')
                .forEach(p => {
                    const age = getAge(p.dob);
                    let match = false;
                    
                    if (showAll) match = true;
                    else if (hasWifeFilter && p.role === 'زوجة' && wifeStatusFilters.includes(f.wifeStatus)) match = true;
                    else if (hasAgeFilter) {
                        ageFilters.forEach(ageF => {
                            if (ageF === '0-1' && age.y === 0) match = true;
                            if (ageF === '1-2' && age.y === 1) match = true;
                            if (ageF === '2-5' && age.y >= 2 && age.y <= 5) match = true;
                            if (ageF === '5-10' && age.y > 5 && age.y <= 10) match = true;
                            if (ageF === '10-17' && age.y > 10 && age.y <= 17) match = true;
                            if (ageF === '18-25' && age.y > 17 && age.y <= 25) match = true;
                            if (ageF === '26-40' && age.y > 25 && age.y <= 40) match = true;
                            if (ageF === '41-80' && age.y > 40 && age.y <= 80) match = true;
                        });
                    }

                    if (match) {
                        resultData.push({
                            ...f,
                            type: 'individual',
                            familyId: f.id,
                            targetName: p.name,
                            targetId: p.id,
                            targetAge: `${age.y} سنة`,
                            targetDob: p.dob,
                            relation: p.role
                        });
                    }
                });
            });
    } else if (currentViewMode === 'health') {
        window.families.forEach(f => {
            if (!matchesSearch(f)) return;
            
            const hasDiseaseFilter = diseaseFilters.length > 0 && !diseaseFilters.includes('all');
            const showAll = !hasDiseaseFilter;

            (f.health || []).forEach(h => {
                if (showAll || diseaseFilters.includes(h.type)) {
                    const patientAge = getAge(h.dob);
                    const pAge = getAge(f.pDob);
                    resultData.push({
                        ...f,
                        type: 'health',
                        familyId: f.id,
                        patientName: h.name,
                        patientId: h.idNum,
                        patientDob: h.dob,
                        patientAge: `${patientAge.y} سنة`,
                        diseaseType: h.type,
                        diseaseDesc: h.desc
                    });
                }
            });
        });
    } else {
        let filtered = window.families.filter(f => {
            const mSearch = matchesSearch(f);
            const mDelegate = delegateFilters.length === 0 || delegateFilters.includes('all') || delegateFilters.includes((f.pDelegate || "").trim());
            const mSocial = socialFilters.length === 0 || socialFilters.includes('all') || socialFilters.includes((f.pSocial || "").trim());
            
            let calculatedCount = 1;
            if(f.wifeName && f.wifeName.trim()) calculatedCount++;
            if(f.members && Array.isArray(f.members)) calculatedCount += f.members.length;

            const mCount = countFilters.length === 0 || countFilters.includes('all') || countFilters.includes(calculatedCount.toString());
            return mSearch && mDelegate && mSocial && mCount;
        });
        if (showDupsOnly) {
            const idCounts = {};
            window.families.forEach(f => idCounts[f.pId] = (idCounts[f.pId] || 0) + 1);
            filtered = filtered.filter(f => idCounts[f.pId] > 1);
        }
        resultData = filtered.map(f => {
            let count = 1; // رب الأسرة
            if(f.wifeName && f.wifeName.trim()) count++; // الزوجة
            if(f.members && Array.isArray(f.members)) count += f.members.length; // الأفراد

            return {
                type: 'family',
                familyId: f.id,
                ...f,
                totalCount: count,
                raw: f 
            };
        });
    }

    currentViewData = resultData;
    renderTable(resultData, isRestricted);
    updateStats(window.families);
}
window.runFilters = runFilters;

function updateStats(data) {
    document.getElementById('totalFamilies').innerText = data.length;
    let total = 0;
    data.forEach(f => {
        total++; // رب الأسرة
        if (f.wifeName && f.wifeName.trim()) total++; // الزوجة
        if (f.members && Array.isArray(f.members)) total += f.members.length; // الأفراد المضافين
    });
    document.getElementById('totalPersons').innerText = total;

    const idCounts = {};
    let dups = 0;
    data.forEach(f => {
        idCounts[f.pId] = (idCounts[f.pId] || 0) + 1;
        if(idCounts[f.pId] === 2) dups++;
    });
    document.getElementById('totalDuplicates').innerText = dups;
}

window.toggleMainSelectAll = function(source) {
    const checkboxes = document.querySelectorAll('.main-row-check');
    checkboxes.forEach(cb => cb.checked = source.checked);
    updateMainSelection();
};

window.updateMainSelection = function() {
    const count = document.querySelectorAll('.main-row-check:checked').length;
    document.getElementById('selectedMainCount').innerText = count;
    const bar = document.getElementById('bulkActionsBar');
    if(count > 0) bar.classList.remove('hidden');
    else bar.classList.add('hidden');
};

window.deleteSelectedRows = async function() {
    if(!hasPerm('remove')) return alert("ليس لديك صلاحية الحذف");
    const checks = document.querySelectorAll('.main-row-check:checked');
    if(checks.length === 0) return;
    
    if(!confirm(`هل أنت متأكد من حذف ${checks.length} سجلات؟ (سيتم حذف العائلة بالكامل)`)) return;

    const idsToDelete = new Set();
    checks.forEach(cb => idsToDelete.add(cb.value)); // value is familyId

    let deletedCount = 0;
    try {
        for(let id of idsToDelete) {
            await window.fs.deleteDoc(window.fs.doc(window.db, "artifacts", window.appId, "public", "data", "families", id));
            deletedCount++;
        }
        alert(`تم حذف ${deletedCount} سجل بنجاح`);
        document.getElementById('bulkActionsBar').classList.add('hidden');
    } catch(e) {
        alert("حدث خطأ أثناء الحذف: " + e.message);
    }
};

function getCellContent(row, colId, isRestricted) {
    const mask = (val) => isRestricted ? '*****' : (val || "-");
    
    // معالجة الأعمدة الديناميكية للأفراد (m1Name, m1Id...)
    if (colId.startsWith('m') && /\d/.test(colId)) {
        const match = colId.match(/^m(\d+)(.+)$/);
        if (match) {
            const idx = parseInt(match[1]) - 1;
            const field = match[2];
            const member = row.members && row.members[idx];
            if (!member) return '-';
            if (field === 'Name') return member.name || '-';
            if (field === 'Rel') return member.relation || '-';
            if (field === 'Dob') return member.dob || '-';
            if (field === 'Id') return `<span class="font-mono">${mask(member.idNum)}</span>`;
        }
    }

    // معالجة الأعمدة الديناميكية للمرضى (h1Name, h1Type...)
    if (colId.startsWith('h') && /\d/.test(colId)) {
        const match = colId.match(/^h(\d+)(.+)$/);
        if (match) {
            const idx = parseInt(match[1]) - 1;
            const field = match[2];
            const health = row.health && row.health[idx];
            if (!health) return '-';
            if (field === 'Name') return `<span class="text-red-600 font-bold">${health.name || '-'}</span>`;
            if (field === 'Type') return `<span class="bg-red-50 text-red-600 px-1 rounded text-xs">${health.type || '-'}</span>`;
            if (field === 'Id') return `<span class="font-mono">${mask(health.idNum)}</span>`;
        }
    }

    // معالجة بيانات الأفراد والحالات الصحية في العرض الرئيسي (تجميع البيانات)
    if (colId === 'targetName') {
        if (row.targetName) return `<span class="font-bold text-indigo-700">${row.targetName}</span>`;
        if (row.members && row.members.length) return row.members.map(m => `<div class="text-xs h-6 flex items-center border-b border-slate-100 last:border-0 truncate">${m.name}</div>`).join('');
        return '-';
    }
    if (colId === 'targetId') {
        if (row.targetId) return `<span class="font-mono">${mask(row.targetId)}</span>`;
        if (row.members && row.members.length) return row.members.map(m => `<div class="text-xs font-mono h-6 flex items-center border-b border-slate-100 last:border-0">${mask(m.idNum)}</div>`).join('');
        return '-';
    }
    if (colId === 'targetDob') {
        if (row.targetDob) return `<span class="font-mono">${row.targetDob}</span>`;
        if (row.members && row.members.length) return row.members.map(m => `<div class="text-xs font-mono h-6 flex items-center border-b border-slate-100 last:border-0">${m.dob || '-'}</div>`).join('');
        return '-';
    }
    if (colId === 'targetAge') {
        if (row.targetAge) return `<span class="text-xs font-bold text-slate-500">${row.targetAge}</span>`;
        if (row.members && row.members.length) return row.members.map(m => { const age = getAge(m.dob); return `<div class="text-xs h-6 flex items-center border-b border-slate-100 last:border-0">${age.y} سنة</div>`; }).join('');
        return '-';
    }
    if (colId === 'relation') {
        if (row.relation) return `<span class="text-xs font-bold text-slate-500">${row.relation}</span>`;
        if (row.members && row.members.length) return row.members.map(m => `<div class="text-xs h-6 flex items-center border-b border-slate-100 last:border-0">${m.relation || '-'}</div>`).join('');
        return '-';
    }

    if (colId === 'patientName') {
        if (row.patientName) return `<span class="font-bold text-red-600">${row.patientName}</span>`;
        if (row.health && row.health.length) return row.health.map(h => `<div class="text-xs h-6 flex items-center border-b border-slate-100 last:border-0 text-red-600 truncate">${h.name}</div>`).join('');
        return '-';
    }
    if (colId === 'patientId') {
        if (row.patientId) return `<span class="font-mono">${mask(row.patientId)}</span>`;
        if (row.health && row.health.length) return row.health.map(h => `<div class="text-xs font-mono h-6 flex items-center border-b border-slate-100 last:border-0">${mask(h.idNum)}</div>`).join('');
        return '-';
    }
    if (colId === 'patientDob') {
        if (row.patientDob) return `<span class="font-mono">${row.patientDob}</span>`;
        if (row.health && row.health.length) return row.health.map(h => `<div class="text-xs font-mono h-6 flex items-center border-b border-slate-100 last:border-0">${h.dob || '-'}</div>`).join('');
        return '-';
    }
    if (colId === 'patientAge') {
        if (row.patientAge) return `<span class="text-xs font-bold text-slate-500">${row.patientAge}</span>`;
        if (row.health && row.health.length) return row.health.map(h => { const age = getAge(h.dob); return `<div class="text-xs h-6 flex items-center border-b border-slate-100 last:border-0">${age.y} سنة</div>`; }).join('');
        return '-';
    }
    if (colId === 'diseaseType') {
        if (row.diseaseType) return `<span class="text-xs font-bold bg-red-50 text-red-600 rounded-lg px-2 py-1">${row.diseaseType}</span>`;
        if (row.health && row.health.length) return row.health.map(h => `<div class="text-xs h-6 flex items-center border-b border-slate-100 last:border-0"><span class="bg-red-50 text-red-600 rounded px-1">${h.type || '-'}</span></div>`).join('');
        return '-';
    }
    if (colId === 'diseaseDesc') {
        if (row.diseaseDesc) return `<span class="text-xs max-w-[200px] truncate block" title="${row.diseaseDesc || ''}">${row.diseaseDesc || '-'}</span>`;
        if (row.health && row.health.length) return row.health.map(h => `<div class="text-xs h-6 flex items-center border-b border-slate-100 last:border-0 max-w-[150px] truncate" title="${h.desc || ''}">${h.desc || '-'}</div>`).join('');
        return '-';
    }

    switch(colId) {
        case 'pName': return `<span class="font-bold text-slate-700">${row.pName || '-'}</span>`;
        case 'pId': return `<span class="font-mono text-slate-500">${mask(row.pId)}</span>`;
        case 'pIdIssue': return row.pIdIssue || '-';
        case 'pDob': return `<span class="font-mono text-slate-500">${row.pDob || '-'}</span>`;
        case 'age': return `<span class="font-bold text-slate-500">${getAge(row.pDob).y} سنة</span>`;
        case 'wifeName': return row.wifeName || '-';
        case 'wifeId': return `<span class="font-mono text-slate-500">${mask(row.wifeId)}</span>`;
        case 'wifeDob': return row.wifeDob || '-';
        case 'wifeStatus': return row.wifeStatus || '-';
        case 'pPhone': return `<span class="font-mono text-slate-500">${mask(row.pPhone ? '0' + row.pPhone : '')}</span>`;
        case 'pAltPhone': return `<span class="font-mono text-slate-500">${mask(row.pAltPhone ? '0' + row.pAltPhone : '')}</span>`;
        case 'pDelegate': return `<span class="px-3 py-1 bg-indigo-50 text-indigo-600 rounded-lg text-xs font-bold">${row.pDelegate || '-'}</span>`;
        case 'pSocial': return `<span class="text-xs font-bold">${row.pSocial || '-'}</span>`;
        case 'originArea': return row.originArea || '-';
        case 'displaceArea': return row.displaceArea || '-';
        case 'totalCount': return `<span class="font-bold">${row.totalCount || 0}</span>`;
        case 'maleCount': return row.maleCount || 0;
        case 'femaleCount': return row.femaleCount || 0;
        case 'walletOwner': return row.walletOwner || '-';
        case 'walletId': return `<span class="font-mono">${mask(row.walletId)}</span>`;
        case 'walletPhone': return `<span class="font-mono">${mask(row.walletPhone)}</span>`;
        case 'shelterType': return row.shelterType || '-';
        case 'displacementPeriod': return row.displacementPeriod || '-';
        case 'citizenStatus': return row.citizenStatus || '-';
        default: return row[colId] || '';
    }
}

function getRawCellContentForExport(row, colId) {
    // معالجة الأعمدة الديناميكية للأفراد للتصدير
    if (colId.startsWith('m') && /\d/.test(colId)) {
        const match = colId.match(/^m(\d+)(.+)$/);
        if (match) {
            const idx = parseInt(match[1]) - 1;
            const field = match[2];
            const member = row.members && row.members[idx];
            if (!member) return '-';
            if (field === 'Name') return member.name || '-';
            if (field === 'Rel') return member.relation || '-';
            if (field === 'Dob') return member.dob || '-';
            if (field === 'Id') return member.idNum || '-';
        }
    }

    // معالجة الأعمدة الديناميكية للمرضى للتصدير
    if (colId.startsWith('h') && /\d/.test(colId)) {
        const match = colId.match(/^h(\d+)(.+)$/);
        if (match) {
            const idx = parseInt(match[1]) - 1;
            const field = match[2];
            const health = row.health && row.health[idx];
            if (!health) return '-';
            if (field === 'Name') return health.name || '-';
            if (field === 'Type') return health.type || '-';
            if (field === 'Id') return health.idNum || '-';
        }
    }

    // معالجة بيانات الأفراد والحالات الصحية للتصدير (تجميع البيانات)
    if (colId === 'targetName') return row.targetName || (row.members ? row.members.map(m => m.name).join(', ') : '-');
    if (colId === 'targetId') return row.targetId || (row.members ? row.members.map(m => m.idNum).join(', ') : '-');
    if (colId === 'targetDob') return row.targetDob || (row.members ? row.members.map(m => m.dob).join(', ') : '-');
    if (colId === 'targetAge') return row.targetAge || (row.members ? row.members.map(m => getAge(m.dob).y).join(', ') : '-');
    if (colId === 'relation') return row.relation || (row.members ? row.members.map(m => m.relation).join(', ') : '-');

    if (colId === 'patientName') return row.patientName || (row.health ? row.health.map(h => h.name).join(', ') : '-');
    if (colId === 'patientId') return row.patientId || (row.health ? row.health.map(h => h.idNum).join(', ') : '-');
    if (colId === 'patientDob') return row.patientDob || (row.health ? row.health.map(h => h.dob).join(', ') : '-');
    if (colId === 'patientAge') return row.patientAge || (row.health ? row.health.map(h => getAge(h.dob).y).join(', ') : '-');
    if (colId === 'diseaseType') return row.diseaseType || (row.health ? row.health.map(h => h.type).join(', ') : '-');
    if (colId === 'diseaseDesc') return row.diseaseDesc || (row.health ? row.health.map(h => h.desc).join(', ') : '-');

    switch(colId) {
        case 'pName': return row.pName || '-';
        case 'pId': return row.pId || '-';
        case 'pIdIssue': return row.pIdIssue || '-';
        case 'pDob': return row.pDob || '-';
        case 'age': return getAge(row.pDob).y;
        case 'wifeName': return row.wifeName || '-';
        case 'wifeId': return row.wifeId || '-';
        case 'wifeDob': return row.wifeDob || '-';
        case 'wifeStatus': return row.wifeStatus || '-';
        case 'pPhone': return row.pPhone ? '0' + row.pPhone : '-';
        case 'pAltPhone': return row.pAltPhone ? '0' + row.pAltPhone : '-';
        case 'pDelegate': return row.pDelegate || '-';
        case 'pSocial': return row.pSocial || '-';
        case 'originArea': return row.originArea || '-';
        case 'displaceArea': return row.displaceArea || '-';
        case 'totalCount': return row.totalCount || 0;
        case 'maleCount': return row.maleCount || 0;
        case 'femaleCount': return row.femaleCount || 0;
        case 'walletOwner': return row.walletOwner || '-';
        case 'walletId': return row.walletId || '-';
        case 'walletPhone': return row.walletPhone || '-';
        case 'shelterType': return row.shelterType || '-';
        case 'displacementPeriod': return row.displacementPeriod || '-';
        case 'citizenStatus': return row.citizenStatus || '-';
        default: return row[colId] || '-';
    }
}

window.closeModal = closeModal;
window.openForm = openForm;
window.addMemberRow = addMemberRow;
window.addHealthRow = addHealthRow;
window.handleSave = handleSave;
window.viewDetails = viewDetails;
window.editFamily = editFamily;
window.triggerDelete = triggerDelete;
window.cancelDelete = cancelDelete;
window.runFilters = runFilters;
window.toggleDuplicateFilter = toggleDuplicateFilter;
window.downloadTemplate = downloadTemplate;
window.openImportModal = openImportModal;
window.triggerImportFile = triggerImportFile;
window.executeImport = executeImport;
window.openMainExportModal = openMainExportModal;
window.executeMainExport = executeMainExport;
window.openExportModal = openExportModal;
window.openCustomExportMetaModal = openCustomExportMetaModal;
window.executeCustomExport = executeCustomExport;
window.printFamilyDetails = printFamilyDetails;
window.openUserManagement = openUserManagement;
window.switchUserTab = switchUserTab;
window.handleCreateUser = handleCreateUser;
window.toggleUserStatus = toggleUserStatus;
window.deleteUserPermanently = deleteUserPermanently;
window.openEditCreds = openEditCreds;
window.handleSaveCreds = handleSaveCreds;
window.openMyProfile = openMyProfile;
window.toggleMultiSelect = toggleMultiSelect;
window.openBeneficiaries = openBeneficiaries;
window.renderBeneficiariesTable = renderBeneficiariesTable;
window.updateBenSelection = updateBenSelection;
window.selectAllBen = selectAllBen;
window.executeBenExport = executeBenExport;
window.switchBenTab = switchBenTab;
window.fetchArchiveData = fetchArchiveData;
window.deleteArchive = deleteArchive;
window.triggerMatchImport = triggerMatchImport;
window.processMatchImport = processMatchImport;
window.executeMatchArchive = executeMatchArchive;
window.reDownloadArchive = reDownloadArchive;
window.renderBeneficiaryView = renderBeneficiaryView;
window.togglePersonalSettings = togglePersonalSettings;
window.calculateFamilyCounts = calculateFamilyCounts;
window.toggleMainSelectAll = toggleMainSelectAll;
window.updateMainSelection = updateMainSelection;
window.deleteSelectedRows = deleteSelectedRows;
window.toggleColumnMenu = toggleColumnMenu;
window.toggleColumn = toggleColumn;
window.selectAllColumns = selectAllColumns;
