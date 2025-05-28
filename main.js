const { app, BrowserWindow, ipcMain, Tray, Menu, globalShortcut, dialog } = require('electron');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const axios = require('axios'); // axios is generally preferred for HTTP requests over fetch in Node.js environments
const express = require('express');
const bcrypt = require('bcrypt');

const LOCAL_SERVER_PORT = 3000;
const LOCAL_SERVER_URL = `http://localhost:${LOCAL_SERVER_PORT}`;

const FLASK_SERVER_URL = `http://localhost:5000`;

let currentSession = null;
let tray = null;
let userSession = null;
const algorithm = 'aes-256-cbc';
let key;

try {
    key = crypto.scryptSync('your-very-secure-and-unique-key-here', 'cyphervault-unique-salt', 32);
} catch (e) {
    const showErrorAndQuit = () => {
        dialog.showErrorBox("Encryption Error", "Failed to initialize secure storage. The app will close.");
        app.quit();
    };
    if (app.isReady()) showErrorAndQuit();
    else app.on('ready', showErrorAndQuit);
    throw new Error("Encryption key generation failed.");
}
ipcMain.handle('login-user', async (event, credentials) => {
  const res = await fetch('http://localhost:5000/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(credentials),
    credentials: 'include'
  });

  const result = await res.json();

  if (result.success) {
    // Store the user session so Electron can return it later
    userSession = { username: credentials.username };
  }

  return result;
});
ipcMain.handle('get-auth-session', () => {
  return userSession;
});

function encrypt(text) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return { encryptedData: encrypted, iv: iv.toString('hex') };
}

ipcMain.handle('check-password', async (_, pwd) => {
    try {
        const res = await axios.get(`${FLASK_SERVER_URL}/checker?pwd=${encodeURIComponent(pwd)}`);
        return res.data;
    } catch (err) {
        console.error(`Error checking password strength: ${err.message}`);
        // Return a structured error, including status code if available
        return { error: `Failed to connect to password checker service: ${err.message}`, status: err.response?.status };
    }
});

const robot = require('robotjs_addon');

function typePassword(text) {
    if (!text) return;
    robot.setKeyboardDelay(20);
    robot.typeString(text);
}

ipcMain.handle('type-password', async (_, password) => {
    console.log("Typing will begin shortly...");

    return new Promise((resolve) => {
        setTimeout(() => {
            typePassword(password);
            resolve({ success: true });
        }, 3000); // 3 second delay to allow user to refocus window
    });
});

ipcMain.handle('store-account', async (_, { profile, username: providedUsername, password }) => {
    console.log("Attempting to store account via Flask server...");

    try {
        if (!profile || !providedUsername || !password) {
            return { success: false, error: "Profile name, username, and password must be provided." };
        }

        const accountDataForFlask = {
            profile_name: profile,
            profile_username: providedUsername,
            profile_password: password
        };

        // Flask's /upload_profile expects form data, not JSON by default.
        const formData = new URLSearchParams();
        for (const key in accountDataForFlask) {
            formData.append(key, accountDataForFlask[key]);
        }

        const response = await axios.post(`${FLASK_SERVER_URL}/upload_profile`, formData.toString(), {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            withCredentials: true // Important for Flask-Login session cookies
        });

        // Flask's /upload_profile route redirects on success. Axios will follow redirects.
        // We check the final URL to confirm success.
        if (response.request.res.responseUrl.includes('/view_profiles')) {
            console.log('Account stored successfully by Flask (redirected to view_profiles).');
            return { success: true, message: 'Account uploaded successfully.' };
        } else {
            // If Flask didn't redirect to /view_profiles, it likely encountered an issue.
            // For a robust API, Flask should return JSON error messages.
            // Here, we'll try to extract an error from the response body if available.
            const errorMessage = response.data || 'Failed to upload profile: Unexpected Flask response.';
            console.error('Flask did not redirect to expected success page after upload:', response.request.res.responseUrl, errorMessage);
            return { success: false, error: errorMessage };
        }
    } catch (err) {
        console.error(`Failed to store account via Flask: ${err.message}`);
        // If Flask returns an error page HTML, err.response.data might contain it.
        const errorMessage = err.response && err.response.data ? err.response.data : err.message;
        return { success: false, error: `Failed to store account: ${errorMessage}` };
    }
});

ipcMain.handle('load-account', async (_, profile) => {
    console.log(`Attempting to load account '${profile}' via Flask server...`);

    if (!profile) {
        return { success: false, error: "Profile name must be provided." };
    }

    try {
        // --- ASSUMPTION: Flask has a /api/profiles JSON endpoint ---
        const response = await axios.get(`${FLASK_SERVER_URL}/api/profiles`, {
            withCredentials: true // Include cookies for session-based authorization
        });

        if (response.status !== 200) {
            return { success: false, error: `Failed to load profiles: ${response.status}`, status: response.status };
        }

        const profiles = response.data.profiles; // Assuming JSON response like { "profiles": [...] }
        const foundProfile = profiles.find(p => p.profile_name === profile);

        if (foundProfile) {
            console.log('Account loaded successfully from Flask:', foundProfile);
            return { success: true, data: foundProfile };
        } else {
            return { success: false, error: `Profile '${profile}' not found.`, status: 404 };
        }
    } catch (err) {
        console.error(`Failed to load account via Flask: ${err.message}`);
        const errorMessage = err.response && err.response.data ? err.response.data : err.message;
        return { success: false, error: `Failed to load account: ${errorMessage}`, status: err.response?.status };
    }
});

ipcMain.handle('register-user', async (event, username, password) => {
    try {
        const res = await fetch('http://localhost:5000/api/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, password })
        });

        const data = await res.json();
        return data;
    } catch (err) {
        console.error("Register IPC handler failed:", err);
        return { success: false, message: err.message };
    }
});
async function login() {
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;

    if (!username || !password) {
        displayMessage('Please enter both username and password.');
        return;
    }

    displayMessage('Logging in...', false);

    try {
        const response = await fetch('/api/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json' // ✅ This is essential
            },
            body: JSON.stringify({ username, password })
        });

        const result = await response.json();

        if (result.success) {
            displayMessage('Login successful!', false);
            window.location.href = 'dashboard.html';
        } else {
            displayMessage(`Login failed: ${result.message || "Invalid credentials."}`);
        }
    } catch (err) {
        console.error("Login failed:", err);
        displayMessage(`An unexpected error occurred during login. (${err.message})`);
    }
}


const fetch = require('node-fetch'); // or global fetch

ipcMain.handle('authenticate', async (event, credentials) => {
    try {
        const res = await fetch('http://localhost:5000/api/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(credentials)
        });

        const data = await res.json();
        return data;
    } catch (err) {
        console.error("Login IPC handler failed:", err);
        return { success: false, message: err.message };
    }
});



// --- NEW IPC HANDLER FOR DELETE ACCOUNT ---
ipcMain.handle('delete-account', async () => {
    console.log("Attempting to delete account via Flask server...");
    try {
        // Flask's delete_account route accepts POST. It relies on the session for authentication.
        const response = await axios.post(`${FLASK_SERVER_URL}/delete_account`, null, {
            withCredentials: true // Important for Flask-Login session cookies
        });

        // Flask's delete_account route redirects on success. Axios will follow.
        // Check if the final URL indicates a successful deletion (e.g., home page or login).
        if (response.request.res.responseUrl.includes('/') || response.request.res.responseUrl.includes('/login')) {
            console.log('Account deleted successfully by Flask (redirected to home/login).');
            currentSession = null; // Clear local session after deletion
            return { success: true, message: 'Account deleted successfully.' };
        } else {
            console.error('Flask did not redirect to expected success page after deletion:', response.request.res.responseUrl);
            return { success: false, error: 'Failed to delete account: Unexpected Flask response.' };
        }
    } catch (err) {
        console.error(`Failed to delete account via Flask: ${err.message}`);
        const errorMessage = err.response && err.response.data ? err.response.data : err.message;
        return { success: false, error: `Failed to delete account: ${errorMessage}`, status: err.response?.status };
    }
});
// --- END NEW IPC HANDLER ---

ipcMain.handle('set-user-session', (_, sessionData) => {
    currentSession = { ...sessionData, createdAt: new Date().toISOString() };
    console.log('User session set:', currentSession.username);
    return { success: true };
});

ipcMain.handle('get-user-session', () => currentSession);

ipcMain.handle('clear-user-session', async () => {
    console.log("Attempting to log out via Flask server...");
    try {
        const response = await axios.get(`${FLASK_SERVER_URL}/logout`, {
            withCredentials: true // Important to send session cookie for logout
        });

        // Flask's logout route redirects on success. Axios will follow.
        if (response.request.res.responseUrl.includes('/')) { // Assuming Flask logout redirects to home
            currentSession = null;
            console.log('User session cleared and logged out from Flask.');
            return { success: true };
        } else {
            console.error('Flask logout did not redirect to home.');
            return { success: false, error: 'Flask logout failed: Unexpected Flask response.' };
        }
    } catch (err) {
        console.error('Failed to log out from Flask:', err);
        const errorMessage = err.response && err.response.data ? err.response.data : err.message;
        return { success: false, error: `Failed to log out: ${errorMessage}`, status: err.response?.status };
    }
});

function createWindow() {
    const preloadPath = path.join(__dirname, 'preload.js');

    const win = new BrowserWindow({
        width: 800,
        height: 600,
        webPreferences: {
            preload: preloadPath,
            contextIsolation: true,
            nodeIntegration: false,
        }
    });

    win.loadURL(LOCAL_SERVER_URL).catch(err =>
        console.error(`Failed to load ${LOCAL_SERVER_URL}:`, err)
    );
}

function createPopupWindow() {
    const popup = new BrowserWindow({
        width: 400,
        height: 300,
        frame: true,
        alwaysOnTop: true,
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),
            contextIsolation: true,
            nodeIntegration: false,
        }
    });
    popup.loadURL(`${LOCAL_SERVER_URL}/popup.html`);
}

function registerGlobalHotkey() {
    const shortcut = 'Control+Shift+P';
    const success = globalShortcut.register(shortcut, createPopupWindow);
    if (!success) console.error('Failed to register hotkey');
}

function createTray() {
    tray = new Tray(path.join(__dirname, 'icon.jpg'));
    const menu = Menu.buildFromTemplate([
        { label: 'Show', click: createWindow },
        { label: 'Quit', click: () => app.quit() }
    ]);
    tray.setToolTip('CypherVault is running');
    tray.setContextMenu(menu);
}

function setupExpressServer() {
    const expressApp = express();
    expressApp.use(express.static(path.join(__dirname)));

    expressApp.get('/', (_, res) => res.sendFile(path.join(__dirname, 'index1.html')));

    return new Promise((resolve, reject) => {
        const server = expressApp.listen(LOCAL_SERVER_PORT, () => {
            console.log(`Electron's internal server running at ${LOCAL_SERVER_URL}`);
            resolve(server);
        });
        server.on('error', reject);
    });
}

ipcMain.handle('register', async (_, username, password) => {
    try {
        const response = await axios.post(`${FLASK_SERVER_URL}/register`,
            new URLSearchParams({ username, password }).toString(),
            {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            }
        );

        // Flask's register route redirects on success. Axios will follow.
        if (response.request.res.responseUrl.includes('/login')) {
            console.log(`User '${username}' registered successfully with Flask.`);
            return { success: true, message: 'Registration successful' };
        } else {
            const errorMessage = response.data || 'Registration failed: Username might be taken or server error.';
            console.error('Flask registration failed or did not redirect to login:', errorMessage);
            return { success: false, message: errorMessage };
        }
    } catch (err) {
        console.error(`Registration failed: ${err.message}`);
        const errorMessage = err.response && err.response.data ? err.response.data : err.message;
        return { success: false, message: 'Registration failed: ' + errorMessage, status: err.response?.status };
    }
});

// --- IPC Handler for deleting a specific password profile ---
// ASSUMPTION: Flask has a /api/profile/<profile_name> DELETE endpoint
ipcMain.handle('delete-credential', async (_, profileName) => {
    console.log(`Attempting to delete credential profile '${profileName}' via Flask server...`);

    try {
        const response = await axios.delete(`${FLASK_SERVER_URL}/api/profile/${encodeURIComponent(profileName)}`, {
            withCredentials: true, // Important for Flask-Login session cookies
            headers: { 'Content-Type': 'application/json' }
        });

        // Assuming Flask's API endpoint returns JSON on success/failure
        if (response.status === 200 && response.data.success) {
            console.log(`Profile "${profileName}" deleted successfully.`);
            return { success: true, message: `Profile "${profileName}" deleted.` };
        } else {
            console.error(`Flask reported error deleting profile: ${response.data.message || response.statusText}`);
            return { success: false, error: response.data.message || `Failed to delete profile: ${response.statusText}`, status: response.status };
        }
    } catch (err) {
        console.error("Failed to delete profile via Flask: " + err.message);
        const errorMessage = err.response && err.response.data ? err.response.data : err.message;
        return { success: false, error: "Failed to delete profile: " + errorMessage, status: err.response?.status };
    }
});


app.commandLine.appendSwitch(
    'unsafely-treat-insecure-origin-as-secure',
    LOCAL_SERVER_URL
);

app.whenReady().then(async () => {
    try {
        await setupExpressServer();
        registerGlobalHotkey();
        createTray();
        createWindow();
    } catch (err) {
        console.error("Fatal: Failed to start Electron's internal Express server", err);
        app.quit();
    }
});

app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
});

app.on('window-all-closed', (e) => {
    // Do nothing to keep the app running in background
});