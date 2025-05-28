// preload.js
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
   
    checkPassword: (pwd) => ipcRenderer.invoke('check-password', pwd),
    typePassword: (password) => ipcRenderer.invoke('type-password', password),
    storeAccount: (data) => ipcRenderer.invoke('store-account', data),
    loadAccount: (profile) => ipcRenderer.invoke('load-account', profile),
    authenticate: (credentials) => ipcRenderer.invoke('authenticate', credentials),
    setAuthSession: (sessionData) => ipcRenderer.invoke('set-user-session', sessionData),
    getAuthSession: () => ipcRenderer.invoke('get-auth-session'),
    clearAuthSession: () => ipcRenderer.invoke('clear-user-session'),
    registerUser: (username, password) => ipcRenderer.invoke('register-user', username, password),

    deleteAccount: () => ipcRenderer.invoke('delete-account'),
    deleteCredential: (profileName) => ipcRenderer.invoke('delete-credential', profileName),
    
});