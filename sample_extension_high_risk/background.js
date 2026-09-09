chrome.tabs.onCreated.addListener((tab) => {
  console.log("New tab opened:", tab.id);
});

chrome.storage.local.set({ lastOpened: Date.now() });