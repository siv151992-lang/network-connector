// Applies the saved/preferred theme before first paint (external file so the
// strict Content-Security-Policy needs no 'unsafe-inline').
try {
  var t = localStorage.getItem("theme") || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  if (t === "dark") document.documentElement.classList.add("dark");
} catch (e) {}
