const STORAGE_KEY = "flop-sentinel-language";

function applyLanguage(language) {
  const selected = language === "en" ? "en" : "ja";
  document.documentElement.lang = selected;
  document.documentElement.dataset.language = selected;
  for (const element of document.querySelectorAll("[data-lang]")) {
    element.hidden = element.dataset.lang !== selected;
  }
  for (const button of document.querySelectorAll("[data-set-language]")) {
    button.setAttribute("aria-pressed", String(button.dataset.setLanguage === selected));
  }
  for (const time of document.querySelectorAll("time[data-iso]")) {
    const value = new Date(time.dataset.iso);
    if (!Number.isNaN(value.valueOf())) {
      time.textContent = new Intl.DateTimeFormat(selected === "ja" ? "ja-JP" : "en-US", {
        dateStyle: "medium",
        timeStyle: "short",
        timeZone: "Asia/Tokyo",
      }).format(value);
    }
  }
  try {
    localStorage.setItem(STORAGE_KEY, selected);
  } catch {
    // Language still works when storage is blocked.
  }
  window.dispatchEvent(new CustomEvent("flop-language-change", { detail: selected }));
}

let initial = "ja";
try {
  initial = localStorage.getItem(STORAGE_KEY) || (navigator.language.startsWith("ja") ? "ja" : "en");
} catch {
  initial = navigator.language.startsWith("ja") ? "ja" : "en";
}

for (const button of document.querySelectorAll("[data-set-language]")) {
  button.addEventListener("click", () => applyLanguage(button.dataset.setLanguage));
}
applyLanguage(initial);
