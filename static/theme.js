const toggle = document.getElementById("themeToggle");

const savedTheme = localStorage.getItem("theme") || "dark";
document.body.classList.add(savedTheme);

if (toggle) {
    toggle.onclick = () => {
        const isDark = document.body.classList.contains("dark");
        document.body.classList.remove(isDark ? "dark" : "light");
        document.body.classList.add(isDark ? "light" : "dark");
        localStorage.setItem("theme", isDark ? "light" : "dark");
    };
}
