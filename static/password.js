function togglePassword(inputId, btn) {
    const input = document.getElementById(inputId);
    if (!input) return;

    const show = input.type === "password";
    input.type = show ? "text" : "password";
    btn.classList.toggle("active", show);
}
