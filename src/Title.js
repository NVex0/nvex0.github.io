function Title() {
  const wrapper = document.createElement("div");

  wrapper.style.position = "fixed";
  wrapper.style.display = "flex";
  wrapper.style.justifyContent = "center";
  wrapper.style.width = "100%";


  const pre = document.createElement("pre");

  pre.style.fontSize = "0.875rem";
  pre.style.fontWeight = "bold";
  pre.style.paddingTop = "12px";
  pre.style.textAlign = "center";

  // Gradient text
  pre.style.background = "linear-gradient(to right, #00e1ff, #ff62d0)";
  pre.style.backgroundClip = "text";
  pre.style.color = "transparent";
  pre.style.fontSize = "42px";

  pre.textContent = `
  ベクスターミナル
  `;

  wrapper.appendChild(pre);

  return wrapper;
}
