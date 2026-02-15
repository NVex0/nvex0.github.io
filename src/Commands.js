function Commands() {

  let consoleOutput = [];

  const commands = {
    help: "whoami blogs clear",

    blogs: createLink("blog_asset/blog_1/blog.html", "Feb-15-2026:\u2009Nghịch\u2009ngợm\u2009deobfuscate\u2009CFF"
    ),

    whoami: createLink(
      "https://github.com/NVex0", "NVex0"
    ),

    // ls: createLS()
  };

  function createLink(url, label) {
    const a = document.createElement("a");
    a.href = url;
    a.textContent = label;
    a.className = "hover-link";
    a.target = "_blank";
    return a;
  }


  // function createLS() {
  //   const span = document.createElement("span");

  //   span.appendChild(createLink(""));
  //   span.append(" { ");

  //   span.appendChild(createLink(""));
  //   span.append(" ");

  //   span.appendChild(createLink(""));
  //   span.append(" ");

  //   span.appendChild(createLink(""));
  //   span.append(" ");

  //   span.appendChild(createLink(""));
  //   span.append(" ");

  //   span.appendChild(createLink(""));
  //   span.append(" ");

  //   span.appendChild(createLink(""));

  //   return span;
  // }

  function updateConsoleOutput(newItem) {
    consoleOutput = consoleOutput.concat(newItem);
    TerminalOutput(consoleOutput);
  }

  function clearConsole() {
    consoleOutput = [];
    TerminalOutput(consoleOutput);
  }

  function onEnter(value, key) {

    const userInput = value.trim();

    if (key !== "Enter") return;

    if (commands[userInput] != null) {

      const wrapper = document.createElement("span");

      const inputSpan = document.createElement("span");
      inputSpan.textContent = userInput;

      const br = document.createElement("br");

      const outputSpan = document.createElement("span");
      outputSpan.className = "command-output";

      const cmdValue = commands[userInput];

      if (cmdValue instanceof HTMLElement) {
        outputSpan.appendChild(cmdValue.cloneNode(true));
      } else {
        outputSpan.textContent = cmdValue;
      }

      wrapper.appendChild(inputSpan);
      wrapper.appendChild(br);
      wrapper.appendChild(outputSpan);

      updateConsoleOutput(wrapper);

    } else if (userInput === "clear") {

      clearConsole();

    } else if (userInput.length === 0) {

      const br = document.createElement("br");
      updateConsoleOutput(br);

    } else {

      const wrapper = document.createElement("span");

      const inputSpan = document.createElement("span");
      inputSpan.textContent = userInput;

      const br = document.createElement("br");

      const errorSpan = document.createElement("span");
      errorSpan.textContent = `${userInput}: command not found`;

      wrapper.appendChild(inputSpan);
      wrapper.appendChild(br);
      wrapper.appendChild(errorSpan);

      updateConsoleOutput(wrapper);
    }
  }

  return {
    getConsoleOutput: () => consoleOutput,
    onEnter
  };
}
