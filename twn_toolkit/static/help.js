(() => {
  const input = document.querySelector("[data-help-search]");
  const clear = document.querySelector("[data-help-search-clear]");
  const status = document.querySelector("[data-help-search-status]");
  const sections = [...document.querySelectorAll(".help-section")];
  if (!input || !clear || !status || !sections.length) return;

  const filter = () => {
    const query = input.value.trim().toLocaleLowerCase();
    let matches = 0;
    sections.forEach((section) => {
      const topics = [...section.querySelectorAll(".help-topic")];
      const headingMatch = section.querySelector("h2")?.textContent.toLocaleLowerCase().includes(query);
      let sectionMatches = 0;
      topics.forEach((topic) => {
        const match = !query || headingMatch || topic.textContent.toLocaleLowerCase().includes(query);
        topic.hidden = !match;
        if (match) sectionMatches += 1;
      });
      section.hidden = Boolean(query) && sectionMatches === 0;
      matches += sectionMatches;
    });
    clear.hidden = !query;
    status.textContent = query ? `${matches} matching topic${matches === 1 ? "" : "s"}` : "";
  };

  input.addEventListener("input", filter);
  clear.addEventListener("click", () => {
    input.value = "";
    filter();
    input.focus();
  });
})();
