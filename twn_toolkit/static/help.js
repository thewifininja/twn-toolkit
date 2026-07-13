(() => {
  const input = document.querySelector("[data-help-search]");
  const clear = document.querySelector("[data-help-search-clear]");
  const status = document.querySelector("[data-help-search-status]");
  const sections = [...document.querySelectorAll(".help-section")];
  if (!input || !clear || !status || !sections.length) return;

  const initialOpenTopics = new Set(
    sections.flatMap((section) => [...section.querySelectorAll(".help-topic[open]")]),
  );

  const filter = () => {
    const query = input.value.trim().toLocaleLowerCase();
    let matches = 0;
    sections.forEach((section) => {
      const topics = [...section.querySelectorAll(".help-topic")];
      const isReleaseNotes = section.id === "release-notes";
      const headingMatch = section.querySelector("h2")?.textContent.toLocaleLowerCase().includes(query);
      let sectionMatches = 0;
      topics.forEach((topic) => {
        const match = !query || headingMatch || topic.textContent.toLocaleLowerCase().includes(query);
        topic.hidden = !match;
        topic.classList.toggle("help-search-match", Boolean(query) && match);
        // Release notes can match broad searches and contain a great deal of text.
        // Keep them visible as a result without letting them dominate the page.
        topic.open = query ? match && !isReleaseNotes : initialOpenTopics.has(topic);
        if (match) sectionMatches += 1;
      });
      section.hidden = Boolean(query) && sectionMatches === 0;
      matches += sectionMatches;
    });
    clear.hidden = !query;
    status.classList.toggle("empty", Boolean(query) && matches === 0);
    status.textContent = query
      ? matches
        ? `${matches} matching topic${matches === 1 ? "" : "s"}. Matching guide topics are expanded below.`
        : `No help topics match “${input.value.trim()}”.`
      : "";
  };

  input.addEventListener("input", filter);
  clear.addEventListener("click", () => {
    input.value = "";
    filter();
    input.focus();
  });
})();
