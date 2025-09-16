---
challenge: <% await tp.system.prompt('Enter Challenge name') %>
type: sherlock
date: <% tp.date.now('YYYY-MM-DD') %>
category: <% await tp.system.suggester(["DFIR","SOC","Threat Intelligence","Malware Analysis"],["DFIR","SOC","Threat Intelligence","Malware Analysis"]) %>
difficulty: <% await tp.system.suggester(["Very Easy","Easy","Medium","Hard","Insane"],["Very Easy","Easy","Medium","Hard","Insane"]) %>
tags:
start:
finish:
status: <% await tp.system.suggester(["scheduled","in-progress","complete"],["scheduled","in-progress","complete"]) %>
---

<%*
/* Prompt for case name */
const sherlockName = await tp.system.prompt("Enter Sherlock Case Name");

/* Build a filename */
const date = tp.date.now("YYYY-MM-DD");
const safeName = sherlockName.replace(/\s+/g, "-"); // replace spaces with underscores
const newTitle = `Case-${date}-${safeName}`;

/* Rename the current file */
await tp.file.rename(newTitle);

/* Print header with new title */
tR += `# Sherlock Case File – ${newTitle}\n\n`;
%>
