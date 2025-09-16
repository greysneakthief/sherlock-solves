<%*
const title = await tp.system.prompt("Step title (short label)");
const overview = await tp.system.prompt("Overview");

tR += `##### ${title}

- **Timestamp:** ${tp.date.now("YYYY-MM-DD HH:mm")}
- **Overview:** ${overview}
`;
-%>