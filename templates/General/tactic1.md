<%*
const title = await tp.system.prompt("Step title (short label)");
const rationale = await tp.system.prompt("Rationale (why this step?)");
const action = await tp.system.prompt("Action taken (tool/method)");
const result = await tp.system.prompt("Result (summary, observations)");
const next = await tp.system.prompt("Next step / lead");

tR += `#### ${title}

- **Timestamp:** ${tp.date.now("YYYY-MM-DD HH:mm")}
- **Action:** ${action}
- **Rationale:** ${rationale}
- **Results:** ${result}
- **Notes:** ${next}
`;
-%>