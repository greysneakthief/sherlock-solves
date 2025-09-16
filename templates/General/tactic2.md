<%*
const title = await tp.system.prompt("Step title (short label)");
const action = await tp.system.prompt("Action taken (tool/method)");
const command = await tp.system.prompt("Command (optional, leave blank if N/A)");
const result = await tp.system.prompt("Summary");
const next = await tp.system.prompt("Next step / lead");

tR += `##### ${title}

- **Timestamp:** ${tp.date.now("YYYY-MM-DD HH:mm")}
- **Action:** ${action}
- **Commands:** ${command}
- **Notes:** ${result}
- **Next Steps:** ${next}
`;
-%>