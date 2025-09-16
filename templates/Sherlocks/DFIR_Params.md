<%*
/* ------------ Engagement Parameters (Templater-correct) ------------ */

async function enumOrCustom(label, shown, values, multi=false) {
  const choice = await tp.system.suggester([...shown, "Custom…"], [...values, "__custom__"], multi, label);
  if (Array.isArray(choice)) {
    if (choice.includes("__custom__")) {
      const extra = await tp.system.prompt(`${label} (custom, comma-separated)`);
      return [...choice.filter(v => v !== "__custom__"), ...(extra ? extra.split(",").map(s=>s.trim()).filter(Boolean) : [])];
    }
    return choice;
  } else {
    if (choice === "__custom__") return await tp.system.prompt(`${label} (custom)`);
    return choice;
  }
}

/* gather parameters */
const timeframe = await enumOrCustom(
  "Select engagement timeframe",
  ["24h","72h","1 Week","Ongoing"],
  ["24h","72h","1w","ongoing"],
  false
);

const restrictions = await enumOrCustom(
  "Select restrictions (multi)",
  ["No Production Impact","Read-Only Access","Business Hours Only","Full Scope"],
  ["no_prod","read_only","biz_hours","full_scope"],
  true
);

const primaryObj = await enumOrCustom(
  "Primary objective",
  ["Identify Root Cause","Scope Compromise","Contain Active Threat","Recover Systems"],
  ["root_cause","scope","contain","recover"],
  false
);

const secondaryObj = await enumOrCustom(
  "Secondary objective",
  ["None","Forensics","Attribution","Compliance Reporting"],
  ["none","forensics","attribution","compliance"],
  false
);

const constraints = await enumOrCustom(
  "Constraints (multi)",
  ["Time","Budget","Legal","Technical","None"],
  ["time","budget","legal","technical","none"],
  true
);

const compliance = await enumOrCustom(
  "Compliance requirements (multi)",
  ["HIPAA","PCI DSS","GDPR","SOX","None"],
  ["hipaa","pci","gdpr","sox","none"],
  true
);

/* collect arbitrary assets */
let assets = [];
while (true) {
  const add = await tp.system.suggester(
    ["Add asset","Done"],
    ["add","done"],
    false,
    assets.length ? "Add another asset?" : "Add first asset?"
  );
  if (add === "done") break;

  const aType = await enumOrCustom(
    "Asset type",
    ["Workstation","Server","Cloud Resource","Network Device","Application","Database","Identity/Account","Storage","Other"],
    ["workstation","server","cloud","net_device","app","db","identity","storage","other"],
    false
  );

  const name = await tp.system.prompt("Asset name/ID (e.g., HR-DB01, 10.10.10.5, okta:acct123)");
  const owner = await tp.system.prompt("Owner/BU (optional)") || "";
  const scopeFlag = await tp.system.suggester(["In Scope","Out of Scope"], ["in","out"], false, "Scope status");
  const env = await enumOrCustom(
    "Environment",
    ["Prod","Staging","Dev","Test","Corp","OT"],
    ["prod","stage","dev","test","corp","ot"],
    false
  );
  const sensitivity = await enumOrCustom(
    "Sensitivity / Data class",
    ["Public","Internal","Confidential","Restricted","Regulated"],
    ["public","internal","confidential","restricted","regulated"],
    false
  );
  const notes = await tp.system.prompt("Notes (optional)") || "";
  assets.push({name, type:aType, owner, scope:scopeFlag, env, sensitivity, notes});
}

/* render markdown via tR */
const j = (x) => Array.isArray(x) ? x.join(", ") : x;

let out = [];
out.push("## Engagement Parameters");
out.push("");
out.push("### Scope");
out.push(`- Timeframe: ${j(timeframe)}`);
out.push(`- Restrictions: ${j(restrictions)}`);
out.push("");
out.push("#### Asset Register");
out.push("| Name/ID | Type | Scope | Env | Sensitivity | Owner/BU | Notes |");
out.push("|---|---|---|---|---|---|---|");
for (const a of assets) {
  out.push(`| ${a.name} | ${a.type} | ${a.scope} | ${a.env} | ${a.sensitivity} | ${a.owner} | ${a.notes} |`);
}
out.push("");
out.push("### Objectives");
out.push(`- Primary: ${j(primaryObj)}`);
out.push(`- Secondary: ${j(secondaryObj)}`);
out.push("");
out.push("### Considerations");
out.push(`- Constraints: ${j(constraints)}`);
out.push(`- Compliance: ${j(compliance)}`);

tR += out.join("\n");
-%>

