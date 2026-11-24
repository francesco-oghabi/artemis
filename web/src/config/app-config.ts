import packageJson from "../../package.json";

const currentYear = new Date().getFullYear();

export const APP_CONFIG = {
  name: "OpenArtemis",
  version: packageJson.version,
  copyright: `© ${currentYear}, OpenArtemis.`,
  meta: {
    title: "OpenArtemis, console di penetration testing autonomo",
    description: "Piattaforma di penetration testing autonomo guidata dall'AI",
  },
};
