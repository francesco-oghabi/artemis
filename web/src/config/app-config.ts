import packageJson from "../../package.json";

const currentYear = new Date().getFullYear();

export const APP_CONFIG = {
  name: "Artemis",
  version: packageJson.version,
  copyright: `© ${currentYear}, Artemis.`,
  meta: {
    title: "Artemis, console di penetration testing autonomo",
    description: "Piattaforma di penetration testing autonomo guidata dall'AI",
  },
};
