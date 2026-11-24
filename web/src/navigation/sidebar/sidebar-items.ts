import {
  Activity,
  Bot,
  Brain,
  Bug,
  ClipboardList,
  FileText,
  FolderSync,
  LayoutDashboard,
  type LucideIcon,
  MessageSquare,
  Network,
  Plug,
  ScrollText,
  Settings2,
  ShieldAlert,
  Sparkles,
  Target,
  UsersRound,
  Wrench,
} from "lucide-react";

export type NavBadge = "new" | "soon";

export interface NavSubItem {
  id: string;
  title: string;
  url: string;
  icon?: LucideIcon;
  badge?: NavBadge;
  disabled?: boolean;
  newTab?: boolean;
}

interface NavItemBase {
  id: string;
  title: string;
  icon?: LucideIcon;
  badge?: NavBadge;
  disabled?: boolean;
  newTab?: boolean;
}

export interface NavMainLinkItem extends NavItemBase {
  url: string;
  subItems?: never;
}

export interface NavMainParentItem extends NavItemBase {
  subItems: NavSubItem[];
}

export type NavMainItem = NavMainLinkItem | NavMainParentItem;

export interface NavGroup {
  id: number;
  label?: string;
  items: NavMainItem[];
}

export const sidebarItems: NavGroup[] = [
  {
    id: 1,
    label: "Funzionalità",
    items: [
      { id: "dashboard", title: "Dashboard", url: "/dashboard", icon: LayoutDashboard },
      { id: "chat", title: "Chat", url: "/chat", icon: MessageSquare },
      { id: "tasks", title: "Task", url: "/function/tasks", icon: Target },
      { id: "findings", title: "Rilievi", url: "/function/findings", icon: Bug },
      { id: "traffic", title: "Traffico", url: "/function/traffic", icon: Activity },
      { id: "assets", title: "Asset", url: "/function/assets", icon: Network },
      { id: "sync", title: "Sincronizzazione Asset", url: "/function/sync", icon: FolderSync },
    ],
  },
  {
    id: 2,
    label: "Sistema",
    items: [
      { id: "llm", title: "LLM", url: "/system/llm", icon: Brain },
      { id: "agents", title: "Agent", url: "/system/agents", icon: Bot },
      { id: "mcp", title: "MCP", url: "/system/mcp", icon: Plug },
      { id: "skills", title: "Skill", url: "/system/skills", icon: Sparkles },
      { id: "tools", title: "Strumenti", url: "/system/tools", icon: Wrench },
      { id: "intercept", title: "Regole di intercettazione", url: "/system/intercept", icon: ShieldAlert },
      { id: "approvals", title: "Approvazioni", url: "/system/intercept/approvals", icon: ClipboardList },
      { id: "rbac", title: "Gestione utenti", url: "/system/rbac", icon: UsersRound },
      { id: "reports", title: "Report", url: "/system/reports", icon: FileText },
      { id: "knowledge", title: "Conoscenza", url: "/system/knowledge", icon: Brain },
      { id: "logs", title: "Log", url: "/system/logs", icon: ScrollText },
      { id: "settings", title: "Impostazioni", url: "/system/settings", icon: Settings2 },
    ],
  },
];
