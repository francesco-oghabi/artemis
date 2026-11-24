package report

// Default deterministic scaffold content shared by all reports (brand-free,
// neutral). This fork is English-only. The delivery conventions (personnel,
// PTES process, test checklist, tools, standards) are fixed; the AI only writes
// the narrative prose. Company name / personnel are user-configured in report
// management; these are the fallbacks.
//
// Selector functions (methodologyIntro/methodology/tools/standards/checklist/
// defaultPersonnel) return the English content; build.go calls them with the
// report locale (now always resolved to en-US).

type kv struct {
	Name string `json:"name"`
	Desc string `json:"desc"`
}

// checklistItem is one row of the 2.3 Test Checklist (English).
type checklistItem struct {
	Category string `json:"category"`
	Name     string `json:"name"`
	Desc     string `json:"desc"`
}

// ---------------------------------------------------------------------------
// 2.1 Tester Information: neutral, brand-free fallbacks (no contact). Overridden by
// user-configured personnel in report settings.
// ---------------------------------------------------------------------------
func defaultPersonnel(loc string) []map[string]string {
	return []map[string]string{
		{"name": "Lead Consultant / Security Engineer", "role": "Lead Consultant / Security Engineer", "contact": ""},
		{"name": "Red Team Assessment Group", "role": "Offensive Security Team", "contact": ""},
	}
}

// ---------------------------------------------------------------------------
// 2.2 Testing Process (PTES 8 phases)
// ---------------------------------------------------------------------------
func methodologyIntro(loc string) string {
	return "The penetration testing service workflow follows the internationally recognized Penetration Testing Execution Standard (PTES), ensuring that every engagement is delivered in a standardized, high-quality manner. The workflow comprises the following 8 phases:"
}

func methodology(loc string) []kv {
	return []kv{
		{"Pre-engagement Interactions", "Project initiation and preparation: both parties agree on the testing scope and specific test items, and authorization confirmation, personnel, and tooling are finalized."},
		{"Intelligence Gathering", "Open-source information collection, asset mapping, and site structure analysis around the authorized assets, culminating in the penetration testing implementation plan."},
		{"Threat Modeling", "Analysis of business assets and processes, assessment of threat actors and their capabilities, and identification of the primary attack surface and risk paths."},
		{"Vulnerability Analysis", "Correlation analysis of scanner results combined with manual verification, reproduction in a controlled environment, and derivation of analytical conclusions."},
		{"Exploitation", "Based on the analysis results, the optimal attack path is selected to perform low-impact, precise verification and confirm the authenticity of each risk."},
		{"Post-Exploitation", "Within the authorized scope, assessment of lateral movement, privilege escalation, and reachability of sensitive data following successful exploitation."},
		{"Reporting", "Consolidation of vulnerability details, evidence, CVSS scoring, and risk ratings into a deliverable penetration test report."},
		{"Remediation Support", "Working with the client to complete remediation based on the report, and conducting retesting where required to confirm that vulnerabilities are fully closed."},
	}
}

// ---------------------------------------------------------------------------
// 2.4 Testing Tools
// ---------------------------------------------------------------------------
func tools(loc string) []kv {
	return []kv{
		{"Burp Suite", "An integrated platform for web application security testing, serving as the primary proxy and packet-capture tool for this penetration test."},
		{"SQLMap", "An open-source tool for detecting and exploiting SQL injection vulnerabilities."},
		{"Nmap", "A network port scanning and service identification tool."},
		{"Nuclei", "A YAML-template-based vulnerability scanner used for bulk fingerprinting and vulnerability verification."},
		{"cURL / httpie", "Command-line tools for crafting HTTP requests and analyzing responses."},
		{"Wappalyzer / EHole", "Web application framework and fingerprint identification tools."},
		{"In-house POC Library", "An internally maintained library of vulnerability verification scripts, used together with a local vulnerability database index."},
	}
}

// ---------------------------------------------------------------------------
// 2.5 Reference Standards
// ---------------------------------------------------------------------------
func standards(loc string) []string {
	return []string{
		"GB/T 25069-2022 Information Security Technology: Terminology",
		"GB/T 22239-2019 Information Security Technology: Baseline for Classified Protection of Cybersecurity",
		"GB/T 28448-2019 Information Security Technology: Evaluation Requirements for Classified Protection of Cybersecurity",
		"GB/T 20271-2006 Information Security Technology: Common Security Techniques Requirement for Information Systems",
		"PTES (Penetration Testing Execution Standard)",
		"OWASP Top 10: 2021",
	}
}

// ---------------------------------------------------------------------------
// 2.3 Test Checklist. checklistRow holds the English rows; checklist(loc) returns
// them. AI-returned checklist_hits are matched against the Name (see buildChecklist)
// -> matched rows render as "fail" (red bold).
// ---------------------------------------------------------------------------
type checklistRow struct {
	Category string
	Name     string
	Desc     string
}

func checklist(loc string) []checklistItem {
	out := make([]checklistItem, 0, len(checklistAll))
	for _, r := range checklistAll {
		out = append(out, checklistItem{Category: r.Category, Name: r.Name, Desc: r.Desc})
	}
	return out
}

var checklistAll = []checklistRow{
	{"Authentication & Session Management", "Brute Force", "Commonly found in login systems; large-scale attempts of login credentials against a known username."},
	{"Authentication & Session Management", "SMS Bombing", "Replaying the SMS verification-code request to flood a target with text messages (SMS bombing)."},
	{"Authentication & Session Management", "Authentication Bypass", "The application lacks a valid token mechanism, allowing authentication information to be modified to bypass server-side authorization."},
	{"Authentication & Session Management", "Malicious Registration", "The user registration function can be abused by an attacker to perform bulk registration."},
	{"Authentication & Session Management", "Session Fixation", "The session ID does not change before and after login, creating a session-hijacking risk."},
	{"Authentication & Session Management", "Plaintext Password Transmission", "Usernames or passwords are transmitted without encryption, making them susceptible to sniffing and interception."},
	{"Authentication & Session Management", "Password Recovery Logic Flaw", "Logic flaws in the password recovery flow can be exploited to illegitimately reset a password."},
	{"Authentication & Session Management", "OAuth Authentication Flaw", "Incomplete OAuth authentication allows unauthorized login to other users' accounts."},
	{"Authentication & Session Management", "Weak Password", "Discovery of weak passwords in the system through brute forcing, guessing, and similar techniques."},
	{"Authentication & Session Management", "Broken Authentication & Session Management", "Vulnerabilities in the authentication and session management functions, including missing session timeout settings."},
	{"Authentication & Session Management", "CAPTCHA Functional Flaw", "The CAPTCHA does not expire and can be reused, enabling brute-force attacks."},
	{"Authentication & Session Management", "Username Enumeration", "Different accounts return different error messages, allowing enumeration of valid accounts in the system."},
	{"Client-Side Security", "CORS Cross-Origin Resource Sharing Vulnerability", "Improper CORS configuration can be exploited to steal users' sensitive data."},
	{"Client-Side Security", "Flash Cross-Domain Access Vulnerability", "An incorrect crossdomain.xml policy leads to cross-domain security issues."},
	{"Client-Side Security", "Outdated jQuery Version", "An outdated jQuery version introduces cross-site scripting and other known security vulnerabilities."},
	{"Client-Side Security", "JSONP Hijacking", "Cross-domain data transfer lacks authorization checks, allowing sensitive data to be read by malicious scripts."},
	{"Client-Side Security", "Cross-Site Request Forgery (CSRF)", "Forces an authenticated user to perform unintended actions within a web application."},
	{"Client-Side Security", "Cross-Site Scripting (XSS)", "Injects malicious scripts into web pages, executing malicious code when the page is viewed."},
	{"Malicious Input / Injection", "Code Injection", "An attacker submits code as input, which the server processes as dynamic code."},
	{"Malicious Input / Injection", "LDAP Injection", "Leverages LDAP query syntax to disclose sensitive user and host information."},
	{"Malicious Input / Injection", "Command Injection", "Injects OS commands via an HTTP request to execute system commands on the server."},
	{"Malicious Input / Injection", "XFF Injection", "Performs SQL injection by manipulating the X-Forwarded-For header."},
	{"Malicious Input / Injection", "SSI Injection", "May allow injection of code into HTML pages and even remote code execution."},
	{"Malicious Input / Injection", "SQL Injection", "By inserting SQL queries, an attacker can read or tamper with data, perform administrative operations, or execute system commands."},
	{"Malicious Input / Injection", "XPath Injection", "Injects elements into an XPath query, potentially bypassing authentication."},
	{"Malicious Input / Injection", "Link or Frame Injection", "Injects frame or iframe tags containing malicious content."},
	{"Malicious Input / Injection", "XML External Entity (XXE) Injection", "XML external entities can be abused to read system files, perform SSRF, and mount other attacks."},
	{"Access Control", "Local File Inclusion", "Includes and executes code on the target server to obtain sensitive files or privileges."},
	{"Access Control", "Vertical Privilege Escalation", "A low-privilege account can access or operate high-privilege functionality."},
	{"Access Control", "Unauthorized Access", "Internal resources or functions can be accessed directly without login or authorization."},
	{"Access Control", "Arbitrary File Upload", "Uploading an executable script file to gain the ability to run commands on the server."},
	{"Access Control", "Arbitrary File Download", "System files, configuration files, and similar can be browsed or downloaded arbitrarily."},
	{"Access Control", "Horizontal Privilege Escalation", "Users at the same privilege level can access or operate other users' resources."},
	{"Access Control", "Remote File Inclusion", "Crafting parameters to include remote code that is executed on the server."},
	{"Information Disclosure", "Error Page Information Disclosure", "Error messages contain sensitive server or database information."},
	{"Information Disclosure", "Test / Backup File Leak", "Leftover outdated files, backup pages, and test files are exposed."},
	{"Information Disclosure", ".git Source Code Leak", "The .git directory was not removed at deployment, allowing source code to be recovered."},
	{"Information Disclosure", "GitHub Information Leak", "Sensitive code, keys, and similar are inadvertently made public on GitHub."},
	{"Information Disclosure", "IIS Short Filename Disclosure", "An IIS file enumeration vulnerability that allows enumeration of files in the root directory."},
	{"Information Disclosure", "Absolute Path Disclosure", "The application discloses its absolute path on the host."},
	{"Information Disclosure", "Directory Listing", "A website configuration flaw results in a browsable directory listing vulnerability."},
	{"Information Disclosure", "Sensitive Information Disclosure", "Configuration files contain sensitive data such as passwords, keys, internal addresses, and employee identifiers."},
	{"Information Disclosure", "Sensitive File Leak", "Program files, configuration files, logs, backups, and database files are exposed."},
	{"Information Disclosure", "Default Page Leak", "Default-installed middleware and frameworks ship with sample pages and documentation."},
	{"Information Disclosure", "Directory Traversal", "An attacker views the website's directory structure and files to mount further attacks."},
	{"Information Disclosure", "Residual Intrusion Traces", "Traces of a prior intrusion remain in the application, such as WebShell files."},
	{"Information Disclosure", "SVN Source Code Leak", "Source code is obtained through an SVN source code disclosure vulnerability."},
	{"Information Disclosure", "Web Console Exposure", "The management console of a web container or database is exposed."},
	{"Security Misconfiguration", "Insecure HTTP Methods", "The server enables insecure methods such as TRACE, PUT, and DELETE."},
	{"Security Misconfiguration", "Server-Side Request Forgery (SSRF)", "The server makes requests on the attacker's behalf, allowing access to internal-network or local resources."},
	{"Security Misconfiguration", "Host Header Attack", "Malicious manipulation of the HTTP Host header to enable phishing, cache poisoning, and similar attacks."},
	{"Security Misconfiguration", "Slow HTTP DoS Attack", "Exhausts server resources through slow HTTP requests."},
	{"Security Misconfiguration", "Unnecessary Web Server Ports Open", "Default ports beyond the required business ports are left open."},
	{"Insecure Storage & Transport", "Insecure Storage", "Important information is not encrypted or is encrypted with insufficient strength."},
	{"Insecure Storage & Transport", "Sensitive Information in HTML", "HTML pages contain sensitive information."},
}
