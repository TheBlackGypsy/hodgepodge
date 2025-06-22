export interface SecurityTutorial {
  slug: string;
  title: string;
  excerpt: string;
  content: string;
  category: string;
  readTime: string;
  publishDate: string;
  featured: boolean;
  author: string;
  tags: string[];
  difficulty: string;
  prerequisites: string[];
  tools: string[];
  steps: number;
}

export const securityTutorials: SecurityTutorial[] = [
  {
    slug: "building-active-directory-lab",
    title: "Building an Active Directory Lab Environment: Complete Step-by-Step Guide",
    excerpt: "Learn how to build a complete Active Directory lab environment using virtual machines for security testing and learning purposes.",
    content: `
# Step-by-Step Guide: Building an Active Directory

This guide will walk you through the process of setting up a basic Active Directory Domain Services (AD DS) environment on a Windows Server.

## 1. Prerequisites

Before you begin, ensure you have the following:

Windows Server Installation Media: A bootable USB or ISO image for a supported Windows Server version (e.g., Windows Server 2019, 2022).

Sufficient Hardware: A physical or virtual machine with adequate CPU, RAM, and disk space for a server. Microsoft recommends at least 2GB RAM for a domain controller.

Network Connectivity: A network connection for the server.

Administrative Privileges: You will need administrator credentials to perform the installation and configuration.

## 2. Install Windows Server Operating System

Boot from Installation Media: Start your physical or virtual machine and boot from the Windows Server installation media.

Follow On-Screen Prompts:

- Choose your language, time and currency format, and keyboard input method.
- Click "Install now."
- Select the "Windows Server (Desktop Experience)" option. This provides a graphical user interface, which is easier for beginners. The "Server Core" option is command-line only.
- Accept the license terms.
- Choose "Custom: Install Windows only (advanced)" to perform a clean installation.
- Select the drive where you want to install Windows Server and click "Next."

Complete Installation: The installation process will begin. Your server will restart multiple times.

Set Administrator Password: After the reboots, you will be prompted to set an administrator password. Choose a strong password and remember it.

Log In: Log in to the server using the administrator account and the password you just set.

## 3. Configure a Static IP Address

A Domain Controller must have a static IP address.

Open Network Connections:

- Right-click on the Start button and select "Network Connections."
- Click on "Change adapter options."

Access Network Adapter Properties:

- Right-click on your active network adapter (e.g., "Ethernet") and select "Properties."

Configure IPv4 Properties:

- Select "Internet Protocol Version 4 (TCP/IPv4)" and click "Properties."

Set Static IP:

- Select "Use the following IP address."
- Enter the following details (replace with your network's specific values):
  - IP address: 192.168.1.10 (or an unused IP in your network)
  - Subnet mask: 255.255.255.0 (common for small networks)
  - Default gateway: 192.168.1.1 (your router's IP address)

For DNS servers, initially, you can point the Preferred DNS server to the server's own IP address (192.168.1.10). This will be crucial once AD DS is installed and configured as a DNS server. If you have an existing DNS server, you can use that as the primary and your own IP as the secondary.

- Click "OK" twice to save the settings.

## 4. Install the Active Directory Domain Services (AD DS) Role

Open Server Manager: Server Manager usually opens automatically on login. If not, open it from the Start menu.

Add Roles and Features Wizard:

- In Server Manager, click on "Manage" in the top right corner, then select "Add Roles and Features."
- Click "Next" on the "Before You Begin" page.
- Select "Role-based or Feature-based installation" and click "Next."
- Ensure your server is selected under "Server Selection" and click "Next."

Select AD DS Role:

- From the list of roles, check the box for "Active Directory Domain Services."
- When prompted to add required features, click "Add Features."
- Click "Next."

Confirm Installation:

- On the "Features" page, click "Next."
- On the "AD DS" page, click "Next."
- On the "Confirmation" page, review your selections and click "Install."

Wait for Installation: The installation process will take some time. Do not close the wizard until it completes.

## 5. Promote the Server to a Domain Controller

After installing the AD DS role, you need to promote the server to a domain controller.

Start Promotion Wizard:

Once the AD DS role installation is complete, you will see a link in the Server Manager notification flag (top right) or on the "Installation Progress" page: "Promote this server to a domain controller." Click it.

Deployment Configuration:

On the "Deployment Configuration" page, you have three options:

- Add a domain controller to an existing domain: If you're adding a DC to an already existing AD domain.
- Add a new domain to an existing forest: If you're creating a new child domain within an existing Active Directory forest.
- Add a new forest: This is what you'll typically choose for your first Active Directory setup.

Select "Add a new forest."

Enter a "Root domain name" for your forest (e.g., yourdomain.local). Choose a name that is unique and descriptive. It's recommended to use a non-routable TLD like .local, .lan, or example.com (if you don't own example.com on the internet).

Click "Next."

Domain Controller Options:

- Functional Levels: Keep the default Windows Server functional levels unless you have specific compatibility requirements with older servers.
- Domain Name System (DNS) server: This checkbox should be selected by default. Your DC will also act as a DNS server.
- Global Catalog (GC): This checkbox should be selected by default. A Global Catalog server holds a partial replica of all objects in the forest.
- Read-only domain controller (RODC): Do NOT check this for your first DC. RODCs are for specific security scenarios.
- Directory Services Restore Mode (DSRM) password: Enter a strong password for DSRM. This password is crucial for recovering Active Directory in case of a disaster. Remember this password!

Click "Next."

DNS Options:

You might see a warning about DNS delegation. You can safely ignore this for a new forest. Click "Next."

Additional Options:

NetBIOS domain name: This will be automatically populated from your domain name (e.g., YOURDOMAIN). Click "Next."

Paths:

Confirm the default paths for the AD DS database, log files, and SYSVOL folder. Click "Next."

Review Options:

Review all your selections. You can click "View script" to see the PowerShell commands that will be executed. Click "Next."

Prerequisites Check:

The wizard will perform a prerequisite check. As long as there are no critical errors, you can proceed. You might see warnings (e.g., about static IP, DNS delegation) which are often fine for a new setup.

Click "Install."

Server Reboot: The server will configure Active Directory Domain Services and automatically restart. This process can take some time.

## 6. Post-Installation Tasks and Verification

After the server reboots, it is now an Active Directory Domain Controller!

Log In as Domain Administrator: Log in using the same administrator password you set earlier. You'll notice your username now appears as YOURDOMAIN\\Administrator.

Verify AD DS Installation:

- Open Server Manager.
- On the left pane, you should now see "AD DS" and "DNS" roles listed.
- Click on "Tools" in Server Manager and verify that you see Active Directory administration tools like:
  - Active Directory Users and Computers
  - Active Directory Administrative Center
  - DNS

Open Active Directory Users and Computers. You should see your new domain listed.

DNS Configuration Check:

- Open DNS Manager (from Tools in Server Manager).
- Expand "Forward Lookup Zones" and confirm your domain (e.g., yourdomain.local) is listed.
- Verify that DNS records (like the host A record for your DC) are present.

Create an Organizational Unit (OU):

- In Active Directory Users and Computers, right-click on your domain, select "New" > "Organizational Unit."
- Give it a name (e.g., Users or Computers). OUs help you organize your AD objects.

Create a User Account:

- Right-click on your newly created OU (or the default "Users" container), select "New" > "User."
- Fill in the required information (First name, Last name, User logon name).
- Set a password and configure password options (e.g., "User must change password at next logon").
- Click "Next" and then "Finish."

## Conclusion

Congratulations! You have successfully built a basic Active Directory environment. You can now join client computers to this domain and manage users and resources.

## Next Steps

- Join Client Computers: Configure workstations to join your new domain
- Create Group Policies: Implement security policies across your domain
- Set Up Additional OUs: Organize your domain structure for better management
- Configure DNS Zones: Set up additional DNS zones if needed
- Implement Security Groups: Create and manage security groups for access control

## Security Best Practices

- Regular Backups: Implement regular backups of your Active Directory database
- Monitor Logs: Regularly review security logs for suspicious activities
- Update Management: Keep your domain controllers updated with latest security patches
- Access Control: Implement least privilege principles for administrative accounts
- Network Security: Secure network communications between domain controllers and clients

Your Active Directory lab environment is now ready for testing and learning cybersecurity concepts!
    `,
    category: "Domain Security",
    readTime: "45 min read",
    publishDate: "March 18, 2025",
    featured: true,
    author: "Quintin McFadden",
    tags: ["Active Directory", "Windows Server", "Virtual Machines", "Lab Setup", "Domain Controller"],
    difficulty: "Intermediate",
    prerequisites: ["Basic Windows administration", "Virtual machine experience", "Networking fundamentals"],
    tools: ["VMware Workstation/VirtualBox", "Windows Server 2019/2022", "Windows 10/11"],
    steps: 6
  },
  {
    slug: "vulnerability-scanning-guide",
    title: "Complete Vulnerability Scanning Guide: From Setup to Remediation",
    excerpt: "Master vulnerability scanning with hands-on tutorials covering Nessus, OpenVAS, and Nmap for comprehensive security assessments.",
    content: `
# Complete Vulnerability Scanning Guide: From Setup to Remediation

[Content removed for brevity]
    `,
    category: "Vulnerability Assessment",
    readTime: "35 min read",
    publishDate: "March 15, 2025",
    featured: true,
    author: "Quintin McFadden",
    tags: ["Vulnerability Scanning", "Nessus", "OpenVAS", "Nmap", "Security Assessment"],
    difficulty: "Intermediate",
    prerequisites: ["Basic networking", "Linux command line", "Virtual machines"],
    tools: ["Nessus", "OpenVAS", "Nmap", "Kali Linux"],
    steps: 8
  },
  {
    slug: "securing-personnel-data-guide",
    title: "Securing Personnel Data: Complete Privacy Protection Implementation",
    excerpt: "Comprehensive guide to implementing data protection measures for personnel information, including encryption, access controls, and compliance frameworks.",
    content: `
# Securing Personnel Data: Complete Privacy Protection Implementation

[Content removed for brevity]
    `,
    category: "Data Protection",
    readTime: "40 min read",
    publishDate: "March 12, 2025",
    featured: false,
    author: "Quintin McFadden",
    tags: ["Data Protection", "Privacy", "GDPR", "CCPA", "Personnel Data", "Encryption"],
    difficulty: "Advanced",
    prerequisites: ["Database administration", "Access control systems", "Privacy regulations"],
    tools: ["Database systems", "Encryption tools", "DLP solutions", "Monitoring systems"],
    steps: 8
  },
  {
    slug: "security-awareness-training-program",
    title: "Building a Comprehensive Security Awareness Training Program",
    excerpt: "Complete guide to designing, implementing, and measuring the effectiveness of security awareness training programs for organizations of all sizes.",
    content: `
# Building a Comprehensive Security Awareness Training Program

[Content removed for brevity]
    `,
    category: "Security Training",
    readTime: "30 min read",
    publishDate: "March 10, 2025",
    featured: false,
    author: "Quintin McFadden",
    tags: ["Security Awareness", "Training Programs", "Phishing Simulation", "Employee Education", "Security Culture"],
    difficulty: "Intermediate",
    prerequisites: ["Basic security knowledge", "Training program experience", "Access to LMS platforms"],
    tools: ["LMS platforms", "Phishing simulation tools", "Content creation software", "Analytics tools"],
    steps: 6
  }
];

// Export functions for easy access
export function getTutorialBySlug(slug: string): SecurityTutorial | undefined {
  return securityTutorials.find(tutorial => tutorial.slug === slug);
}

export function getTutorialsByDifficulty(difficulty: string): SecurityTutorial[] {
  return securityTutorials.filter(tutorial => tutorial.difficulty === difficulty);
}

export function getFeaturedTutorials(): SecurityTutorial[] {
  return securityTutorials.filter(tutorial => tutorial.featured);
}

export function getAllTutorials(): SecurityTutorial[] {
  return securityTutorials;
}