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
# Building an Active Directory Lab Environment: Complete Step-by-Step Guide

[Content removed for brevity]
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
    steps: 8
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