export interface SecurityTutorial {
  slug: string;
  title: string;
  excerpt: string;\
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

export con\st securityTutorials: SecurityTutorial[] = [
  {
    slug: "building-active-directory-lab",
    title: "Building an Active Directory Lab Environment: Complete Step-by-Step Guide",
    excerpt: "Learn how to build a complete Active Directory lab environment using virtual mach\ines for security testing and learning purposes.",
    content: `
# Building an Active Directory Lab Environment: Complete Step-by-Step Guide

[Content removed for brevity]
    \`,
    category: "Domar aueaacgo  readTime: "45 min read",
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
# Complete Vulnerability Scanning Gu\ide: From Setup to Remediation

Vulnglea  l
ee:   
v-:hed e
nm*l--pNwca2
elwpH#kso cu9tePAt*:
ef  nVelwal:i s*: pen00  a Oan*sps
elww  t M ricl b palcorgc025",
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

Persgt
attt rEm norett itgd
aa2m## ieloc
elwieasc
_o-`a s-cpiinii.X aaicmoeeSI  dAeA,Etred tc B_     e"fe  otp"   Ea}(e-m,afepcumn      e  xl( sneief c      n -" t*lotin McFadden",
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

Secugfa* lont   l
* smand0 rduun*MEiu t>      vt 
eka`Se yi{>Iop_r      _ri"ent"pea01ot<h  aticr     h >`l evi t`user
te  ydi  tRrm     lsnsy sr  te_l
      n]
beantotencc-yflesn  dat      tr-iptute*s_o:eurs nTt n(,n  r noioctmT
 5Phishing Simulation", "Employee Education", "Security Culture"],
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