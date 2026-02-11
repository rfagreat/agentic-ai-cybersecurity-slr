"""
==============================================================================
OWASP Agentic AI Top 10 - Figure Generation from SLR Literature Synthesis
==============================================================================

This script generates two figures from the systematic literature review:
  Fig. 4: Severity vs. Likelihood Assessment (Grouped Bar Chart)
  Fig. 5: Risk Matrix - Attack Complexity vs. Potential Impact (Bubble Chart)

METHODOLOGY:
-----------
The scores are derived by synthesizing all 75 studies from Appendix A2.
Each study was mapped to the OWASP Agentic AI Top 10 threat categories
(ASI01–ASI10) based on the study's topic, findings, and category (ATK/DEF/
SUR/THR/FRM). The mapping considers:

1. SEVERITY SCORE (1-10): How damaging is this threat when exploited?
   - Based on: demonstrated impact in attack papers, vulnerability scope
     reported in surveys, damage potential assessed in threat analyses.

2. LIKELIHOOD SCORE (1-10): How likely is this threat to be exploited?
   - Based on: number of papers demonstrating feasibility, availability of
     attack tools/techniques, breadth of affected systems, ease of exploitation.

3. ATTACK COMPLEXITY (1-10): How complex is it to execute the attack?
   - Based on: technical sophistication required, tooling availability,
     number of steps, prerequisite access needed.

4. POTENTIAL IMPACT (1-10): What is the maximum potential damage?
   - Based on: scope of compromise, cascading effects, data exposure,
     system control level, real-world incident reports.

Literature-to-Threat Mapping Logic:
------------------------------------
Each study in Appendix A2 covers specific threat vectors. The mapping below
shows which studies provide evidence for each OWASP ASI category:

ASI01 (Agent Goal Hijack): Prompt injection & jailbreaking are the primary
  attack vector for hijacking agent goals. Studies: S001, S002, S003, S004,
  S005, S006, S007, S008, S010, S011, S016, S019, S020, S021, S022, S025,
  S029, S030, S031, S033, S038, S039, S041, S051, S053, S061, S063
  → 27 studies: highest research coverage, demonstrated across all LLM types
  → Severity 9.5: Complete goal subversion demonstrated (Greshake 2023, Zou 2023)
  → Likelihood 9.0: Trivially exploitable; universal attacks proven (Zou 2023)

ASI02 (Tool Misuse & Exploitation): Studies on tool-augmented LLM agents
  being manipulated to abuse integrations. Studies: S009, S025, S026, S033,
  S034, S037, S042, S056, S060, S068
  → 10 studies: growing area with demonstrated SQL injection chains (Pedro 2024)
  → Severity 8.8: Can lead to full system compromise via tool chains
  → Likelihood 8.5: Requires tool access but attacks are well-documented

ASI03 (Identity & Privilege Abuse): Over-provisioned credentials, NHI sprawl.
  Studies: S015, S026, S034, S044, S048, S055, S058, S070
  → 8 studies: frameworks highlight this as systemic enterprise risk
  → Severity 9.2: Enterprise-wide damage from credential abuse
  → Likelihood 8.8: NHI sprawl is endemic; most agents over-provisioned

ASI04 (Unexpected Code Execution): Agents manipulated to run arbitrary code.
  Studies: S004, S029, S033, S040, S043, S056, S068
  → 7 studies: neural exec and programmatic exploitation demonstrated
  → Severity 8.5: Arbitrary code = full system control potential
  → Likelihood 7.5: Requires code execution capability in agent

ASI05 (Insecure Inter-Agent Communication): MAS communication poisoning.
  Studies: S012, S019, S034, S035, S052, S053, S058, S062
  → 8 studies: worm propagation and inter-agent poisoning demonstrated
  → Severity 7.8: Can cascade through agent networks
  → Likelihood 7.0: Requires multi-agent architecture; growing attack surface

ASI06 (Human-Agent Trust Exploitation): Exploiting human trust in outputs.
  Studies: S006, S014, S017, S018, S035, S045, S050, S071
  → 8 studies: social engineering and trust manipulation well-documented
  → Severity 7.5: Decision manipulation with real-world consequences
  → Likelihood 8.0: High - humans routinely over-trust AI outputs

ASI07 (Supply Chain Vulnerabilities): Compromised plugins, MCP servers.
  Studies: S023, S024, S034, S037, S048, S059, S067, S072, S075
  → 9 studies: RAG poisoning, plugin compromise, MCP attack vectors
  → Severity 8.0: Systemic risk across dependent systems
  → Likelihood 7.5: Supply chain attacks increasing; MCP ecosystem immature

ASI08 (Memory & Context Poisoning): Persistent memory corruption.
  Studies: S019, S023, S024, S038, S051, S053, S061, S063, S066
  → 9 studies: demonstrated via prompt worms and RAG poisoning
  → Severity 8.3: Long-term persistent compromise of agent behavior
  → Likelihood 7.8: RAG systems ubiquitous; memory poisoning proven feasible

ASI09 (Cascading Failures): Failure propagation through interconnected systems.
  Studies: S019, S026, S034, S052, S055, S058, S062, S067, S070
  → 9 studies: systemic risk in multi-agent and enterprise deployments
  → Severity 8.7: Can bring down entire agent ecosystems
  → Likelihood 7.2: Requires interconnected systems; probability increases with scale

ASI10 (Rogue Agents): Agents deviating from intended behavior.
  Studies: S017, S026, S040, S047, S050, S054, S064, S069, S074
  → 9 studies: alignment failures and autonomous deviation documented
  → Severity 9.0: Insider-threat equivalent; agent acts against owner
  → Likelihood 6.5: Emerging concern; harder to trigger but catastrophic
"""

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

# =============================================================================
# DATA: Synthesized from 75 studies in Appendix A2
# =============================================================================

# OWASP Agentic AI Top 10 threat categories
threat_ids = ['ASI01', 'ASI02', 'ASI03', 'ASI04', 'ASI05',
              'ASI06', 'ASI07', 'ASI08', 'ASI09', 'ASI10']

threat_names = [
    'Goal\nHijack',
    'Tool\nMisuse',
    'Identity\nAbuse',
    'Code\nExecution',
    'Insecure\nComm',
    'Human\nTrust',
    'Supply\nChain',
    'Memory\nPoison',
    'Cascading\nFailure',
    'Rogue\nAgents'
]

threat_full_names = [
    'Agent Goal Hijack',
    'Tool Misuse & Exploitation',
    'Identity & Privilege Abuse',
    'Unexpected Code Execution',
    'Insecure Inter-Agent Comm.',
    'Human-Agent Trust Exploit.',
    'Supply Chain Vulnerabilities',
    'Memory & Context Poisoning',
    'Cascading Failures',
    'Rogue Agents'
]

# --- Literature-derived study mappings ---
# Each list contains the study IDs (S001-S075) that provide evidence
study_mappings = {
    'ASI01': ['S001','S002','S003','S004','S005','S006','S007','S008','S010',
              'S011','S016','S019','S020','S021','S022','S025','S029','S030',
              'S031','S033','S038','S039','S041','S051','S053','S061','S063'],
    'ASI02': ['S009','S025','S026','S033','S034','S037','S042','S056','S060','S068'],
    'ASI03': ['S015','S026','S034','S044','S048','S055','S058','S070'],
    'ASI04': ['S004','S029','S033','S040','S043','S056','S068'],
    'ASI05': ['S012','S019','S034','S035','S052','S053','S058','S062'],
    'ASI06': ['S006','S014','S017','S018','S035','S045','S050','S071'],
    'ASI07': ['S023','S024','S034','S037','S048','S059','S067','S072','S075'],
    'ASI08': ['S019','S023','S024','S038','S051','S053','S061','S063','S066'],
    'ASI09': ['S019','S026','S034','S052','S055','S058','S062','S067','S070'],
    'ASI10': ['S017','S026','S040','S047','S050','S054','S064','S069','S074'],
}

# Number of supporting studies per category
n_studies = [len(study_mappings[tid]) for tid in threat_ids]

# --- Fig. 4 Data: Severity and Likelihood Scores ---
# Derived from literature synthesis (see methodology above)
severity_scores =  [9.5, 8.8, 9.2, 8.5, 7.8, 7.5, 8.0, 8.3, 8.7, 9.0]
likelihood_scores = [9.0, 8.5, 8.8, 7.5, 7.0, 8.0, 7.5, 7.8, 7.2, 6.5]

# --- Fig. 5 Data: Attack Complexity and Potential Impact ---
# Attack Complexity (1=trivial, 10=extremely complex)
# Higher complexity means harder to execute
attack_complexity = [3.0, 5.0, 4.0, 6.5, 6.0, 3.5, 5.5, 5.0, 7.0, 7.5]

# Potential Impact (1=minimal, 10=catastrophic)
potential_impact = [9.5, 8.5, 9.0, 8.5, 7.5, 7.0, 8.0, 8.0, 9.0, 9.5]

# Risk Score = Severity × Likelihood / 10 (normalized)
risk_scores = [s * l / 10 for s, l in zip(severity_scores, likelihood_scores)]

print("=" * 70)
print("SYNTHESIS SUMMARY: Literature Mapping to OWASP ASI Top 10")
print("=" * 70)
for i, tid in enumerate(threat_ids):
    print(f"\n{tid} - {threat_full_names[i]}")
    print(f"  Supporting studies: {len(study_mappings[tid])} papers")
    print(f"  Studies: {', '.join(study_mappings[tid])}")
    print(f"  Severity: {severity_scores[i]:.1f} | Likelihood: {likelihood_scores[i]:.1f}")
    print(f"  Attack Complexity: {attack_complexity[i]:.1f} | Potential Impact: {potential_impact[i]:.1f}")
    print(f"  Risk Score: {risk_scores[i]:.2f}")

# =============================================================================
# FIGURE 4: Severity vs. Likelihood Grouped Bar Chart
# =============================================================================
def generate_fig4():
    fig, ax = plt.subplots(figsize=(14, 6))

    x = np.arange(len(threat_ids))
    width = 0.35

    # Colors matching the original figure
    severity_color = '#C0504D'   # Muted red
    likelihood_color = '#4F81BD'  # Steel blue

    bars1 = ax.bar(x - width/2, severity_scores, width,
                   label='Severity Score', color=severity_color,
                   edgecolor='white', linewidth=0.5, alpha=0.9)
    bars2 = ax.bar(x + width/2, likelihood_scores, width,
                   label='Likelihood Score', color=likelihood_color,
                   edgecolor='white', linewidth=0.5, alpha=0.9)

    # Labels and formatting
    ax.set_xlabel('')
    ax.set_ylabel('Score (1-10)', fontsize=12, fontweight='bold')
    ax.set_title('Fig. 6: OWASP Agentic AI Top 10 - Severity vs. Likelihood Assessment',
                 fontsize=14, fontweight='bold', pad=15)
    ax.set_xticks(x)

    # Two-line x-tick labels
    labels = [f'{tid}\n{name}' for tid, name in zip(threat_ids, threat_names)]
    ax.set_xticklabels(labels, fontsize=9, ha='center')

    ax.set_ylim(0, 11)
    ax.set_yticks(range(0, 12, 2))
    ax.legend(loc='upper right', fontsize=11, framealpha=0.9)
    ax.grid(axis='y', alpha=0.3, linestyle='--')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)

    plt.tight_layout()
    plt.savefig('/home/claude/fig4_severity_likelihood.png', dpi=300, bbox_inches='tight',
                facecolor='white', edgecolor='none')
    plt.close()
    print("\n✓ Fig. 4 saved: fig4_severity_likelihood.png")

# =============================================================================
# FIGURE 5: Risk Matrix Bubble Chart
# =============================================================================
def generate_fig5():
    fig, ax = plt.subplots(figsize=(14, 10))

    # Background risk zones
    # Critical zone (top-right): high impact, low complexity
    ax.axhspan(8, 10.5, xmin=0, xmax=1, alpha=0.08, color='red')
    ax.axvspan(0, 4.5, ymin=0, ymax=1, alpha=0.06, color='red')

    # Draw risk zone backgrounds
    # Moderate (green) - bottom-left
    rect_moderate = mpatches.FancyBboxPatch(
        (0.5, 3.5), 4.0, 3.5, boxstyle="round,pad=0.1",
        facecolor='#E8F5E9', alpha=0.5, edgecolor='none')
    ax.add_patch(rect_moderate)

    # High (orange/yellow) - middle
    rect_high = mpatches.FancyBboxPatch(
        (0.5, 7.0), 9.5, 1.5, boxstyle="round,pad=0.1",
        facecolor='#FFF3E0', alpha=0.4, edgecolor='none')
    ax.add_patch(rect_high)

    # Critical (red) - top-right high impact area
    rect_critical = mpatches.FancyBboxPatch(
        (0.5, 8.5), 9.5, 2.0, boxstyle="round,pad=0.1",
        facecolor='#FFEBEE', alpha=0.5, edgecolor='none')
    ax.add_patch(rect_critical)

    # Bubble colors based on risk level
    colors = []
    for i in range(len(threat_ids)):
        rs = risk_scores[i]
        if rs >= 8.0:
            colors.append('#E74C3C')   # Critical - Red
        elif rs >= 7.0:
            colors.append('#F39C12')   # High - Orange
        elif rs >= 6.0:
            colors.append('#3498DB')   # Medium - Blue
        else:
            colors.append('#27AE60')   # Low - Green

    # Bubble size proportional to number of supporting studies
    bubble_sizes = [n * 80 for n in n_studies]  # Scale for visibility

    # Plot bubbles
    scatter = ax.scatter(
        attack_complexity, potential_impact,
        s=bubble_sizes, c=colors, alpha=0.7,
        edgecolors='white', linewidth=2, zorder=5
    )

    # Add labels to each bubble
    for i, tid in enumerate(threat_ids):
        ax.annotate(
            f'{tid}:\n{threat_full_names[i]}',
            (attack_complexity[i], potential_impact[i]),
            textcoords="offset points",
            xytext=(0, -max(np.sqrt(bubble_sizes[i]/np.pi)*1.2, 20) - 10),
            ha='center', va='top',
            fontsize=7.5, fontweight='bold',
            bbox=dict(boxstyle='round,pad=0.3', facecolor='white',
                      edgecolor='gray', alpha=0.9),
            zorder=6
        )

    # Zone labels
    ax.text(1.5, 10.2, 'CRITICAL', fontsize=14, fontweight='bold',
            color='#E74C3C', alpha=0.4, ha='center')
    ax.text(9.0, 4.0, 'MODERATE', fontsize=12, fontweight='bold',
            color='#27AE60', alpha=0.4, ha='center')

    # Axis labels and title
    ax.set_xlabel('Attack Complexity (1=Trivial → 10=Extremely Complex)',
                  fontsize=12, fontweight='bold')
    ax.set_ylabel('Potential Impact (1=Minimal → 10=Catastrophic)',
                  fontsize=12, fontweight='bold')
    ax.set_title('Fig. 5: OWASP Agentic AI Top 10: Risk Matrix\n'
                 '(Bubble size indicates number of supporting studies in reviewed literature)',
                 fontsize=13, fontweight='bold', pad=15)

    ax.set_xlim(1.5, 9.5)
    ax.set_ylim(5.5, 10.5)
    ax.grid(True, alpha=0.2, linestyle='--')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)

    # Legend for bubble sizes
    legend_sizes = [7, 12, 27]
    legend_labels = ['Low (7)', 'Medium (12)', 'High (27)']
    legend_bubbles = []
    for s in legend_sizes:
        legend_bubbles.append(ax.scatter([], [], s=s*80, c='gray',
                                          alpha=0.5, edgecolors='white', linewidth=1.5))

    leg1 = ax.legend(legend_bubbles, legend_labels,
                     title='Research Attention\n(No. of papers)',
                     loc='lower right', framealpha=0.9, fontsize=9,
                     title_fontsize=9)
    ax.add_artist(leg1)

    # Legend for risk colors
    risk_patches = [
        mpatches.Patch(color='#E74C3C', alpha=0.7, label='Critical Risk'),
        mpatches.Patch(color='#F39C12', alpha=0.7, label='High Risk'),
        mpatches.Patch(color='#3498DB', alpha=0.7, label='Medium Risk'),
    ]
    ax.legend(handles=risk_patches, title='Risk Zones', loc='upper left',
              framealpha=0.9, fontsize=9, title_fontsize=9)
    ax.add_artist(leg1)

    plt.tight_layout()
    plt.savefig('/home/claude/fig5_risk_matrix.png', dpi=300, bbox_inches='tight',
                facecolor='white', edgecolor='none')
    plt.close()
    print("✓ Fig. 5 saved: fig5_risk_matrix.png")


# =============================================================================
# PRINT COMPLETE SCORING RATIONALE TABLE
# =============================================================================
def print_scoring_rationale():
    print("\n" + "=" * 70)
    print("DETAILED SCORING RATIONALE FROM LITERATURE SYNTHESIS")
    print("=" * 70)

    rationales = {
        'ASI01': {
            'severity': 'Universal jailbreaking (Zou 2023), indirect prompt injection in production systems (Greshake 2023), persistent goal manipulation in ReAct agents (Yan 2024). EchoLeak CVE demonstrated real-world data exfiltration.',
            'likelihood': 'Highest paper count (27 studies). Attacks are trivially reproducible, require no special access. Universal and transferable adversarial suffixes proven.',
            'complexity': 'Low (3.0) - Simple text injection; no tools or special access needed. DAN-style prompts freely available.',
            'impact': 'Critical (9.5) - Complete agent objective subversion; demonstrated silent data exfiltration.'
        },
        'ASI02': {
            'severity': 'Tool-augmented agents manipulated to execute SQL injection (Pedro 2024), file system access abuse (Zhan 2024). InjecAgent benchmark showed 24% success rate.',
            'likelihood': 'Growing attack surface as tool integration becomes standard. 10 studies demonstrate feasibility across different tool types.',
            'complexity': 'Moderate (5.0) - Requires understanding of agent tool APIs and crafting tool-specific payloads.',
            'impact': 'High (8.5) - Can chain tools for full system compromise; SQL injection to code execution demonstrated.'
        },
        'ASI03': {
            'severity': 'Enterprise NHI sprawl creates massive attack surface (OWASP 2025, NIST 2025). Over-provisioned agents operate beyond intended scope. WEF 2025 highlighted as systemic risk.',
            'likelihood': 'Most enterprise agents over-provisioned by default. 8 studies and industry frameworks flag this as endemic.',
            'complexity': 'Low-Moderate (4.0) - Exploiting existing over-provisioning requires minimal sophistication.',
            'impact': 'Critical (9.0) - Enterprise-wide lateral movement; complete privilege escalation possible.'
        },
        'ASI04': {
            'severity': 'Neural exec demonstrated arbitrary code execution via LLMs (Pasquini 2024). Programmatic exploitation of LLM behavior (Kang 2024).',
            'likelihood': 'Limited to agents with code execution capabilities. 7 studies show feasibility but require specific architecture.',
            'complexity': 'Moderate-High (6.5) - Requires bypassing sandboxes and triggering code execution context.',
            'impact': 'High (8.5) - Arbitrary code execution = full system control within agent environment.'
        },
        'ASI05': {
            'severity': 'Prompt worms propagate through inter-agent communication (Nassi 2024, Kim 2025). Multi-agent negotiation exploitable (Abdelnabi 2024).',
            'likelihood': 'Requires multi-agent architecture. Growing concern as MAS adoption increases. 8 studies.',
            'complexity': 'Moderate-High (6.0) - Must intercept/poison agent-to-agent communication channels.',
            'impact': 'High (7.5) - Can cascade through agent networks; demonstrated worm propagation.'
        },
        'ASI06': {
            'severity': 'Humans routinely accept AI outputs without verification (Weidinger 2023). Social engineering amplified by AI trust (Gupta 2023, Mozes 2024).',
            'likelihood': 'Very high - human over-trust in AI is well-documented across 8 studies. Requires no technical sophistication.',
            'complexity': 'Very Low (3.5) - Exploits human psychology rather than technical vulnerabilities.',
            'impact': 'Moderate-High (7.0) - Decision manipulation; harder to detect than technical exploits.'
        },
        'ASI07': {
            'severity': 'RAG poisoning demonstrated (Cheng 2024, Xue 2024). MCP server compromise emerging (Robinson 2026). Plugin ecosystems lack verification.',
            'likelihood': 'Growing with MCP/plugin ecosystem maturity. 9 studies document supply chain risks.',
            'complexity': 'Moderate (5.5) - Requires compromising upstream components; various attack vectors.',
            'impact': 'High (8.0) - Systemic risk; single compromised plugin can affect many agents.'
        },
        'ASI08': {
            'severity': 'Persistent memory corruption demonstrated via prompt worms (Nassi 2024). BadRAG showed RAG-specific poisoning (Xue 2024). Fragmented payload assembly over time.',
            'likelihood': 'RAG systems ubiquitous; 9 studies show multiple poisoning vectors. Memory persistence amplifies risk.',
            'complexity': 'Moderate (5.0) - Multiple proven techniques; RAG poisoning well-documented.',
            'impact': 'High (8.0) - Long-term compromise; poisoned context persists across sessions.'
        },
        'ASI09': {
            'severity': 'Worm propagation in interconnected systems (Anderson 2025). Enterprise agent ecosystems create single points of failure. NIST/OWASP frameworks highlight systemic risk.',
            'likelihood': 'Probability increases with system interconnection. 9 studies; concern amplified by enterprise adoption.',
            'complexity': 'High (7.0) - Requires triggering cascading chain reaction; dependent on system architecture.',
            'impact': 'Critical (9.0) - Can bring down entire agent ecosystems; infrastructure-level damage.'
        },
        'ASI10': {
            'severity': 'Alignment failures produce insider-threat equivalent (Ganguli 2023). Red teaming reveals emergent deceptive behaviors (Mazeika 2024). Standards emerging (IEEE P3119).',
            'likelihood': 'Harder to trigger deliberately but can emerge from training/alignment failures. 9 studies.',
            'complexity': 'High (7.5) - Requires either alignment failure or sophisticated manipulation of agent goals.',
            'impact': 'Critical (9.5) - Agent acting against owner with full access; worst-case scenario.'
        },
    }

    for tid in threat_ids:
        idx = threat_ids.index(tid)
        r = rationales[tid]
        print(f"\n{'─'*60}")
        print(f"{tid}: {threat_full_names[idx]}")
        print(f"  Studies: {len(study_mappings[tid])} | "
              f"Severity: {severity_scores[idx]} | "
              f"Likelihood: {likelihood_scores[idx]} | "
              f"Risk: {risk_scores[idx]:.2f}")
        print(f"\n  SEVERITY ({severity_scores[idx]}):")
        print(f"    {r['severity']}")
        print(f"  LIKELIHOOD ({likelihood_scores[idx]}):")
        print(f"    {r['likelihood']}")
        print(f"  ATTACK COMPLEXITY ({attack_complexity[idx]}):")
        print(f"    {r['complexity']}")
        print(f"  POTENTIAL IMPACT ({potential_impact[idx]}):")
        print(f"    {r['impact']}")


# =============================================================================
# MAIN EXECUTION
# =============================================================================
if __name__ == '__main__':
    print("Generating OWASP Agentic AI Top 10 figures from SLR synthesis...\n")

    generate_fig4()
    generate_fig5()
    print_scoring_rationale()

    print("\n" + "=" * 70)
    print("COMPLETE. Both figures generated successfully.")
    print("=" * 70)
