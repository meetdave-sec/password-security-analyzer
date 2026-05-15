from analyzer import analyze_password
from rich import print
from rich.panel import Panel
from rich.text import Text

def generate_recommendations(result: dict) -> list:
    recommendations = []
    
    if result["score"] < 50:
        recommendations.append(
            "Use at least 12 characters — longer is substantially harder to crack"
        )
        recommendations.append(
            "Mix uppercase, lowercase, digits, and symbols without a predictable pattern"
        )

    for issue in result["issues"]:
        il = issue.lower()

        if "exact match to top common password" in il or "contains well-known password" in il:
            recommendations.append(
                "Avoid known common passwords or passwords based on them"
            )

        if "dictionary word" in il:
            recommendations.append(
                "Avoid real words, names, places, and brand names as password components"
            )

        if "year embedded" in il:
            recommendations.append(
                "Remove embedded years — they are among the first mutations cracking tools try"
            )

        if "predictable template" in il:
            recommendations.append(
                "Avoid formulaic structures (Word@Year, Word+Digits) — use random character sequences"
            )

        if "keyboard walk" in il:
            recommendations.append(
                "Avoid keyboard patterns such as 'qwerty' or 'asdfgh'"
            )

        if "sequential" in il:
            recommendations.append(
                "Avoid sequential runs like '123', 'abc', or their reverses"
            )

        if "repeated characters" in il:
            recommendations.append(
                "Avoid repeated characters (e.g. 'aaa', '111')"
            )

        if "low diversity" in il:
            recommendations.append(
                "Spread characters across multiple classes — don't rely on one type alone"
            )

    seen: set = set()
    deduped = []
    for rec in recommendations:
        if rec not in seen:
            deduped.append(rec)
            seen.add(rec)
    return deduped


def get_strength_color(strength: str) -> str:
    """Map a strength label to a Rich colour / style string."""
    return {
        "Very Weak":   "bold red",
        "Weak":        "red",
        "Moderate":    "yellow",
        "Strong":      "green",
        "Very Strong": "bold green",
    }.get(strength, "white")



def main() -> None:
    print(Panel.fit("[bold cyan]Password Security Analyzer[/bold cyan]"))

    password = input("Enter password: ")

    result          = analyze_password(password)
    recommendations = generate_recommendations(result)
    strength_color  = get_strength_color(result["strength"])

    print("\n")
  
    summary = Text()
    summary.append(f"Score: {result['score']}/100\n", style="bold white")
    summary.append(f"Strength: {result['strength']}\n",  style=strength_color)
    summary.append(f"Entropy: {result['entropy']} bits",  style="cyan")
    print(Panel(summary, title="Security Summary"))
    
    if result["issues"]:
        issues_text = "\n".join(f"- {issue}" for issue in result["issues"])
        print(Panel(issues_text, title="[red]Risk Factors[/red]"))
    else:
        print(Panel("[green]No significant weaknesses detected[/green]", title="Risk Factors"))
   
    if recommendations:
        rec_text = "\n".join(f"- {rec}" for rec in recommendations)
        print(Panel(rec_text, title="[yellow]Recommendations[/yellow]"))
    else:
        print(Panel(
            "[green]Strong password — no improvements needed[/green]",
            title="Recommendations",
        ))


if __name__ == "__main__":
    main()
