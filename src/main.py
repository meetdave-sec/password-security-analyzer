from analyzer import analyze_password


def generate_recommendations(result):
    recommendations = []

    if result["score"] < 50:
        recommendations.append("Increase password length (at least 8 characters)")
        recommendations.append("Use a mix of uppercase, lowercase, numbers, and symbols")

    for issue in result["issues"]:
        if "common pattern" in issue:
            recommendations.append("Avoid common words and patterns (e.g., 'password', '1234')")

        if "sequential" in issue:
            recommendations.append("Avoid sequential characters (e.g., 'abcd', '1234')")

        if "keyboard" in issue:
            recommendations.append("Avoid keyboard patterns (e.g., 'qwerty')")

        if "predictable pattern" in issue:
            recommendations.append("Avoid predictable structures (e.g., word + numbers)")

        if "repeated" in issue:
            recommendations.append("Avoid repeated characters")

    return list(set(recommendations))


def main():
    print("\n=== Password Security Analyzer ===\n")

    password = input("Enter password: ")

    result = analyze_password(password)

    recommendations = generate_recommendations(result)

    print("\n=== PASSWORD SECURITY REPORT ===\n")

    print(f"Score: {result['score']}/100 ({result['strength']})")
    print(f"Entropy: {result['entropy']} bits\n")

    print("Risk Factors:")
    if result["issues"]:
        for issue in result["issues"]:
            print(f"- {issue}")
    else:
        print("- No major issues detected")

    print("\nRecommendations:")
    if recommendations:
        for rec in recommendations:
            print(f"- {rec}")
    else:
        print("- Strong password. No immediate improvements needed.")


if __name__ == "__main__":
    main()
