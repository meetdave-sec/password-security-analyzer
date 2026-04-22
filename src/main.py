from analyzer import analyze_password

def main():
    print("Password Security Analyzer")
    
    password = input("Enter password: ")

    result = analyze_password(password)

    print("\nResults:")
    print(f"Entropy: {result['entropy']} bits")

    if result["issues"]:
        print("Issues detected:")
        for issue in result["issues"]:
            print(f"- {issue}")

    else:
        print("No major issues detected.")        
        
if __name__ == "__main__":
    main()