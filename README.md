# 🔐 Entropy-Based Password Risk Engine

A behavior-based password security analysis tool that evaluates password strength using entropy modeling, structural pattern detection, and attacker-style heuristics inspired by real-world credential attacks.

It simulates how attackers think by identifying predictable human password behaviors rather than relying only on simple dictionary checks.

---

## 🎯 Security Focus

This project is designed from an attacker's perspective.

Instead of simply checking password rules, it models how real-world attackers evaluate password weakness using:
- entropy estimation
- predictable human behavior patterns
- structural password analysis

---

## 🚀 Features

- 📊 Entropy-based password strength estimation  
- 🧠 Detection of weak patterns (common passwords, keyboard sequences, repeated characters)  
- 🔁 Sequential pattern detection (e.g., abcd, 1234)  
- 🏗️ Structure analysis (word + numbers, predictable formats)  
- 🧾 Risk scoring system (0–100 scale)  
- 💡 Smart security recommendations  
- 🎨 Rich CLI output for better readability  

---

## 🧠 How It Works

### 1. Entropy Analysis
Estimates randomness based on character set complexity and password length.

### 2. Pattern Detection
Flags known weak patterns such as:
- Common passwords (admin, password)
- Keyboard patterns (qwerty, asdfgh)
- Sequential patterns (abcd, 1234)

### 3. Structure Analysis
Detects predictable formats like:
- Letters + numbers (Meet123)
- Word + symbol + numbers (Meet@123)

### 4. Scoring Engine
Final score is calculated using:
- Entropy contribution (primary factor)
- Length bonus (secondary factor)
- Pattern penalties (risk reduction)

---

## 🖥️ Usage

```bash
python -m src.main
```

---

## 📊 Example Output

### Weak Password
Score: 18/100  
Strength: Very Weak  

Risk Factors:
- common pattern: password
- sequential pattern detected: 1234

---

### Strong Password
Score: 92/100  
Strength: Very Strong  

No major issues detected.

---

## 📸 Screenshots

### 🔴 Weak Password Analysis
![Weak Password](assets/weak.png)

### 🟢 Strong Password Analysis
![Strong Password](assets/strong.png)

---

## 🧪 Project Structure

```
src/
├── analyzer.py
├── main.py
│
assets/
├── weak.png
├── strong.png
│
requirements.txt
README.md
.gitignore
```

---

## 🎯 Why This Project Matters

Most password checkers rely on static rule validation (length, digits, symbols).

This project goes further by simulating attacker reasoning:

- How predictable is the password structure?
- Does it resemble human-generated patterns?
- How much entropy does it realistically contain?

This makes it closer to real-world security evaluation systems used in defensive security engineering and penetration testing environments.

---

## 🛠️ Tech Stack

- Python 3
- Regex
- Mathematical entropy modeling
- Rich CLI formatting

---

## 👤 Author

Cybersecurity portfolio project focused on password analysis, attacker simulation, and defensive security modeling.

> Built as part of a cybersecurity learning path focused on defensive security engineering and attack simulation models.
