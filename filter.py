import re
from typing import Dict, List

def load_abusive(filepath="abusive_words.txt"):
    """Load abusive words from file"""
    try:
        with open(filepath, "r") as f:
            return [line.strip().lower() for line in f.readlines() if line.strip()]
    except FileNotFoundError:
        return ["stupid", "idiot", "fuck", "hate", "dumb", "shit", "damn", "asshole", "bitch", "moron"]

abusive_words = load_abusive()

# FIXED: More precise positive context patterns
positive_context_patterns = [
    r"fucking (awesome|brilliant|amazing|great|good|cool|nice|perfect|excellent)",
    r"damn (good|great|awesome|cool|nice|impressive)",
    r"shit (ton|load) of (good|great|awesome|fun)",
    r"badass (in a good way|move|skill|talent)",
    r"stupid (simple|easy|obvious|clear)",
    r"stupidly (brilliant|good|simple|easy|awesome)",
]

# ENHANCED: Comprehensive abusive patterns - ALL CASE INSENSITIVE
clearly_abusive_patterns = [
    r"\byou (are|'re) (stupid|idiot|dumb|fucking|an asshole|a bitch|shit)\b",
    r"\byou (stupid|dumb|fucking) (idiot|moron|bitch|asshole)\b",
    r"\bfuck you\b",
    r"\bf\W*\*+\W*k\s+you\b",
    r"\bgo\s*to\s*hell\b",
    r"\bgo\s+to\s+hell\b",  
    r"\b(burn|rot)\s*in\s*hell\b",
    r"\bgo\s*die\b",
    r"\bdrop\s*dead\b",
    r"\bkill yourself\b",
    r"\bkys\b",
    r"\bhate you\b", 
    r"\bpiece of (shit|crap)\b",
    r"\byou asshole\b",
    r"\byou (are an|'re an) asshole\b",
    r"\bstupid (bitch|asshole|idiot|moron)\b",
    r"\bfucking (idiot|moron|stupid|dumb)\b",
    r"\bshut up\b.*\b(you )?(stupid|dumb|fucking|bitch|asshole|idiot)\b",
    r"\byou suck\b",
    r"\bdie\b.*\b(bitch|asshole|idiot)\b",
    r"\b(get|go)\s*(lost|away)\b.*\b(idiot|moron|stupid)\b",
    r"\bgo\s*f\*\*k\s*yourself\b",
    r"\bg\s*o\s*t\s*o\s*h\s*e\s*l\s*l\b",  # Spaced variant
    r"\bare\s+you\s+(stupid|dumb|idiot|moron)\b",  # ADDED: Sarcastic questions
]

highly_abusive_words = ["asshole", "bitch", "moron", "idiot"]

def analyze_context(text: str) -> Dict[str, any]:
    """Analyze context to determine if flagged words might be non-abusive"""
    text_lower = text.lower().strip()
    
    positive_context_score = 0
    for pattern in positive_context_patterns:
        if re.search(pattern, text_lower, re.IGNORECASE):
            positive_context_score += 1
    
    clearly_abusive_score = 0
    for pattern in clearly_abusive_patterns:
        if re.search(pattern, text_lower, re.IGNORECASE):
            clearly_abusive_score += 2
    
    highly_abusive_score = 0
    for word in highly_abusive_words:
        direct_attack_patterns = [
            rf"\byou (are )?{word}\b",
            rf"\byou're (a |an )?{word}\b", 
            rf"\b{word}$",  
            rf"^{word}\b",  
        ]
        
        for attack_pattern in direct_attack_patterns:
            if re.search(attack_pattern, text_lower, re.IGNORECASE):
                highly_abusive_score += 3
    
    # IMPROVED: More nuanced politeness detection
    is_question = text.strip().endswith('?')
    
    # Check for sarcastic/rhetorical questions
    sarcastic_indicators = [
        r"\bwhat the (hell|fuck)\b",
        r"\bwhy the (hell|fuck)\b",
        r"\bare you (stupid|dumb|idiot|moron)\b",
        r"\bhow (stupid|dumb)\b",
    ]
    is_sarcastic = any(re.search(pattern, text_lower, re.IGNORECASE) for pattern in sarcastic_indicators)
    
    has_please = 'please' in text_lower
    has_thanks = any(word in text_lower for word in ['thanks', 'thank you', 'thx'])
    
    # Only count question as polite if NOT sarcastic and NOT already flagged as clearly abusive
    is_genuinely_polite_question = is_question and not is_sarcastic and not clearly_abusive_score
    
    politeness_score = sum([is_genuinely_polite_question, has_please, has_thanks])
    
    return {
        "positive_context": positive_context_score,
        "clearly_abusive": clearly_abusive_score,
        "highly_abusive": highly_abusive_score,
        "politeness_score": politeness_score,
        "likely_false_positive": positive_context_score > 0 and clearly_abusive_score == 0 and highly_abusive_score == 0
    }

def is_abusive_with_auto_review(text: str) -> Dict[str, any]:
    """Enhanced detection with proper case insensitivity and context awareness"""
    if not text or not text.strip():
        return {
            "is_abusive": 0,
            "confidence": 0,
            "flagged_words": [],
            "auto_action": "approve",
            "reason": "empty_text"
        }
    
    text_lower = text.lower().strip()
    
    # Method 1: Exact word matches with word boundaries (CASE INSENSITIVE)
    exact_matches = []
    for word in abusive_words:
        pattern = r'\b' + re.escape(word) + r'\b'
        if re.search(pattern, text_lower, re.IGNORECASE):
            exact_matches.append(word)
    
    # Method 2: Repeated characters (stuuuupid -> stupid)
    repeated_chars = []
    for word in abusive_words:
        pattern = r'\b'
        for char in word:
            pattern += char + '+'
        pattern += r'\b'
        
        if re.search(pattern, text_lower, re.IGNORECASE) and word not in exact_matches:
            repeated_chars.append(word)
    
    # Method 3: Character substitutions (st*pid, f**k, stup1d)
    substitution_matches = []
    for word in abusive_words:
        pattern = r'\b'
        for char in word:
            if char.isalpha():
                substitutions = {
                    'a': '[a@4*#]', 'e': '[e3*#]', 'i': '[i1!*#]', 'o': '[o0*#]', 's': '[s$5*#]',
                    'b': '[b6*#]', 'g': '[g9*#]', 'l': '[l1*#]', 't': '[t7*#]',
                    'u': '[u*#]', 'c': '[c*#]', 'k': '[k*#]', 'f': '[f*#]', 
                    'd': '[d*#]', 'm': '[m*#]', 'n': '[n*#]', 'p': '[p*#]'
                }
                pattern += substitutions.get(char, f'[{char}*#]')
            else:
                pattern += char
        pattern += r'\b'
        
        if re.search(pattern, text_lower, re.IGNORECASE) and word not in exact_matches and word not in repeated_chars:
            substitution_matches.append(word)
    
    # Method 4: Multiple asterisk masking (f***ing, f**k)
    asterisk_matches = []
    for word in abusive_words:
        if len(word) >= 3:
            first_last_pattern = f'{word[0]}\\*+{word[-1]}'
            if re.search(first_last_pattern, text_lower, re.IGNORECASE) and word not in exact_matches:
                asterisk_matches.append(word)
            
            if len(word) >= 4:
                first_two_pattern = f'{word[0]}{word[1]}\\*+{word[-1]}'
                if re.search(first_two_pattern, text_lower, re.IGNORECASE) and word not in exact_matches:
                    asterisk_matches.append(word)
    
    # Method 5: Spaced out words (s t u p i d)
    spaced_matches = []
    for word in abusive_words:
        spaced_pattern = r'\b' + r'\s*'.join(list(word)) + r'\b'
        if re.search(spaced_pattern, text_lower, re.IGNORECASE) and word not in exact_matches:
            spaced_matches.append(word)
    
    all_matches = list(set(exact_matches + repeated_chars + substitution_matches + spaced_matches + asterisk_matches))
    
    # OPTIMIZATION: Filter out "hell" if it's just an expletive (not "go to hell")
    if "hell" in all_matches:
        if not re.search(r"\bgo\s*to\s*hell\b", text_lower, re.IGNORECASE):
            if not re.search(r"\b(burn|rot)\s*in\s*hell\b", text_lower, re.IGNORECASE):
                all_matches.remove("hell")  # Just emphasis, not abusive
    
    # Analyze context
    context_analysis = analyze_context(text)
    
    # CRITICAL: Check for phrase-level abuse even without word matches
    if not all_matches and (context_analysis["clearly_abusive"] > 0 or context_analysis["highly_abusive"] > 0):
        all_matches.append("phrase_abuse")
    
    # If no abusive content found, approve
    if not all_matches:
        return {
            "is_abusive": 0,
            "confidence": 0,
            "flagged_words": [],
            "auto_action": "approve",
            "reason": "no_abusive_words"
        }
    
    # DECISION LOGIC (Same as before, but with better detection)
    
    # 1. DEFINITELY ABUSIVE - Auto-hide
    if (context_analysis["clearly_abusive"] > 0 or 
        context_analysis["highly_abusive"] > 0 or
        len(all_matches) >= 3):
        
        return {
            "is_abusive": 1,
            "confidence": 0.95,
            "flagged_words": all_matches,
            "auto_action": "keep_hidden",
            "reason": "clearly_abusive_pattern_or_highly_abusive_words",
            "context_analysis": context_analysis
        }
    
    # 2. POSITIVE CONTEXT - Auto-approve
    elif context_analysis["likely_false_positive"]:
        return {
            "is_abusive": 0,
            "confidence": 0.3,
            "flagged_words": all_matches,
            "auto_action": "auto_approve",
            "reason": "positive_context_detected",
            "context_analysis": context_analysis
        }
    
    # 3. POLITE TONE - Auto-approve
    elif len(all_matches) == 1 and context_analysis["politeness_score"] > 0:
        return {
            "is_abusive": 0,
            "confidence": 0.4,
            "flagged_words": all_matches,
            "auto_action": "auto_approve", 
            "reason": "polite_tone_detected",
            "context_analysis": context_analysis
        }
    
    # 4. SINGLE HIGH-RISK WORD - Auto-hide
    elif len(all_matches) == 1 and any(word in highly_abusive_words for word in all_matches):
        return {
            "is_abusive": 1,
            "confidence": 0.8,
            "flagged_words": all_matches,
            "auto_action": "keep_hidden",
            "reason": "high_risk_word_detected",
            "context_analysis": context_analysis
        }
    
    # 5. UNCERTAIN - Human review needed
    else:
        return {
            "is_abusive": 1,
            "confidence": 0.6,
            "flagged_words": all_matches,
            "auto_action": "human_review_needed",
            "reason": "uncertain_context",
            "context_analysis": context_analysis
        }

def is_abusive(text: str) -> Dict[str, any]:
    """Simple abuse detection (backward compatibility)"""
    result = is_abusive_with_auto_review(text)
    return {
        "is_abusive": result["is_abusive"],
        "confidence": result["confidence"],
        "flagged_words": result["flagged_words"]
    }

# Test cases to verify behavior
if __name__ == "__main__":
    test_cases = [
        # Should AUTO-HIDE (clearly abusive)
        ("Go to hell", "keep_hidden"),
        ("GO TO HELL", "keep_hidden"),
        ("You fucking idiot", "keep_hidden"),
        ("You stupid moron", "keep_hidden"),
        ("Shut up bitch", "keep_hidden"),
        ("Are you stupid?", "keep_hidden"),  # Sarcastic question
        
        # Should AUTO-APPROVE (positive context)
        ("This is fucking awesome!", "auto_approve"),
        ("That's stupid simple to understand", "auto_approve"),
        ("Damn good work!", "auto_approve"),
        ("What the hell is this about?", "approve"),  # Just expletive
        ("Can you help me please?", "approve"),  # Genuinely polite
        
        # Should go to HUMAN REVIEW (uncertain)
        ("This is stupid", "human_review_needed"),
        ("That's dumb", "human_review_needed"),
        ("stupid but confusing", "human_review_needed"),
        ("You're dumb", "human_review_needed"),
    ]
    
    print("Testing Enhanced Filter System")
    print("=" * 70)
    
    for text, expected_action in test_cases:
        result = is_abusive_with_auto_review(text)
        actual_action = result["auto_action"]
        status = "✓" if actual_action == expected_action else "✗"
        
        print(f"\n{status} Text: '{text}'")
        print(f"  Expected: {expected_action}")
        print(f"  Got: {actual_action}")
        if result["flagged_words"]:
            print(f"  Flagged: {result['flagged_words']}")
        print(f"  Reason: {result['reason']}")