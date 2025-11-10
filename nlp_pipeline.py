from transformers import AutoTokenizer, AutoModelForSequenceClassification, pipeline
import torch
import spacy
import re

# Load phishing detection model and tokenizer
tokenizer = AutoTokenizer.from_pretrained("./phishing_model")
model = AutoModelForSequenceClassification.from_pretrained("./phishing_model")

# Load spaCy NER model
nlp = spacy.load("en_core_web_sm")

# ✅ Use BERT-based sentiment model
sentiment_model_name = "cardiffnlp/twitter-roberta-base-sentiment"
sentiment_tokenizer = AutoTokenizer.from_pretrained(sentiment_model_name)
sentiment_model = AutoModelForSequenceClassification.from_pretrained(sentiment_model_name)
sentiment_pipeline = pipeline("sentiment-analysis", model=sentiment_model, tokenizer=sentiment_tokenizer)

# ✅ Whitelist management
sender_whitelist = set()

def set_sender_whitelist(whitelist_emails):
    global sender_whitelist
    sender_whitelist = set([e.lower() for e in whitelist_emails])

def is_sender_trusted(sender_email):
    return sender_email.lower() in sender_whitelist

def classify_text(text):
    inputs = tokenizer(text, return_tensors="pt", truncation=True, max_length=512, padding=True)
    outputs = model(**inputs)
    probs = torch.softmax(outputs.logits, dim=1).detach().cpu().numpy()[0]
    phishing_prob = probs[1]  # label 1 = phishing/spam

    # ✅ Extract suspicious keywords
    suspicious_keywords = []
    keywords_list = ["urgent", "verify", "password", "click", "login", "suspend", "legal action", "immediately"]
    for kw in keywords_list:
        if re.search(r"\b" + re.escape(kw) + r"\b", text, flags=re.I):
            suspicious_keywords.append(kw)

    return phishing_prob, suspicious_keywords

def analyze_ner(text):
    doc = nlp(text)
    return [(ent.text, ent.label_) for ent in doc.ents]

def analyze_sentiment(text):
    result = sentiment_pipeline(text)[0]
    
    label_map = {
        "LABEL_0": "Negative",
        "LABEL_1": "Neutral",
        "LABEL_2": "Positive"
    }
    
    label = label_map.get(result["label"], result["label"])
    
    return {
        "label": label,
        "confidence": f"{result['score']*100:.2f}%"
    }
