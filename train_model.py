import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
import joblib


def load_data(csv_path: str = "CEAS_08.csv") -> pd.DataFrame:
    df = pd.read_csv(csv_path)

    # Basic cleaning / feature engineering
    df["subject"] = df["subject"].fillna("")
    df["body"] = df["body"].fillna("")
    df["text"] = df["subject"] + " " + df["body"]

    # Make sure urls is numeric and non-null
    df["urls"] = df["urls"].fillna(0).astype(int)

    return df


def build_pipeline():
    """
    Build a pipeline:
      - ColumnTransformer:
          text -> TfidfVectorizer
          urls -> StandardScaler
      - Classifier: LogisticRegression
    """
    text_transformer = TfidfVectorizer(
        max_features=30000,
        ngram_range=(1, 2),
        stop_words="english"
    )

    preprocessor = ColumnTransformer(
        transformers=[
            ("text", text_transformer, "text"),
            ("urls", StandardScaler(with_mean=False), ["urls"])
        ]
    )

    clf = LogisticRegression(
        max_iter=200,
        n_jobs=-1,
        class_weight="balanced"
    )

    model = Pipeline(
        steps=[
            ("preprocessor", preprocessor),
            ("clf", clf)
        ]
    )

    return model


def main():
    print("[*] Loading data...")
    df = load_data("CEAS_08.csv")

    X = df[["text", "urls"]]
    y = df["label"]  # 1 = phishing/spam, 0 = legitimate

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y
    )

    print("[*] Building model pipeline...")
    model = build_pipeline()

    print("[*] Training model...")
    model.fit(X_train, y_train)

    print("[*] Evaluating model...")
    y_pred = model.predict(X_test)
    print(classification_report(y_test, y_pred, digits=4))

    print("[*] Saving model to model.joblib...")
    joblib.dump(model, "model.joblib")

    print("[*] Done.")


if __name__ == "__main__":
    main()
