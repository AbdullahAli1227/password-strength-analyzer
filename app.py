import streamlit as st
from analyzer import analyze, breach_count, generate_password, generate_passphrase

st.set_page_config(page_title="Password Strength Analyzer", page_icon="🔐", layout="wide")
st.markdown("<h1>🔐 Password Strength Analyzer</h1>", unsafe_allow_html=True)
st.caption("Entropy analysis, pattern detection, crack-time estimates and breach lookup. Nothing is stored or logged.")
tab1, tab2, tab3 = st.tabs(["Analyze", "Generator", "How it works"])

with tab1:
    pw = st.text_input("Enter a password", type="password", placeholder="Type or paste a password to test")
    if pw:
        r = analyze(pw)
        c1, c2, c3 = st.columns(3)
        c1.metric("Strength", r["label"], f'{r["score"]}/100')
        c2.metric("Entropy", f'{r["bits"]:.0f} bits')
        c3.metric("Length", len(pw))
        st.progress(r["score"] / 100)
        left, right = st.columns(2)
        with left:
            st.subheader("Requirements")
            for k, ok in r["checks"].items(): st.write(("✅ " if ok else "❌ ") + k)
            st.subheader("Weaknesses found")
            for i in r["issues"] or []: st.warning(i)
            if not r["issues"]: st.success("No common patterns detected")
        with right:
            st.subheader("Estimated time to crack")
            for k, v in r["times"].items(): st.write(f"**{k}**: {v}")
            st.subheader("Breach check")
            if st.button("Check Have I Been Pwned"):
                try:
                    n = breach_count(pw)
                    st.error(f"Found in {n:,} known breaches. Do not use it.") if n else st.success("Not found in known breaches")
                except Exception as e: st.info(f"Could not reach the service: {e}")
        if r["score"] < 80:
            st.info(f"Suggested stronger password: `{generate_password()}`")

with tab2:
    mode = st.radio("Type", ["Random password", "Passphrase"], horizontal=True)
    if mode == "Random password":
        n = st.slider("Length", 12, 64, 20); sym = st.checkbox("Include symbols", True)
        st.code(generate_password(n, sym))
    else:
        w = st.slider("Words", 4, 8, 5); st.code(generate_passphrase(w))
    st.caption("Generated locally with Python's cryptographically secure `secrets` module. Refresh the page for a new one.")

with tab3:
    st.markdown("""
- **Entropy** = length x log2(character pool), reduced for predictable patterns.
- **Crack time** assumes an attacker tries half the keyspace at three realistic guess rates.
- **Breach check** uses k-anonymity: only the first 5 characters of the SHA-1 hash are sent.
- **Tip:** length beats complexity. A long passphrase is stronger and easier to remember.""")
