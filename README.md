# WAF using Character-level CNN

If you just want run, contact me to get the pre-trained model. Then run:

```bash
pip install -r requirements.txt
python3 ./waf/waf2.py
python3 ./waf/dasboard.py
streamlit run ./analysis/analysis.py
cd vuln
docker-compose up --build
```