import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt

st.markdown('# WAffle Dashboard')


df_block = pd.read_csv('block.csv')
st.markdown('## Traffics blocked')
st.write(df_block)


df_through = pd.read_csv('through.csv')
st.markdown('## Traffics through')
st.write(df_through)
