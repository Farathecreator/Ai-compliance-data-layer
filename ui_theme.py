"""Shared dark theme for the Streamlit dashboards."""

CSS = """
<style>
  [data-testid="stSidebar"], [data-testid="collapsedControl"] {display: none;}
  .block-container {padding-top: 3.2rem; max-width: 1480px;}
  [data-testid="stVerticalBlockBorderWrapper"] {border-color: #1f2937 !important; border-radius: 8px;
      background: #050a18;}
  .crumb {color: #e5e7eb; font-size: 0.95rem; padding: 4px 0 10px 0; border-bottom: 1px solid #1f2937;}
  .crumb span {color: #6b7280; margin: 0 8px;}
  .page {font-size: 1.15rem; font-weight: 600; color: #f3f4f6; padding: 12px 0 6px 0;}
  .card-title {font-size: 1.3rem; font-weight: 600; color: #f3f4f6; margin: 2px 0 10px 0;}
  .big {font-size: 1.75rem; font-weight: 500; color: #f3f4f6;}
  .big small {font-size: 0.85rem; color: #9ca3af; margin-left: 8px; font-weight: 400;}
  .muted {color: #9ca3af; font-size: 0.85rem;}
  .hbar {display: flex; align-items: center; margin: 9px 0;}
  .hbar .track {flex: 1; position: relative; height: 34px;}
  .hbar .fill {position: absolute; left: 0; top: 0; bottom: 0; background: #312e81; border-radius: 4px;
               min-width: 6px;}
  .hbar .lbl {position: absolute; left: 10px; top: 7px; color: #e5e7eb; font-size: 0.92rem; white-space: nowrap;}
  .hbar .num {width: 48px; text-align: right; color: #e5e7eb; font-size: 0.92rem;}
  table.dt {width: 100%; border-collapse: collapse; font-size: 0.85rem; color: #d1d5db;}
  table.dt th {text-align: left; font-weight: 600; color: #f3f4f6; padding: 10px 6px; border-bottom: 1px solid #374151;}
  table.dt td {padding: 10px 6px; border-bottom: 1px solid #1f2937;}
  table.dt .r {text-align: right;}
  .sev {display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 6px;}
  .headline {color: #c7d2fe; font-size: 0.92rem; margin: 4px 0 2px 0;}
  .tl {position: relative; margin: 8px 0 8px 10px; padding-left: 26px; border-left: 2px solid #1f2937;}
  .tl-step {position: relative; margin-bottom: 18px;}
  .tl-dot {position: absolute; left: -35px; top: 2px; width: 16px; height: 16px; border-radius: 50%;
           border: 3px solid #030712;}
  .tl-title {font-weight: 600; font-size: 0.95rem; color: #f3f4f6;}
  .tl-body {margin-top: 4px; padding: 10px 12px; border-radius: 6px; background: #0b1120;
            border: 1px solid #1f2937; font-size: 0.9rem; color: #d1d5db; white-space: pre-wrap;}
  .tl-body.bad {background: #1f0a0f; border-color: #7f1d1d;}
  .pill {display: inline-block; padding: 3px 10px; border-radius: 999px; font-size: 0.8rem;
         font-weight: 600; margin: 2px 6px 2px 0;}
  .pill.pass {background: #052e1c; color: #34d399;}
  .pill.fail {background: #3b0a12; color: #fca5a5;}
  .pill.flag {background: #0c1f3d; color: #93c5fd;}
  .tag {display: inline-block; padding: 1px 8px; border-radius: 6px; background: #1e1b4b; color: #c7d2fe;
        font-size: 0.75rem; margin-left: 6px;}
  .stTabs [data-baseweb="tab-list"] {gap: 22px;}
</style>
"""
