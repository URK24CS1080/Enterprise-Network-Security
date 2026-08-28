import pandas as pd
import streamlit as st
from pathlib import Path

st.set_page_config(
    page_title="Security Operations Center",
    layout="wide",
    initial_sidebar_state="expanded"
)


BASE_DIR = Path(__file__).resolve().parent

VALIDATION_FILE = BASE_DIR / "data" / "policy_validation.csv"
ATTACK_FILE = BASE_DIR / "data" / "attack_simulation.csv"
EVENTS_FILE = BASE_DIR / "logs" / "security_events.csv"
ALERTS_FILE = BASE_DIR / "logs" / "alerts.csv"


st.markdown(
    """
    <style>

    /* Main background */
    .stApp {
        background-color: #0e1117;
    }

    /* Main content */
    .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
        max-width: 1500px;
    }

    /* Sidebar */
    section[data-testid="stSidebar"] {
        background-color: #111827;
        border-right: 1px solid #263244;
    }

    /* Header */
    .soc-header {
        padding: 10px 0 5px 0;
    }

    .soc-title {
        font-size: 34px;
        font-weight: 700;
        letter-spacing: 0.5px;
        margin-bottom: 3px;
    }

    .soc-subtitle {
        color: #9ca3af;
        font-size: 15px;
    }

    /* KPI Cards */
    .metric-card {
        background: #151b26;
        border: 1px solid #263244;
        border-radius: 12px;
        padding: 20px;
        min-height: 125px;
    }

    .metric-title {
        color: #9ca3af;
        font-size: 13px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.8px;
    }

    .metric-value {
        color: #f9fafb;
        font-size: 32px;
        font-weight: 700;
        margin-top: 7px;
    }

    .metric-description {
        color: #6b7280;
        font-size: 12px;
        margin-top: 4px;
    }

    /* Security status */
    .status-good {
        background: #10251d;
        border: 1px solid #1f6b4b;
        color: #7ee2b8;
        border-radius: 10px;
        padding: 14px 18px;
        font-weight: 600;
    }

    .status-warning {
        background: #29200f;
        border: 1px solid #795b18;
        color: #f4cf70;
        border-radius: 10px;
        padding: 14px 18px;
        font-weight: 600;
    }

    .status-danger {
        background: #2b1417;
        border: 1px solid #7f2933;
        color: #ff9aa5;
        border-radius: 10px;
        padding: 14px 18px;
        font-weight: 600;
    }

    /* Section headings */
    .section-title {
        font-size: 21px;
        font-weight: 650;
        margin-top: 12px;
        margin-bottom: 12px;
    }

    /* Footer */
    .footer {
        text-align: center;
        color: #6b7280;
        font-size: 12px;
        padding-top: 20px;
    }

    </style>
    """,
    unsafe_allow_html=True
)


@st.cache_data
def load_data():

    validation = pd.read_csv(VALIDATION_FILE)
    attacks = pd.read_csv(ATTACK_FILE)
    events = pd.read_csv(EVENTS_FILE)
    alerts = pd.read_csv(ALERTS_FILE)

    return validation, attacks, events, alerts


try:

    validation, attacks, events, alerts = load_data()

except FileNotFoundError as error:

    st.error(f"Required file could not be found: {error}")
    st.stop()


st.markdown(
    """
    <div class="soc-header">
        <div class="soc-title"> Security Operations Center</div>
        <div class="soc-subtitle">
            Network Security Validation, Attack Simulation & Monitoring
        </div>
    </div>
    """,
    unsafe_allow_html=True
)

st.divider()

with st.sidebar:

    st.markdown("## SOC Controls")

    st.markdown(
        """
        **Monitoring Scope**

        Network segmentation  
        Attack simulation  
        Policy validation  
        Security events  
        Alert monitoring
        """
    )

    st.divider()

    st.markdown("### Policy Filters")

    status_options = sorted(
        validation["Status"].dropna().unique()
    )

    selected_status = st.multiselect(
        "Validation Status",
        status_options,
        default=status_options
    )

    source_options = sorted(
        validation["Source"].dropna().unique()
    )

    selected_sources = st.multiselect(
        "Source",
        source_options,
        default=source_options
    )

    destination_options = sorted(
        validation["Destination"].dropna().unique()
    )

    selected_destinations = st.multiselect(
        "Destination",
        destination_options,
        default=destination_options
    )

    st.divider()

    if st.button(
        "Refresh Monitoring Data",
        use_container_width=True
    ):

        st.cache_data.clear()
        st.rerun()


total_policy_tests = len(validation)

policy_pass = len(
    validation[
        validation["Status"] == "PASS"
    ]
)

policy_fail = len(
    validation[
        validation["Status"] == "FAIL"
    ]
)

policy_review = len(
    validation[
        validation["Status"] == "REVIEW"
    ]
)

total_events = len(events)

total_alerts = len(alerts)

unauthorized = attacks[
    attacks["Expected"].astype(str).str.upper() == "DENY"
]

unauthorized_attempts = len(unauthorized)

blocked_attacks = len(
    unauthorized[
        unauthorized["Result"]
        .astype(str)
        .str.upper()
        == "BLOCKED"
    ]
)

successful_unauthorized = len(
    unauthorized[
        unauthorized["Result"]
        .astype(str)
        .str.upper()
        != "BLOCKED"
    ]
)

attack_effectiveness = (
    blocked_attacks / unauthorized_attempts * 100
    if unauthorized_attempts > 0
    else 0
)


if successful_unauthorized == 0:

    st.markdown(
        """
        <div class="status-good">
            SECURITY STATUS: PROTECTED — All simulated unauthorized
            access attempts were blocked.
        </div>
        """,
        unsafe_allow_html=True
    )

else:

    st.markdown(
        f"""
        <div class="status-danger">
             SECURITY STATUS: ATTENTION REQUIRED — 
            {successful_unauthorized} unauthorized attempt(s)
            were not blocked.
        </div>
        """,
        unsafe_allow_html=True
    )


st.write("")

st.markdown(
    '<div class="section-title"> Security Posture</div>',
    unsafe_allow_html=True
)

c1, c2, c3, c4, c5 = st.columns(5)


def metric_card(column, title, value, description):

    with column:

        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-title">{title}</div>
                <div class="metric-value">{value}</div>
                <div class="metric-description">{description}</div>
            </div>
            """,
            unsafe_allow_html=True
        )


metric_card(
    c1,
    "Policy Tests",
    total_policy_tests,
    "Network validation tests"
)

metric_card(
    c2,
    "Policy Pass",
    policy_pass,
    "Successful policy checks"
)

metric_card(
    c3,
    "Attack Attempts",
    unauthorized_attempts,
    "Unauthorized scenarios"
)

metric_card(
    c4,
    "Blocked",
    blocked_attacks,
    "Unauthorized attempts blocked"
)

metric_card(
    c5,
    "Effectiveness",
    f"{attack_effectiveness:.0f}%",
    "Security control effectiveness"
)


st.write("")
st.divider()


tab1, tab2, tab3, tab4= st.tabs(
    [
        " Policy Validation",
        " Attack Simulation",
        " Security Events",
        " Analytics",
        
    ]
)


with tab1:

    st.header("Policy Validation")

    filtered_validation = validation[
        validation["Status"].isin(selected_status)
        & validation["Source"].isin(selected_sources)
        & validation["Destination"].isin(selected_destinations)
    ]

    if filtered_validation.empty:

        st.warning(
            "No validation records match the selected filters."
        )

    else:

        display_columns = [
            "Test_ID",
            "Source",
            "Source_IP",
            "Destination",
            "Destination_IP",
            "Expected",
            "Actual",
            "Status"
        ]

        st.dataframe(
            filtered_validation[display_columns],
            use_container_width=True,
            hide_index=True
        )

        st.caption(
            f"Showing {len(filtered_validation)} "
            f"of {len(validation)} validation tests."
        )


with tab2:

    st.header("Attack Simulation")

    st.markdown(
        """
        Controlled attack scenarios simulate attempted lateral
        movement and unauthorized cloud access from APP-A.
        """
    )

    st.write("")

    a1, a2, a3, a4 = st.columns(4)

    metric_card(
        a1,
        "Total Tests",
        len(attacks),
        "All simulation scenarios"
    )

    metric_card(
        a2,
        "Unauthorized",
        unauthorized_attempts,
        "Expected DENY"
    )

    metric_card(
        a3,
        "Blocked",
        blocked_attacks,
        "Successfully prevented"
    )

    metric_card(
        a4,
        "Unauthorized Access",
        successful_unauthorized,
        "Successful violations"
    )

    st.write("")

    st.progress(
        attack_effectiveness / 100
    )

    st.caption(
        f"Security Control Effectiveness: "
        f"**{attack_effectiveness:.1f}%**"
    )

    st.divider()

    st.subheader("Attack Simulation Evidence")

    attack_columns = [
        "Attack_ID",
        "Source",
        "Source_IP",
        "Target",
        "Target_IP",
        "Attack_Type",
        "Expected",
        "Observed",
        "Result"
    ]

    st.dataframe(
        attacks[attack_columns],
        use_container_width=True,
        hide_index=True
    )

    st.divider()

    chart_col1, chart_col2 = st.columns(2)

    with chart_col1:

        st.subheader("Attack Outcome")

        outcome_counts = (
            attacks["Result"]
            .value_counts()
        )

        st.bar_chart(
            outcome_counts,
            height=330
        )

    with chart_col2:

        st.subheader("Attack Categories")

        category_counts = (
            attacks["Attack_Type"]
            .value_counts()
        )

        st.bar_chart(
            category_counts,
            height=330
        )

    st.divider()


    st.subheader("Security Assessment")

    if successful_unauthorized == 0:

        st.success(
            "All unauthorized attack attempts were blocked. "
            "No successful unauthorized access was observed "
            "during the controlled simulation."
        )

    else:

        st.error(
            f"{successful_unauthorized} unauthorized access "
            "attempt(s) were not blocked and require investigation."
        )


with tab3:

    st.header("Security Event Monitoring")

    # Severity counts

    severity_counts = (
        events["severity"]
        .value_counts()
        .reindex(
            ["INFO", "WARNING", "CRITICAL"],
            fill_value=0
        )
    )

    e1, e2, e3 = st.columns(3)

    metric_card(
        e1,
        "INFO",
        severity_counts.get("INFO", 0),
        "Informational events"
    )

    metric_card(
        e2,
        "WARNING",
        severity_counts.get("WARNING", 0),
        "Events requiring review"
    )

    metric_card(
        e3,
        "CRITICAL",
        severity_counts.get("CRITICAL", 0),
        "Critical security events"
    )

    st.write("")

    st.subheader("Security Event Log")

    event_columns = [
        "timestamp",
        "test_id",
        "source",
        "source_ip",
        "destination",
        "destination_ip",
        "expected",
        "actual",
        "status",
        "severity"
    ]

    st.dataframe(
        events[event_columns],
        use_container_width=True,
        hide_index=True
    )


with tab4:

    st.header("Security Analytics")

    st.subheader("Policy Validation Status")

    status_counts = (
        validation["Status"]
        .value_counts()
        .reindex(
            ["PASS", "REVIEW", "FAIL"],
            fill_value=0
        )
    )

    st.bar_chart(
        status_counts,
        height=350
    )

    st.caption(
        "Distribution of policy validation outcomes."
    )

    st.divider()

    st.subheader("Security Event Severity")

    st.bar_chart(
        severity_counts,
        height=350
    )

    st.caption(
        "Distribution of security events by severity."
    )

    st.divider()

    st.subheader("Network Communication Paths")

    communication = (
        validation
        .groupby(
            ["Source", "Destination"]
        )
        .size()
        .reset_index(
            name="Tests"
        )
    )

    communication["Network Path"] = (
        communication["Source"]
        + " → "
        + communication["Destination"]
    )

    path_counts = (
        communication
        .set_index("Network Path")["Tests"]
    )

    st.bar_chart(
        path_counts,
        height=450
    )

    st.caption(
        "Validation coverage across source-to-destination paths."
    )

    st.divider()

    st.subheader("Attack Simulation Effectiveness")

    effectiveness_data = pd.Series(
        {
            "Blocked": blocked_attacks,
            "Successful": successful_unauthorized
        }
    )

    st.bar_chart(
        effectiveness_data,
        height=300
    )

st.divider()

st.markdown(
    """
    <div class="footer">
        Security Monitoring System |
        Network Security Project |
        Security Operations Dashboard
    </div>
    """,
    unsafe_allow_html=True
)