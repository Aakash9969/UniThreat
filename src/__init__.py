"""UniThreat — AI-based detection of cyber threats in unidirectional IP traffic.

A production-grade network intrusion detection sensor designed to sit on the
receiving end of a data diode (unidirectional gateway). It captures one-way IP
traffic, aggregates it into unidirectional flows, extracts CICFlowMeter-
compatible features, and classifies each flow with a trained machine-learning
model (Random Forest / XGBoost), surfacing live verdicts and alerts through a
FastAPI dashboard.
"""

__version__ = "0.1.0"
