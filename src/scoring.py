class ThreatScoringEngine:
    def __init__(self, config):
        self.config = config.get('scoring', {})
        self.scores = {
            'LOW': self.config.get('low', 1),
            'MEDIUM': self.config.get('medium', 5),
            'HIGH': self.config.get('high', 10)
        }
        self.risk_thresholds = self.config.get('risk_thresholds', {})

    def get_score(self, severity):
        return self.scores.get(severity.upper(), 1)
    
    def calculate_risk(self, total_score):
        if total_score >= self.risk_thresholds.get('high', 20):
            return "HIGH"
        elif total_score >= self.risk_thresholds.get('medium', 5):
            return "MEDIUM"
        return "LOW"
