from sklearn.preprocessing import RobustScaler


def build_scaler() -> RobustScaler:
    return RobustScaler(quantile_range=(10, 90), unit_variance=True)

