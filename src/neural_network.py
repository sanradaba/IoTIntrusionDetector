""" Carga de modelo de Red de neuronas para detección de tráfico
    https://github.com/omossad/cmpt980
"""
from keras.models import load_model
import numpy as np
import pandas as pd
from sklearn.preprocessing import QuantileTransformer


class DDoSDetector(object):
    """Detector de ataques DDoS
    """
    def __new__(cls):
        if not hasattr(cls, 'instance'):
            cls.instance = super(DDoSDetector, cls).__new__(cls)
        return cls.instance

    def __init__(self):
        self.model = load_model("prediction_models/keras")

    def evaluate(self, trafficFeatures):
        df = pd.DataFrame(trafficFeatures)
        prediction = np.argmax(self.model.predict(xTest), axis=1)


def read_file(filename, y_out):
    max_val = 99999
    with open("C:\\Users\\ingsr\\workspace\\TFM\\PEC3\\cmpt980\\code\\features.txt") as f:
        features = [feature.strip() for feature in f]
    features.remove('Label')
    df = pd.read_csv(filename)
    df.columns = df.columns.str.strip()
    df = df[features]
    print(df.info)
    df = df.replace('Infinity', max_val)
    x = df.values
    scaler = QuantileTransformer(n_quantiles=1000, random_state=42)
    scaled_df = scaler.fit_transform(x)
    x = pd.DataFrame(scaled_df)
    return x


if __name__ == "__main__":
    new_x = pd.DataFrame()
    temp_y = []
    new_x = new_x.append(read_file("C:\\Users\\ingsr\\iot-intrusion-detector\\captures\\s81d0a280fa_2022-12-06T214939.csv", temp_y))
    print(new_x)
    model = load_model("prediction_models/keras")
    xTest = np.asarray(new_x)
    print(xTest)
    prediction = np.argmax(model.predict(xTest), axis=1)
    print(prediction)
