""" Carga de modelo de Red de neuronas para detección de tráfico
    https://github.com/omossad/cmpt980
"""
from keras.models import load_model
import numpy as np
import pandas as pd
from sklearn.preprocessing import QuantileTransformer

# características del tráfico seleccionadas para los pronósticos
# comunes a cicflowmeter y a la colección CICDDoS2019
FEATURES = ['Fwd Packet Length Max', 'Fwd Packet Length Min',
            'Fwd Packet Length Std', 'Flow IAT Mean', 'Flow IAT Max',
            'Fwd IAT Mean', 'Fwd IAT Max', 'Fwd Header Length',
            'Fwd Packets/s', 'Min Packet Length', 'Max Packet Length',
            'Packet Length Std', 'ACK Flag Count', 'Init_Win_bytes_forward',
            'min_seg_size_forward']


class DDoSDetector(object):
    """Detector de ataques DDoS
    """
    def __new__(cls):
        if not hasattr(cls, 'instance'):
            cls.instance = super(DDoSDetector, cls).__new__(cls)
        return cls.instance

    def __init__(self):
        self.model = load_model("src/prediction_models/keras")

    def evaluate(self, traffic_features):
        """Realiza la evaluación de los flujos de tráfico
        extraídos con cicflowmeter e intenta predecir si 
        tiene los sintomas de un ataque DDoS

        Args:
            traffic_features (_type_): dataframe con las carácterísticas 
            del tráfico de red a analizar

        Returns:
            Array: unos y ceros, donde 1 significa flujo de tráfico de ataque
            y 0 significa tráfico normal (BENIGN)
        """
        new_x = pd.DataFrame(traffic_features)
        xTest = np.asarray(new_x)
        prediction = self.model.predict(xTest)
        prediction = np.argmax(prediction, axis=1)
        return prediction


def prepare_data(df: pd.DataFrame) -> pd.DataFrame:
    """Realiza la preparación de datos idéntica 
    a la que se realizó para entrenar na RNA

    Args:
        df (pd.DataFrame): carácterísticas de los flujos
        de datos extraídas por cicflowmeter

    Returns:
        pd.DataFrame: características preparadas para ser
        evaluadas por la RNA
    """
    max_val = 99999
    df.columns = df.columns.str.strip()
    df = df[FEATURES]
    df = df.replace('Infinity', max_val)
    x = df.values
    scaler = QuantileTransformer(n_quantiles=1000, random_state=42)
    scaled_df = scaler.fit_transform(x)
    x = pd.DataFrame(scaled_df)
    return x


def read_file(filename):
    max_val = 99999
    with open("C:\\Users\\ingsr\\workspace\\TFM\\PEC3\\cmpt980\\code\\features.txt") as f:
        features = [feature.strip() for feature in f]
    features.remove('Label')
    df = pd.read_csv(filename)
    return prepare_data(df)


if __name__ == "__main__":
    new_x = pd.DataFrame()
    new_x = new_x.append(read_file("C:\\Users\\ingsr\\iot-intrusion-detector\\captures\\s81d0a280fa_2022-12-07T180248.csv"))
    print(new_x)
    model = load_model("C:\\Users\\ingsr\\workspace\\TFM\\PEC3\\IoTIntrusionDetector\\src\\prediction_models\\keras")
    xTest = np.asarray(new_x)
    print(xTest)
    prediction = np.argmax(model.predict(xTest), axis=1)
    print(prediction)
