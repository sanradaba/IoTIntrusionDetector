""" Carga de modelo de Red de neuronas para detección de tráfico
    https://github.com/omossad/cmpt980
"""
from keras.models import load_model
import numpy as np
import pandas as pd
from sklearn.preprocessing import QuantileTransformer
from os import path

# características del tráfico seleccionadas para los pronósticos
# comunes a cicflowmeter y a la colección CICDDoS2019


MODEL_PATH = "src/prediction_models/keras/19feat"


class DDoSDetector(object):
    """Detector de ataques DDoS
    """
    def __new__(cls):
        if not hasattr(cls, 'instance'):
            cls.instance = super(DDoSDetector, cls).__new__(cls)
        return cls.instance

    def __init__(self):
        self.model = load_model(MODEL_PATH)
        self.features = read_features(MODEL_PATH)

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
        new_x = prepare_data(self.features, new_x)
        xTest = np.asarray(new_x)
        prediction = self.model.predict(xTest)
        prediction = np.argmax(prediction, axis=1)
        return prediction

    def get_features(self):
        return self.features.copy()


def prepare_data(features, df: pd.DataFrame) -> pd.DataFrame:
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
    df = df[features]
    df = df.replace('Infinity', max_val)
    x = df.values
    scaler = QuantileTransformer(n_quantiles=len(df.values), random_state=42)
    scaled_df = scaler.fit_transform(x)
    # scaled_df = (df-df.mean())/df.std()
    x = pd.DataFrame(scaled_df)
    return x


def read_features(features_file_path) -> list:
    """lee el fichero de características con que fue entrenada
    la RNA. El fichero debe contener una característica de cicflowmeter por 
    cada línea

    Args:
        path (str): ruta donde leer el fichero features.txt
    Returns:
        Array con características del fichero
    """
    with open(features_file_path + path.sep + "features.txt") as f:
        features = [feature.strip() for feature in f]
    features.remove('Label')
    return features


def read_file(filename):
    features = read_features("C:\\Users\\ingsr\\workspace\\TFM\\PEC3\\IoTIntrusionDetector\\src\\prediction_models\\keras\\19feat")
    print(features)
    df = pd.read_csv(filename)
    return prepare_data(features, df)


if __name__ == "__main__":
    new_x = pd.DataFrame()
    new_x = new_x.append(read_file("C:\\Users\\ingsr\\iot-intrusion-detector\\captures\\sd96f293d4e_2022-12-10T104826.csv"))
    print(new_x.info)
    model = load_model("C:\\Users\\ingsr\\workspace\\TFM\\PEC3\\IoTIntrusionDetector\\src\\prediction_models\\keras\\19feat")
    xTest = np.asarray(new_x)
    print(xTest)
    prediction = np.argmax(model.predict(xTest), axis=1)
    print(prediction)
