"""Synthetic Spanish speech and exact transcript intervals for D01 acceptance."""

import json


SEGMENTS = (
    (1.0, 9.0, "Bienvenidos al taller. Hoy compartimos dos aprendizajes prácticos de nuestra comunidad."),
    (26.0, 34.0, "Para el huerto instalamos un depósito de agua de lluvia debajo del canalón del techo."),
    (35.0, 43.0, "Una malla retiene las hojas antes de que el agua de lluvia entre en el depósito."),
    (44.0, 52.0, "Cerramos la tapa para evitar insectos y conectamos una manguera para regar el huerto."),
    (53.0, 62.0, "Este sistema de recolección de lluvia permite guardar agua para las plantas entre tormentas."),
    (1142.0, 1151.0, "Para reparar el freno de una bicicleta, primero comprobá que la rueda gire sin rozar."),
    (1152.0, 1161.0, "Ajustá el cable del freno hasta que la maneta tenga recorrido sin tocar el manubrio."),
    (1162.0, 1171.0, "Revisá las pastillas del freno y alinealas con la llanta antes de apretar el tornillo."),
    (1172.0, 1181.0, "Por último probá el freno de la bicicleta a baja velocidad antes de volver a circular."),
)


def transcript():
    return [{"start": start, "end": end, "text": words} for start, end, words in SEGMENTS]


if __name__ == "__main__":
    print(json.dumps(transcript(), ensure_ascii=False))
