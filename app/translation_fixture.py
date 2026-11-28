"""Known bilingual speech events for the protected INT translation rehearsal."""

import json


FILENAME = "translation.mp4"
DURATION = 54
SPAN = {"es": (4, 19), "en": (29, 44)}
TITLES = {"es": "Original de Lucía", "en": "Maya's original export"}
TEXT = {
    "es": ("Lucía no vendió el equipo Atlas.", "Pesaba 14 kilogramos.", "Entregó 3 cajas en Córdoba."),
    "en": ("Maya did not sell the Orion camera.", "It weighed 18 kilograms.", "She delivered 5 boxes to Boston."),
}


def cues(language):
    return [{"start": 5 * index, "end": 5 * (index + 1), "text": text}
            for index, text in enumerate(TEXT[language])]


def timeline():
    rows = []
    for language, (start, _) in SPAN.items():
        for cue in cues(language):
            row = {**cue, "start": start + cue["start"], "end": start + cue["end"]}
            words = []
            if language == "es":
                for index, word in enumerate(row["text"].split()):
                    offset = row["start"] + .2 + index * .76
                    words.append({"start": round(offset, 2), "end": round(offset + .7, 2), "text": word})
            rows.append({**row, "language": language, "words": words})
    return rows


def recipe():
    events = []
    for row in timeline():
        source = row["words"] or [{**row, "start": row["start"] + .2, "end": row["end"] - .1}]
        events.extend({"language": row["language"], "start": word["start"],
                       "duration": round(word["end"] - word["start"], 2), "text": word["text"]}
                      for word in source)
    return {"duration": DURATION, "speech": events}


if __name__ == "__main__":
    print(json.dumps(recipe(), ensure_ascii=False))
