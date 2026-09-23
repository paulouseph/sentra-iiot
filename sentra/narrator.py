"""
narrator.py
-----------
Turns a model verdict into English.

A probability vector is not an alert. "Ransomware, 0.83" tells an analyst
nothing about what to do, how sure to be, or what the machine actually
noticed. This module is the layer that answers those three questions, and it
is deliberately conservative: when the model is unsure, the wording says so
rather than dressing a coin-flip up as a finding.

Everything here is templated from real numbers. Nothing is invented.
"""
from __future__ import annotations

from .ml.schema import friendly, unit

# How confident is confident? These bands are what the UI prints instead of a
# bare decimal, because "0.61" reads as certainty to most people and it is not.
CONFIDENCE_BANDS: list[tuple[float, str, str]] = [
    (0.95, "near certain", "The model has seen this pattern many times and is not hedging."),
    (0.80, "confident", "A clear match, with a little probability spread across neighbours."),
    (0.60, "likely", "The leading class is ahead, but a second one is plausible."),
    (0.40, "uncertain", "The model is close to a coin flip. Treat this as a prompt to look, not a finding."),
    (0.00, "guessing", "No class fits well. This needs a human before any action is taken."),
]


def confidence_band(confidence: float) -> tuple[str, str]:
    for floor, word, note in CONFIDENCE_BANDS:
        if confidence >= floor:
            return word, note
    return "guessing", CONFIDENCE_BANDS[-1][2]


def describe_deviation(feature: str, value: float, mean: float, z: float) -> str:
    """One sentence on how a single measurement compares to quiet-hours normal."""
    name = friendly(feature)
    suffix = f" {unit(feature)}" if unit(feature) else ""
    direction = "above" if z > 0 else "below"
    magnitude = abs(z)

    if magnitude >= 8:
        strength = "nothing like"
    elif magnitude >= 4:
        strength = "far"
    elif magnitude >= 2:
        strength = "clearly"
    else:
        strength = "a little"

    if mean > 0 and value > 0 and 0.05 < (value / mean) < 200:
        ratio = value / mean
        comparison = (
            f"{ratio:.1f}x the usual {mean:,.1f}{suffix}"
            if ratio >= 1
            else f"{1 / ratio:.1f}x lower than the usual {mean:,.1f}{suffix}"
        )
    else:
        comparison = f"baseline sits at {mean:,.1f}{suffix}"

    if strength == "nothing like":
        return f"{name} is {value:,.1f}{suffix} — nothing like normal, {comparison}."
    return f"{name} is {value:,.1f}{suffix} — {strength} {direction} normal, {comparison}."


def headline(attack_type: str, profile: dict, novel: bool, confidence: float) -> str:
    if novel:
        return "Traffic that does not match anything in training"
    if confidence < 0.4:
        return f"Possible {profile['headline'].lower()} — needs a second opinion"
    return profile["headline"]


def summarise(
    *,
    attack_type: str,
    profile: dict,
    confidence: float,
    novel: bool,
    deviations: list[dict],
    runner_up: tuple[str, float] | None,
) -> dict:
    """Assemble the full narrative block attached to every alert."""
    word, band_note = confidence_band(confidence)

    if novel:
        story = (
            "This flow sits outside the distribution of everything the model was "
            "trained on. The classifier still picked a nearest label, but that "
            f"label ({attack_type}) is a best guess rather than a match. Novel "
            "traffic is how a zero-day looks on its first day."
        )
        actions = [
            "Capture a full PCAP of this flow before anything changes",
            "Check whether new equipment was commissioned on this segment today",
            "Do not dismiss this because the classifier is unsure — that is the signal",
        ]
    else:
        story = profile["story"]
        actions = list(profile["actions"])

    evidence = [d["sentence"] for d in deviations[:3]]

    if runner_up and runner_up[1] > 0.15:
        second = (
            f"The model's second choice was {runner_up[0].replace('_', ' ')} at "
            f"{runner_up[1]:.0%}. If the first read does not fit what you see on "
            "the floor, check that one."
        )
    else:
        second = ""

    return {
        "headline": headline(attack_type, profile, novel, confidence),
        "story": story,
        "evidence": evidence,
        "actions": actions,
        "confidence_word": word,
        "confidence_note": band_note,
        "second_opinion": second,
    }
