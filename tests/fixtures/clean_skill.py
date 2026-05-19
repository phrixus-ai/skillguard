# Clean AI Skill - Weather Helper
# This skill should produce 0 critical/high findings

import json


def get_weather(city: str) -> dict:
    """Get weather data for a city."""
    return {"city": city, "temperature": 22, "condition": "sunny"}


def format_weather(data: dict) -> str:
    """Format weather data for display."""
    return f"Weather in {data['city']}: {data['temperature']}°C, {data['condition']}"


if __name__ == "__main__":
    weather = get_weather("Istanbul")
    print(format_weather(weather))
