# Clean Skill Sample — FOR TESTING ONLY (should produce 0 critical findings)

def greet(name: str) -> str:
    """Return a greeting message."""
    return f"Hello, {name}!"


def calculate_sum(numbers: list[int]) -> int:
    """Calculate the sum of a list of numbers."""
    return sum(numbers)


class TaskManager:
    """Simple task manager."""

    def __init__(self):
        self.tasks: list[str] = []

    def add_task(self, task: str) -> None:
        self.tasks.append(task)

    def list_tasks(self) -> list[str]:
        return self.tasks.copy()

    def clear(self) -> None:
        self.tasks.clear()
