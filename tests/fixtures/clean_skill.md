# Clean Markdown Skill - Task Manager

## Description
A simple task management skill for AI agents.

## Usage
Ask the agent to add, list, or remove tasks.

## Examples
- "Add task: review code"
- "List my tasks"
- "Remove task 3"

## Parameters
- `action`: add | list | remove
- `task`: string (for add action)
- `id`: number (for remove action)

## Notes
- Tasks are stored in memory during session
- No persistent storage required
- Maximum 50 tasks per session
