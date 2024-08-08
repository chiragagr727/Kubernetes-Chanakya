from enum import Enum


class RoleEnum(Enum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"

    @classmethod
    def choices(cls):
        return [(role.value, role.name.capitalize()) for role in cls]
