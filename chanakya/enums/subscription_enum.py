from enum import Enum


class SubsEnum(Enum):
    GOOGLE = "google"
    APPLE = "apple"
    STRIPE = "stripe"
    FREE = "free"

    @classmethod
    def choices(cls):
        return [(role.value, role.name.capitalize()) for role in cls]
