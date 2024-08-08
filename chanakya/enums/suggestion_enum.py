class Suggestion:
    def __init__(self, suggestions: list, logos: str):
        self.suggestions = suggestions
        self.logos = logos


class SuggestionPrompt:
    def __init__(self, suggestions: str, prompt: str):
        self.suggestions = suggestions
        self.prompt = prompt


class Productivity(Suggestion):
    suggestions = [
        SuggestionPrompt("Effective Time Management techniques", "What are some effective time management techniques?"),
        SuggestionPrompt("Mere exams start ho rahe hai me kaise padhu", "How should I study for upcoming exams?"),
        SuggestionPrompt("How to achieve Work-Life Balance", "How can I achieve a work-life balance?"),
        SuggestionPrompt("I want to increase my productivity give me some advice.",
                         "How can I increase my productivity?"),
        SuggestionPrompt("How can I plan my day.", "How can I effectively plan my day?")
    ]
    logos = "https://res.cloudinary.com/neurobridge/image/upload/v1717139258/androi_kp4q8j.png"


class Travel(Suggestion):
    suggestions = [
        SuggestionPrompt("Offbeat Indian Destinations", ""),
        SuggestionPrompt("I want to Solo Travel any tips?", ""),
        SuggestionPrompt("Mujhe koi thandi jagha jani hai", ""),
        SuggestionPrompt("Mera summer vacations chalu ho raha hai me kaha jau?", "")
    ]
    logos = "https://res.cloudinary.com/neurobridge/image/upload/v1717139054/Plane_emtstv.png"


class FoodAndDiet(Suggestion):
    suggestions = [
        SuggestionPrompt("Healthy Breakfast Recipes", ""),
        SuggestionPrompt("Vegetarian Diet Plan", ""),
        SuggestionPrompt("Mujhe bhuk lagi hai me kya banu?", ""),
        SuggestionPrompt("Poha kaise banate hai?", ""),
        SuggestionPrompt("Suggest me some food or recipes for a house party.", "")
    ]
    logos = "https://res.cloudinary.com/neurobridge/image/upload/v1719572062/suggestion_gjta6q.png"


class History(Suggestion):
    suggestions = [
        SuggestionPrompt("Lesser-Known Historical Sites in India", ""),
        SuggestionPrompt("List some Indian Independence Fighters", ""),
        SuggestionPrompt("Jan Gan Man kisne likha tha?", ""),
        SuggestionPrompt("Tell me a story about Chanakya", ""),
        SuggestionPrompt("Non Violence movement ki details bato", "")
    ]
    logos = "https://res.cloudinary.com/neurobridge/image/upload/v1719572062/suggestion_gjta6q.png"


class Technology(Suggestion):
    suggestions = [
        SuggestionPrompt("Me ethical hacking kaise sikh sakta hu", ""),
        SuggestionPrompt("What are some new technologies", ""),
        SuggestionPrompt("Learn Coding Online", ""),
        SuggestionPrompt("How does LLM works", ""),
        SuggestionPrompt("How does Spotify maintain that very low latency", ""),
        SuggestionPrompt("How to install linux?", "")
    ]
    logos = "https://res.cloudinary.com/neurobridge/image/upload/v1717139258/androi_kp4q8j.png"


class HealthAndWellness(Suggestion):
    suggestions = [
        SuggestionPrompt("Beginner’s Yoga Routine", ""),
        SuggestionPrompt("Managing Stress and Anxiety", ""),
        SuggestionPrompt("Mujhe healthy hone hai koi tips?", ""),
        SuggestionPrompt("Infection se bachne ke liye kya karna chaiye?", "")
    ]
    logos = "https://res.cloudinary.com/neurobridge/image/upload/v1719572062/suggestion_gjta6q.png"


class Education(Suggestion):
    suggestions = [
        SuggestionPrompt("UPSC Study plan", ""),
        SuggestionPrompt("Scholarship Opportunities in Indian Institutes", ""),
        SuggestionPrompt("Emerging Career Field", ""),
        SuggestionPrompt("How many questions are there in JEE Mains?", ""),
        SuggestionPrompt("How can I plan my education and career?", "")
    ]
    logos = "https://res.cloudinary.com/neurobridge/image/upload/v1719572062/suggestion_gjta6q.png"


class Creativity(Suggestion):
    suggestions = [
        SuggestionPrompt("Write a poem on blue skies and coffee", ""),
        SuggestionPrompt("Write a small story about a small dog, with comedic tone", ""),
        SuggestionPrompt("Ek aacha sa geet likho pyaar pe", ""),
        SuggestionPrompt("Make social media post about Chanakya", "")
    ]
    logos = "https://res.cloudinary.com/neurobridge/image/upload/v1717139258/androi_kp4q8j.png"


class Funny(Suggestion):
    suggestions = [
        SuggestionPrompt("Ek mast sa joke sunnao", ""),
        SuggestionPrompt("Aache din kab aayega", ""),
        SuggestionPrompt("Make some witty and funny lines", "")
    ]
    logos = "https://res.cloudinary.com/neurobridge/image/upload/v1719572062/suggestion_gjta6q.png"


class PhilosophyAndHypotheticals(Suggestion):
    suggestions = [
        SuggestionPrompt("What were Aristotle’s views on life", ""),
        SuggestionPrompt("What is the grandfather paradox", ""),
        SuggestionPrompt("Who came first chicken or egg?", ""),
        SuggestionPrompt("What is existence?", ""),
        SuggestionPrompt("Why is there something rather than nothing?", "")
    ]
    logos = "https://res.cloudinary.com/neurobridge/image/upload/v1719572062/suggestion_gjta6q.png"


class MathAndScience(Suggestion):
    suggestions = [
        SuggestionPrompt("How to convert Fahrenheit to Celsius?", ""),
        SuggestionPrompt("Plane kaise chalta hai?", ""),
        SuggestionPrompt("Example of Food chains", ""),
        SuggestionPrompt("What are the big 5 animals", ""),
        SuggestionPrompt("Explain quadratic equations", ""),
        SuggestionPrompt("What is a palindrome? with different different approach name", "")
    ]
    logos = "https://res.cloudinary.com/neurobridge/image/upload/v1719572062/suggestion_gjta6q.png"
