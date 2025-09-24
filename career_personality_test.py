import random

class CareerPathTest:
    def __init__(self):
        self.career_categories = {
            "Technology & Future Careers": {
                "careers": [
                    "Software Developer / Programmer 💻",
                    "AI & Machine Learning Specialist 🤖",
                    "Cybersecurity Analyst 🔐",
                    "Data Scientist 📊",
                    "Robotics Engineer 🤖🔧"
                ],
                "traits": ["analytical", "tech_savvy", "problem_solver", "innovative", "logical"]
            },
            "Healthcare & Wellness Careers": {
                "careers": [
                    "Nurse / Nurse Practitioner 🩺",
                    "Mental Health Counselor / Therapist 💙",
                    "Physical Therapist 🏃",
                    "Biotech Researcher 🧬",
                    "Nutritionist / Wellness Coach 🥗"
                ],
                "traits": ["compassionate", "helpful", "patient", "detail_oriented", "science_interested"]
            },
            "Environment & Sustainability": {
                "careers": [
                    "Environmental Scientist 🌍",
                    "Renewable Energy Engineer ☀️💨",
                    "Urban Planner 🏙️",
                    "Agritech Specialist 🌾"
                ],
                "traits": ["nature_lover", "problem_solver", "innovative", "future_focused", "science_interested"]
            },
            "Creativity & Media": {
                "careers": [
                    "Digital Content Creator 🎥",
                    "Graphic Designer / UX Designer 🎨",
                    "Game Developer 🎮",
                    "Film & Media Producer 🎬"
                ],
                "traits": ["creative", "expressive", "tech_savvy", "storyteller", "visual_thinker"]
            },
            "Trades & Skilled Professions": {
                "careers": [
                    "Electrician ⚡",
                    "Plumber 🚰",
                    "Construction Manager 🏗️",
                    "Mechanic (EV / Robotics) 🚗🔋"
                ],
                "traits": ["hands_on", "practical", "problem_solver", "detail_oriented", "mechanical_aptitude"]
            },
            "Leadership & Society": {
                "careers": [
                    "Entrepreneur / Startup Founder 🚀",
                    "Social Worker 🤝",
                    "Public Health Specialist 🏥",
                    "Politician / Policy Maker 🏛️"
                ],
                "traits": ["leader", "communicator", "compassionate", "analytical", "people_focused"]
            }
        }
        
        self.questions = [
            {
                "question": "What type of activities do you enjoy most?",
                "answers": {
                    "A": {"text": "Working with computers and technology", "traits": ["tech_savvy", "analytical", "logical"]},
                    "B": {"text": "Helping people solve their problems", "traits": ["compassionate", "helpful", "people_focused"]},
                    "C": {"text": "Creating art, videos, or digital content", "traits": ["creative", "expressive", "visual_thinker"]},
                    "D": {"text": "Working with my hands to build things", "traits": ["hands_on", "practical", "mechanical_aptitude"]}
                }
            },
            {
                "question": "Which environment would you prefer to work in?",
                "answers": {
                    "A": {"text": "An office with the latest technology", "traits": ["tech_savvy", "logical", "innovative"]},
                    "B": {"text": "A hospital, clinic, or care facility", "traits": ["compassionate", "helpful", "science_interested"]},
                    "C": {"text": "A creative studio or media production space", "traits": ["creative", "expressive", "storyteller"]},
                    "D": {"text": "Outdoors or in a workshop", "traits": ["nature_lover", "hands_on", "practical"]}
                }
            },
            {
                "question": "What motivates you the most?",
                "answers": {
                    "A": {"text": "Solving complex problems and puzzles", "traits": ["analytical", "problem_solver", "logical"]},
                    "B": {"text": "Making a positive difference in people's lives", "traits": ["compassionate", "helpful", "people_focused"]},
                    "C": {"text": "Expressing myself and inspiring others", "traits": ["creative", "expressive", "storyteller"]},
                    "D": {"text": "Building something useful with my hands", "traits": ["hands_on", "practical", "detail_oriented"]}
                }
            },
            {
                "question": "Which subject do you find most interesting?",
                "answers": {
                    "A": {"text": "Math, Science, and Computer Programming", "traits": ["analytical", "logical", "science_interested"]},
                    "B": {"text": "Biology, Psychology, and Health Sciences", "traits": ["science_interested", "compassionate", "patient"]},
                    "C": {"text": "Art, Media, and Communication", "traits": ["creative", "visual_thinker", "expressive"]},
                    "D": {"text": "Engineering, Physics, and Hands-on Learning", "traits": ["mechanical_aptitude", "practical", "problem_solver"]}
                }
            },
            {
                "question": "How do you prefer to work?",
                "answers": {
                    "A": {"text": "Independently on technical projects", "traits": ["analytical", "tech_savvy", "logical"]},
                    "B": {"text": "In teams helping and supporting others", "traits": ["compassionate", "helpful", "communicator"]},
                    "C": {"text": "Creatively with freedom to express ideas", "traits": ["creative", "innovative", "expressive"]},
                    "D": {"text": "With tools and equipment to build things", "traits": ["hands_on", "practical", "mechanical_aptitude"]}
                }
            },
            {
                "question": "What kind of impact do you want to make?",
                "answers": {
                    "A": {"text": "Advance technology and innovation", "traits": ["innovative", "tech_savvy", "future_focused"]},
                    "B": {"text": "Improve health and well-being", "traits": ["compassionate", "helpful", "science_interested"]},
                    "C": {"text": "Inspire and entertain people", "traits": ["creative", "expressive", "storyteller"]},
                    "D": {"text": "Build infrastructure and practical solutions", "traits": ["practical", "hands_on", "problem_solver"]}
                }
            },
            {
                "question": "Which activity sounds most appealing?",
                "answers": {
                    "A": {"text": "Coding an app or analyzing data", "traits": ["tech_savvy", "analytical", "logical"]},
                    "B": {"text": "Volunteering at a hospital or counseling center", "traits": ["compassionate", "helpful", "patient"]},
                    "C": {"text": "Making videos or designing graphics", "traits": ["creative", "visual_thinker", "expressive"]},
                    "D": {"text": "Fixing things or working on mechanical projects", "traits": ["hands_on", "mechanical_aptitude", "practical"]}
                }
            },
            {
                "question": "What type of recognition do you value most?",
                "answers": {
                    "A": {"text": "Being known for technical expertise", "traits": ["analytical", "tech_savvy", "logical"]},
                    "B": {"text": "Being appreciated for helping others", "traits": ["compassionate", "helpful", "people_focused"]},
                    "C": {"text": "Having your creative work admired", "traits": ["creative", "expressive", "visual_thinker"]},
                    "D": {"text": "Being respected for practical skills", "traits": ["hands_on", "practical", "detail_oriented"]}
                }
            }
        ]
    
    def calculate_results(self, answers):
        """Calculate personality test results based on user answers"""
        trait_scores = {}
        
        # Count trait occurrences from answers
        for i, answer_choice in enumerate(answers):
            if i < len(self.questions):
                question = self.questions[i]
                if answer_choice in question["answers"]:
                    traits = question["answers"][answer_choice]["traits"]
                    for trait in traits:
                        trait_scores[trait] = trait_scores.get(trait, 0) + 1
        
        # Find matching career categories
        category_scores = {}
        for category_name, category_data in self.career_categories.items():
            score = 0
            category_traits = category_data["traits"]
            for trait in category_traits:
                if trait in trait_scores:
                    score += trait_scores[trait]
            category_scores[category_name] = score
        
        # Sort categories by score
        sorted_categories = sorted(category_scores.items(), key=lambda x: x[1], reverse=True)
        
        # Get top 3 career matches
        top_matches = []
        for category_name, score in sorted_categories[:3]:
            if score > 0:  # Only include categories with some match
                category_data = self.career_categories[category_name]
                top_matches.append({
                    "category": category_name,
                    "score": score,
                    "careers": category_data["careers"],
                    "match_percentage": min(100, int((score / len(self.questions)) * 100))
                })
        
        return {
            "trait_scores": trait_scores,
            "top_matches": top_matches,
            "primary_traits": sorted(trait_scores.items(), key=lambda x: x[1], reverse=True)[:5]
        }