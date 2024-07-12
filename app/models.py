from transformers import pipeline

def get_summarization_pipeline():
    summarization_pipeline = pipeline("summarization")
    return summarization_pipeline

def get_question_answering_pipeline():
    qa_pipeline = pipeline("question-answering")
    return qa_pipeline

