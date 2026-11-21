from openai import OpenAI

client = OpenAI(api_key="{{secret:openai_key:app7}}")


def summarize(text):
    return client.responses.create(model="gpt-4o-mini", input=text)
