import os
import openai
from logging import getLogger

CURR_DIR = os.path.dirname( os.path.abspath(__file__) )
PROMPT_DIR = CURR_DIR+"/prompts"

logger = getLogger()

class OpenAIChat(object):
    _MODEL = "gpt-4o"
    
    @classmethod
    def set_model(cls, model):
        cls._MODEL = model

    def __init__(self, api_key, system_prompt):
        self.client = openai.OpenAI(api_key=api_key)
        self.system_prompt = system_prompt

    def ask_with_omit_input(self, user_input, omit_max_length, omit_use_which, system_prompt=None):
        user_input = self.omit_user_input(user_input, omit_max_length, omit_use_which)
        return self.ask_at_once(user_input, system_prompt)

    def omit_user_input(self, user_input, omit_max_length, omit_use_which):
        curr_length = len(user_input)
        if curr_length > omit_max_length:
            logger.info("need to omit -> inputLength:{} Max:{} Type:{}".format(len(user_input), omit_max_length, omit_use_which))
            if omit_use_which == "head":
                return user_input[0:omit_max_length]
            elif omit_use_which == "tail":
                return user_input[curr_length-omit_max_length:]
            elif omit_use_which == "both":
                head_length = int(omit_max_length/2)
                tail_length = omit_max_length - head_length
                return user_input[0:head_length] +" -- omission -- "+ user_input[curr_length-tail_length:]
        else:
            logger.info("no need to omit -> inputLength:{}".format(len(user_input)))
            return user_input

    def ask_at_once(self, user_input, system_prompt=None):
        messages=[]
        if system_prompt:
            msg_system = {"role" : "system", "content" : system_prompt}
            messages.append(msg_system)
        elif self.system_prompt:
            msg_system = {"role" : "system", "content" : self.system_prompt}
            messages.append(msg_system)
        msg_user = {"role": "user", "content": user_input}
        messages.append(msg_user)
        completion = self.client.chat.completions.create(messages=messages, model=self._MODEL)
        return completion.choices[0].message.content

def get_openai_creds(creds_cfg):
    if creds_cfg["type"] == "osenv":
        return os.environ[creds_cfg["api_key_name"]]
    else:
        assert False, "not yet supported creds type -> {}".format(str(creds_cfg["type"]))

def get_system_prompt(system_prompt_cfg):
    prompt_file_name = PROMPT_DIR+"/"+system_prompt_cfg["use_prompt_file"]
    if os.path.exists(prompt_file_name):
        with open(prompt_file_name) as f:
            system_prompt = f.read()
        return system_prompt
    else:
        assert False, "system prompt file is not found -> {}".format(prompt_file_name)

def start_chat(openai_config):
    api_key = get_openai_creds(openai_config["creds"])
    system_prompt = get_system_prompt(openai_config["system_prompt"])
    logger.info("use system prompt file -> {}".format(openai_config["system_prompt"]))
    logger.debug("use system prompt -> {}".format(system_prompt))
    return OpenAIChat(api_key, system_prompt)
