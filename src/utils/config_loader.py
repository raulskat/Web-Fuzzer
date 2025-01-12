import json

def load_config(config_file='config/default_config.json'):
    with open(config_file, 'r') as file:
        config = json.load(file)
    return config
