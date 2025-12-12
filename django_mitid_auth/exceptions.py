class LoginException(Exception):
    def __init__(self, errordict):
        self.errordict = errordict
