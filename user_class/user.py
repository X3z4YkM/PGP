class User:
    def __init__(self,name, email, algo, key_size, key_pass):
        self.name = name
        self.email = email
        self.algorithm = algo
        self.key_size = key_size
        self.key_password = key_pass

    def get_info(self):
        return {"name": self.name,
                "email": self.email,
                "algorithm": self.algorithm,
                "key_size": self.key_size,
                "key_password": self.key_password}