class KeyMismatchException(Exception):
    def __init__(self, *args):
        super().__init__(*args)
        self.message = "Key Mismatch"
