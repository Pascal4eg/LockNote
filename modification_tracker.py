class ModificationTracker:
    def __init__(self, initial_content=""):
        self._clean_content = initial_content
        self._is_modified = False

    def is_modified(self):
        return self._is_modified

    def check(self, current_content):
        self._is_modified = (current_content != self._clean_content)
        return self._is_modified

    def reset(self, new_clean_content):
        self._clean_content = new_clean_content
        self._is_modified = False
