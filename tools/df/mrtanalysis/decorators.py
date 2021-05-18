from analysis import Analyzer


def Analyzer(Cls, AnalyzerClass: Analyzer):
    class Analyzer:
        def __init__(self, *args, **kwargs):
            self._decorated_class = Cls(*args, **kwargs)
            setattr(self._decorated_class, "ANALYZER", AnalyzerClass)

    return Analyzer
