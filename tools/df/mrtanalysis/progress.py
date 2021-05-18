import time


class ProgressReporter:
    def __init__(self, total=1000, every=1000, fmt=None):
        self._total = total
        self._every = every
        if not fmt:
            self._fmt = "Processed {0} of {1} blocks {2:4.1f}% done"

    @property
    def total(self):
        return self._total

    @total.setter
    def total(self, total):
        self._total = total

    @property
    def percent(self):
        return self._percent

    @property
    def every(self):
        return self._every

    @every.setter
    def every(self, value):
        self._every

    def should_report(self, block):
        return block % self.every == 0

    def _update_progress(self, block, total=None):
        if not total:
            total = self._total
        self._percent = float(block) * 100.0 / float(total)

    def update(self, block, total=None):
        if self.should_report(block):
            self._update_progress(block, total)
            print(self._fmt.format(block, total, self._percent))


class TimedProgressReporter(ProgressReporter):
    def __init__(self, total=1000, every=1000, fmt=None):
        super(TimedProgressReporter, self).__init__(total, every, fmt)
        self._start_time = None
        self._fmt = fmt
        if not fmt:
            self._fmt = "{0:10.3f}s {1:4.5f}% done - {2:8} blocks left - {3:4.5f} blocks/s - {4:4.5f}s left"

    def start(self):
        self._start_time = time.monotonic()

    def update(self, block, total=None):
        if not self._start_time:
            self.start()

        if not total:
            total = self._total
        if self.should_report(block):
            super(TimedProgressReporter, self)._update_progress(block, total)
            self._now = time.monotonic()
            self._passed = self._now - self._start_time
            self._left = total - block
            self._performance = float(block) / self._passed
            self._forecast_left = self._left / self._performance
            self._last_message = self._fmt.format(
                self._passed,
                self._percent,
                self._left,
                self._performance,
                self._forecast_left,
            )
            print(self._last_message)
