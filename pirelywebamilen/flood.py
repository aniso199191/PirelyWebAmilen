"""洪水回弹：把每秒上百次的请求原路弹回去。

思路（不含核心评分逻辑，属于可开源的壳）：

* 正常用户 1 秒最多几十次请求，超过 100 次就只可能是脚本；
* 第一次越线不返回内容，直接 302 到 ``http://127.0.0.1/``——让脚本去打自己的本机；
* 继续加码（>=300/s）就不再陪它玩，302 到诱饵站，同时可回调 ``on_flood`` 做封禁。

这里只做计数与跳转，不做封禁决策：封不封由调用方决定。
"""
from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field

LOOPBACK_REBOUND = "http://127.0.0.1/"


@dataclass
class FloodRebound:
    """按 IP 的秒级计数器。

    Parameters
    ----------
    per_second:
        1 秒内允许的请求数，达到即触发。
    decoy_after:
        1 秒内达到这个数就改用诱饵站，默认是 ``per_second * 3``。
    rebound_to:
        回弹目标，默认对方本机 ``http://127.0.0.1/``。
    decoy_to:
        诱饵站地址；为空时仍用 ``rebound_to``。
    max_ips:
        记录上限，超过就整体清空，避免被海量伪造 IP 撑爆内存。
    """

    per_second: int = 100
    decoy_after: int = 0
    rebound_to: str = LOOPBACK_REBOUND
    decoy_to: str = ""
    max_ips: int = 20000
    _hits: dict[str, deque] = field(default_factory=lambda: defaultdict(deque), repr=False)

    def __post_init__(self) -> None:
        if self.per_second < 1:
            raise ValueError("per_second must be >= 1")
        if self.decoy_after <= 0:
            self.decoy_after = self.per_second * 3

    def _window(self, q: deque, now: float, seconds: float = 1.0) -> int:
        while q and now - q[0] > seconds:
            q.popleft()
        return len(q)

    def check(self, ip: str, now: float | None = None) -> str | None:
        """记录一次请求；返回跳转目标，正常放行返回 ``None``。"""
        now = time.monotonic() if now is None else now
        if len(self._hits) > self.max_ips:
            self._hits.clear()
        q = self._hits[ip]
        q.append(now)
        n = self._window(q, now)
        if n < self.per_second:
            return None
        if n < self.decoy_after:
            return self.rebound_to
        return self.decoy_to or self.rebound_to

    def reset(self, ip: str | None = None) -> None:
        if ip is None:
            self._hits.clear()
        else:
            self._hits.pop(ip, None)
