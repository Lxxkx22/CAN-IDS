# 硬编码的周期性ID白名单
self._periodic_whitelist = {
    '0x0018': {
        'expected_intervals': [200],
        'tolerance': 19,
        'description': '周期性消息 (平均间隔: 199.9ms)'
    },
    '0x0034': {
        'expected_intervals': [1000],
        'tolerance': 100,
        'description': '周期性消息 (平均间隔: 1000.0ms)'
    },
    '0x0042': {
        'expected_intervals': [1000],
        'tolerance': 100,
        'description': '周期性消息 (平均间隔: 1000.0ms)'
    },
    '0x0043': {
        'expected_intervals': [1000],
        'tolerance': 100,
        'description': '周期性消息 (平均间隔: 1000.0ms)'
    },
    '0x0044': {
        'expected_intervals': [1000],
        'tolerance': 100,
        'description': '周期性消息 (平均间隔: 1000.0ms)'
    },
    '0x0050': {
        'expected_intervals': [200],
        'tolerance': 19,
        'description': '周期性消息 (平均间隔: 199.9ms)'
    },
    '0x0080': {
        'expected_intervals': [10],
        'tolerance': 1,
        'description': '周期性消息 (平均间隔: 10.0ms)'
    },
    '0x0081': {
        'expected_intervals': [10],
        'tolerance': 1,
        'description': '周期性消息 (平均间隔: 10.0ms)'
    },
    '0x00A0': {
        'expected_intervals': [99, 100, 98],
        'tolerance': 10,
        'description': '周期性消息 (平均间隔: 100.0ms)'
    },
    '0x00A1': {
        'expected_intervals': [99, 100],
        'tolerance': 10,
        'description': '周期性消息 (平均间隔: 100.0ms)'
    },
    '0x0110': {
        'expected_intervals': [100],
        'tolerance': 10,
        'description': '周期性消息 (平均间隔: 100.0ms)'
    },
    '0x0120': {
        'expected_intervals': [200],
        'tolerance': 20,
        'description': '周期性消息 (平均间隔: 200.0ms)'
    },
    '0x0165': {
        'expected_intervals': [10],
        'tolerance': 1,
        'description': '周期性消息 (平均间隔: 10.0ms)'
    },
    '0x018F': {
        'expected_intervals': [10, 9, 11],
        'tolerance': 1,
        'description': '周期性消息 (平均间隔: 10.0ms)'
    },
    '0x0260': {
        'expected_intervals': [10, 9, 11],
        'tolerance': 1,
        'description': '周期性消息 (平均间隔: 10.0ms)'
    },
    '0x02A0': {
        'expected_intervals': [10, 9, 11],
        'tolerance': 1,
        'description': '周期性消息 (平均间隔: 10.0ms)'
    },
    '0x02B0': {
        'expected_intervals': [10],
        'tolerance': 1,
        'description': '周期性消息 (平均间隔: 10.0ms)'
    },
    '0x0316': {
        'expected_intervals': [10, 9, 11],
        'tolerance': 1,
        'description': '周期性消息 (平均间隔: 10.0ms)'
    },
    '0x0329': {
        'expected_intervals': [10, 9, 11],
        'tolerance': 1,
        'description': '周期性消息 (平均间隔: 10.0ms)'
    },
    '0x0350': {
        'expected_intervals': [20],
        'tolerance': 2,
        'description': '周期性消息 (平均间隔: 20.0ms)'
    },
    '0x0370': {
        'expected_intervals': [10],
        'tolerance': 1,
        'description': '周期性消息 (平均间隔: 10.0ms)'
    },
    '0x0382': {
        'expected_intervals': [20, 21, 19],
        'tolerance': 2,
        'description': '周期性消息 (平均间隔: 20.0ms)'
    },
    '0x043F': {
        'expected_intervals': [10],
        'tolerance': 1,
        'description': '周期性消息 (平均间隔: 10.0ms)'
    },
    '0x0440': {
        'expected_intervals': [10],
        'tolerance': 1,
        'description': '周期性消息 (平均间隔: 10.0ms)'
    },
    '0x04F0': {
        'expected_intervals': [20, 19, 21],
        'tolerance': 2,
        'description': '周期性消息 (平均间隔: 20.0ms)'
    },
    '0x04F1': {
        'expected_intervals': [100],
        'tolerance': 10,
        'description': '周期性消息 (平均间隔: 100.0ms)'
    },
    '0x04F2': {
        'expected_intervals': [20, 21, 19],
        'tolerance': 2,
        'description': '周期性消息 (平均间隔: 20.0ms)'
    },
    '0x0510': {
        'expected_intervals': [100],
        'tolerance': 10,
        'description': '周期性消息 (平均间隔: 100.0ms)'
    },
    '0x0517': {
        'expected_intervals': [200, 201, 199],
        'tolerance': 20,
        'description': '周期性消息 (平均间隔: 200.0ms)'
    },
    '0x051A': {
        'expected_intervals': [200, 199, 201],
        'tolerance': 20,
        'description': '周期性消息 (平均间隔: 200.0ms)'
    },
    '0x0545': {
        'expected_intervals': [10, 11, 9],
        'tolerance': 1,
        'description': '周期性消息 (平均间隔: 10.0ms)'
    },
    '0x0587': {
        'expected_intervals': [100],
        'tolerance': 10,
        'description': '周期性消息 (平均间隔: 100.0ms)'
    },
    '0x059B': {
        'expected_intervals': [100, 101, 99],
        'tolerance': 10,
        'description': '周期性消息 (平均间隔: 100.0ms)'
    },
    '0x05E4': {
        'expected_intervals': [100, 99, 101],
        'tolerance': 10,
        'description': '周期性消息 (平均间隔: 100.0ms)'
    },
    '0x05F0': {
        'expected_intervals': [200],
        'tolerance': 20,
        'description': '周期性消息 (平均间隔: 200.0ms)'
    },
    '0x0690': {
        'expected_intervals': [100, 99, 101],
        'tolerance': 10,
        'description': '周期性消息 (平均间隔: 100.0ms)'
    },
}
