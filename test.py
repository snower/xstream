# -*- coding: utf-8 -*-
# 2015/8/23
# create by: snower
def xor_string(key, data, encrypt=True):
    if isinstance(key, basestring):
        key = ord(key[0])
    result = []
    for c in data:
        r = ord(c) ^ key
        result.append(chr(r))
        key = r if encrypt else ord(c)
    return "".join(result)

print xor_string('a', 'sdgdgsfbsfbsfs')
print xor_string('a', xor_string('a', 'fhfdfswrhds'), False)