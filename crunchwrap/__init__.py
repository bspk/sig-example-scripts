def hardwrap(src, space = 2, width = 68):
    lines = src.split('\n') # split existing lines
    out = [] # output buffer
    for l in lines:
        lout = [] # internal output buffer
        if len(l) > width:
            ll = l[slice(width - 1)] # leave room for a backslash
            lout.append(ll)
            l = l[slice(width - 1, len(l))]
            while len(l) > width: # the middle leaves room for spaces, too
                ll = l[slice(width - 1 - space)]
                lout.append(ll)
                l = l[slice(width - 1 - space, len(l))]
            lout.append(l) # add the last bits
        else:
            lout.append(l)
        out.append(('\\\n' + (' ' * space)).join(lout))
    return ('\n').join(out)

def softwrap(src, space = 2, width = 68, breakon = '; ', minfill=  0):
    lines = src.split('\n') # split existing lines
    out = [] # output buffer
    for l in lines:
        lout = [] # internal output buffer
        if len(l) > width:
            ll = l[slice(width - 1)] # leave room for a backslash
            # find if there's a better place to break
            br = max([ll.rfind(ch, minfill) for ch in breakon])
            if br > -1:
                if ll[br] == ' ':
                    br = br + 1 # capture the space
                ll = l[slice(br)] # re-slice
            else:
                br = width - 1 # no match found, use the default
            lout.append(ll)
            l = l[slice(br, len(l))]
            while len(l) > width: # the middle leaves room for spaces, too
                ll = l[slice(width - 1 - space)]
                # find if there's a better place to break
                br = max(map(ll.rfind, breakon))
                if br > -1:
                    if ll[br] == ' ':
                        br = br + 1 # capture the space
                    ll = l[slice(br)] # re-slice
                else:
                    br = width - 1 - space # no match found, use the default
                lout.append(ll)
                l = l[slice(br, len(l))]
            lout.append(l) # add the last bits
        else:
            lout.append(l)
        out.append(('\\\n' + (' ' * space)).join(lout))
    return ('\n').join(out)

