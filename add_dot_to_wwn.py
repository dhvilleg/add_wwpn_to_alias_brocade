if __name__ == '__main__':
    count_leters = 1
    count_lines = 0
    wwn_final = ""
    f = open("wwns.conf")
    for i in f:
        for e in i:
            wwn_final += e
            if count_lines < 7:
                if count_leters == 2:
                    wwn_final += ':'
                    count_leters = 0
                    count_lines += 1
            count_leters += 1
        count_lines = 0
        count_leters = 1
    print(wwn_final)