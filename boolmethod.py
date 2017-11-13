# -*- coding: utf-8 -*-

def readFile(path):

    pagefile = open(path, "r")
    return pagefile.read()




def compare(ruleset,unreaddataset, num): 

    dataset = readFile(unreaddataset)

    w = dataset #news source
    n = len(w) #len of the news source
    b = [False]*n 

    malware = []

    #extract all content and put it in a list called malware!!!
    ruleset = ruleset.split("; ")

    split = []
    #splits up into letters!!! 
    for word in ruleset:
        if word.startswith("content:"):
            split = (word.split(":"))
            content = split[1]
            for i in content: 
               malware.append(''.join(i))


    init = 0
    
    rules = set()
    tempnum = num
    
    #this splits up the ruleset into fours!!! 
    for i in range(1,len(malware)):
        word = (''.join((malware[init:tempnum])))
        rules.add(''.join((malware[init:tempnum])))
        init = init+1
        tempnum = tempnum+1

  

    data = []
        #splits up all the chars in the dataset textfile
    for word in dataset:
        for letter in word:
            data.append(letter)

    dat = set()
    tokensmatched = set()
    init2 = 0
    num2 = num
    i = 0
    #this splits up the dataset into fours!!! 
    for j in range(1,len(data)):
        word = ((''.join((data[init2:num2]))))
        dat.add(word)
        if word in rules: 
            tokensmatched.add(word)
            b[i] = True
        init2 = init2+1
        num2 = num2+1
        i = i+1



    r = 0 
    for i in range(len(b)):
        if b[i] == True:
            r = r+1

            
    
    print(unreaddataset + " char matched for " + str(num) + ": ")
    print(r)
    print("amount of tokens matched: " + str(len(tokensmatched)))
    
    print("total number of chars in the dataset: " + str(n))
    print("total number of tokens in the dataset: " + str(len(dat)))



ruleset = readFile("http_rules.txt")
nyt = ("nytimes.txt")
wsj = ("wsj.txt")
cnn = ("cnn.txt")

token = [4,8,16,32]

for i in range(len(token)): 
    compare(ruleset,nyt,token[i])
    compare(ruleset,wsj,token[i])
    compare(ruleset,cnn,token[i])


def reject(ruleset,unreaddataset, num):

    dataset = readFile(unreaddataset)

    malware = [] #everything with "content:__________"
    analyze = []
    rejected =[]

    #extract all content and put it in a list called malware!!!
    ruleset = ruleset.split("; ")


    for word in ruleset:
        if word.startswith("content:"):
            malware.append(word)

    

   #adds all the data past "content" into analyze!!!
    for i in range(len(malware)):
        analyze.append((malware[i].split(":"))[1])
    #print(len(analyze))

    for word in analyze: 
        if (len(word)<num):
            rejected.append(word)


    print(unreaddataset + " UNmatched for " + str(num) + ": ")
    print(len(rejected))    



for i in range(len(token)): 
    reject(ruleset,nyt,token[i])
    reject(ruleset,wsj,token[i])
    reject(ruleset,cnn,token[i])




