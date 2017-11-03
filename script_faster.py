# -*- coding: utf-8 -*-

def readFile(path):

    pagefile = open(path, "r")
    return pagefile.read()


ruleset = readFile("http_rules.txt")
dataset = readFile("tcp4.txt")


def writeFile(path, contents):
    with open(path, "wt") as f:
        f.write(contents)


#contentsToWrite = "This is a test!"
#writeFile("attack.txt", contentsToWrite)


def equalcompare(ruleset,dataset): 
    datasetSet = set(dataset.split())
    print(datasetSet)
    rulesetSet = set(ruleset.split())
    final = datasetSet & rulesetSet
    return final

(equalcompare(ruleset,dataset))





def get_substrings(input_string,num,arr):
  length = len(input_string)
  for i in range(length): 
    for j in range(i,length): 
        if (len(input_string[i:j+1]) == num):
            arr.append((input_string[i:j+1]))
  return arr

#print(get_all_substrings(('abcde'),4,[]))

def tokenizecompare(num, ruleset,dataset):


    #load the malware

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

    
    #print(malware)

    init = 0
    
    rules = set()
    tempnum = num
    
    #this splits up the ruleset into fours!!! 
    for i in range(1,len(malware)):
        rules.add(''.join((malware[init:tempnum])))
        init = init+1
        tempnum = tempnum+1
    #print(rules)

  


    #count number of characters -> c
    datasetArr = [False]*(len(dataset))
    #print(datasetArr)

    data = []
        #splits up all the chars in the dataset textfile
    for word in dataset:
        for letter in word:
            data.append(letter)

    dat = set()
    init2 = 0
    num2 = num
    #this splits up the dataset into fours!!! 
    for j in range(1,len(data)):
        dat.add(''.join((data[init2:num2])))
        init2 = init2+1
        num2 = num2+1


    #so dat has the combination of all the DATASETS! 
    #rules has the combinatioes of all the RULESETS!

    hi = rules & dat
    #print("this is what's similar!: ")
    #print(hi)
    #print("\n")
    #print("this is how many chars are similar!!: ")
    #print(len(hi)*num)
    #print("\n")

    #print("this is how many words are similar!!: ")
    #print(len(hi))

    
    

(tokenizecompare(20, ruleset, dataset))


def reject(num, ruleset,dataset):


    malware = [] #everything with "content:__________"
    analyze = []
    reject =[]

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
            reject.append(word)
    #print("this is how many content strings we rejected!!: ")
    #print(len(reject))



(reject(32, ruleset, dataset))

