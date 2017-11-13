#Parse through IDS rules from given path to find content rules
def getRules(rule_path):
	ruleset = []
	rule_file = open(rule_path, "r") 
	for line in rule_file: 
		 splitline = line.split("; ")
		 for word in splitline:
		 	if word.startswith("content"):
		 		splitword = word.split(":")
		 		rule = splitword[1]
		 		ruleset.append(rule)
	return ruleset

#Create a count of all of the different rule lengths
def countRuleLengths(ruleset):
	ruleCounts = [0] * 40
	for rule in ruleset:
		while len(ruleCounts) <= len(rule):
		  ruleCounts.append(0)
		ruleCounts[len(rule)] += 1 
	grouped_counts = []
	for x in range(1, len(ruleCounts), 10):
		grouped_counts.append(sum(ruleCounts[x:x+10]))
	    
	return grouped_counts

#Split a given string into all of it's n-sized tokens
def tokenizeString(input_string, n):
	arr = []
	length = len(input_string)
 	for i in range(length):
 		if (i+n <= length):
 			arr.append((input_string[i:i+n]))
 	return arr

#Split all of the content rules into each of their n-sized tokens- also track which rules are rejected on account of being smaller than n
def tokenizeRuleset(rule_path, num):
	ruleset = getRules(rule_path)
	rejectedRules = []
	rule_tokens = set()
	for rule in ruleset:
		if (len(rule) < num):
			rejectedRules.append(rule)
			continue
		rule_substrings = tokenizeString(rule, num)
		rule_tokens.update(rule_substrings)
	return [rule_tokens, rejectedRules]

#Incorparate all of the methods to return effectiveness of rule detection
with open("rules.txt", "wt") as f:
	rule_results = getRules("http_rules.txt")
	rule_counts = countRuleLengths(rule_results)
	for i in range(1, len(rule_counts)):
		f.write("%d rules with length of %d-%d \n" %(rule_counts[i], ((i-1)*10)+1, i*10 ))
