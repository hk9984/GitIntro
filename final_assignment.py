from DataSimulator import DataSimulator
import hashlib
import ECC


#The hash of the last block is stored as a global variable for the block linking according to the previous hash
hash_of_last_block = "0"

#blockchainStore actually stores all the blocks in the blockchain which are linked together
blockchainStore = []

#DataSimulator simulates an I/o interface
DataSim = DataSimulator()

#
blockHeadlinesDict = {}

validRoot=None

#verifiedHeadlines is the list of all headlines which have been verified through elliptive curve cryptography
verifiedHeadlines = []

#The method generateHash() computes the hash according to SHA-256 hashing algorithm
#It takes in the nonce, previous hash and the merkle root hash of the block calling this method
def generateHash(nonce, previousHash, merkle):
    h = hashlib.sha256()
    h.update(
        str(nonce).encode('utf-8') +
        str(previousHash).encode('utf-8') +
        str(merkle).encode('utf-8')
    )
    return h.hexdigest()


#class MerkleNode actually represents the leaf node of the merkle tree of each block
class MerkleNode:
    def __init__(self,hashValue=None,leftHash=None,rightHash=None):
        self.value = hashValue
        self.leftHash = leftHash
        self.rightHash = rightHash

    #the method merkleTreePath is used to save the whole merkle tree for each block
    #this method takes in the argument
    @staticmethod
    def merkleTreePath(listOfElement, posLeft, posRight):
        if posRight >= posLeft:
            if (posLeft == posRight):
                m = hashlib.sha256(str(listOfElement[posLeft]).encode())
                m = m.hexdigest()
                node = MerkleNode(m)
                return node
            middle = int((posLeft + posRight) / 2)
            leftHash = MerkleNode.merkleTreePath(listOfElement, posLeft, middle)
            rightHash = MerkleNode.merkleTreePath(listOfElement, middle + 1, posRight)
            m1 = hashlib.sha256((leftHash.value + rightHash.value).encode())
            m1=m1.hexdigest()
            node = MerkleNode(m1,leftHash,rightHash)
            return node

#Block is the basic data structure of the blocks in the blockchain
#previousHash: Hash of the previous block
#merkleRoot: Hash of the merkle root of the current block
#nonce: Nonce value of the current block
#hash: Hash of the current block
class Block:
    previousHash = 0
    merkleRoot = 0
    nonce = 0
    hash = 0

    def __init__(self):
        pass #default values have been provided for the parameters already

#Blockchain class signifies the actual blockchain
#the class consists of two methods:
#       1.)mineBlock(): this method mines the block by checking the hash value to start with 4 "0" hexadecimal digits (16 "0" binary digits)
#       2.)headlineValidation(): this method validates whether a user-provided headline has been put on the blockchain or not
class Blockchain:
                        
    def mineBlock(self, blockData):
        global hash_of_last_block
        minedBlock = Block()
        nonceTry = 0
        minedBlock_merkleRoot = MerkleNode.merkleTreePath(blockData, 0, len(blockData) - 1).value
        while (1):
            if (generateHash(nonceTry, hash_of_last_block, minedBlock_merkleRoot)[:4] == "0000"):
                minedBlock.previousHash = hash_of_last_block
                minedBlock.nonce = nonceTry
                minedBlock.merkleRoot = minedBlock_merkleRoot
                minedBlock.hash = generateHash(minedBlock.nonce, minedBlock.previousHash, minedBlock.merkleRoot)
                blockchainStore.append(minedBlock)
                hash_of_last_block = minedBlock.hash
                break
            
            else:
                nonceTry += 1

    def headlineValidation(self, headline):

        for blockNo in blockHeadlinesDict.keys():
            temp = blockHeadlinesDict[blockNo]

            for entry in temp:
                if headline == entry['msg']:
                    searchedBlockNo = blockNo

        validRoot = MerkleNode.merkleTreePath(blockHeadlinesDict[searchedBlockNo], 0,
                                              len(blockHeadlinesDict[searchedBlockNo]) - 1)
        for iter in range(len(blockchainStore)):
            if (blockchainStore[iter].merkleRoot == validRoot.value):
                print("\nThe provided headline has been put on the blockchain, at block number " + str(iter))
                return
        print("\nThe provided headline isn't present on the blockchain")


for i in range(6):
    Dsim = DataSim.getNewData()
    headlinesList = []
    for data in Dsim:
        publicKey = data['pk']
        message = data['msg']
        signature = data['signature']
        isVerified = ECC.verify(publicKey, message, signature)
        if (isVerified):
            headlinesList.append(data)
    blockHeadlinesDict[i]=headlinesList
    verifiedHeadlines.append(headlinesList)


blockchainObj = Blockchain()
for i in range(len(verifiedHeadlines)):
    blockchainObj.mineBlock(verifiedHeadlines[i])



#The details of each mined block have been shown for the sake of verification of the blockchain

for i in range(6):
    print("\n***********************************************************************")
    print("Block " + str(i) + "\nNonce: " + str(blockchainStore[i].nonce) +
          "\nMerkle Root Hash: " + str(blockchainStore[i].merkleRoot) +
          "\nPrevious Hash: " + str(blockchainStore[i].previousHash) +
          "\nBlock Hash: " + str(blockchainStore[i].hash))

#validation of a user-provided headline
inputHeadline = input("\nEnter headline you want to validate: ")
blockchainObj.headlineValidation(inputHeadline)

