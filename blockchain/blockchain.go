package blockchain

import (
	"time"
	"errors"
	"bytes"
	"sort"
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
	"os"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	mrand "math/rand"
)

type BlockChain struct {
	DB *sql.DB					// Pointer to the database to add to and from which takes blocks
}

type Block struct {
	Nonce uint64				// Confirmation result
	Difficulty uint8			// Block difficulty
	CurrHash []byte				// Hash of current block
	PrevHash []byte				// Hash of previous block
	Transactions []Transaction	// User Transaction
	Mapping map[string]uint64	// User Balance
	Miner string				// User who mined block
	Signature []byte			// Miner signature pointing to CurrHash
	TimeStamp string			// TimeStamp of block creation
}

type Transaction struct {
	RandBytes []byte            // Random bytes
	PrevBlock []byte 			// Hash of last block
	Sender string				// Sender's name
	Receiver string				// Receiver's name
	Value uint64				// The amount of money transferred to the receiver
	ToStorage uint64			// The amount of money transferred to the storage
	CurrHash []byte 			// Current transaction hash
	Signature []byte 			// Sender's signature
}

type User struct {
	PrivateKey *rsa.PrivateKey  // Private Key of User
}

const (
	CREATE_TABLE = `
	CREATE TABLE BlockChain (
		Id INTEGER PRIMARY KEY AUTOINCREMENT,
		Hash VARCHAR(44) UNIQUE,
		Block TEXT
	);
	`
)

const (
	GENESIS_BLOCK = "GENESIS-BLOCK"
	STORAGE_VALUE = 100
	GENESIS_REWARD = 100
	STORAGE_CHAIN = "STORAGE-CHAIN"
)

const (
	DIFFICULTY = 20
)

const (
	RAND_BYTES = 32
	START_PERCENT = 10
	STORAGE_REWARD = 1
)

const (
	TXS_LIMIT = 2   	// Defines the maximum number of transactions in one block.
)

const (
	DEBUG = true
)

const (
	KEY_SIZE = 512
)

// Creation of blockchain //
func NewChain(filename, receiver string) error {
	file, error := os.Create(filename)
	if error != nil {
		return error
	}
	file.Close()
	db, error := sql.Open("sqlite3", filename)
	if error != nil {
		return error
	}
	defer db.Close()
	_, error = db.Exec(CREATE_TABLE)
	chain := &BlockChain {
		DB : db,
	}
	genesis := &Block {
		PrevHash : []byte(GENESIS_BLOCK),
		Mapping : make(map[string]uint64),
		Miner : receiver,
		TimeStamp : time.Now().Format(time.RFC3339),
	}
	genesis.Mapping[STORAGE_CHAIN] = STORAGE_VALUE
	genesis.Mapping[receiver] = GENESIS_REWARD
	genesis.CurrHash = genesis.hash()
	chain.AddBlock(genesis)
	return nil
}

// Load function to use the already created blockchain//
func LoadChain(filename string) *BlockChain {
	db, error := sql.Open("sqlite3", filename)
	if error != nil {
		return nil
	}
	chain := &BlockChain{
		DB : db,
	}
	return chain
}

// Creates sample of block //
func NewBlock(miner string, prevHash []byte) *Block {
	return &Block {
		Difficulty : DIFFICULTY,
		PrevHash : prevHash,
		Miner : miner,
		Mapping : make(map[string]uint64),
	}
}

// Adding new block in DB //
func (chain *BlockChain) AddBlock(block *Block) {
	chain.DB.Exec("INSERT INTO BlockChain (Hash, Block) VALUES ($1, $2)",
		Base64Encode(block.CurrHash),
		SerializeBlock(block),
	)
}

func Base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func SerializeBlock(block *Block) string {
	jsonData, error := json.MarshalIndent(*block, "", "\t")
	if error != nil {
		return ""
	}
	return string(jsonData)
}

// After creating a block, user transactions need to be entered into it //
func NewTransaction(user *User, lasthash []byte, to string, value uint64) *Transaction {
	tx := &Transaction {
		RandBytes : GenerateRandomBytes(RAND_BYTES),
		PrevBlock : lasthash,
		Sender : user.Address(),
		Receiver : to,
		Value : value,
	}
	if value > START_PERCENT {
		tx.ToStorage = STORAGE_REWARD
	}
	tx.CurrHash = tx.hash()
	tx.Signature = tx.sign(user.Private())
	return tx
}

// Adding a transaction to the block //
func (block *Block) AddTransaction(chain *BlockChain, tx *Transaction) error {
	if tx == nil {
		return errors.New("tx is null")
	}
	if tx.Value == 0 {
		return errors.New("tx valuse = 0")
	}
	if tx.Sender != STORAGE_CHAIN && len(block.Transactions) == TXS_LIMIT {
		return errors.New("len tx = limit")
	}
	if tx.Sender != STORAGE_CHAIN && tx.Value > START_PERCENT && tx.ToStorage != STORAGE_REWARD {
		return errors.New("storage reward pass")
	}
	if !bytes.Equal(tx.PrevBlock, chain.LastHash()) {
		return errors.New("prev block in tx /= last hash in chain")
	}
	var balanceInChain uint64
	balanceInTX := tx.Value + tx.ToStorage
	if value, ok :=  block.Mapping[tx.Sender]; ok {
		balanceInChain = value
	} else {
		balanceInChain = chain.Balance(tx.Sender, chain.Size())
	}
	if balanceInTX > balanceInChain {
		return errors.New("incufficient funds")
	}
	block.Mapping[tx.Sender] = balanceInChain - balanceInTX
	block.addBalance(chain, tx.Receiver, tx.Value)
	block.addBalance(chain, STORAGE_CHAIN, tx.ToStorage)
	block.Transactions = append(block.Transactions, *tx)
	return nil
}

// User balance //
func (chain *BlockChain) Balance(address string, size uint64) uint64 {
	var (
		sblock string
		block *Block
		balance uint64
	)
	rows, error := chain.DB.Query("SELECT Block FROM BlockChain WHERE Id <= $1 ORDER BY Id DESC", size)
	if error != nil {
		return balance
	}
	defer rows.Close()
	for rows.Next() {
		rows.Scan(&sblock)
		block = DeserializeBlock(sblock)
		if value, ok := block.Mapping[address]; ok {
			balance = value
			break
		}
	}
	return balance
}

// Adds coins to user balance //
func (block *Block) addBalance(chain *BlockChain, receiver string, value uint64) {
	var balanceInChain uint64
	if v, ok := block.Mapping[receiver]; ok {
		balanceInChain = v
	} else {
		balanceInChain = chain.Balance(receiver, chain.Size())
	}
	block.Mapping[receiver] = balanceInChain + value
}

// Returns the number of blocks in the local database //
func (chain *BlockChain) Size() uint64 {
	var size uint64
	row := chain.DB.QueryRow("SELECT Id FROM BlockChain ORDER BY Id DESC")
	row.Scan(&size)
	return size
}

func DeserializeBlock(data string) *Block {
	var block Block
	error := json.Unmarshal([]byte(data), &block)
	if error != nil {
		return nil
	}
	return &block
}

// Converts the public key to a string //
func (user *User) Address() string {
	return StringPublic(user.Public())
}

func (user *User) Private() *rsa.PrivateKey {
	return user.PrivateKey
}

// _.?._sign_.?._ THERE WAS PEPE _.?._sign_.?._ //

// Concatenates the bytes of the object's fields, and then produces over the resulting hash value //
func (tx *Transaction) hash() []byte {
	return HashSum(bytes.Join(
		[][]byte {
			tx.RandBytes,
			tx.PrevBlock,
			[]byte(tx.Sender),
			[]byte(tx.Receiver),
			ToBytes(tx.Value),
			ToBytes(tx.ToStorage),
		},
		[]byte {},
	))
}

func (tx *Transaction) sign(priv *rsa.PrivateKey) []byte {
	return Sign(priv, tx.CurrHash)
}

// Translates the public key into a set of bytes, then applies base64 encoding to translate to a string // 
func StringPublic(pub *rsa.PublicKey) string {
	return Base64Encode(x509.MarshalPKCS1PublicKey(pub))
}

func (user *User) Public() *rsa.PublicKey {
	return &(user.PrivateKey).PublicKey
}

func HashSum(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

// Converts a number to a set of bytes //
func ToBytes(num uint64) []byte {
	var data = new(bytes.Buffer)
	error := binary.Write(data, binary.BigEndian, num)
	if error != nil {
		return nil
	}
	return data.Bytes()
}

// Signs the data based on the private key //
func Sign(priv *rsa.PrivateKey, data []byte) []byte {
	signature, error := rsa.SignPSS(rand.Reader, priv, crypto.SHA256, data, nil)
	if error != nil {
		return nil
	}
	return signature
}

// Returns a slice of pseudo-random bytes //
func GenerateRandomBytes(max uint) []byte {
	var slice []byte = make([]byte, max)
	_, error := rand.Read(slice)
	if error != nil {
		return nil
	}
	return slice
}

// After placing all transactions in a block, it must be confirmed // 
func (block *Block) Accept(chain *BlockChain, user *User, ch chan bool) error {
	if !block.transactionsIsValid(chain, chain.Size()) {
		return errors.New("transactions is not valid")
	}
	block.AddTransaction(chain, &Transaction {
		RandBytes : GenerateRandomBytes(RAND_BYTES),
		PrevBlock : chain.LastHash(), 
		Sender : STORAGE_CHAIN,
		Receiver : user.Address(),
		Value : STORAGE_REWARD,
	})
	block.TimeStamp = time.Now().Format(time.RFC3339)
	block.CurrHash = block.hash()
	block.Signature = block.sign(user.Private())
	block.Nonce = block.proof(ch)
	return nil
}

// Every single transaction is checked, its hash, sender's signature, and the balances of the sender and recipient by block state //
func (block *Block) transactionsIsValid(chain *BlockChain, size uint64) bool {
	lentxs := len(block.Transactions)
	plusStorage := 0
	for i := 0; i < lentxs; i++ {
		if block.Transactions[i].Sender == STORAGE_CHAIN {
			plusStorage = 1
			break
		}
	}
	if lentxs == 0 || lentxs > TXS_LIMIT + plusStorage {
		return false
	}
	for i := 0; i < lentxs - 1; i++ {
		for j := i + 1; j < lentxs; j++ {
			if bytes.Equal(block.Transactions[i].RandBytes,
				block.Transactions[j].RandBytes) {
					return false
				}
			if block.Transactions[i].Sender == STORAGE_CHAIN &&
				block.Transactions[j].Sender == STORAGE_CHAIN {
					return false
				}
		}
	}
	for i := 0; i < lentxs; i++ {
		tx := block.Transactions[i]
		if tx.Sender == STORAGE_CHAIN {
			if tx.Receiver != block.Miner || tx.Value != STORAGE_REWARD {
				return false
			}
		} else {
			if !tx.hashIsValid() {
				return false
			}
			if !tx.signIsValid() {
				return false
			}
		}
		if !block.balanceIsValid(chain, tx.Sender, size) {
			return false
		}
		if !block.balanceIsValid(chain, tx.Receiver, size) {
			return false
		}
	}
	return true
}

// All transaction hashing
func (block *Block) hash() []byte {
	var tempHash []byte
	for _, tx := range block.Transactions {
		tempHash = HashSum(bytes.Join(
			[][]byte{
				tempHash,
				tx.CurrHash,
			},
			[]byte {},
		))
	}
	var list []string 
	for hash := range block.Mapping {
		list = append(list, hash)
	}
	sort.Strings(list)
	for _, hash := range list {
		tempHash = HashSum(bytes.Join(
			[][]byte {
				tempHash,
				[]byte(hash),
				ToBytes(block.Mapping[hash]),
			},
			[]byte {},
		))
	}
	return HashSum(bytes.Join(
		[][]byte {
			tempHash,
			ToBytes(uint64(block.Difficulty)),
			block.PrevHash,
			[]byte(block.Miner),
			[]byte(block.TimeStamp),
		},
		[]byte {},
	))
}

func (block *Block) sign(priv *rsa.PrivateKey) []byte {
	return Sign(priv, block.CurrHash)
}

func (block *Block) proof(ch chan bool) uint64 {
	return ProofOfWork(block.CurrHash, block.Difficulty, ch)
}

func (tx *Transaction) hashIsValid() bool {
	return bytes.Equal(tx.hash(), tx.CurrHash)
}

func (tx *Transaction) signIsValid() bool {
	return Verify(ParsePublic(tx.Sender), tx.CurrHash, tx.Signature) == nil
}

// Checks the compatibility of data stored in transactions with data that is stored in the state at the specified user name //
func (block *Block) balanceIsValid(chain *BlockChain, address string, size uint64) bool {
	if _, ok := block.Mapping[address]; !ok {
		return false
	}
	lentxs := len(block.Transactions)
	balanceInChain := chain.Balance(address, size)
	balanceSubBlock := uint64(0)
	balanceAddBlock := uint64(0)
	for j := 0; j < lentxs; j++ {
		tx := block.Transactions[j]
		if tx.Sender == address {
			balanceSubBlock += tx.Value + tx.ToStorage
		}
		if tx.Receiver == address {
			balanceAddBlock += tx.Value
		}
		if STORAGE_CHAIN == address {
			balanceAddBlock += tx.ToStorage
		}
	}
	if (balanceInChain + balanceAddBlock - balanceSubBlock) != 
	block.Mapping[address] {
		return false
	}
	return true
}


func ProofOfWork(blockHash []byte, difficulty uint8, ch chan bool) uint64 {
	var (
		Target = big.NewInt(1)
		intHash = big.NewInt(1)
		nonce = uint64(mrand.Intn(math.MaxUint32))
		hash []byte
	)
	Target.Lsh(Target, 256 - uint(difficulty))
	for nonce < math.MaxUint64 {
		select {
		case <- ch:
			if DEBUG {
				fmt.Println()
			}
			return nonce
		default:
		hash = HashSum(bytes.Join(
			[][]byte {
				blockHash,
				ToBytes(nonce),
			},
			[]byte {},
		))
		if DEBUG {
			fmt.Printf("\rMining: %s", Base64Encode(hash))
		}
		intHash.SetBytes(hash)
		if intHash.Cmp(Target) == -1 {
			if DEBUG {
				fmt.Println()
			}
			return nonce
		}
		nonce++
		}
	
	}
	return nonce
}


// Uses the public key to verify signed data with initial //
func Verify(pub *rsa.PublicKey, data, sign []byte) error {
	return rsa.VerifyPSS(pub, crypto.SHA256, data, sign, nil)
}

func ParsePublic(pubData string) *rsa.PublicKey {
	pub, error := x509.ParsePKCS1PublicKey(Base64Decode(pubData))
	if error != nil {
		return nil
	}
	return pub
}

// Changes the seed of the pseudo-random number generator, from the math/rand package, current time calculation method //
func init() {
	mrand.Seed(time.Now().UnixNano())
}

func Base64Decode(data string) []byte {
	result, error := base64.StdEncoding.DecodeString(data)
	if error != nil {
		return nil
	}
	return result
}

func GeneratePrivate(bits uint) *rsa.PrivateKey {
	priv, error := rsa.GenerateKey(rand.Reader, int(bits))
	if error != nil {
		return nil
	}
	return priv
}

func StringPrivate(priv *rsa.PrivateKey) string {
	return Base64Encode(x509.MarshalPKCS1PrivateKey(priv))
}

func ParsePrivate(privData string) *rsa.PrivateKey {
	priv, error := x509.ParsePKCS1PrivateKey(Base64Decode(privData))
	if error != nil {
		return nil
	}
	return priv 
}

func NewUser() *User {
	return &User {
		PrivateKey : GeneratePrivate(KEY_SIZE),
			}
}

func LoadUser(purse string) *User {
	priv := ParsePrivate(purse)
	if priv == nil {
		return nil
	}
	return &User {
		PrivateKey : priv,
	}
}

func (user *User) Purse() string {
	return StringPrivate(user.Private())
}

func (chain *BlockChain) LastHash() []byte {
	var hash string
	row := chain.DB.QueryRow("SELECT Hash FROM BlockChain ORDER BY Id DESC")
	row.Scan(&hash)
	return Base64Decode(hash)
}

func (block *Block) IsValid(chain *BlockChain, size uint64) bool {
	switch {
	case block == nil:
		return false
	case block.Difficulty != DIFFICULTY:
		return false
	case !block.hashIsValid(chain, size):
		return false
	case !block.signIsValid():
		return false
	case !block.proofIsValid():
		return false
	case !block.mappingIsValid():
		return false
	case !block.timeIsValid(chain):
		return false
	case !block.transactionsIsValid(chain, size):
		return false
	}
	return true
}

func SerializeTX(tx *Transaction) string {
	jsonData, error := json.MarshalIndent(*tx, "", "\t")
	if error != nil {
		return ""
	}
	return string(jsonData)
}

func DeserializeTX(data string) *Transaction {
	var tx Transaction
	error := json.Unmarshal([]byte(data), &tx)
	if error != nil {
		return nil
	}
	return &tx
}

/*****************************************************************************************
Checks the hash of the current block passed through the hash method with a hash,
stored in the block field. Also checks the hash of the previous block from the blockchain
with a hash stored in the block field by obtaining its ID from the database. returns
false if an error is encountered, otherwise true
******************************************************************************************/
func (block *Block) hashIsValid(chain *BlockChain, size uint64) bool {
	if !bytes.Equal(block.hash(), block.CurrHash) {
		return false
	}
	var id uint64
	row := chain.DB.QueryRow("SELECT Id FROM BlockChain WHERE Hash = $1",
			Base64Encode(block.PrevHash))
	row.Scan(&id)
	return id == size
}

func (block *Block) signIsValid() bool {
	return Verify(ParsePublic(block.Miner), block.CurrHash, block.Signature) == nil
}

// Checks the correct operation using the Nonce fields specified in the block and CurrHash with Difficulty complexity //
func (block *Block) proofIsValid() bool {
	intHash := big.NewInt(1)
	Target := big.NewInt(1)
	hash := HashSum(bytes.Join(
		[][]byte {
			block.CurrHash,
			ToBytes(block.Nonce),
		},
		[]byte {},
	))
	intHash.SetBytes(hash)
	Target.Lsh(Target, 256 - uint(block.Difficulty))
	if intHash.Cmp(Target) == -1 {
		return true
	}
	return false
}


// Checks the state of the block for users who are not indicated in transactions //
func (block *Block) mappingIsValid() bool {
	for hash := range block.Mapping {
		if hash == STORAGE_CHAIN {
			continue
		}
		flag := false
		for _, tx := range block.Transactions {
			if tx.Sender == hash || tx.Receiver == hash {
				flag = true
				break
			}
		}
		if !flag {
			return false
		}
	}
	return true
}

func (block *Block) timeIsValid(chain *BlockChain) bool {
	btime, error := time.Parse(time.RFC3339, block.TimeStamp)
	if error != nil {
		return false
	}
	diff := time.Now().Sub(btime)
	if diff < 0 {
		return false
	}
	var sblock string
	row := chain.DB.QueryRow("SELECT Block FROM BlockChain WHERE Hash = $1",
			Base64Encode(block.PrevHash))
	row.Scan(&sblock)
	lblock := DeserializeBlock(sblock)
	if lblock == nil {
		return false
	}
	ltime, error := time.Parse(time.RFC3339, lblock.TimeStamp)
	if error != nil {
		return false
	}
	result := btime.Sub(ltime)
	return result > 0
}