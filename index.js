const ethers = require("ethers")
const abi = require("./abi.json")
require("dotenv").config()

const priv_key = process.env.PRIVATE_KEY
const api_key = process.env.API_KEY

provider = new ethers.InfuraProvider("sepolia", api_key)
const wallet = new ethers.Wallet(priv_key, provider)

//0x686d5e23b01260f0708ebe65ce0a81dfed44f010 - sepolia
const sepolia_sender_contract = new ethers.Contract("0x686d5e23b01260f0708ebe65ce0a81dfed44f010", abi, wallet)

async function main() {
    const proof = {
        a: [
            "0x004eca896b8dbf2189265e3f439dcd9bafaeb51f09cd89914f1228b5b56b337a",
            "0x0f66bd7acc441fa3e5fa8deca1cba6f57ebff3179699b99de0ea3ff00a5f4537"
          ],
        b:  [
            [
              "0x16552f5be5c790217011a31b586e94b7391cdaa7d9481fe5764cfbfa31a208eb",
              "0x17265c3cf723cb7de70b4f6747042196f1fa84d26a1a16c2908f464dfd98da5c"
            ],
            [
              "0x2138b989fa9b84083af6418c23937f80a7948c795ea6b29cf44cc706c1510dd1",
              "0x2fcdebe67724d70e8ee66f3e0e77cde057ca67f44133e5c24ab7f4d6716a9f1c"
            ]
          ],
        c: [
            "0x0affa3f1bad2df2f8a21ffba3b550008871abc7ee82a0632c5e933d263628e1b",
            "0x10d325481d32a952678b882379308eef80c80eef699232ff9de696c9870ad954"
          ]
    }

    const tx = await sepolia_sender_contract.sendMessagePayLINK(BigInt("14767482510784806043"), "0x425292CA710f1bc0DF6d778803f734450e6BC09a", proof);
    console.log(tx)
}

main()
