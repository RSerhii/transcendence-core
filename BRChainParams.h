//
//  BRChainParams.h
//
//  Created by Aaron Voisine on 1/10/18.
//  Copyright (c) 2019 breadwallet LLC
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.

#ifndef BRChainParams_h
#define BRChainParams_h

#include "BRMerkleBlock.h"
#include "BRPeer.h"
#include "BRSet.h"
#include "BRPeer.h"
#include <assert.h>

typedef struct {
    uint32_t height;
    UInt256 hash;
    uint32_t timestamp;
    uint32_t target;
} BRCheckPoint;

typedef struct {
    const char * const *dnsSeeds; // NULL terminated array of dns seeds
    uint16_t standardPort;
    uint32_t magicNumber;
    uint64_t services;
    int (*verifyDifficulty)(const BRMerkleBlock *block, const BRSet *blockSet); // blockSet must have last 2016 blocks
    const BRCheckPoint *checkpoints;
    size_t checkpointsCount;
} BRChainParams;

static const char *BRMainNetDNSSeeds[] = {
"209.182.216.144","198.13.50.121",NULL
};

static const char *BRTestNetDNSSeeds[] = {
    "testnet-seed.bitcoin.jonasschnelli.ch.", "seed.testnet.bitcoin.sprovoost.nl.",
    "testnet-seed.bluematt.me.", NULL
};

// blockchain checkpoints - these are also used as starting points for partial chain downloads, so they must be at
// difficulty transition boundaries in order to verify the block difficulty at the immediately following transition
static const BRCheckPoint BRMainNetCheckpoints[] = {
{0,uint256("0000041e482b9b9691d98eefb48473405c0b8ec31b76df3797c74a78680ef818"), 1454124731,0x1e0ffff0},
{30000,uint256("925782a994fc03f1d17fdfd25a17f1623c11270596d5642f2d9221f8e0886285"), 1528353748,0x1b1ab8f8},
{60000,uint256("81d0ba09d4e32412c0031269d49c355cf740efec788880066cddb3b91c6167ec"), 1529646817,0x1b2bf51c},
{90000,uint256("fea56aa1fda3a58414fc76e0ced334ab1824c4d948b80fa94559366d9ca65dac"), 1530936420,0x1b0c76e6},
{120000,uint256("7b767fbcb20f32baaeb456138f1cc6ecb5bbe37dd93726ec81b6e6ac6091517e"), 1532289807,0x1b0ff266},
{150000,uint256("1a9d9e2ee87e546cbbc152add82b5d5fbfd6233788531c325a76ea587c4be5b9"), 1533642839,0x1b07bd52},
{180000,uint256("688a5f8eba9dced67e8febf7857ffddb6aca0e0e0e5920415e0a023988d6be54"), 1534988979,0x1b05fc96},
{210000,uint256("1371b59c352906da314afb0831bedb43c49811162a40c75cc32cb643cc4caa11"), 1536341669,0x1b042d0b},
{240000,uint256("eba134bac12524ed80842b972c9a11ce836de706f7fb4997176e11ebd564258f"), 1537673093,0x1b03d565},
{270000,uint256("0fa8471b9f410306a033fe568dbe6d85388223d8cc933d9562d2125acf31b43d"), 1539027403,0x1b024a9f},
{300000,uint256("7fbc18479405c1f96139668ccef172cb63e037e805460115458fef54cc2030cc"), 1540382914,0x1b0349ba},
{330000,uint256("b028cec7eac86d3897e01426ddddee384e2347a79b26070011c5078e384dcf5d"), 1541731855,0x1b02036b},
{360000,uint256("6352889333b74c7a26ef502d0c216049f08bb5f3b9e6cf4ca089333d6babb4ea"), 1543083997,0x1b029d66},
{390000,uint256("521acc3d8221531a32fb8d17f8ba7db0f4a01122a8e008b19988cedd4cf7d33f"), 1544435144,0x1b02a25f},
{420000,uint256("1626aa82a45b308f81d30b3e21ba4cb0bff807a6152e663d97a5d31238dd721f"), 1545788998,0x1b01e674},
{450000,uint256("e77b392996aaaec4ffc77caf8a1b93ec19b0e0eee1fc44538f9bec534f65adfb"), 1547144623,0x1b016f83},
{480000,uint256("ce722cadb9b90b542600e2a951ed7e1e5ad1a8fdf1079a71909b5a1e11c5e751"), 1548501148,0x1b01b016},
{510000,uint256("93cc1834c4531631d23a2955bf2eba4d8e61e42e0454535c25efc0bc1473e4af"), 1549857564,0x1b01846f},
{540000,uint256("bda6dbd4cade4f8654474ca067b9a01be203bd8b82fc0bc7c9f9484f23a098f7"), 1551214838,0x1b01b562},
{570000,uint256("12fcb69e36a0fb6440823f16b3776ff47a3561cd23e2294af2ea5b7190cf4be7"), 1552573278,0x1b0185ee},
{600000,uint256("c6c87c5f70578ebb270012492e0dd222d6532a864853beefc894840aad73f021"), 1553928645,0x1b013ff4},
{630000,uint256("d9f475e5452757948f25afff4575b1553dcb8eb9608fb1616bf826b2f2836b0d"), 1555281592,0x1b01334c},
{660000,uint256("c72610ab61c49b54b2c86169cf66550d3532d7c98d84fe5d1e7fe67c46d044e2"), 1556635221,0x1b014bac},
{690000,uint256("b08fd0a54973888d4e092bc086f86dffdfc7f3a312742cf56a20e915e669ced2"), 1557991484,0x1b016382},
{720000,uint256("dc3a60b38113319f9df466e5990769bd27aa4cc73a56f8936286b754f5d4a9d6"), 1559348284,0x1b017d7e},
{750000,uint256("3a2e428b060c18f7be194a7ac9ad88d89c476c18581b16edb548909008ba839c"), 1560702280,0x1b010a69},
{780000,uint256("5e17b957553f8972e6f835be2c9eb3c0b43d5bde2de6224b80b0021e503d1e50"), 1562058748,0x1b010d69},
{810000,uint256("53ad9ac26c69b53c19b3c13593276121349f4c196aecbc3cc6e9e85498dc05ea"), 1563416315,0x1b00f407},
{840000,uint256("731c8bf731a24d52f0150136907824f03ef7b474b6d16439f2a6cb7298c23347"), 1564773156,0x1b010c66},
{870000,uint256("d13a9d6a1cf9be78aa4d22968411b1de7d32b1b441d028f1db6dc4b403f5b04b"), 1566130662,0x1b0126f6},
{900000,uint256("23614a26ae6b3e457eec08dde3ad04ff15b0ca4e0ec3e8acf0c4c153beb997eb"), 1567484888,0x1b0109f5},
{930000,uint256("e957258eb9659fc970da995bff635710be375a883811b01e06b647bd095f1538"), 1568937621,0x1b019d70},
{956036,uint256("0105895a1bf9de5792bbdb0937db831342f97758d9909a8d23583f13613ab60f"), 1570115947,0x1b0154f2}
};

static const BRCheckPoint BRTestNetCheckpoints[] = {
    {       0, uint256("000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"), 1296688602, 0x1d00ffff },
    {  100800, uint256("0000000000a33112f86f3f7b0aa590cb4949b84c2d9c673e9e303257b3be9000"), 1376543922, 0x1c00d907 },
    {  201600, uint256("0000000000376bb71314321c45de3015fe958543afcbada242a3b1b072498e38"), 1393813869, 0x1b602ac0 },
    {  302400, uint256("0000000000001c93ebe0a7c33426e8edb9755505537ef9303a023f80be29d32d"), 1413766239, 0x1a33605e },
    {  403200, uint256("0000000000ef8b05da54711e2106907737741ac0278d59f358303c71d500f3c4"), 1431821666, 0x1c02346c },
    {  504000, uint256("0000000000005d105473c916cd9d16334f017368afea6bcee71629e0fcf2f4f5"), 1436951946, 0x1b00ab86 },
    {  604800, uint256("00000000000008653c7e5c00c703c5a9d53b318837bb1b3586a3d060ce6fff2e"), 1447484641, 0x1a092a20 },
    {  705600, uint256("00000000004ee3bc2e2dd06c31f2d7a9c3e471ec0251924f59f222e5e9c37e12"), 1455728685, 0x1c0ffff0 },
    {  806400, uint256("0000000000000faf114ff29df6dbac969c6b4a3b407cd790d3a12742b50c2398"), 1462006183, 0x1a34e280 },
    {  907200, uint256("0000000000166938e6f172a21fe69fe335e33565539e74bf74eeb00d2022c226"), 1469705562, 0x1c00ffff },
    { 1008000, uint256("000000000000390aca616746a9456a0d64c1bd73661fd60a51b5bf1c92bae5a0"), 1476926743, 0x1a52ccc0 },
    { 1108800, uint256("00000000000288d9a219419d0607fb67cc324d4b6d2945ca81eaa5e739fab81e"), 1490751239, 0x1b09ecf0 },
    { 1209600, uint256("0000000000000026b4692a26f1651bec8e9d4905640bd8e56056c9a9c53badf8"), 1507353706, 0x1973e180 },
    { 1310400, uint256("0000000000013b434bbe5668293c92ef26df6d6d4843228e8958f6a3d8101709"), 1527063804, 0x1b0ffff0 },
    { 1411200, uint256("00000000000000008b3baea0c3de24b9333c169e1543874f4202397f5b8502cb"), 1535560970, 0x194ac105 }
};

static int BRMainNetVerifyDifficulty(const BRMerkleBlock *block, const BRSet *blockSet) {
    return 1; // skip diff check for now
}

static int BRTestNetVerifyDifficulty(const BRMerkleBlock *block, const BRSet *blockSet) {
    return 1; // XXX skip testnet difficulty check for now
}

static const BRChainParams BRMainNetParams = {
    BRMainNetDNSSeeds,
    8765,                  // standardPort
    0x13fdc403,            // magicNumber
    0, // services
    BRMainNetVerifyDifficulty,
    BRMainNetCheckpoints,
    sizeof(BRMainNetCheckpoints)/sizeof(*BRMainNetCheckpoints)
};

static const BRChainParams BRTestNetParams = {
    BRTestNetDNSSeeds,
    18333,                 // standardPort
    0x0709110b,            // magicNumber
    0, // services
    BRTestNetVerifyDifficulty,
    BRTestNetCheckpoints,
    sizeof(BRTestNetCheckpoints)/sizeof(*BRTestNetCheckpoints)
};

#endif // BRChainParams_h
