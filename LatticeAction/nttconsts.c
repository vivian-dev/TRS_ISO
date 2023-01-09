#include <stdint.h>
#include "params.h"

#define QINV 4236238847 // -q^(-1) mod 2^32
#define MONT 4193792ULL
#define DIV (((MONT*MONT % Q) * (Q-1) % Q) * ((Q-1) >> 8) % Q)

const uint32_t _8xqinv[8] asm("_8xqinv") __attribute__((aligned(32)))
  = {QINV, QINV, QINV, QINV, QINV, QINV, QINV, QINV};
const uint32_t _8xq[8] asm("_8xq") __attribute__((aligned(32)))
  = {Q, Q, Q, Q, Q, Q, Q, Q};
const uint32_t _8x2q[8] asm("_8x2q") __attribute__((aligned(32)))
  = {2*Q, 2*Q, 2*Q, 2*Q, 2*Q, 2*Q, 2*Q, 2*Q};
const uint32_t _8x256q[8] asm("_8x256q")  __attribute__((aligned(32)))
  = {256*Q, 256*Q, 256*Q, 256*Q, 256*Q, 256*Q, 256*Q, 256*Q};
const uint32_t _mask[8] asm("_mask") __attribute__((aligned(32)))
  = {0, 2, 4, 6, 0, 0, 0, 0};
const uint32_t _8x23ones[8] asm("_8x23ones") __attribute__((aligned(32)))
  = {0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF,
     0x7FFFFF};
const uint32_t _8xdiv[8] asm("_8xdiv") __attribute__((aligned(32))) = {DIV, DIV, DIV, DIV, DIV, DIV, DIV, DIV};

#undef QINV
#undef MONT
#undef DIV

const uint32_t zetas[N] __attribute__((aligned(32))) = {0, 25847, 5771523, 7861508, 237124, 7602457, 7504169, 466468, 1826347, 2725464, 1024112, 2706023, 95776, 3077325, 3530437, 4450022, 4702672, 6927966, 2176455, 6851714, 5339162, 3475950, 6795196, 2091667, 5037939, 266997, 4860065, 3407706, 2244091, 2434439, 4621053, 2316500, 5933984, 7144689, 7183191, 3817976, 4817955, 3513181, 5187039, 2353451, 7300517, 3585928, 6718724, 4788269, 5842901, 3915439, 7122806, 4296819, 5190273, 4747489, 1939314, 7380215, 5223087, 126922, 900702, 495491, 7725090, 4823422, 1859098, 6767243, 5257975, 7855319, 909542, 8337157, 2031748, 7611795, 819034, 7857917, 3207046, 4784579, 8021166, 7830929, 7260833, 4519302, 5336701, 3574422, 5512770, 3412210, 2147896, 5412772, 7969390, 7396998, 2715295, 4686924, 5903370, 342297, 3437287, 2842341, 4055324, 286988, 5038140, 2691481, 1247620, 5942594, 1735879, 5790267, 2486353, 4108315, 203044, 1265009, 1595974, 6288512, 2619752, 6271868, 3539968, 8079950, 2348700, 7841118, 7709315, 8357436, 7998430, 1852771, 7151892, 7072248, 1349076, 6949987, 4613401, 5386378, 7047359, 7929317, 1250494, 1869119, 1237275, 1312455, 2635921, 1903435, 5062207, 3306115, 4832145, 7329447, 6950192, 6417775, 3119733, 6262231, 4520680, 6681150, 6736599, 3505694, 4558682, 5037034, 508951, 44288, 904516, 264944, 3097992, 7280319, 3958618, 7100756, 1500165, 7838005, 5796124, 1917081, 777191, 5548557, 4656147, 5834105, 2235880, 6709241, 594136, 7005614, 3406031, 6533464, 4603424, 5495562, 6980856, 5102745, 3507263, 6239768, 6779997, 3699596, 4656075, 1653064, 2389356, 759969, 8371839, 5130689, 8169440, 7063561, 6366809, 1957272, 5196991, 810149, 2432395, 3369112, 162844, 1652634, 2454455, 185531, 1616392, 4686184, 8215696, 7173032, 3014001, 6581310, 3111497, 1757237, 8360995, 811944, 531354, 954230, 3881043, 189548, 3159746, 5971092, 1315589, 4827145, 6529015, 8202977, 1341330, 5341501, 2213111, 7953734, 6712985, 3523897, 7404533, 1723600, 7276084, 3866901, 1717735, 6577327, 8119771, 269760, 472078, 1910376, 4546524, 2680103, 4010497, 280005, 3900724, 5823537, 2071892, 5582638, 1285669, 7567685, 5361315, 4751448, 6795489, 6940675, 4499357, 3839961, 5441381, 183443, 7826001, 3937738, 6144432, 7403526, 3919660, 1400424, 7959518, 1612842, 8332111, 7534263, 6094090, 4834730, 7018208, 1976782};

const uint32_t zetas_inv[N] __attribute__((aligned(32))) = {6403635, 1362209, 3545687, 2286327, 846154, 48306, 6767575, 420899, 6979993, 4460757, 976891, 2235985, 4442679, 554416, 8196974, 2939036, 4540456, 3881060, 1439742, 1584928, 3628969, 3019102, 812732, 7094748, 2797779, 6308525, 2556880, 4479693, 8100412, 4369920, 5700314, 3833893, 6470041, 7908339, 8110657, 260646, 1803090, 6662682, 4513516, 1104333, 6656817, 975884, 4856520, 1667432, 426683, 6167306, 3038916, 7039087, 177440, 1851402, 3553272, 7064828, 2409325, 5220671, 8190869, 4499374, 7426187, 7849063, 7568473, 19422, 6623180, 5268920, 1799107, 5366416, 1207385, 164721, 3694233, 6764025, 8194886, 5925962, 6727783, 8217573, 5011305, 5948022, 7570268, 3183426, 6423145, 2013608, 1316856, 210977, 3249728, 8578, 7620448, 5991061, 6727353, 3724342, 4680821, 1600420, 2140649, 4873154, 3277672, 1399561, 2884855, 3776993, 1846953, 4974386, 1374803, 7786281, 1671176, 6144537, 2546312, 3724270, 2831860, 7603226, 6463336, 2584293, 542412, 6880252, 1279661, 4421799, 1100098, 5282425, 8115473, 7475901, 8336129, 7871466, 3343383, 3821735, 4874723, 1643818, 1699267, 3859737, 2118186, 5260684, 1962642, 1430225, 1050970, 3548272, 5074302, 3318210, 6476982, 5744496, 7067962, 7143142, 6511298, 7129923, 451100, 1333058, 2994039, 3767016, 1430430, 7031341, 1308169, 1228525, 6527646, 381987, 22981, 671102, 539299, 6031717, 300467, 4840449, 2108549, 5760665, 2091905, 6784443, 7115408, 8177373, 4272102, 5894064, 2590150, 6644538, 2437823, 7132797, 5688936, 3342277, 8093429, 4325093, 5538076, 4943130, 8038120, 2477047, 3693493, 5665122, 983419, 411027, 2967645, 6232521, 4968207, 2867647, 4805995, 3043716, 3861115, 1119584, 549488, 359251, 3595838, 5173371, 522500, 7561383, 768622, 6348669, 43260, 7470875, 525098, 3122442, 1613174, 6521319, 3556995, 655327, 7884926, 7479715, 8253495, 3157330, 1000202, 6441103, 3632928, 3190144, 4083598, 1257611, 4464978, 2537516, 3592148, 1661693, 4794489, 1079900, 6026966, 3193378, 4867236, 3562462, 4562441, 1197226, 1235728, 2446433, 6063917, 3759364, 5945978, 6136326, 4972711, 3520352, 8113420, 3342478, 6288750, 1585221, 4904467, 3041255, 1528703, 6203962, 1452451, 3677745, 3930395, 4849980, 5303092, 8284641, 5674394, 7356305, 5654953, 6554070, 7913949, 876248, 777960, 8143293, 518909, 2608894, 3975713};