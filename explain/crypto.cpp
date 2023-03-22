// cryptographic stuff



void uc_state_init(uint32_t st[12], const unsigned char key[32], const unsigned char iv[16])
{
    memcpy(&st[0], iv, 16);
    memcpy(&st[4], key, 32);
    endian_swap_all(st);
    permute(st);
}



///////////////////////////////////////////////////////////////////////////////////////////////////////////////////


typedef struct Context_ {
    // blablabla
    // blablabla
    uint32_t      uc_kx_st[12]; // 12 * 32 bits = 384 bits = 48 bytes
    uint32_t      uc_st[2][12]; // 2 * 384
} Context;


static void client_disconnect(Context *context)
{
    if (context->client_fd == -1) {
        return;
    }
    (void) close(context->client_fd);
    context->client_fd          = -1;
    context->fds[POLLFD_CLIENT] = (struct pollfd){ .fd = -1, .events = 0 };
    memset(context->uc_st, 0, sizeof context->uc_st);
}

static int server_key_exchange(Context *context, const int client_fd)
{
    uint32_t st[12];
    uint8_t  pkt1[32 + 8 + 32], pkt2[32 + 32];
    uint8_t  h[32];
    uint8_t  k[32];
    uint8_t  iv[16] = { 0 };
    uint64_t ts, now;

    memcpy(st, context->uc_kx_st, sizeof st);
    errno = EACCES;
    if (safe_read(client_fd, pkt1, sizeof pkt1, ACCEPT_TIMEOUT) != sizeof pkt1) {
        return -1;
    }
    uc_hash(st, h, pkt1, 32 + 8);
    if (memcmp(h, pkt1 + 32 + 8, 32) != 0) {
        return -1;
    }
    memcpy(&ts, pkt1 + 32, 8);
    ts  = endian_swap64(ts);
    now = time(NULL);
    if ((ts > now && ts - now > TS_TOLERANCE) || (now > ts && now - ts > TS_TOLERANCE)) {
        fprintf(stderr,
                "Clock difference is too large: %" PRIu64 " (client) vs %" PRIu64 " (server)\n", ts,
                now);
        return -1;
    }
    uc_randombytes_buf(pkt2, 32);
    uc_hash(st, pkt2 + 32, pkt2, 32);
    if (safe_write_partial(client_fd, pkt2, sizeof pkt2) != sizeof pkt2) {
        return -1;
    }
    // ??
    uc_hash(st, k, NULL, 0);
    iv[0] = context->is_server;
    uc_state_init(context->uc_st[0], k, iv);
    iv[0] ^= 1;
    uc_state_init(context->uc_st[1], k, iv);

    return 0;
}

static int tcp_accept(Context *context, int listen_fd)
{
    if ((client_fd = accept(listen_fd, (struct sockaddr *) &client_ss, &client_ss_len)) < 0) {
        return -1;
    }
    if (server_key_exchange(context, client_fd) != 0) {
        fprintf(stderr, "Authentication failed\n");
        (void) close(client_fd);
        errno = EACCES;
        return -1;
    }
}

static int client_key_exchange(Context *context)
{
    uint32_t st[12];
    // 32 + 8 + 32 = 72   32 + 32 = 64
    uint8_t  pkt1[32 + 8 + 32], pkt2[32 + 32];
    uint8_t  h[32];
    uint8_t  k[32];
    uint8_t  iv[16] = { 0 };
    uint64_t now;

    // uc_kx_st ---> st
    memcpy(st, context->uc_kx_st, sizeof st);

    // pkt1 ---> randombytes (0...32) + now (32...40)
    uc_randombytes_buf(pkt1, 32);
    now = endian_swap64(time(NULL));
    memcpy(pkt1 + 32, &now, 8);
    // pkt1 ---> randombytes (0...32) + now (32...40) + hash_of(pkt1[0:40]) (40:72)
    uc_hash(st, pkt1 + 32 + 8, pkt1, 32 + 8);

    // server will check if hash(pkt1[0:40]) == pkt[40:72]
    // in response server will compute its own hash and send it over so client can verify 
    if (safe_write(context->client_fd, pkt1, sizeof pkt1, TIMEOUT) != sizeof pkt1) {
        return -1;
    }
    errno = EACCES;

    if (safe_read(context->client_fd, pkt2, sizeof pkt2, TIMEOUT) != sizeof pkt2) {
        return -1;
    }
    uc_hash(st, h, pkt2, 32);
    if (memcmp(h, pkt2 + 32, 32) != 0) {
        return -1;
    }
    // ??
    uc_hash(st, k, NULL, 0);
    iv[0] = context->is_server;
    uc_state_init(context->uc_st[0], k, iv);
    iv[0] ^= 1;
    uc_state_init(context->uc_st[1], k, iv);

    return 0;
}

static int client_connect(Context *context)
{
    memset(context->uc_st, 0, sizeof context->uc_st);
    context->uc_st[context->is_server][0] ^= 1;
    context->client_fd = tcp_client(context->server_ip, context->server_port);
    if (client_key_exchange(context) != 0) {
        fprintf(stderr, "Authentication failed\n");
        client_disconnect(context);
        sleep(1);
        return -1;
    }
    return 0;
}


static int event_loop(Context *context)
{
    if (fds[POLLFD_TUN].revents & POLLIN) {

            memcpy(tun_buf.len, &binlen, 2);
            uc_encrypt(context->uc_st[0], tun_buf.data, len, tag_full);
            memcpy(tun_buf.tag, tag_full, TAG_LEN);
            writenb = safe_write_partial(context->client_fd, tun_buf.len, 2U + TAG_LEN + len);
    }

    if (fds[POLLFD_CLIENT].revents & POLLIN) {
        while (client_buf->pos >= 2 + TAG_LEN) {
            if (uc_decrypt(context->uc_st[1], client_buf->data, len, client_buf->tag, TAG_LEN) !=
                0) {
                fprintf(stderr, "Corrupted stream\n");
                sleep(1);
                return client_reconnect(context);
            }
            if (tun_write(context->tun_fd, client_buf->data, len) != len)
                perror("tun_write");
        }
    }
    return 0;
}


static int load_key_file(Context *context, const char *file)
{
    unsigned char key[32];
    int           fd;

    if ((fd = open(file, O_RDONLY)) == -1) {
        return -1;
    }
    if (safe_read(fd, key, sizeof key, -1) != sizeof key) {
        (void) close(fd);
        return -1;
    }
    uc_state_init(context->uc_kx_st, key, (const unsigned char *) "VPN Key Exchange");
    uc_memzero(key, sizeof key);

    return close(fd);
}


int main(int argc, char *argv[])
{
    if (load_key_file(&context, argv[2]) != 0) {
        fprintf(stderr, "Unable to load the key file [%s]\n", argv[2]);
        return 1;
    }
}


