// logic of the application 


// tun_fd = tun_create(.....);

// below calls socket() and connect()
// client_fd = tcp_client(server details); client side

// client_fd = accept(...)                 server side


// below calls socket() bind() and listen()
// listen_fd = tcp_listener(....)






////////// so here's what event_loop does 

static int event_loop(Context *context)
{
//    struct pollfd *const fds = context->fds;
//    Buf                  tun_buf;
//    Buf *                client_buf = &context->client_buf;
//    ssize_t              len;
//    int                  found_fds;
//    int                  new_client_fd;
//
//    if (exit_signal_received != 0) {
//        return -2;
//    }


// below how pollfd works
//####################################################################################################
//
//          struct pollfd {
//               int   fd;         /* file descriptor */
//               short events;     /* requested events */
//               short revents;    /* returned events */
//           };
//
//           POLLIN - data to read
//
//           int nfds, num_open_fds;
//           struct pollfd *pfds;
//
//           pfds = calloc(nfds, sizeof(struct pollfd));
//
//           for (int j = 0; j < nfds; j++) {
//               pfds[j].fd = open(argv[j + 1], O_RDONLY);
//               pfds[j].events = POLLIN;
//           }
//
//           while (num_open_fds > 0) {
//               int ready;
//
//               ready = poll(pfds, nfds, -1);
//               if (ready == -1) errExit("poll");
//
//               for (int j = 0; j < nfds; j++) {
//                   char buf[10];
//
//                   if (pfds[j].revents != 0) {
//
//                       if (pfds[j].revents & POLLIN) {
//                           ssize_t s = read(pfds[j].fd, buf, sizeof(buf));
//                       } else {                /* POLLERR | POLLHUP */
//                           if (close(pfds[j].fd) == -1) errExit("close");
//                           num_open_fds--;
//                       }
//                   }
//               }
//           }
//
//####################################################################################################


//# can happen on server only
//if client wants to connect:
//    accept connection
//
//if got sth on tun socket:
//    read from tun socket and encrypt
//    write into client socket # on client side it goes out to server, on server side to client
//
//if got sth on client socket:
//    read and decrypt  # on client side it's from server, on server side from client
//    write into tun socket


/*
    if ((found_fds = poll(fds, POLLFD_COUNT, 1500)) == -1) {
        return errno == EINTR ? 0 : -1;
    }

    // accepting a new client
    if (fds[POLLFD_LISTENER].revents & POLLIN) {
        new_client_fd = tcp_accept(context, context->listen_fd);
        if (context->client_fd != -1) // ...
        context->client_fd = new_client_fd;
        client_buf->pos    = 0;
        memset(client_buf->data, 0, sizeof client_buf->data);
        fds[POLLFD_CLIENT] = (struct pollfd){ .fd = context->client_fd, .events = POLLIN };
    }

    if (fds[POLLFD_TUN].revents & POLLIN) {
        len = tun_read(context->tun_fd, tun_buf.data, sizeof tun_buf.data);
        if (context->client_fd != -1) {
            unsigned char tag_full[16];
            ssize_t       writenb;
            uint16_t      binlen = endian_swap16((uint16_t) len);

            memcpy(tun_buf.len, &binlen, 2);
            uc_encrypt(context->uc_st[0], tun_buf.data, len, tag_full);
            memcpy(tun_buf.tag, tag_full, TAG_LEN);
            writenb = safe_write_partial(context->client_fd, tun_buf.len, 2U + TAG_LEN + len);
            if (writenb < (ssize_t) 0) {
                context->congestion = 1;
                writenb             = (ssize_t) 0;
            }
            if (writenb != (ssize_t)(2U + TAG_LEN + len)) {
                writenb = safe_write(context->client_fd, tun_buf.len + writenb,
                                     2U + TAG_LEN + len - writenb, TIMEOUT);
            }
        }
    }

    // client disconnected
    if ((fds[POLLFD_CLIENT].revents & POLLERR) || (fds[POLLFD_CLIENT].revents & POLLHUP)) {
    }

    if (fds[POLLFD_CLIENT].revents & POLLIN) {
        uint16_t binlen;
        size_t   len_with_header;
        ssize_t  readnb;

        if ((readnb = safe_read_partial(context->client_fd, client_buf->len + client_buf->pos,
                                        2 + TAG_LEN + MAX_PACKET_LEN - client_buf->pos)) <= 0) {
            puts("Client disconnected");
            return client_reconnect(context);
        }
        client_buf->pos += readnb;
        while (client_buf->pos >= 2 + TAG_LEN) {
            memcpy(&binlen, client_buf->len, 2);
            len = (ssize_t) endian_swap16(binlen);
            if (client_buf->pos < (len_with_header = 2 + TAG_LEN + (size_t) len)) {
                break;
            }
            if (uc_decrypt(context->uc_st[1], client_buf->data, len, client_buf->tag, TAG_LEN) !=
                0) {
                fprintf(stderr, "Corrupted stream\n");
                sleep(1);
                return client_reconnect(context);
            }
            if (tun_write(context->tun_fd, client_buf->data, len) != len) {
                perror("tun_write");
            }
            if (2 + TAG_LEN + MAX_PACKET_LEN != len_with_header) {
                unsigned char *rbuf      = client_buf->len;
                size_t         remaining = client_buf->pos - len_with_header, i;
                for (i = 0; i < remaining; i++) {
                    rbuf[i] = rbuf[len_with_header + i];
                }
            }
            client_buf->pos -= len_with_header;
        }
    }
    return 0;
}
*/



////////// so here's what doit does 

static int doit(Context *context)
{
//    below client_reconnect calls client_connect which in turn calls tcp_client
//    if (context->is_server) {
//        if ((context->listen_fd = tcp_listener(....)) == -1) {
//            return -1;
//        }
//        context->fds[POLLFD_LISTENER] =  .....  = context->listen_fd ..... ;
//    }
//    if (!context->is_server && client_reconnect(context) != 0) {
//        return -1;
//    }
//    while (event_loop(context) == 0)
//        ;
//    return 0;
}



////////// so here's what main does 

int main(int argc, char *argv[])
{
/*
    configure stuff

    doit(&context)

    // below happens in doit
    while (event_loop(context) == 0)
        ;
*/

    return 0;
}



