#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pico/stdlib.h"
#include "hardware/pwm.h"
#include "pico/cyw43_arch.h"
#include "lwip/tcp.h"

#define WIFI_SSID "Tesla"
#define WIFI_PASSWORD "123456788"

#define LED_RED_PIN 13
#define LED_GREEN_PIN 11
#define LED_BLUE_PIN 12

uint slice_r, slice_g, slice_b;
uint channel_r, channel_g, channel_b;

// Variáveis globais para armazenar o valor atual de RGB
int current_r = 0, current_g = 0, current_b = 0;

char* get_param(char* query, const char* key) {
    char* match = strstr(query, key);
    if (!match) return NULL;

    match += strlen(key);
    if (*match != '=') return NULL;
    match++;

    char* end = strchr(match, '&');
    size_t len = end ? (size_t)(end - match) : strlen(match);

    char* value = malloc(len + 1);
    strncpy(value, match, len);
    value[len] = '\0';
    return value;
}

void user_request_rgb(char *request) {
    char* r_str = get_param(request, "r");
    char* g_str = get_param(request, "g");
    char* b_str = get_param(request, "b");

    if (r_str) current_r = atoi(r_str);
    if (g_str) current_g = atoi(g_str);
    if (b_str) current_b = atoi(b_str);

    free(r_str); free(g_str); free(b_str);

    pwm_set_chan_level(slice_r, channel_r, current_r);
    pwm_set_chan_level(slice_g, channel_g, current_g);
    pwm_set_chan_level(slice_b, channel_b, current_b);

    printf("R:%d G:%d B:%d\n", current_r, current_g, current_b);
}

void gpio_pwm_init(uint pin, uint* slice, uint* channel) {
    gpio_set_function(pin, GPIO_FUNC_PWM);
    *slice = pwm_gpio_to_slice_num(pin);
    *channel = pwm_gpio_to_channel(pin);
    pwm_set_wrap(*slice, 255);
    pwm_set_chan_level(*slice, *channel, 0);
    pwm_set_enabled(*slice, true);
}


static err_t tcp_server_recv(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err) {
    if (!p) {
        tcp_close(tpcb);
        return ERR_OK;
    }

    char *req = calloc(p->len + 1, sizeof(char));
    memcpy(req, p->payload, p->len);
    req[p->len] = '\0';

    printf("Request: %s\n", req);

    if (strstr(req, "GET /status") != NULL) {
        // Envia resposta JSON com código de verificação e valores RGB
        char json_response[200];
        snprintf(json_response, sizeof(json_response),
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
            "{\"codigo\":\"123456788\",\"r\":%d,\"g\":%d,\"b\":%d}",
            current_r, current_g, current_b);
        tcp_write(tpcb, json_response, strlen(json_response), TCP_WRITE_FLAG_COPY);
    } else {
        // Trata o comando RGB normal
        user_request_rgb(req);
        const char *response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nOK";
        tcp_write(tpcb, response, strlen(response), TCP_WRITE_FLAG_COPY);
    }

    pbuf_free(p);
    free(req);
    return ERR_OK;
}



static err_t tcp_server_accept(void *arg, struct tcp_pcb *newpcb, err_t err) {
    tcp_recv(newpcb, tcp_server_recv);
    return ERR_OK;
}

int main() {
    stdio_init_all();

    if (cyw43_arch_init()) {
        printf("Erro ao iniciar Wi-Fi\n");
        return -1;
    }

    cyw43_arch_enable_sta_mode();

    if (cyw43_arch_wifi_connect_timeout_ms(WIFI_SSID, WIFI_PASSWORD, CYW43_AUTH_WPA2_AES_PSK, 30000)) {
        printf("Erro ao conectar no Wi-Fi\n");
        return -1;
    }

    printf("Conectado com IP: %s\n", ipaddr_ntoa(&netif_default->ip_addr));

    gpio_pwm_init(LED_RED_PIN, &slice_r, &channel_r);
    gpio_pwm_init(LED_GREEN_PIN, &slice_g, &channel_g);
    gpio_pwm_init(LED_BLUE_PIN, &slice_b, &channel_b);

    struct tcp_pcb *server = tcp_new();
    tcp_bind(server, IP_ADDR_ANY, 80);
    server = tcp_listen(server);
    tcp_accept(server, tcp_server_accept);

    while (true) {
        cyw43_arch_poll();
        sleep_ms(100);
    }

    cyw43_arch_deinit();
    return 0;
}
